//go:build darwin || linux

package container

import (
	"context"
	"encoding/json"
	"fmt"
	osexec "os/exec"
	"regexp"
	"strings"
	"time"

	iexec "github.com/Anvil-Cloud-AI/anvil-scanner/internal/exec"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
)

// imageScanTimeout bounds a single image scan. Generous because the scanner
// may pull the image (for registry refs) before analyzing layers.
const imageScanTimeout = 180 * time.Second

// ImageCVE is one known vulnerability in a scanned image.
type ImageCVE struct {
	ID       string // CVE-… or GHSA-…
	Severity string // CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN (normalized uppercase)
	Package  string
	Version  string
	FixedIn  string  // fixed version(s), empty when none published
	Risk     float64 // grype composite risk (EPSS+KEV); 0 for trivy/unavailable
}

// ImageScan is the CVE result for a single image reference.
type ImageScan struct {
	Ref      string
	Findings []ImageCVE
	Error    string // non-empty when this image could not be scanned
}

// ImageCVEResult is the output of an image CVE pass.
type ImageCVEResult struct {
	Scanner    string // "grype" | "trivy" | ""
	Scans      []ImageScan
	Skipped    bool
	SkipReason string
}

// selectScanner returns the preferred CVE scanner on PATH: grype first (for
// its EPSS+KEV composite risk score), then trivy, then "" when neither exists.
func selectScanner() string {
	for _, bin := range []string{"grype", "trivy"} {
		if _, err := osexec.LookPath(bin); err == nil {
			return bin
		}
	}
	return ""
}

// ScanImages runs an image CVE pass. The images of all running containers are
// scanned automatically; extraRefs adds explicit references (e.g. registry
// images that are not running locally — the scanner pulls them).
//
// Behavior:
//   - No scanner on PATH      → Skipped result with an install hint.
//   - Scanner present, no refs → empty (non-skipped) result.
//   - Otherwise               → one ImageScan per deduplicated ref; a failure
//     on one image is captured in ImageScan.Error and never aborts the rest.
func ScanImages(ctx context.Context, extraRefs []string) *ImageCVEResult {
	scanner := selectScanner()
	if scanner == "" {
		return &ImageCVEResult{
			Skipped:    true,
			SkipReason: "neither grype nor trivy found on PATH — install one to enable image CVE scanning",
		}
	}

	var refs []string
	if bin := detectRuntime(); bin != "" {
		refs = runningImages(bin)
	}
	refs = dedupe(append(refs, extraRefs...))

	res := &ImageCVEResult{Scanner: scanner}
	for _, ref := range refs {
		// Stop promptly if the run was cancelled (e.g. SIGINT) rather than
		// kicking off another scanner subprocess.
		if ctx.Err() != nil {
			break
		}
		// Refs discovered from the runtime are external data too — validate
		// every ref (not just --scan-image ones) before it reaches the
		// scanner, so a hostile image name can't smuggle in scanner flags.
		if err := ValidateImageRef(ref); err != nil {
			res.Scans = append(res.Scans, ImageScan{Ref: ref, Error: "skipped: " + err.Error()})
			continue
		}
		res.Scans = append(res.Scans, scanOne(ctx, scanner, ref))
	}
	return res
}

// scanOne scans a single image reference with the chosen scanner. The parent
// context is honored (e.g. Ctrl-C cancels an in-flight image pull); the
// per-image timeout is layered on top as a ceiling.
//
// The image ref is placed after a "--" separator so a ref that begins with a
// dash cannot be reinterpreted as a scanner flag (defense in depth alongside
// validateImageRef). Scanner flags must therefore precede the "--".
func scanOne(ctx context.Context, scanner, ref string) ImageScan {
	ctx, cancel := context.WithTimeout(ctx, imageScanTimeout)
	defer cancel()

	var r iexec.Result
	switch scanner {
	case "grype":
		r = iexec.RunCtx(ctx, nil, "grype", "-o", "json", "--", ref)
	case "trivy":
		r = iexec.RunCtx(ctx, nil, "trivy", "image", "--quiet", "-f", "json", "--", ref)
	}

	if r.TimedOut {
		return ImageScan{Ref: ref, Error: fmt.Sprintf("%s timed out after %ds", scanner, int(imageScanTimeout.Seconds()))}
	}
	// grype exits non-zero by default when vulnerabilities are found, but still
	// prints valid JSON, so parse stdout regardless of exit code and only treat
	// it as an error when nothing parseable came back.
	cves, err := parse(scanner, r.Stdout)
	if err != nil {
		detail := strings.TrimSpace(r.Stderr)
		if detail == "" {
			detail = err.Error()
		}
		if len(detail) > 200 {
			detail = detail[:200]
		}
		return ImageScan{Ref: ref, Error: fmt.Sprintf("%s failed (exit %d): %s", scanner, r.ExitCode, detail)}
	}
	return ImageScan{Ref: ref, Findings: cves}
}

func parse(scanner, stdout string) ([]ImageCVE, error) {
	switch scanner {
	case "grype":
		return parseGrype(stdout)
	case "trivy":
		return parseTrivy(stdout)
	}
	return nil, fmt.Errorf("unknown scanner %q", scanner)
}

// grypeDoc captures the subset of grype's JSON we consume. Unknown fields are
// ignored by encoding/json.
type grypeDoc struct {
	Matches []struct {
		Vulnerability struct {
			ID       string  `json:"id"`
			Severity string  `json:"severity"`
			Risk     float64 `json:"risk"`
			Fix      struct {
				Versions []string `json:"versions"`
			} `json:"fix"`
		} `json:"vulnerability"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"artifact"`
	} `json:"matches"`
}

func parseGrype(stdout string) ([]ImageCVE, error) {
	var doc grypeDoc
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		return nil, fmt.Errorf("parse grype json: %w", err)
	}
	out := make([]ImageCVE, 0, len(doc.Matches))
	for _, m := range doc.Matches {
		out = append(out, ImageCVE{
			ID:       m.Vulnerability.ID,
			Severity: normalizeSeverity(m.Vulnerability.Severity),
			Package:  m.Artifact.Name,
			Version:  m.Artifact.Version,
			FixedIn:  strings.Join(m.Vulnerability.Fix.Versions, ", "),
			Risk:     m.Vulnerability.Risk,
		})
	}
	return out, nil
}

// trivyDoc captures the subset of trivy's JSON we consume.
type trivyDoc struct {
	Results []struct {
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			Severity         string `json:"Severity"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func parseTrivy(stdout string) ([]ImageCVE, error) {
	var doc trivyDoc
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		return nil, fmt.Errorf("parse trivy json: %w", err)
	}
	var out []ImageCVE
	for _, res := range doc.Results {
		for _, v := range res.Vulnerabilities {
			out = append(out, ImageCVE{
				ID:       v.VulnerabilityID,
				Severity: normalizeSeverity(v.Severity),
				Package:  v.PkgName,
				Version:  v.InstalledVersion,
				FixedIn:  v.FixedVersion,
			})
		}
	}
	return out, nil
}

// RunImageCVECheck emits a single rollup check (CONTAINER-CVE) so that image
// CVE severity reaches the Priority Findings filter and the JSON output
// without flooding the check list with one row per CVE. The detailed table
// lives in the HTML report's Containers section.
func RunImageCVECheck(b *scan.CheckBuilder, r *ImageCVEResult) {
	const id = "CONTAINER-CVE"
	const name = "Container images free of critical/high CVEs"
	// Severity is policy-fixed per check ID regardless of status (see
	// scan.Check docs): a critical/high CVE is a critical finding, so the
	// rollup is always Critical. Only the Status varies. This keeps a WARN
	// (high-only) result promotable into Priority Findings.
	const sev = scan.SeverityCritical

	if r == nil || r.Skipped {
		reason := "image CVE scanning skipped"
		if r != nil && r.SkipReason != "" {
			reason = r.SkipReason
		}
		b.Skip(id, name, reason, sev)
		return
	}
	if len(r.Scans) == 0 {
		b.Skip(id, name, "no container images found to scan", sev)
		return
	}

	crit, high, total := r.SeverityCounts()
	switch {
	case crit > 0:
		b.Fail(id, name, fmt.Sprintf("%d critical and %d high CVE(s) across %d image(s) — see the Containers section",
			crit, high, len(r.Scans)), sev)
	case high > 0:
		b.Warn(id, name, fmt.Sprintf("%d high-severity CVE(s) across %d image(s) — see the Containers section",
			high, len(r.Scans)), sev)
	default:
		b.Pass(id, name, fmt.Sprintf("No critical/high CVEs across %d image(s) (%d finding(s) total)",
			len(r.Scans), total), sev)
	}
}

// SeverityCounts returns the number of CRITICAL and HIGH findings plus the
// total finding count across all scanned images.
func (r *ImageCVEResult) SeverityCounts() (crit, high, total int) {
	for _, s := range r.Scans {
		for _, f := range s.Findings {
			total++
			switch f.Severity {
			case "CRITICAL":
				crit++
			case "HIGH":
				high++
			}
		}
	}
	return crit, high, total
}

func normalizeSeverity(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return s
	default:
		return "UNKNOWN"
	}
}

// maxImageRefLen bounds an image reference. Real refs are well under this;
// the cap guards against absurd inputs bloating error messages and the report.
const maxImageRefLen = 512

// imageRefRE matches the characters legal in an OCI image reference
// (registry host, path, tag, and @digest). Anything outside this set — or a
// leading dash — is rejected to prevent argument injection into grype/trivy.
var imageRefRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.\-/:@]*$`)

// ValidateImageRef reports whether ref is a syntactically plausible image
// reference safe to pass to an external scanner. It is intentionally strict:
// it rejects flag-like and shell-meta inputs rather than trying to sanitize.
func ValidateImageRef(ref string) error {
	switch {
	case ref == "":
		return fmt.Errorf("image ref is empty")
	case len(ref) > maxImageRefLen:
		return fmt.Errorf("image ref exceeds %d characters", maxImageRefLen)
	case strings.HasPrefix(ref, "-"):
		return fmt.Errorf("image ref %q looks like a flag argument", ref)
	case !imageRefRE.MatchString(ref):
		return fmt.Errorf("image ref %q contains invalid characters", ref)
	}
	return nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
