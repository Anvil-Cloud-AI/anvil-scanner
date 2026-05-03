//go:build darwin || linux

package threat

import (
	"fmt"
	"regexp"
	"runtime"
	"strings"

	iexec "github.com/Anvil-Cloud-AI/anvil-scanner/internal/exec"
)

// cveEntry describes one CVE record in the bundled database.
type cveEntry struct {
	CVE          string
	AffectedBelow string
	Severity     string
	Desc         string
}

// knownCVEs is the curated vulnerability database, ported from the Python reference.
var knownCVEs = map[string][]cveEntry{
	"openssh-server": {
		{CVE: "CVE-2024-6387", AffectedBelow: "9.8", Severity: "CRITICAL",
			Desc: "regreSSHion — race condition allows unauthenticated RCE"},
	},
	"openssh-client": {
		{CVE: "CVE-2024-6387", AffectedBelow: "9.8", Severity: "CRITICAL",
			Desc: "regreSSHion — race condition allows unauthenticated RCE"},
	},
	"openssl": {
		{CVE: "CVE-2024-5535", AffectedBelow: "3.0.14", Severity: "HIGH",
			Desc: "SSL_select_next_proto buffer overread"},
		{CVE: "CVE-2024-0727", AffectedBelow: "3.0.13", Severity: "HIGH",
			Desc: "PKCS12 NULL dereference denial of service"},
	},
	"libssl3": {
		{CVE: "CVE-2024-5535", AffectedBelow: "3.0.14", Severity: "HIGH",
			Desc: "SSL_select_next_proto buffer overread"},
	},
	"curl": {
		{CVE: "CVE-2024-2398", AffectedBelow: "8.6.0", Severity: "HIGH",
			Desc: "HTTP/2 push headers memory leak"},
		{CVE: "CVE-2023-38545", AffectedBelow: "8.4.0", Severity: "CRITICAL",
			Desc: "SOCKS5 heap buffer overflow"},
	},
	"libcurl4": {
		{CVE: "CVE-2024-2398", AffectedBelow: "8.6.0", Severity: "HIGH",
			Desc: "HTTP/2 push headers memory leak"},
	},
	"sudo": {
		{CVE: "CVE-2023-22809", AffectedBelow: "1.9.12p2", Severity: "HIGH",
			Desc: "sudoedit arbitrary file write via EDITOR"},
	},
	"polkit": {
		{CVE: "CVE-2021-4034", AffectedBelow: "0.120", Severity: "CRITICAL",
			Desc: "PwnKit — local privilege escalation via pkexec"},
	},
	"nginx": {
		{CVE: "CVE-2024-7347", AffectedBelow: "1.27.1", Severity: "HIGH",
			Desc: "mp4 module buffer overread"},
	},
	"apache2": {
		{CVE: "CVE-2024-38476", AffectedBelow: "2.4.62", Severity: "HIGH",
			Desc: "Server-side request forgery via mod_rewrite"},
		{CVE: "CVE-2023-25690", AffectedBelow: "2.4.56", Severity: "CRITICAL",
			Desc: "HTTP request smuggling via mod_proxy"},
	},
	"linux-image-generic": {
		{CVE: "CVE-2024-1086", AffectedBelow: "6.6.15", Severity: "CRITICAL",
			Desc: "nf_tables use-after-free local privilege escalation"},
	},
	"bind9": {
		{CVE: "CVE-2023-50387", AffectedBelow: "9.18.24", Severity: "HIGH",
			Desc: "KeyTrap — DNSSEC validation CPU exhaustion DoS"},
	},
	"systemd": {
		{CVE: "CVE-2023-26604", AffectedBelow: "247.3", Severity: "HIGH",
			Desc: "systemd-coredump privilege escalation via less pager"},
	},
	"git": {
		{CVE: "CVE-2024-32002", AffectedBelow: "2.45.1", Severity: "CRITICAL",
			Desc: "Remote code execution via recursive clone with symlinks"},
	},
	"xz-utils": {
		{CVE: "CVE-2024-3094", AffectedBelow: "5.6.0", Severity: "CRITICAL",
			Desc: "Supply chain backdoor in XZ Utils (affected 5.6.0-5.6.1)"},
	},
	"glibc": {
		{CVE: "CVE-2023-4911", AffectedBelow: "2.39", Severity: "CRITICAL",
			Desc: "Looney Tunables — buffer overflow in ld.so GLIBC_TUNABLES"},
	},
	"libc6": {
		{CVE: "CVE-2023-4911", AffectedBelow: "2.39", Severity: "CRITICAL",
			Desc: "Looney Tunables — buffer overflow in ld.so GLIBC_TUNABLES"},
	},
}

// getPkgVersion returns the installed version of pkg on the current platform,
// or an empty string if the package is not installed or the tool is unavailable.
func getPkgVersion(pkg string) string {
	if runtime.GOOS == "linux" {
		res := iexec.Run("dpkg", "-l", pkg)
		if res.Success() {
			for _, line := range strings.Split(res.Stdout, "\n") {
				if strings.HasPrefix(line, "ii") {
					parts := strings.Fields(line)
					if len(parts) >= 3 {
						return parts[2]
					}
				}
			}
		}
	} else if runtime.GOOS == "darwin" {
		res := iexec.Run("brew", "list", "--versions", pkg)
		if res.Success() && strings.TrimSpace(res.Stdout) != "" {
			parts := strings.Fields(strings.TrimSpace(res.Stdout))
			if len(parts) >= 2 {
				return parts[len(parts)-1]
			}
		}
	}
	return ""
}

// normalizeVersion strips epoch prefixes (e.g. "1:2.0" -> "2.0"), pre-release
// suffixes after '-', and build metadata after '+', leaving a plain dotted
// numeric version string suitable for comparison.
func normalizeVersion(v string) string {
	// Strip epoch (e.g. "2:1.0.3" -> "1.0.3")
	if idx := strings.Index(v, ":"); idx >= 0 {
		v = v[idx+1:]
	}
	// Take only the portion before the first '-' (Debian revision / pre-release).
	v = strings.SplitN(v, "-", 2)[0]
	// Strip +build metadata.
	v = strings.SplitN(v, "+", 2)[0]
	return v
}

var digitRE = regexp.MustCompile(`^(\d+)`)

// versionLT returns true when installed < threshold. It strips epoch prefixes
// (e.g. "1:9.7p1") and pre-release suffixes, then compares numeric dotted
// segments. No external packages are used.
func versionLT(installed, threshold string) bool {
	norm := func(v string) []int {
		v = normalizeVersion(v)

		var parts []int
		for _, seg := range strings.Split(v, ".") {
			m := digitRE.FindString(seg)
			if m == "" {
				break
			}
			n := 0
			fmt.Sscan(m, &n)
			parts = append(parts, n)
		}
		return parts
	}

	a := norm(installed)
	b := norm(threshold)

	// Compare element by element; treat missing segments as 0.
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	for i := 0; i < maxLen; i++ {
		var av, bv int
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av < bv {
			return true
		}
		if av > bv {
			return false
		}
	}
	return false // equal
}

// CheckCVEExposure cross-references installed packages against the curated
// CVE database and returns all findings.
func CheckCVEExposure() CVEResult {
	var findings []CVEFinding
	var packagesChecked []string

	for pkg, cves := range knownCVEs {
		version := getPkgVersion(pkg)
		if version == "" {
			continue
		}
		packagesChecked = append(packagesChecked, fmt.Sprintf("%s %s", pkg, version))

		for _, cve := range cves {
			// Special handling for XZ Utils supply-chain backdoor: the
			// backdoor was *in* 5.6.0-5.6.1, not in versions below 5.6.0.
			if cve.CVE == "CVE-2024-3094" {
				norm := normalizeVersion(version)
				if norm == "5.6.0" || norm == "5.6.1" {
					fix := fmt.Sprintf("Upgrade %s immediately — this version contains a known backdoor", pkg)
					findings = append(findings, CVEFinding{
						Package:  pkg,
						Version:  version,
						CVE:      cve.CVE,
						Severity: cve.Severity,
						Desc:     cve.Desc,
						Fix:      fix,
					})
				}
				continue
			}

			if versionLT(version, cve.AffectedBelow) {
				fix := fmt.Sprintf("Upgrade %s to >= %s", pkg, cve.AffectedBelow)
				if runtime.GOOS == "darwin" {
					fix += " (brew upgrade " + pkg + ")"
				}
				findings = append(findings, CVEFinding{
					Package:  pkg,
					Version:  version,
					CVE:      cve.CVE,
					Severity: cve.Severity,
					Desc:     cve.Desc,
					Fix:      fix,
				})
			}
		}
	}

	if findings == nil {
		findings = []CVEFinding{}
	}
	if packagesChecked == nil {
		packagesChecked = []string{}
	}

	return CVEResult{
		Findings:        findings,
		PackagesChecked: packagesChecked,
	}
}
