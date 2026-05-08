//go:build darwin || linux

package openclaw

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	iexec "github.com/Anvil-Cloud-AI/anvil-scanner/internal/exec"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
)

const (
	auditTimeout   = 30 * time.Second
	versionTimeout = 5 * time.Second

	skipID   = "OC-AUDIT-000"
	skipName = "OpenClaw security audit"
)

// Path fragments that identify each install channel. Matching is done on a
// lower-cased, forward-slash-normalised path to cover both POSIX and Windows.
var npmPathMarkers = []string{
	"/node_modules/",
	"/.npm/",
	"/npm/",
	"/yarn/global/",
	"/pnpm/global/",
}

var brewPathMarkers = []string{
	"/cellar/",
	"/opt/homebrew/",
	"/home/linuxbrew/",
	"/usr/local/opt/",
}

// Channel-specific upgrade commands that replace OpenClaw's generic
// "update openclaw" remediation text.
var upgradeCommands = map[string]string{
	"npm":    "npm update -g openclaw",
	"brew":   "brew upgrade openclaw",
	"source": "cd $OPENCLAW_SRC && git pull && make install",
	"unknown": "see https://openclaw.io/install for upgrade instructions",
}

// Triggers we recognise as generic "please update OpenClaw" copy. Kept narrow
// so we only touch remediation text we're confident is a version-bump
// instruction.
var genericUpdateTriggers = []string{
	"run `openclaw update`",
	"run openclaw update",
	"openclaw update",
	"update openclaw",
	"upgrade openclaw",
}

// Per-channel hints appended to a SKIP finding for failure modes that
// disproportionately affect a particular install channel.
var channelSkipHints = map[string]map[string]string{
	"npm": {
		"timeout": " (npm installs can be slow to warm up on the first run of the day; rerun once and see if it resolves)",
	},
}

// InstallInfo holds the result of DetectInstall.
type InstallInfo struct {
	// Channel is "npm", "brew", "source", or "unknown".
	Channel string
	// Version is the raw first line of `openclaw --version`, or "" if unknown.
	Version string
	// BinaryPath is the resolved absolute path of the openclaw binary,
	// or "" if it was not found on PATH.
	BinaryPath string
}

// sourceTag builds the "openclaw:<channel>:<version>" stamp attached to every
// finding. Downstream renderers use this to surface a release-channel badge.
func (i InstallInfo) sourceTag() string {
	v := i.Version
	if v == "" {
		v = "?"
	}
	return fmt.Sprintf("openclaw:%s:%s", i.Channel, v)
}

// DetectInstall detects the OpenClaw install channel, version, and binary
// path. It is a best-effort probe; a failure here never causes a scan failure.
func DetectInstall() InstallInfo {
	// Use `openclaw --version` as both the existence check and version probe.
	// If the binary is missing, ExitCode will be -1.
	ctx, cancel := context.WithTimeout(context.Background(), versionTimeout)
	defer cancel()

	res := iexec.RunCtx(ctx, nil, "openclaw", "--version")

	if res.ExitCode == -1 {
		// Binary not found.
		return InstallInfo{Channel: "unknown"}
	}

	// Try to extract the version string even on non-zero exits (some tools
	// write version to stderr with exit 1).
	raw := strings.TrimSpace(res.Stdout)
	if raw == "" {
		raw = strings.TrimSpace(res.Stderr)
	}
	var version string
	if raw != "" {
		version = strings.SplitN(raw, "\n", 2)[0]
		version = strings.TrimSpace(version)
	}

	// Determine the binary path via `which openclaw`.
	binaryPath := ""
	whichRes := iexec.Run("which", "openclaw")
	if whichRes.ExitCode == 0 {
		binaryPath = strings.TrimSpace(whichRes.Stdout)
	}

	// Detect channel from path markers first.
	normPath := strings.ToLower(strings.ReplaceAll(binaryPath, "\\", "/"))
	channel := channelFromPath(normPath)
	// If path heuristic was inconclusive, a dev/git-describe suffix in the
	// version string is a strong signal the user built from source.
	if channel == "unknown" && looksLikeSourceVersion(version) {
		channel = "source"
	}

	return InstallInfo{
		Channel:    channel,
		Version:    version,
		BinaryPath: binaryPath,
	}
}

// channelFromPath returns the install channel detected from a lower-cased,
// forward-slash-normalised binary path. Returns "unknown" when no marker
// matches. This is exported to the package so tests can call it directly
// with synthetic paths without spawning a subprocess.
func channelFromPath(normPath string) string {
	for _, marker := range npmPathMarkers {
		if strings.Contains(normPath, marker) {
			return "npm"
		}
	}
	for _, marker := range brewPathMarkers {
		if strings.Contains(normPath, marker) {
			return "brew"
		}
	}
	return "unknown"
}

// looksLikeSourceVersion returns true when version carries a suffix that
// typically only appears on source/dev builds.
func looksLikeSourceVersion(version string) bool {
	v := strings.ToLower(version)
	return strings.Contains(v, "-dev") ||
		strings.Contains(v, "-rc") ||
		strings.Contains(v, "-alpha") ||
		strings.Contains(v, "-beta") ||
		strings.Contains(v, "+g")
}

// TailorRemediation rewrites a generic "update openclaw" remediation string
// into the concrete command for the user's install channel. Unrelated text
// is returned unchanged.
func TailorRemediation(text, channel string) string {
	if text == "" {
		return text
	}
	lowered := strings.ToLower(text)
	for _, trigger := range genericUpdateTriggers {
		idx := strings.Index(lowered, trigger)
		if idx != -1 {
			cmd, ok := upgradeCommands[channel]
			if !ok {
				cmd = upgradeCommands["unknown"]
			}
			return text[:idx] + cmd + text[idx+len(trigger):]
		}
	}
	return text
}

// auditFinding is one entry in the findings list.
type auditFinding struct {
	CheckID     string `json:"checkId"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

// TranslateFinding translates one OpenClaw finding into a scan.Check and
// records it on b. Exported so tests can exercise the translation logic
// directly without a subprocess.
func TranslateFinding(b *scan.CheckBuilder, f auditFinding, install InstallInfo) {
	sev := strings.ToLower(f.Severity)

	var status scan.Status
	var severity scan.Severity
	switch sev {
	case "critical":
		status = scan.StatusFail
		severity = scan.SeverityCritical
	case "warn":
		status = scan.StatusWarn
		severity = scan.SeverityMedium
	case "info":
		status = scan.StatusPass
		severity = scan.SeverityLow
	default:
		status = scan.StatusSkip
		severity = scan.SeverityLow
	}

	detail := f.Detail
	if f.Remediation != "" {
		tailored := TailorRemediation(f.Remediation, install.Channel)
		if detail != "" {
			detail = detail + "\nFix: " + tailored
		} else {
			detail = "Fix: " + tailored
		}
	}

	sourceStamp := "Source: " + install.sourceTag()

	switch status {
	case scan.StatusPass:
		b.Pass(f.CheckID, f.Title, detail, severity)
	case scan.StatusFail:
		b.Fail(f.CheckID, f.Title, detail, severity)
	case scan.StatusWarn:
		b.Warn(f.CheckID, f.Title, detail, severity)
	default:
		b.Skip(f.CheckID, f.Title, detail, severity)
	}
	b.WithRemediation(sourceStamp)
}

// addSkip appends a single SKIP check with ID "OC-AUDIT-000" and the given
// detail message. The source stamp is derived from install.
func addSkip(b *scan.CheckBuilder, detail string, install InstallInfo) {
	b.Skip(skipID, skipName, detail, scan.SeverityLow)
	b.WithRemediation("Source: " + install.sourceTag())
}

// RunAudit runs `openclaw security audit --json` and translates findings into
// checks on b. If the binary is missing, times out, fails, or emits unexpected
// output, exactly one SKIP check is added so the broader scan can continue.
func RunAudit(b *scan.CheckBuilder) {
	install := DetectInstall()

	// Binary not found.
	if install.BinaryPath == "" && install.Version == "" {
		// Double-check by looking at whether ExitCode was -1 from DetectInstall.
		// DetectInstall returns BinaryPath="" and Version="" when the binary is
		// missing; that is the canonical "not found" signal.
		addSkip(b,
			"openclaw not found on PATH; skipping OpenClaw configuration audit. "+
				"Install OpenClaw or add it to PATH to enable this check.",
			install)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), auditTimeout)
	defer cancel()

	res := iexec.RunCtx(ctx, nil, "openclaw", "security", "audit", "--json")

	if res.TimedOut {
		hint := ""
		if hints, ok := channelSkipHints[install.Channel]; ok {
			hint = hints["timeout"]
		}
		addSkip(b,
			fmt.Sprintf("openclaw security audit timed out after %ds%s", int(auditTimeout.Seconds()), hint),
			install)
		return
	}

	if res.ExitCode == -1 {
		addSkip(b, "openclaw not found on PATH", install)
		return
	}

	if res.ExitCode != 0 {
		stderr := strings.TrimSpace(res.Stderr)
		if len(stderr) > 200 {
			stderr = stderr[:200]
		}
		addSkip(b,
			fmt.Sprintf("openclaw security audit exited %d: %s", res.ExitCode, stderr),
			install)
		return
	}

	// Parse JSON.
	var payload struct {
		Findings json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &payload); err != nil {
		addSkip(b, "could not parse openclaw audit output as JSON", install)
		return
	}

	if payload.Findings == nil {
		addSkip(b, "openclaw audit returned no findings list", install)
		return
	}

	var findings []auditFinding
	if err := json.Unmarshal(payload.Findings, &findings); err != nil {
		addSkip(b, "could not parse openclaw audit output as JSON", install)
		return
	}

	// Empty findings list is fine — just return with no checks added.
	for _, f := range findings {
		TranslateFinding(b, f, install)
	}
}
