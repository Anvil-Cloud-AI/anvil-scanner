//go:build darwin || linux

package openclaw

import (
	"fmt"
	"regexp"
	"strings"
)

// OCVulnFinding is a single advisory match against the installed openclaw-gateway version.
type OCVulnFinding struct {
	ID            string  // CVE-XXXX or GHSA-XXXX
	Severity      string  // CRITICAL, HIGH, MEDIUM, LOW
	CVSS          float64 // 0 when not published
	Desc          string
	AffectedBelow string
}

// OCVulnResult is the output of the bundled-database vulnerability check.
type OCVulnResult struct {
	Version  string
	Findings []OCVulnFinding
	Checked  int    // total entries compared
	Error    string // non-empty when the check could not run
}

// ocVersionRE extracts the first dotted-numeric version string from raw output.
var ocVersionRE = regexp.MustCompile(`(\d+\.\d+(?:\.\d+)*)`)

type ocCVEEntry struct {
	ID            string
	AffectedBelow string
	Severity      string
	CVSS          float64 // 0 when not published
	Desc          string
}

// openclawGatewayCVEs is the bundled advisory database for openclaw-gateway,
// ported from python/anvil_scanner/scanner.py OPENCLAW_CVES["openclaw-gateway"].
var openclawGatewayCVEs = []ocCVEEntry{
	// ── CRITICAL ──────────────────────────────────────────────────────────────
	{ID: "CVE-2026-22172", AffectedBelow: "2026.3.12", Severity: "CRITICAL", CVSS: 10.0,
		Desc: "WebSocket shared-auth connections could self-declare elevated scopes (CVE-2026-22172)"},
	{ID: "GHSA-4jpw-hj22-2xmc", AffectedBelow: "2026.3.11", Severity: "CRITICAL", CVSS: 10.0,
		Desc: "Pairing-scoped device tokens could mint operator.admin and reach Node RCE"},
	{ID: "GHSA-8rh7-6779-cjqq", AffectedBelow: "2026.3.28", Severity: "CRITICAL", CVSS: 9.7,
		Desc: "CWD .env injection bypasses host-env policy and allows config takeover"},
	{ID: "GHSA-j7p2-qcwm-94v4", AffectedBelow: "2026.3.22", Severity: "CRITICAL", CVSS: 9.7,
		Desc: "Incomplete host env sanitization blocklist — supply-chain redirection via package-manager env overrides"},
	{ID: "CVE-2026-28466", AffectedBelow: "2026.2.14", Severity: "CRITICAL", CVSS: 9.4,
		Desc: "RCE via Node Invoke Approval Bypass in Gateway (CVE-2026-28466)"},
	{ID: "GHSA-hf68-49fm-59cq", AffectedBelow: "2026.3.22", Severity: "CRITICAL", CVSS: 9.4,
		Desc: "device.pair.approve: operator.pairing escalates to operator.admin → Node RCE"},
	{ID: "GHSA-4rj2-gpmh-qq5x", AffectedBelow: "2026.2.2", Severity: "CRITICAL", CVSS: 9.4,
		Desc: "Inbound allowlist policy bypass in voice-call extension (empty caller ID + suffix matching)"},
	{ID: "GHSA-qrq5-wjgg-rvqw", AffectedBelow: "2026.2.1", Severity: "CRITICAL", CVSS: 9.3,
		Desc: "Path Traversal in Plugin Installation"},
	{ID: "GHSA-9hjh-fr4f-gxc4", AffectedBelow: "2026.3.25", Severity: "CRITICAL", CVSS: 9.3,
		Desc: "Non-admin operator can self-claim operator.admin via backend reconnect scope bypass"},
	{ID: "GHSA-fqw4-mph7-2vr8", AffectedBelow: "2026.3.25", Severity: "CRITICAL", CVSS: 9.4,
		Desc: "Silent shared-auth reconnect widens paired device scope from operator.read to operator.admin — can reach node RCE"},
	{ID: "GHSA-hc5h-pmr3-3497", AffectedBelow: "2026.3.28", Severity: "CRITICAL",
		Desc: "/pair approve command path omitted caller scope subsetting — reopened pairing escalation"},
	// ── HIGH ──────────────────────────────────────────────────────────────────
	{ID: "CVE-2026-25593", AffectedBelow: "2026.1.20", Severity: "HIGH", CVSS: 8.4,
		Desc: "Unauthenticated Local RCE via WebSocket config.apply (CVE-2026-25593)"},
	{ID: "CVE-2026-24763", AffectedBelow: "2026.1.29", Severity: "HIGH", CVSS: 8.8,
		Desc: "Command Injection in Clawdbot Docker Execution via PATH environment variable (CVE-2026-24763)"},
	{ID: "CVE-2026-25157", AffectedBelow: "2026.1.29", Severity: "HIGH", CVSS: 7.8,
		Desc: "OS Command Injection via Project Root Path in sshNodeCommand (macOS) (CVE-2026-25157)"},
	{ID: "GHSA-g8p2-7wf7-98mq", AffectedBelow: "2026.2.1", Severity: "HIGH",
		Desc: "1-Click RCE via Authentication Token Exfiltration from gatewayUrl"},
	{ID: "GHSA-3cw3-5vxw-g2h3", AffectedBelow: "2026.3.29", Severity: "HIGH",
		Desc: "CLI Remote Onboarding persists unauthenticated discovery endpoint and exfiltrates gateway credentials"},
	{ID: "GHSA-f44p-c7w9-7xr7", AffectedBelow: "2026.3.29", Severity: "HIGH",
		Desc: "Gateway WebSocket denial of service via unbounded pre-auth upgrades"},
	{ID: "GHSA-2pr2-hcv6-7gwv", AffectedBelow: "2026.3.29", Severity: "HIGH",
		Desc: "Device removal and token revocation do not terminate active WebSocket sessions"},
	{ID: "GHSA-h4jx-hjr3-fhgc", AffectedBelow: "2026.3.25", Severity: "HIGH",
		Desc: "Plugin subagent fallback deleteSession uses synthetic operator.admin scope instead of caller scope"},
	{ID: "GHSA-9p93-7j67-5pc2", AffectedBelow: "2026.3.25", Severity: "HIGH",
		Desc: "HTTP /sessions/:sessionKey/kill reaches admin kill path without validating caller scope"},
	{ID: "GHSA-qm2m-28pf-hgjw", AffectedBelow: "2026.3.25", Severity: "HIGH",
		Desc: "Gateway plugin HTTP auth mints operator.admin runtime scope for all callers regardless of actual permissions"},
	{ID: "GHSA-94pw-c6m8-p9p9", AffectedBelow: "2026.3.24", Severity: "HIGH",
		Desc: "operator.write scope can modify admin-class channel allowlist configuration via chat.send"},
	{ID: "GHSA-rhfg-j8jq-7v2h", AffectedBelow: "2026.3.25", Severity: "HIGH",
		Desc: "SSRF via unguarded configured base URLs in multiple channel extensions (incomplete fix for CVE-2026-28476)"},
	{ID: "GHSA-56pc-6hvp-4gv4", AffectedBelow: "2026.2.22", Severity: "HIGH",
		Desc: "Arbitrary file read via $include directive"},
	{ID: "GHSA-7xr2-q9vf-x4r5", AffectedBelow: "2026.3.25", Severity: "HIGH",
		Desc: "Symlink traversal via IDENTITY.md appendFile (incomplete fix for CVE-2026-32013)"},
	{ID: "GHSA-vvjh-f6p9-5vcf", AffectedBelow: "2026.2.22", Severity: "HIGH", CVSS: 7.4,
		Desc: "ZDI-CAN-29311: OpenClaw Canvas Authentication Bypass via IP-matching fallback"},
	// ── MEDIUM ────────────────────────────────────────────────────────────────
	{ID: "GHSA-68f8-9mhj-h2mp", AffectedBelow: "2026.3.24", Severity: "MEDIUM",
		Desc: "HTTP /v1/models route bypasses operator.read scope — any bearer token can enumerate models"},
	{ID: "GHSA-5jvj-hxmh-6h6j", AffectedBelow: "2026.3.25", Severity: "MEDIUM",
		Desc: "HTTP session history route bypasses operator.read scope check applied on the WebSocket path"},
	{ID: "GHSA-3h52-cx59-c456", AffectedBelow: "2026.3.25", Severity: "MEDIUM",
		Desc: "Feishu webhook parses request body before signature validation — DoS via resource exhaustion"},
	{ID: "GHSA-4hmj-39m8-jwc7", AffectedBelow: "2026.3.25", Severity: "MEDIUM",
		Desc: "ACP CLI approval prompt vulnerable to ANSI escape sequence injection via untrusted tool metadata"},
	{ID: "GHSA-9wqx-g2cw-vc7r", AffectedBelow: "2026.3.25", Severity: "MEDIUM",
		Desc: "Matrix verification notices bypass DM access policy and can reply to unpaired peers"},
}

// ocVersionLT returns true when v1 < v2 using dot-split numeric comparison.
// Non-numeric segments are treated as 0.
func ocVersionLT(v1, v2 string) bool {
	split := func(v string) []int {
		var parts []int
		for _, seg := range strings.Split(v, ".") {
			n := 0
			fmt.Sscan(seg, &n)
			parts = append(parts, n)
		}
		return parts
	}
	a, b := split(v1), split(v2)
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	for i := 0; i < maxLen; i++ {
		av, bv := 0, 0
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
	return false
}

// CheckVulns checks version against the bundled CVE database and returns
// all advisories that apply. version is the raw string from openclaw --version;
// the numeric portion is extracted automatically.
func CheckVulns(version string) OCVulnResult {
	result := OCVulnResult{
		Version: version,
		Checked: len(openclawGatewayCVEs),
	}

	if version == "" {
		result.Error = "OpenClaw version unavailable — cannot check vulnerabilities"
		return result
	}

	m := ocVersionRE.FindStringSubmatch(version)
	if m == nil {
		result.Error = "Could not parse version: " + version
		return result
	}
	ver := m[1]

	for _, entry := range openclawGatewayCVEs {
		if ocVersionLT(ver, entry.AffectedBelow) {
			result.Findings = append(result.Findings, OCVulnFinding{
				ID:            entry.ID,
				Severity:      entry.Severity,
				CVSS:          entry.CVSS,
				Desc:          entry.Desc,
				AffectedBelow: entry.AffectedBelow,
			})
		}
	}

	return result
}

// RunVulnCheck detects the installed OpenClaw version and checks it against
// the bundled advisory database. Returns nil when openclaw is not found on PATH.
func RunVulnCheck() *OCVulnResult {
	install := DetectInstall()
	if install.Version == "" {
		return nil
	}
	r := CheckVulns(install.Version)
	return &r
}
