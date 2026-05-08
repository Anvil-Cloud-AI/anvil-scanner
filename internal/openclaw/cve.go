//go:build darwin || linux

package openclaw

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// cveFeedURL is the canonical live advisory database.
// It is a raw file in the public repo, updated whenever new advisories land.
const cveFeedURL = "https://raw.githubusercontent.com/Anvil-Cloud-AI/anvil-scanner/main/security/openclaw-cves.json"

// cveBundledUpdated is the date the compiled-in database was last refreshed.
// Used only when neither live fetch nor on-disk cache is available.
const cveBundledUpdated = "2026-05-08"

const (
	cveCacheFile   = "cve-cache.json"
	cveCacheMaxAge = 24 * time.Hour
	cveFetchTimeout = 10 * time.Second
	cveFetchMaxBody = 1 << 19 // 512 KiB
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
	Version   string
	Findings  []OCVulnFinding
	Checked   int    // total entries compared
	Error     string // non-empty when the check could not run
	DBSource  string // "live", "cached (Xh ago)", "bundled (compile-time)"
	DBUpdated string // "updated" field from the feed, e.g. "2026-05-08"
}

// ocVersionRE extracts the first dotted-numeric version string from raw output.
var ocVersionRE = regexp.MustCompile(`(\d+\.\d+(?:\.\d+)*)`)

// feedEntry is the JSON wire format for a single advisory.
type feedEntry struct {
	ID            string  `json:"id"`
	AffectedBelow string  `json:"affectedBelow"`
	Severity      string  `json:"severity"`
	CVSS          float64 `json:"cvss"`
	Desc          string  `json:"desc"`
}

// feedPayload is the top-level JSON structure of the live feed and the cache file.
type feedPayload struct {
	Updated   string      `json:"updated"`             // YYYY-MM-DD from the feed
	Entries   []feedEntry `json:"entries"`
	FetchedAt string      `json:"fetchedAt,omitempty"` // RFC3339, written only by the cache
}

// ocCVEEntry is the internal representation used by ocVersionLT / CheckVulns.
type ocCVEEntry struct {
	ID            string
	AffectedBelow string
	Severity      string
	CVSS          float64
	Desc          string
}

// openclawGatewayCVEs is the compiled-in fallback database used when both the
// live fetch and the on-disk cache are unavailable.
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
	{ID: "GHSA-x7p3-gjpc-hr57", AffectedBelow: "2026.4.25", Severity: "CRITICAL", CVSS: 9.8,
		Desc: "Pre-auth WebSocket frame parser heap overflow — unauthenticated remote code execution via malformed continuation frame"},
	{ID: "CVE-2026-31294", AffectedBelow: "2026.4.22", Severity: "CRITICAL", CVSS: 9.6,
		Desc: "Plugin loader accepts .so filenames with directory separators — path traversal enables arbitrary shared-library execution"},
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
	{ID: "GHSA-cwj3-xrxp-6jq7", AffectedBelow: "2026.4.18", Severity: "HIGH",
		Desc: "Node execute permission not re-validated on WebSocket session resume after gateway restart — prior revoked sessions regain access"},
	{ID: "GHSA-m9vj-4xhc-r58q", AffectedBelow: "2026.5.1", Severity: "HIGH", CVSS: 8.1,
		Desc: "OAuth2 PKCE flow leaks authorization code in Referer header during gateway redirect — code interception by co-located services"},
	{ID: "GHSA-2fwq-h743-r6vp", AffectedBelow: "2026.5.1", Severity: "HIGH",
		Desc: "Device token refresh endpoint accepts expired tokens within a 90-second grace window without re-validating device pairing status"},
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
	{ID: "GHSA-5r6q-9v42-wrph", AffectedBelow: "2026.4.20", Severity: "MEDIUM",
		Desc: "Audit log entries for failed authentication can be suppressed via malformed Accept-Language header — forensic blind-spot"},
	{ID: "GHSA-qj5h-r8wv-4p3x", AffectedBelow: "2026.4.25", Severity: "MEDIUM",
		Desc: "Clawdbot task descriptions rendered in CLI without ANSI stripping — terminal injection via crafted task name"},
}

// cveCachePath returns the path to the on-disk cache file, or an error if the
// home directory cannot be determined.
func cveCachePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".anvil-scanner", cveCacheFile), nil
}

// cveFetchClient is the HTTP client used to pull the live feed.
// Hardcoded to reach github.com only; no user-supplied URL is involved.
var cveFetchClient = &http.Client{
	Timeout: cveFetchTimeout,
	Transport: &http.Transport{
		TLSHandshakeTimeout: 5 * time.Second,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
	},
}

// fetchCVEFeed downloads the live advisory feed and returns the parsed payload.
func fetchCVEFeed() (*feedPayload, error) {
	req, err := http.NewRequest(http.MethodGet, cveFeedURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "anvil-scanner/1.0")

	resp, err := cveFetchClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feed returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, cveFetchMaxBody))
	if err != nil {
		return nil, err
	}

	var p feedPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, err
	}
	if len(p.Entries) == 0 {
		return nil, fmt.Errorf("feed contained no entries")
	}
	return &p, nil
}

// loadCVECache reads the on-disk cache. Returns the payload, its age, and any
// error (e.g. file missing, parse failure).
func loadCVECache() (*feedPayload, time.Duration, error) {
	path, err := cveCachePath()
	if err != nil {
		return nil, 0, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	var p feedPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, 0, err
	}
	if p.FetchedAt == "" {
		return nil, 0, fmt.Errorf("cache has no fetchedAt timestamp")
	}
	fetched, err := time.Parse(time.RFC3339, p.FetchedAt)
	if err != nil {
		return nil, 0, err
	}
	return &p, time.Since(fetched), nil
}

// saveCVECache writes the payload to the on-disk cache, stamping FetchedAt.
// Errors are silently ignored — a failed cache write is non-fatal.
func saveCVECache(p *feedPayload) error {
	path, err := cveCachePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	p.FetchedAt = time.Now().UTC().Format(time.RFC3339)
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

// feedToInternal converts the JSON wire format to the internal representation.
func feedToInternal(entries []feedEntry) []ocCVEEntry {
	out := make([]ocCVEEntry, len(entries))
	for i, e := range entries {
		out[i] = ocCVEEntry{
			ID:            e.ID,
			AffectedBelow: e.AffectedBelow,
			Severity:      e.Severity,
			CVSS:          e.CVSS,
			Desc:          e.Desc,
		}
	}
	return out
}

// formatCacheAge converts a duration to a human-readable "Xh ago" string.
func formatCacheAge(d time.Duration) string {
	h := int(d.Hours())
	if h < 1 {
		return "< 1h"
	}
	return fmt.Sprintf("%dh", h)
}

// loadCVEDatabase returns the best-available CVE entry list and metadata about
// where the data came from. Precedence:
//
//  1. On-disk cache, if < 24 h old  (no network call)
//  2. Live fetch from GitHub, saved to cache
//  3. Stale on-disk cache (network unavailable)
//  4. Compiled-in bundled database
func loadCVEDatabase() (entries []ocCVEEntry, source, updated string) {
	// Fast path: fresh cache avoids a network call on most runs.
	if p, age, err := loadCVECache(); err == nil && age < cveCacheMaxAge {
		src := fmt.Sprintf("cached (%s old)", formatCacheAge(age))
		return feedToInternal(p.Entries), src, p.Updated
	}

	// Cache stale or missing — try live feed.
	if p, err := fetchCVEFeed(); err == nil {
		_ = saveCVECache(p)
		return feedToInternal(p.Entries), "live", p.Updated
	}

	// Live fetch failed — use stale cache if present.
	if p, age, err := loadCVECache(); err == nil {
		src := fmt.Sprintf("cached (stale, %s old)", formatCacheAge(age))
		return feedToInternal(p.Entries), src, p.Updated
	}

	// Last resort: compiled-in database.
	return openclawGatewayCVEs, "bundled (compile-time)", cveBundledUpdated
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

// CheckVulns checks version against the live-or-cached CVE database and returns
// all advisories that apply. version is the raw string from openclaw --version;
// the numeric portion is extracted automatically.
func CheckVulns(version string) OCVulnResult {
	result := OCVulnResult{Version: version}

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

	entries, source, updated := loadCVEDatabase()
	result.Checked = len(entries)
	result.DBSource = source
	result.DBUpdated = updated

	for _, entry := range entries {
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
// the live-or-cached advisory database. Returns nil when openclaw is not found on PATH.
func RunVulnCheck() *OCVulnResult {
	install := DetectInstall()
	if install.Version == "" {
		return nil
	}
	r := CheckVulns(install.Version)
	return &r
}
