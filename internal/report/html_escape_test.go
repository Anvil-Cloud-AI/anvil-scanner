package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/openclaw"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/threat"
)

// ---- e() unit tests ---------------------------------------------------------

// TestEscapeFunc_SpecialChars verifies each HTML special character is
// escaped to its entity representation.
func TestEscapeFunc_SpecialChars(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"less-than", "<", "&lt;"},
		{"greater-than", ">", "&gt;"},
		{"ampersand", "&", "&amp;"},
		{"double-quote", `"`, "&#34;"},
		{"single-quote", "'", "&#39;"},
		{"script tag", `<script>alert("XSS")</script>`, "&lt;script&gt;alert(&#34;XSS&#34;)&lt;/script&gt;"},
		{"sql injection", "'; DROP TABLE users; --", "&#39;; DROP TABLE users; --"},
		{"entity in input", "&lt;b&gt;", "&amp;lt;b&amp;gt;"},
		{"empty string", "", ""},
		{"plain text", "hello world", "hello world"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := e(tc.input)
			if got != tc.want {
				t.Errorf("e(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestEscapeFunc_UnicodePassthrough verifies non-ASCII Unicode is not
// mutated by e() — html.EscapeString only touches the five HTML special chars.
func TestEscapeFunc_UnicodePassthrough(t *testing.T) {
	input := "日本語テスト"
	if got := e(input); got != input {
		t.Errorf("e(%q) = %q; Unicode should pass through unchanged", input, got)
	}
}

// TestEscapeFunc_AllFiveCharsInOnce verifies a string with all five special
// chars is fully escaped in a single call and each expected entity is present.
func TestEscapeFunc_AllFiveCharsInOnce(t *testing.T) {
	input := `<>&"'`
	got := e(input)

	// Verify each entity representation is present.
	for _, want := range []string{"&lt;", "&gt;", "&amp;", "&#34;", "&#39;"} {
		if !strings.Contains(got, want) {
			t.Errorf("e(%q) missing entity %q: got %q", input, want, got)
		}
	}
	// Verify unescaped angle brackets and bare unescaped quote are gone.
	// (We cannot check for bare & because &amp; itself contains &.)
	for _, raw := range []string{"<", ">"} {
		if strings.Contains(got, raw) {
			t.Errorf("e(%q) still contains raw %q: got %q", input, raw, got)
		}
	}
}

// ---- renderHTML: platform string escaped ------------------------------------

// TestRenderHTML_PlatformEscaped verifies a platform string containing HTML
// special characters is escaped in output.
func TestRenderHTML_PlatformEscaped(t *testing.T) {
	malicious := `<script>alert(1)</script>`
	d := Data{
		Platform:  malicious,
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Checks:    []scan.Check{},
		Analysis:  AIAnalysis{Skipped: true},
	}
	out := renderHTML(d)

	if strings.Contains(out, malicious) {
		t.Error("raw <script> platform string must not appear in HTML output")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("expected escaped &lt;script&gt; in HTML output")
	}
}

// ---- renderSSHConfig: error message and directive values escaped -------------

// TestRenderSSHConfig_ErrorMessageEscaped verifies the _error key value is
// HTML-escaped.
func TestRenderSSHConfig_ErrorMessageEscaped(t *testing.T) {
	malicious := `<img src=x onerror=alert(1)>`
	d := Data{
		SSHDirectives: map[string]string{"_error": malicious},
	}
	out := renderSSHConfig(d, "Linux")

	if strings.Contains(out, malicious) {
		t.Error("raw HTML in _error value must be escaped")
	}
	if !strings.Contains(out, "&lt;img") {
		t.Errorf("expected &lt;img in output, got: %s", out)
	}
}

// TestRenderSSHConfig_DirectiveValueEscaped verifies a directive value
// containing HTML is escaped in the table row.
func TestRenderSSHConfig_DirectiveValueEscaped(t *testing.T) {
	malicious := `yes<script>`
	d := Data{
		SSHDirectives: map[string]string{
			"permitrootlogin":        malicious,
			"passwordauthentication": "no",
		},
	}
	out := renderSSHConfig(d, "Linux")

	if strings.Contains(out, malicious) {
		t.Error("raw directive value with HTML must be escaped")
	}
	if !strings.Contains(out, "yes&lt;script&gt;") {
		t.Errorf("expected escaped value in output: %s", out)
	}
}

// TestRenderSSHConfig_IncludeMessageEscaped verifies the _include message is
// HTML-escaped.
func TestRenderSSHConfig_IncludeMessageEscaped(t *testing.T) {
	malicious := `<b>warn</b>`
	d := Data{
		SSHDirectives: map[string]string{
			"permitrootlogin": "no",
			"_include":        malicious,
		},
	}
	out := renderSSHConfig(d, "Linux")

	if strings.Contains(out, malicious) {
		t.Error("raw HTML in _include must be escaped")
	}
	if !strings.Contains(out, "&lt;b&gt;") {
		t.Errorf("expected &lt;b&gt; in output: %s", out)
	}
}

// ---- renderAISection: user-supplied AI text escaped -------------------------

// TestRenderAISection_OverviewEscaped verifies the AI overview is HTML-escaped.
func TestRenderAISection_OverviewEscaped(t *testing.T) {
	malicious := `<iframe src="evil.com">`
	out := renderAISection(AIAnalysis{Overview: malicious})

	if strings.Contains(out, malicious) {
		t.Error("raw HTML in AI overview must be escaped")
	}
	if !strings.Contains(out, "&lt;iframe") {
		t.Errorf("expected &lt;iframe in output: %s", out)
	}
}

// TestRenderAISection_RiskItemEscaped verifies each risk item is escaped.
func TestRenderAISection_RiskItemEscaped(t *testing.T) {
	malicious := `<script>steal(document.cookie)</script>`
	out := renderAISection(AIAnalysis{Risks: []string{malicious, "normal risk"}})

	if strings.Contains(out, malicious) {
		t.Error("raw <script> in risk item must be escaped")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("expected escaped script tag in output: %s", out)
	}
}

// TestRenderAISection_RecommendationEscaped verifies recommendation strings
// are HTML-escaped.
func TestRenderAISection_RecommendationEscaped(t *testing.T) {
	malicious := `Run "sudo rm -rf /" & reboot`
	out := renderAISection(AIAnalysis{Recommendations: []string{malicious}})

	if strings.Contains(out, malicious) {
		t.Error("raw ampersand/quotes in recommendation must be escaped")
	}
	if !strings.Contains(out, "&amp;") {
		t.Errorf("expected &amp; in output: %s", out)
	}
}

// TestRenderAISection_ErrorEscaped verifies the AI error message is escaped.
func TestRenderAISection_ErrorEscaped(t *testing.T) {
	malicious := `<b>API error</b> & timeout`
	out := renderAISection(AIAnalysis{Error: malicious})

	if strings.Contains(out, malicious) {
		t.Error("raw HTML in AI error must be escaped")
	}
	if !strings.Contains(out, "&lt;b&gt;") {
		t.Errorf("expected &lt;b&gt; in output: %s", out)
	}
}

// ---- renderThreatIntel: IoC strings escaped ---------------------------------

func makeThreatResultWithIOC(ioc threat.LocalIOCResult) *threat.Result {
	return &threat.Result{
		LocalIOC: ioc,
	}
}

// TestRenderThreatIntel_SuspiciousCronEscaped verifies suspicious cron finding
// strings containing HTML are escaped.
func TestRenderThreatIntel_SuspiciousCronEscaped(t *testing.T) {
	malicious := `/etc/cron.d/evil (line 1): <script>alert(1)</script> — URL in cron`
	r := makeThreatResultWithIOC(threat.LocalIOCResult{
		SuspiciousCron:      []string{malicious},
		SuspiciousProcesses: []string{},
		SuspiciousTempFiles: []string{},
		SSHPersistence:      []string{},
		ListeningBackdoors:  []string{},
		AuthAnomalies:       []string{},
	})
	out := renderThreatIntel(r)

	if strings.Contains(out, "<script>") {
		t.Error("raw <script> in suspicious cron must be escaped")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("expected &lt;script&gt; in IoC output: %s", out)
	}
}

// TestRenderThreatIntel_AuthAnomalyEscaped verifies auth anomaly strings are escaped.
func TestRenderThreatIntel_AuthAnomalyEscaped(t *testing.T) {
	malicious := `Successful login from <evil> IP 8.8.8.8`
	r := makeThreatResultWithIOC(threat.LocalIOCResult{
		SuspiciousCron:      []string{},
		SuspiciousProcesses: []string{},
		SuspiciousTempFiles: []string{},
		SSHPersistence:      []string{},
		ListeningBackdoors:  []string{},
		AuthAnomalies:       []string{malicious},
	})
	out := renderThreatIntel(r)

	if strings.Contains(out, "<evil>") {
		t.Error("raw HTML tag in auth anomaly must be escaped")
	}
	if !strings.Contains(out, "&lt;evil&gt;") {
		t.Errorf("expected &lt;evil&gt; in output: %s", out)
	}
}

// TestRenderThreatIntel_CVEDescEscaped verifies CVE descriptions with HTML are escaped.
func TestRenderThreatIntel_CVEDescEscaped(t *testing.T) {
	maliciousDesc := `<b>RCE</b> via crafted "input" & overflow`
	r := &threat.Result{
		CVE: threat.CVEResult{
			Findings: []threat.CVEFinding{
				{
					Package:  "openssl",
					Version:  "1.0.0",
					CVE:      "CVE-2024-0001",
					Severity: "critical",
					Desc:     maliciousDesc,
					Fix:      "upgrade to 3.0",
				},
			},
			PackagesChecked: []string{"openssl"},
		},
		LocalIOC: threat.LocalIOCResult{
			SuspiciousCron:      []string{},
			SuspiciousProcesses: []string{},
			SuspiciousTempFiles: []string{},
			SSHPersistence:      []string{},
			ListeningBackdoors:  []string{},
			AuthAnomalies:       []string{},
		},
	}
	out := renderThreatIntel(r)

	if strings.Contains(out, maliciousDesc) {
		t.Error("raw HTML in CVE description must be escaped")
	}
	if !strings.Contains(out, "&lt;b&gt;") {
		t.Errorf("expected &lt;b&gt; in CVE description output: %s", out)
	}
	if !strings.Contains(out, "&amp;") {
		t.Errorf("expected &amp; in CVE description output: %s", out)
	}
}

// TestRenderThreatIntel_ShodanHostnameEscaped verifies Shodan hostnames are escaped.
func TestRenderThreatIntel_ShodanHostnameEscaped(t *testing.T) {
	maliciousHostname := `<script>alert("shodan")</script>.example.com`
	r := &threat.Result{
		Shodan: threat.ShodanResult{
			IP:        "1.2.3.4",
			Hostnames: []string{maliciousHostname},
		},
		LocalIOC: threat.LocalIOCResult{
			SuspiciousCron:      []string{},
			SuspiciousProcesses: []string{},
			SuspiciousTempFiles: []string{},
			SSHPersistence:      []string{},
			ListeningBackdoors:  []string{},
			AuthAnomalies:       []string{},
		},
	}
	out := renderThreatIntel(r)

	if strings.Contains(out, "<script>") {
		t.Error("raw <script> in Shodan hostname must be escaped")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("expected &lt;script&gt; in output: %s", out)
	}
}

// TestRenderThreatIntel_ShodanVulnEscaped verifies Shodan CVE strings are escaped.
func TestRenderThreatIntel_ShodanVulnEscaped(t *testing.T) {
	maliciousVuln := `CVE-2024-<script>`
	r := &threat.Result{
		Shodan: threat.ShodanResult{
			IP:    "1.2.3.4",
			Vulns: []string{maliciousVuln},
		},
		LocalIOC: threat.LocalIOCResult{
			SuspiciousCron:      []string{},
			SuspiciousProcesses: []string{},
			SuspiciousTempFiles: []string{},
			SSHPersistence:      []string{},
			ListeningBackdoors:  []string{},
			AuthAnomalies:       []string{},
		},
	}
	out := renderThreatIntel(r)

	if strings.Contains(out, "<script>") {
		t.Error("raw <script> in Shodan vuln must be escaped")
	}
}

// TestRenderThreatIntel_ShodanErrorEscaped verifies Shodan error strings are escaped.
func TestRenderThreatIntel_ShodanErrorEscaped(t *testing.T) {
	maliciousErr := `network error: <timeout> & retry`
	r := &threat.Result{
		Shodan: threat.ShodanResult{
			Error: maliciousErr,
		},
		LocalIOC: threat.LocalIOCResult{
			SuspiciousCron:      []string{},
			SuspiciousProcesses: []string{},
			SuspiciousTempFiles: []string{},
			SSHPersistence:      []string{},
			ListeningBackdoors:  []string{},
			AuthAnomalies:       []string{},
		},
	}
	out := renderThreatIntel(r)

	if strings.Contains(out, maliciousErr) {
		t.Error("raw HTML in Shodan error must be escaped")
	}
}

// ---- renderOCVulns: CVE description and version escaped ---------------------

// TestRenderOCVulns_CVEDescEscaped verifies CVE descriptions in the OpenClaw
// vuln section are HTML-escaped.
func TestRenderOCVulns_CVEDescEscaped(t *testing.T) {
	maliciousDesc := `<img src=x onerror="alert(1)"> auth bypass`
	r := &openclaw.OCVulnResult{
		Version: "2.0.0",
		Checked: 50,
		Findings: []openclaw.OCVulnFinding{
			{
				ID:       "CVE-2024-9999",
				Severity: "CRITICAL",
				Desc:     maliciousDesc,
				CVSS:     9.8,
			},
		},
	}
	out := renderOCVulns(r)

	if strings.Contains(out, "<img") {
		t.Error("raw <img> in CVE description must be escaped")
	}
	if !strings.Contains(out, "&lt;img") {
		t.Errorf("expected &lt;img in output: %s", out)
	}
}

// TestRenderOCVulns_VersionEscaped verifies the OpenClaw version string is escaped.
func TestRenderOCVulns_VersionEscaped(t *testing.T) {
	maliciousVersion := `1.0<script>`
	r := &openclaw.OCVulnResult{
		Version:  maliciousVersion,
		Checked:  10,
		Findings: []openclaw.OCVulnFinding{},
	}
	out := renderOCVulns(r)

	if strings.Contains(out, "<script>") {
		t.Error("raw <script> in version string must be escaped")
	}
}

// TestRenderOCVulns_ErrorEscaped verifies the error message is HTML-escaped.
func TestRenderOCVulns_ErrorEscaped(t *testing.T) {
	maliciousErr := `failed: <b>timeout</b> & retry`
	r := &openclaw.OCVulnResult{
		Error: maliciousErr,
	}
	out := renderOCVulns(r)

	if strings.Contains(out, maliciousErr) {
		t.Error("raw HTML in OCVulns error must be escaped")
	}
	if !strings.Contains(out, "&lt;b&gt;") {
		t.Errorf("expected &lt;b&gt; in output: %s", out)
	}
}

// ---- renderHTML: priority finding detail escaped ----------------------------

// TestRenderHTML_FindingDetailEscaped verifies a check's Detail field with HTML
// is escaped in the priority findings section.
func TestRenderHTML_FindingDetailEscaped(t *testing.T) {
	maliciousDetail := `<script>steal()</script> bad config`
	d := Data{
		Platform:  "Linux",
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Checks: []scan.Check{
			{
				ID:        "SSH-006",
				Name:      "MaxAuthTries",
				Status:    scan.StatusFail,
				Severity:  scan.SeverityHigh,
				Detail:    maliciousDetail,
				Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
		Analysis: AIAnalysis{Skipped: true},
	}
	out := renderHTML(d)

	if strings.Contains(out, "<script>steal()") {
		t.Error("raw <script> in check detail must be escaped in priority findings")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("expected &lt;script&gt; in output")
	}
}

// TestRenderHTML_CheckNameEscaped verifies a check's Name field is escaped.
func TestRenderHTML_CheckNameEscaped(t *testing.T) {
	maliciousName := `MaxAuthTries <b>DANGER</b>`
	d := Data{
		Platform:  "Linux",
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Checks: []scan.Check{
			{
				ID:        "SSH-006",
				Name:      maliciousName,
				Status:    scan.StatusFail,
				Severity:  scan.SeverityHigh,
				Detail:    "detail",
				Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
		Analysis: AIAnalysis{Skipped: true},
	}
	out := renderHTML(d)

	if strings.Contains(out, "<b>DANGER</b>") {
		t.Error("raw <b> in check name must be escaped")
	}
}

// TestRenderHTML_OpenPortEscaped verifies open port strings are HTML-escaped.
func TestRenderHTML_OpenPortEscaped(t *testing.T) {
	maliciousPort := `80"><script>alert(1)</script>`
	d := Data{
		Platform:  "Linux",
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		OpenPorts: []string{maliciousPort},
		Checks:    []scan.Check{},
		Analysis:  AIAnalysis{Skipped: true},
	}
	out := renderHTML(d)

	if strings.Contains(out, `"><script>`) {
		t.Error("script injection via port string must be escaped")
	}
}

// ---- renderExtendedChecks: check detail escaped -----------------------------

// TestRenderExtendedChecks_DetailEscaped verifies check Detail strings with HTML
// are escaped in the extended checks table.
func TestRenderExtendedChecks_DetailEscaped(t *testing.T) {
	maliciousDetail := `bad value <"quotes"> & ampersand`
	checks := []scan.Check{
		{
			ID:        "SSH-006",
			Name:      "MaxAuthTries",
			Status:    scan.StatusFail,
			Severity:  scan.SeverityHigh,
			Detail:    maliciousDetail,
			Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}
	out := renderExtendedChecks(checks)

	if strings.Contains(out, maliciousDetail) {
		t.Error("raw HTML in check detail must be escaped in extended checks table")
	}
	if !strings.Contains(out, "&lt;") {
		t.Errorf("expected &lt; in extended checks output: %s", out)
	}
	if !strings.Contains(out, "&amp;") {
		t.Errorf("expected &amp; in extended checks output: %s", out)
	}
}
