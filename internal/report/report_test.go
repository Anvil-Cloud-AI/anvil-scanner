package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
)

var fixedTime = time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC)

func makeCheck(id, name string, status scan.Status, sev scan.Severity) scan.Check {
	return scan.Check{
		ID:        id,
		Name:      name,
		Status:    status,
		Severity:  sev,
		Detail:    "test detail",
		Timestamp: fixedTime,
	}
}

// TestPriorityCard_Zero ensures the zero-findings card renders green.
func TestPriorityCard_Zero(t *testing.T) {
	got := renderPriorityCard(0, 0)
	if !strings.Contains(got, "#4ade80") {
		t.Errorf("expected green color for zero findings, got: %s", got)
	}
	if !strings.Contains(got, ">0<") {
		t.Errorf("expected zero count in card, got: %s", got)
	}
}

// TestPriorityCard_CritAndHigh checks that both counts appear and colors are correct.
func TestPriorityCard_CritAndHigh(t *testing.T) {
	got := renderPriorityCard(2, 3)
	if !strings.Contains(got, "#dc2626") {
		t.Errorf("expected critical (red) color, got: %s", got)
	}
	if !strings.Contains(got, "#f97316") {
		t.Errorf("expected high (orange) color, got: %s", got)
	}
	if !strings.Contains(got, "2") || !strings.Contains(got, "3") {
		t.Errorf("expected counts 2 and 3, got: %s", got)
	}
}

// TestPriorityFindings_Filter ensures the promotion rule is applied.
func TestPriorityFindings_Filter(t *testing.T) {
	checks := []scan.Check{
		makeCheck("SSH-006", "MaxAuthTries", scan.StatusFail, scan.SeverityMedium),   // medium → no
		makeCheck("MACOS-001", "SIP", scan.StatusFail, scan.SeverityCritical),        // fail+crit → yes
		makeCheck("FW-001", "Firewall", scan.StatusWarn, scan.SeverityHigh),          // warn+high → yes
		makeCheck("MACOS-002", "FileVault", scan.StatusWarn, scan.SeverityMedium),    // medium → no
		makeCheck("SSH-008", "Grace", scan.StatusPass, scan.SeverityHigh),            // pass → no
		makeCheck("SSH-016", "MACs", scan.StatusFail, scan.SeverityHigh),             // fail+high → yes
	}
	got := PriorityFindings(checks)
	if len(got) != 3 {
		t.Errorf("expected 3 priority findings, got %d: %+v", len(got), got)
	}
}

// TestPriorityFindings_NilInput verifies that a nil slice returns an empty
// (non-nil) slice rather than nil.
func TestPriorityFindings_NilInput(t *testing.T) {
	got := PriorityFindings(nil)
	if got == nil {
		t.Error("PriorityFindings(nil) returned nil; want empty non-nil slice")
	}
	if len(got) != 0 {
		t.Errorf("PriorityFindings(nil) returned %d items; want 0", len(got))
	}
}

// TestPriorityFindings_MediumNeverPromotes verifies that FAIL+medium checks are
// never included in priority findings regardless of status.
func TestPriorityFindings_MediumNeverPromotes(t *testing.T) {
	checks := []scan.Check{
		makeCheck("SSH-006", "MaxAuthTries", scan.StatusFail, scan.SeverityMedium),
		makeCheck("SSH-008", "LoginGrace", scan.StatusWarn, scan.SeverityMedium),
		makeCheck("SSH-030", "LogLevel", scan.StatusFail, scan.SeverityLow),
	}
	got := PriorityFindings(checks)
	if len(got) != 0 {
		t.Errorf("expected 0 priority findings for medium/low severity, got %d: %+v", len(got), got)
	}
}

// TestGenerateJSON_Structure verifies the JSON payload has required top-level keys.
func TestGenerateJSON_Structure(t *testing.T) {
	d := Data{
		Platform:  "Darwin",
		Timestamp: fixedTime,
		Checks: []scan.Check{
			makeCheck("MACOS-001", "SIP", scan.StatusFail, scan.SeverityCritical),
			makeCheck("MACOS-002", "FileVault", scan.StatusWarn, scan.SeverityMedium),
		},
		Analysis: AIAnalysis{Skipped: true},
	}
	data, err := MarshalJSON(d)
	if err != nil {
		t.Fatalf("MarshalJSON error: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, key := range []string{"platform", "timestamp", "checks", "summary", "priority_findings", "open_ports"} {
		if _, ok := payload[key]; !ok {
			t.Errorf("missing key %q in JSON output", key)
		}
	}
	summary, ok := payload["summary"].(map[string]any)
	if !ok {
		t.Fatal("summary is not an object")
	}
	if summary["total"] != float64(2) {
		t.Errorf("expected total=2, got %v", summary["total"])
	}
	if summary["fail"] != float64(1) {
		t.Errorf("expected fail=1, got %v", summary["fail"])
	}
}

// TestGenerateJSON_PriorityFindings checks that only critical/high actionable checks appear.
func TestGenerateJSON_PriorityFindings(t *testing.T) {
	d := Data{
		Platform:  "Darwin",
		Timestamp: fixedTime,
		Checks: []scan.Check{
			makeCheck("MACOS-001", "SIP", scan.StatusFail, scan.SeverityCritical),
			makeCheck("MACOS-002", "FileVault", scan.StatusWarn, scan.SeverityMedium),
		},
		Analysis: AIAnalysis{Skipped: true},
	}
	data, _ := MarshalJSON(d)
	var payload map[string]any
	json.Unmarshal(data, &payload)
	pf := payload["priority_findings"].([]any)
	if len(pf) != 1 {
		t.Errorf("expected 1 priority finding, got %d", len(pf))
	}
}

// TestGenerateHTML_SubnavStructure verifies the scroll-spy subnav is present.
func TestGenerateHTML_SubnavStructure(t *testing.T) {
	d := Data{
		Platform:  "Darwin",
		Timestamp: fixedTime,
		Checks:    []scan.Check{},
		Analysis:  AIAnalysis{Skipped: true},
	}
	html := renderHTML(d)
	if !strings.Contains(html, `class="subnav"`) {
		t.Error("expected .subnav element")
	}
	if !strings.Contains(html, `data-nav-section`) {
		t.Error("expected data-nav-section attributes for scroll-spy")
	}
	if !strings.Contains(html, `href="#summary"`) {
		t.Error("expected summary tab in subnav")
	}
	if !strings.Contains(html, `href="#ai"`) {
		t.Error("expected AI tab in subnav")
	}
}

// TestGenerateHTML_PriorityTabAppearsWhenFindings checks conditional subnav tab.
func TestGenerateHTML_PriorityTabAppearsWhenFindings(t *testing.T) {
	dNo := Data{
		Platform:  "Darwin",
		Timestamp: fixedTime,
		Checks:    []scan.Check{makeCheck("MACOS-002", "FileVault", scan.StatusWarn, scan.SeverityMedium)},
		Analysis:  AIAnalysis{Skipped: true},
	}
	if strings.Contains(renderHTML(dNo), `href="#priority"`) {
		t.Error("priority tab should NOT appear when no priority findings")
	}

	dYes := Data{
		Platform:  "Darwin",
		Timestamp: fixedTime,
		Checks:    []scan.Check{makeCheck("MACOS-001", "SIP", scan.StatusFail, scan.SeverityCritical)},
		Analysis:  AIAnalysis{Skipped: true},
	}
	if !strings.Contains(renderHTML(dYes), `href="#priority"`) {
		t.Error("priority tab SHOULD appear when there are priority findings")
	}
}

// TestGenerateHTML_AISkipMessage tests the quiet empty-state path.
func TestGenerateHTML_AISkipMessage(t *testing.T) {
	d := Data{
		Platform:  "Darwin",
		Timestamp: fixedTime,
		Checks:    []scan.Check{},
		Analysis:  AIAnalysis{Skipped: true},
	}
	html := renderHTML(d)
	if !strings.Contains(html, `class="ai-skip"`) {
		t.Error("expected ai-skip div for skipped AI")
	}
	// Check that the failure div element does NOT appear (CSS rules are OK, div is not)
	if strings.Contains(html, `class="ai-fail"`) {
		t.Error("should not show ai-fail div when AI is skipped")
	}
}

// TestGenerateHTML_AIFailMessage tests the loud error state.
func TestGenerateHTML_AIFailMessage(t *testing.T) {
	d := Data{
		Platform:  "Darwin",
		Timestamp: fixedTime,
		Checks:    []scan.Check{},
		Analysis:  AIAnalysis{Error: "No AI provider available"},
	}
	html := renderHTML(d)
	if !strings.Contains(html, `class="ai-fail"`) {
		t.Error("expected ai-fail div for AI error")
	}
	if !strings.Contains(html, "No AI provider available") {
		t.Error("expected error message in HTML")
	}
}

// TestGenerateHTML_ExtendedChecks verifies checks table rendering.
func TestGenerateHTML_ExtendedChecks(t *testing.T) {
	d := Data{
		Platform:  "Darwin",
		Timestamp: fixedTime,
		Checks: []scan.Check{
			makeCheck("SSH-006", "MaxAuthTries", scan.StatusPass, scan.SeverityMedium),
			makeCheck("MACOS-001", "SIP", scan.StatusFail, scan.SeverityCritical),
		},
		Analysis: AIAnalysis{Skipped: true},
	}
	html := renderHTML(d)
	if !strings.Contains(html, "Extended Hardening Checks") {
		t.Error("expected extended checks section")
	}
	if !strings.Contains(html, "SSH-006") {
		t.Error("expected SSH-006 in extended checks table")
	}
	if !strings.Contains(html, "MACOS-001") {
		t.Error("expected MACOS-001 in extended checks table")
	}
}

// TestGenerateHTML_Disclaimer verifies AI disclaimer is present when AI ran.
func TestGenerateHTML_Disclaimer(t *testing.T) {
	score := 5
	d := Data{
		Platform:  "Darwin",
		Timestamp: fixedTime,
		Checks:    []scan.Check{},
		Analysis: AIAnalysis{
			RiskScore: &score,
			Overview:  "Test overview",
		},
	}
	html := renderHTML(d)
	if !strings.Contains(html, "ai-disclaimer") {
		t.Error("expected ai-disclaimer when AI result is present")
	}
}

// TestOpenPortsEmptySlice verifies nil ports serialize as empty array, not null.
func TestOpenPortsEmptySlice(t *testing.T) {
	d := Data{
		Platform:  "Darwin",
		Timestamp: fixedTime,
		Analysis:  AIAnalysis{Skipped: true},
	}
	data, _ := MarshalJSON(d)
	if !strings.Contains(string(data), `"open_ports": []`) {
		t.Errorf("expected open_ports to be empty array, got: %s", string(data))
	}
}
