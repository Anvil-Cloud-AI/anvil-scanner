package scan

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// fixedClock returns a deterministic time source for tests that care
// about Timestamp. Using a sentinel like 2026-04-21T12:00:00Z makes
// wire-format test failures easy to spot.
func fixedClock() func() time.Time {
	t, _ := time.Parse(time.RFC3339, "2026-04-21T12:00:00Z")
	return func() time.Time { return t }
}

func TestStatus_IsValid(t *testing.T) {
	for _, s := range []Status{StatusPass, StatusFail, StatusWarn, StatusSkip} {
		if !s.IsValid() {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range []Status{"", "pass", "unknown", "Error"} {
		if Status(s).IsValid() {
			t.Errorf("%q should not be valid", s)
		}
	}
}

func TestSeverity_IsValid(t *testing.T) {
	for _, s := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
		if !s.IsValid() {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range []string{"", "Critical", "info", "HIGH"} {
		if Severity(s).IsValid() {
			t.Errorf("%q should not be valid (Python lowercases severity on the wire)", s)
		}
	}
}

// TestSeverity_Rank locks down the ordering used by priority-finding
// logic. If someone reorders the constants, this should catch it.
func TestSeverity_Rank(t *testing.T) {
	if !(SeverityCritical.rank() > SeverityHigh.rank() &&
		SeverityHigh.rank() > SeverityMedium.rank() &&
		SeverityMedium.rank() > SeverityLow.rank()) {
		t.Fatalf("severity rank ordering broken: c=%d h=%d m=%d l=%d",
			SeverityCritical.rank(), SeverityHigh.rank(),
			SeverityMedium.rank(), SeverityLow.rank())
	}
}

func TestCheck_Validate(t *testing.T) {
	tests := []struct {
		name    string
		c       Check
		wantErr bool
	}{
		{"ok", Check{ID: "SSH-000", Status: StatusPass, Severity: SeverityHigh}, false},
		{"empty id", Check{Status: StatusPass, Severity: SeverityHigh}, true},
		{"whitespace id", Check{ID: "   ", Status: StatusPass, Severity: SeverityHigh}, true},
		{"bad status", Check{ID: "SSH-000", Status: "error", Severity: SeverityHigh}, true},
		{"bad severity", Check{ID: "SSH-000", Status: StatusPass, Severity: "medium!"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.c.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestBuilder_AddsAllFourStatuses(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	b.Pass("P-1", "pass check", "all good", SeverityLow)
	b.Fail("F-1", "fail check", "broken", SeverityCritical)
	b.Warn("W-1", "warn check", "suggestion", SeverityMedium)
	b.Skip("S-1", "skip check", "not applicable", SeverityHigh)

	r := b.Build()
	if got, want := len(r.Checks), 4; got != want {
		t.Fatalf("got %d checks, want %d", got, want)
	}
	if r.Count(StatusPass) != 1 ||
		r.Count(StatusFail) != 1 ||
		r.Count(StatusWarn) != 1 ||
		r.Count(StatusSkip) != 1 {
		t.Errorf("summary counts off: %+v", r.Checks)
	}
	// Timestamp should come from the injected clock on every row.
	for _, c := range r.Checks {
		if c.Timestamp.IsZero() {
			t.Errorf("%s: Timestamp zero — clock injection broken", c.ID)
		}
	}
}

func TestBuilder_WithRemediation(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	b.Fail("FW-001", "firewall disabled", "ufw is inactive", SeverityCritical)
	b.WithRemediation("sudo ufw enable")

	r := b.Build()
	if r.Checks[0].Remediation != "sudo ufw enable" {
		t.Errorf("remediation not attached: got %q", r.Checks[0].Remediation)
	}
}

func TestBuilder_WithRemediation_NoopBeforeAdd(t *testing.T) {
	b := NewBuilder()
	// Calling WithRemediation on an empty builder must not panic; it's a no-op.
	b.WithRemediation("never attached")
	r := b.Build()
	if len(r.Checks) != 0 {
		t.Errorf("expected no checks, got %d", len(r.Checks))
	}
}

// TestResult_MarshalJSON locks down the summary-count serialization.
// Downstream report consumers (HTML renderer, JSON schema clients)
// rely on `summary.pass` / `.fail` / `.warn` / `.skip` being present
// and counting correctly.
func TestResult_MarshalJSON(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	b.Pass("X-1", "a", "", SeverityLow)
	b.Pass("X-2", "b", "", SeverityLow)
	b.Fail("X-3", "c", "", SeverityCritical)
	b.Warn("X-4", "d", "", SeverityMedium)

	bytes, err := json.Marshal(b.Build())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(bytes)

	for _, want := range []string{
		`"summary":`,
		`"pass":2`,
		`"fail":1`,
		`"warn":1`,
		`"skip":0`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("JSON missing %q\nfull output: %s", want, s)
		}
	}
}

// TestBuilder_Len is trivial but guards against someone swapping
// the internal representation from a slice to a map.
func TestBuilder_Len(t *testing.T) {
	b := NewBuilder()
	if b.Len() != 0 {
		t.Fatalf("empty builder Len=%d", b.Len())
	}
	b.Pass("P-1", "x", "", SeverityLow)
	if b.Len() != 1 {
		t.Fatalf("after one add, Len=%d", b.Len())
	}
}
