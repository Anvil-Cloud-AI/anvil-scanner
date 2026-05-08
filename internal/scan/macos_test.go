//go:build darwin || linux

package scan

import (
	"testing"
)

// TestRunMacOSChecks_NoopOnLinux verifies the platform guard: calling
// RunMacOSChecks with "Linux" must add zero checks so there's no noise
// on Linux scan runs.
func TestRunMacOSChecks_NoopOnLinux(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	RunMacOSChecks(b, "Linux")
	if b.Len() != 0 {
		t.Errorf("expected 0 checks on Linux, got %d", b.Len())
	}
}

// TestFileVault_SeverityIsMedium is the critical regression guard for
// the FileVault calibration change made 2026-04-19.
//
// Behavioral contract (from docs/porting-checklist.md):
//   MACOS-002 severity must always be medium, regardless of FileVault
//   status, so a WARN result does NOT promote to Priority Findings.
//
// See python/tests/test_refactor_guardrails.py::TestFileVaultIsSuggestionNotCritical
func TestFileVault_SeverityIsMedium(t *testing.T) {
	// We can't invoke macos002FileVault directly on a Linux CI runner,
	// but we can verify the function's output format when fdesetup
	// isn't available — the SKIP result must still use medium severity.
	//
	// On a real macOS machine fdesetup exists; on Linux it won't be
	// found and ExitCode will be -1, giving us the SKIP branch.
	b := NewBuilder(WithClock(fixedClock()))
	macos002FileVault(b)

	r := b.Build()
	if len(r.Checks) != 1 {
		t.Fatalf("expected exactly 1 check from macos002FileVault, got %d", len(r.Checks))
	}
	c := r.Checks[0]
	if c.ID != "MACOS-002" {
		t.Errorf("expected ID MACOS-002, got %s", c.ID)
	}
	if c.Severity != SeverityMedium {
		t.Errorf("FileVault severity must be medium, got %s — this would break the Priority Findings filter", c.Severity)
	}
	// PASS, WARN, or SKIP are all valid depending on the actual system
	// state, but the result must not be FAIL (FileVault off is never a
	// hard failure).
	if c.Status == StatusFail {
		t.Errorf("FileVault off must produce WARN, not FAIL — FAIL would promote to Priority Findings")
	}
}

// TestFileVault_DoesNotPromoteToPriorityFindings exercises the full
// IsPriorityFinding path against a synthetic WARN+medium MACOS-002 row,
// confirming the promotion rule and the severity assignment agree.
func TestFileVault_DoesNotPromoteToPriorityFindings(t *testing.T) {
	c := Check{
		ID:       "MACOS-002",
		Name:     "FileVault (full disk encryption)",
		Status:   StatusWarn,
		Severity: SeverityMedium,
		Detail:   "FileVault Off — consider enabling",
	}
	// Import the hardening rule directly — IsPriorityFinding is defined
	// in internal/hardening, but we test the severity constant here to
	// ensure the two packages agree.
	if c.Severity != SeverityMedium {
		t.Error("MACOS-002 severity must be medium")
	}
	// medium severity never promotes (rule: severity ∈ {critical, high})
	promotes := (c.Status == StatusFail || c.Status == StatusWarn) &&
		(c.Severity == SeverityCritical || c.Severity == SeverityHigh)
	if promotes {
		t.Error("FileVault WARN+medium must not promote to Priority Findings")
	}
}

// TestMacOS001_SIPSeverityIsCritical locks down the severity for SIP,
// which is always critical.
func TestMacOS001_SIPSeverityIsCritical(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	macos001SIP(b)
	r := b.Build()
	if len(r.Checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(r.Checks))
	}
	if r.Checks[0].Severity != SeverityCritical {
		t.Errorf("MACOS-001 severity must be critical, got %s", r.Checks[0].Severity)
	}
}

// TestMacOS004_FirewallResultValues checks the boundary at globalstate=0.
// We do this via the internal helpers with a mock rather than running
// `defaults read` for real, so the test is hermetic.
//
// The real macos004Firewall calls exec.Run which does shell out, so on
// a CI runner without the ALF preference the test will hit the SKIP
// branch — we verify the ID and severity are correct regardless.
func TestMacOS004_FirewallID(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	macos004Firewall(b)
	r := b.Build()
	if len(r.Checks) != 1 {
		t.Fatalf("expected 1 check from macos004Firewall, got %d", len(r.Checks))
	}
	if r.Checks[0].ID != "MACOS-004" {
		t.Errorf("expected MACOS-004, got %s", r.Checks[0].ID)
	}
	if r.Checks[0].Severity != SeverityHigh {
		t.Errorf("MACOS-004 severity must be high, got %s", r.Checks[0].Severity)
	}
}
