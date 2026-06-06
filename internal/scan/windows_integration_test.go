//go:build windows

package scan

import "testing"

// TestWindowsChecksIntegration runs the full Windows check suite against the
// live host (executes on the windows-latest CI runner). It validates the real
// PowerShell collector + parser round-trip that the Mac-side unit tests cannot
// cover. It does not assert specific pass/fail verdicts (runner state varies),
// but every check must emit a valid status, and the checks that rely on
// always-present registry/service state must not SKIP (a SKIP there means the
// collector or parser broke).
func TestWindowsChecksIntegration(t *testing.T) {
	b := NewBuilder()
	RunAllChecksInto(b)
	result := b.Build()

	got := map[string]Check{}
	for _, c := range result.Checks {
		got[c.ID] = c
		t.Logf("%-12s %-5s %s — %s", c.ID, c.Status, c.Name, c.Detail)
	}

	wantIDs := []string{
		"WIN-000", "WIN-FW-001", "WIN-AV-001",
		"WIN-SMB-001", "WIN-RDP-001", "WIN-UAC-001", "WIN-UPD-001",
	}
	for _, id := range wantIDs {
		c, ok := got[id]
		if !ok {
			t.Errorf("%s not emitted", id)
			continue
		}
		if !c.Status.IsValid() {
			t.Errorf("%s: invalid status %q", id, c.Status)
		}
	}

	// These read registry/service state present on every Windows host, so a
	// SKIP indicates a broken collector or parser rather than a missing feature.
	for _, id := range []string{"WIN-FW-001", "WIN-RDP-001", "WIN-UAC-001", "WIN-UPD-001"} {
		if c, ok := got[id]; ok && c.Status == StatusSkip {
			t.Errorf("%s unexpectedly SKIPPED on a real Windows host: %s", id, c.Detail)
		}
	}
}
