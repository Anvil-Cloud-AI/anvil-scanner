//go:build windows

package scan

import "testing"

// TestWindowsFirewallCheckIntegration exercises the real WIN-FW-001 check
// against the live Windows host (it runs on the windows-latest CI runner). It
// asserts the check produces exactly one result with a valid status — it does
// NOT assert firewall on/off, since runner state may vary. This validates that
// the PowerShell collector + parser round-trip works on a real Windows box,
// which the Mac-side unit tests cannot cover.
func TestWindowsFirewallCheckIntegration(t *testing.T) {
	b := NewBuilder()
	checkWindowsFirewall(b)
	result := b.Build()

	var found *Check
	for i := range result.Checks {
		if result.Checks[i].ID == "WIN-FW-001" {
			found = &result.Checks[i]
			break
		}
	}
	if found == nil {
		t.Fatal("WIN-FW-001 not emitted")
	}
	if !found.Status.IsValid() {
		t.Errorf("invalid status %q", found.Status)
	}
	// A real runner should resolve to a concrete state, not a parse SKIP.
	if found.Status == StatusSkip {
		t.Errorf("firewall check skipped on a real Windows host: %s", found.Detail)
	}
}
