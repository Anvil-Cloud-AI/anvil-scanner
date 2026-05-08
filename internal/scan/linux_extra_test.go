//go:build darwin || linux

package scan

import (
	"runtime"
	"testing"
)

// TestRunLinuxChecks_OnCurrentPlatform calls RunLinuxChecks with the real
// platform string and verifies every produced check validates cleanly.
// On Darwin this is a no-op; on Linux the real firewall checks run.
func TestRunLinuxChecks_OnCurrentPlatform(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	RunLinuxChecks(b, Platform())
	r := b.Build()
	for _, c := range r.Checks {
		if err := c.Validate(); err != nil {
			t.Errorf("RunLinuxChecks produced invalid check: %v", err)
		}
	}
}

// TestFW001Firewall_RunsWithoutPanic exercises fw001Firewall on the current
// host. On macOS ufw is absent (ExitCode=-1 from exec.Run) so the function
// falls through to the iptables path and then to the FAIL branch. On Linux
// the result depends on whether ufw/iptables is installed. In all cases
// exactly one check must be added and it must have ID "FW-001".
func TestFW001Firewall_RunsWithoutPanic(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fw001Firewall produces meaningful results only on Linux")
	}
	b := NewBuilder(WithClock(fixedClock()))
	_, _ = fw001Firewall(b)
	r := b.Build()
	if len(r.Checks) != 1 {
		t.Fatalf("expected 1 check from fw001Firewall, got %d", len(r.Checks))
	}
	if r.Checks[0].ID != "FW-001" {
		t.Errorf("expected FW-001, got %s", r.Checks[0].ID)
	}
	if !r.Checks[0].Status.IsValid() {
		t.Errorf("FW-001 status %q is not valid", r.Checks[0].Status)
	}
}
