//go:build darwin || linux

package scan

import (
	"testing"
)

// These tests call the macOS check functions unconditionally. On a real macOS
// machine the sub-processes run and return real results. On Linux CI the
// binaries (spctl, systemsetup, launchctl, firmwarepasswd) are absent so
// exec.Run returns ExitCode=-1 → the check functions emit SKIP. Both paths
// are valid; what we assert is that:
//   (a) exactly one Finding is produced (no panic, no extra rows), and
//   (b) the ID and severity are correct.

// TestMacOS003_Gatekeeper verifies macos003Gatekeeper emits exactly one check
// with ID "MACOS-003" and severity "high".
func TestMacOS003_Gatekeeper(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	macos003Gatekeeper(b)
	r := b.Build()
	if len(r.Checks) != 1 {
		t.Fatalf("expected 1 check from macos003Gatekeeper, got %d", len(r.Checks))
	}
	c := r.Checks[0]
	if c.ID != "MACOS-003" {
		t.Errorf("expected MACOS-003, got %s", c.ID)
	}
	if c.Severity != SeverityHigh {
		t.Errorf("MACOS-003 severity must be high, got %s", c.Severity)
	}
	if !c.Status.IsValid() {
		t.Errorf("MACOS-003 status %q is not a valid Status", c.Status)
	}
}

// TestMacOS005_RemoteLogin verifies macos005RemoteLogin emits exactly one check
// with ID "MACOS-005" and severity "medium".
func TestMacOS005_RemoteLogin(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	macos005RemoteLogin(b)
	r := b.Build()
	if len(r.Checks) != 1 {
		t.Fatalf("expected 1 check from macos005RemoteLogin, got %d", len(r.Checks))
	}
	c := r.Checks[0]
	if c.ID != "MACOS-005" {
		t.Errorf("expected MACOS-005, got %s", c.ID)
	}
	if c.Severity != SeverityMedium {
		t.Errorf("MACOS-005 severity must be medium, got %s", c.Severity)
	}
	if !c.Status.IsValid() {
		t.Errorf("MACOS-005 status %q is not valid", c.Status)
	}
}

// TestMacOS006_ScreenSharing verifies macos006ScreenSharing emits exactly one
// check with ID "MACOS-006" and severity "medium".
func TestMacOS006_ScreenSharing(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	macos006ScreenSharing(b)
	r := b.Build()
	if len(r.Checks) != 1 {
		t.Fatalf("expected 1 check from macos006ScreenSharing, got %d", len(r.Checks))
	}
	c := r.Checks[0]
	if c.ID != "MACOS-006" {
		t.Errorf("expected MACOS-006, got %s", c.ID)
	}
	if c.Severity != SeverityMedium {
		t.Errorf("MACOS-006 severity must be medium, got %s", c.Severity)
	}
	if !c.Status.IsValid() {
		t.Errorf("MACOS-006 status %q is not valid", c.Status)
	}
}

// TestMacOS007_AutoLogin verifies macos007AutoLogin emits exactly one check
// with ID "MACOS-007" and severity "medium".
func TestMacOS007_AutoLogin(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	macos007AutoLogin(b)
	r := b.Build()
	if len(r.Checks) != 1 {
		t.Fatalf("expected 1 check from macos007AutoLogin, got %d", len(r.Checks))
	}
	c := r.Checks[0]
	if c.ID != "MACOS-007" {
		t.Errorf("expected MACOS-007, got %s", c.ID)
	}
	if c.Severity != SeverityMedium {
		t.Errorf("MACOS-007 severity must be medium, got %s", c.Severity)
	}
	if !c.Status.IsValid() {
		t.Errorf("MACOS-007 status %q is not valid", c.Status)
	}
}

// TestMacOS008_FirmwarePassword verifies macos008FirmwarePassword emits exactly
// one check with ID "MACOS-008" and severity "medium".
func TestMacOS008_FirmwarePassword(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	macos008FirmwarePassword(b)
	r := b.Build()
	if len(r.Checks) != 1 {
		t.Fatalf("expected 1 check from macos008FirmwarePassword, got %d", len(r.Checks))
	}
	c := r.Checks[0]
	if c.ID != "MACOS-008" {
		t.Errorf("expected MACOS-008, got %s", c.ID)
	}
	if c.Severity != SeverityMedium {
		t.Errorf("MACOS-008 severity must be medium, got %s", c.Severity)
	}
	if !c.Status.IsValid() {
		t.Errorf("MACOS-008 status %q is not valid", c.Status)
	}
}

// TestRunMacOSChecks_OnCurrentPlatform calls RunMacOSChecks with the real
// platform string. On Darwin all eight checks run; on Linux it is a no-op
// (already guarded by a test in macos_test.go).
func TestRunMacOSChecks_OnCurrentPlatform(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	RunMacOSChecks(b, Platform())
	r := b.Build()
	// Every returned check must validate cleanly.
	for _, c := range r.Checks {
		if err := c.Validate(); err != nil {
			t.Errorf("invalid check: %v", err)
		}
	}
}
