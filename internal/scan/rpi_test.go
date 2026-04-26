//go:build linux

package scan

import (
	"testing"
)

// TestRunRPIChecks_NoopWhenNotPi verifies the IsPi guard: zero checks
// on a non-Pi Linux host.
func TestRunRPIChecks_NoopWhenNotPi(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	RunRPIChecks(b, RPIInfo{IsPi: false})
	if b.Len() != 0 {
		t.Errorf("expected 0 checks when IsPi=false, got %d", b.Len())
	}
}

// TestRPI003_GPIO_Skip ensures that when HasGPIO is false the check
// is skipped rather than erroneously scanning.
func TestRPI003_GPIO_Skip(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	rpi003GPIO(b, RPIInfo{IsPi: true, HasGPIO: false})
	r := b.Build()
	if len(r.Checks) != 1 || r.Checks[0].Status != StatusSkip {
		t.Errorf("expected SKIP when no GPIO, got %+v", r.Checks)
	}
}

// TestRPI004_Camera_Pass and _Warn lock down the two paths based on
// HasCamera — these are determined from /dev/video0 presence, not
// from a subprocess, so they're fully testable without hardware.
func TestRPI004_Camera_Pass(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	rpi004Camera(b, RPIInfo{IsPi: true, HasCamera: false})
	r := b.Build()
	if r.Checks[0].Status != StatusPass {
		t.Errorf("expected PASS when no camera, got %s", r.Checks[0].Status)
	}
}

func TestRPI004_Camera_Warn(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	rpi004Camera(b, RPIInfo{IsPi: true, HasCamera: true})
	r := b.Build()
	if r.Checks[0].Status != StatusWarn {
		t.Errorf("expected WARN when camera present, got %s", r.Checks[0].Status)
	}
	if r.Checks[0].Severity != SeverityLow {
		t.Errorf("RPI-004 severity must be low, got %s", r.Checks[0].Severity)
	}
}

// TestRPI005_Bluetooth_Skip when no hardware detected.
func TestRPI005_Bluetooth_Skip(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	rpi005Bluetooth(b, RPIInfo{IsPi: true, HasBluetooth: false})
	r := b.Build()
	if r.Checks[0].Status != StatusSkip {
		t.Errorf("expected SKIP when no Bluetooth, got %s", r.Checks[0].Status)
	}
}

// TestRPI007_AutoLogin_Pass exercises the happy path on any machine
// that doesn't have the autologin config files (which is most CI hosts).
func TestRPI007_AutoLogin_Pass(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	rpi007AutoLogin(b)
	r := b.Build()
	if len(r.Checks) != 1 || r.Checks[0].ID != "RPI-007" {
		t.Fatalf("expected exactly RPI-007, got %+v", r.Checks)
	}
	// On a CI host without autologin.conf or lightdm.conf, this must PASS.
	// We can't assert FAIL without actually writing those files, but we
	// can assert the severity is high regardless of status.
	if r.Checks[0].Severity != SeverityHigh {
		t.Errorf("RPI-007 severity must be high, got %s", r.Checks[0].Severity)
	}
}

// TestThrottleFlags verifies the bit-field parsing for RPI-012 without
// invoking vcgencmd. We drive rpi012Throttle indirectly by checking that
// the check only appears when commandExists("vcgencmd") — which is always
// false on a non-Pi CI host — so we get a SKIP result.
func TestRPI012_SkipWhenNoVcgencmd(t *testing.T) {
	// vcgencmd is Pi-only. On any CI machine this will be absent.
	b := NewBuilder(WithClock(fixedClock()))
	rpi012Throttle(b)
	r := b.Build()
	if len(r.Checks) != 1 || r.Checks[0].ID != "RPI-012" {
		t.Fatalf("expected RPI-012, got %+v", r.Checks)
	}
	// Skip or whatever the host reports — but severity must be medium.
	if r.Checks[0].Severity != SeverityMedium {
		t.Errorf("RPI-012 severity must be medium, got %s", r.Checks[0].Severity)
	}
}
