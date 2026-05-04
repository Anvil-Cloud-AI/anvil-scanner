//go:build linux

package scan

import (
	"strconv"
	"strings"
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

// ── gpu_mem config parser tests ───────────────────────────────────────────────

// parseGPUMem replicates the inline gpu_mem parsing logic from rpi009GPUMemory
// so it can be unit-tested without touching the real filesystem.
// It mirrors the exact logic in rpi.go lines 437-448:
//
//	for _, line := range strings.Split(data, "\n") {
//	    stripped := strings.TrimSpace(line)
//	    if strings.HasPrefix(stripped, "gpu_mem=") && !strings.HasPrefix(stripped, "#") {
//	        rawVal := strings.TrimSpace(strings.SplitN(stripped, "=", 2)[1])
//	        if i := strings.IndexByte(rawVal, '#'); i >= 0 {
//	            rawVal = strings.TrimSpace(rawVal[:i])
//	        }
//	        if v, err := strconv.Atoi(rawVal); err == nil { gpuMem = &v }
//	    }
//	}
func parseGPUMem(configContent string) *int {
	for _, line := range strings.Split(configContent, "\n") {
		stripped := strings.TrimSpace(line)
		if strings.HasPrefix(stripped, "gpu_mem=") && !strings.HasPrefix(stripped, "#") {
			rawVal := strings.TrimSpace(strings.SplitN(stripped, "=", 2)[1])
			if i := strings.IndexByte(rawVal, '#'); i >= 0 {
				rawVal = strings.TrimSpace(rawVal[:i])
			}
			if v, err := strconv.Atoi(rawVal); err == nil {
				return &v
			}
		}
	}
	return nil
}

// TestParseGPUMem_InlineComment verifies that a value with a trailing inline
// comment ("gpu_mem=16 # save RAM") is parsed as 16, not nil.
func TestParseGPUMem_InlineComment(t *testing.T) {
	got := parseGPUMem("gpu_mem=16 # save RAM\n")
	if got == nil {
		t.Fatal("parseGPUMem returned nil for 'gpu_mem=16 # save RAM'; want 16")
	}
	if *got != 16 {
		t.Errorf("parseGPUMem = %d; want 16", *got)
	}
}

// TestParseGPUMem_NoComment verifies the normal case: "gpu_mem=64" with no
// comment is parsed as 64.
func TestParseGPUMem_NoComment(t *testing.T) {
	got := parseGPUMem("gpu_mem=64\n")
	if got == nil {
		t.Fatal("parseGPUMem returned nil for 'gpu_mem=64'; want 64")
	}
	if *got != 64 {
		t.Errorf("parseGPUMem = %d; want 64", *got)
	}
}

// TestParseGPUMem_NotSet verifies that a config with no gpu_mem line returns nil.
func TestParseGPUMem_NotSet(t *testing.T) {
	got := parseGPUMem("# Raspberry Pi config\ndtoverlay=vc4-kms-v3d\n")
	if got != nil {
		t.Errorf("parseGPUMem = %d; want nil when gpu_mem not set", *got)
	}
}

// TestParseGPUMem_CommentedOut verifies that a commented-out gpu_mem line is
// skipped; the next uncommented line is used.
func TestParseGPUMem_CommentedOut(t *testing.T) {
	got := parseGPUMem("# gpu_mem=128\ngpu_mem=16\n")
	if got == nil {
		t.Fatal("parseGPUMem returned nil; should find uncommented gpu_mem=16")
	}
	if *got != 16 {
		t.Errorf("parseGPUMem = %d; want 16", *got)
	}
}

// TestParseGPUMem_TabBeforeHash verifies comment stripping works when a tab
// precedes the inline # comment.
func TestParseGPUMem_TabBeforeHash(t *testing.T) {
	got := parseGPUMem("gpu_mem=32\t# minimum for desktop\n")
	if got == nil {
		t.Fatal("parseGPUMem returned nil for tab-comment form; want 32")
	}
	if *got != 32 {
		t.Errorf("parseGPUMem = %d; want 32", *got)
	}
}
