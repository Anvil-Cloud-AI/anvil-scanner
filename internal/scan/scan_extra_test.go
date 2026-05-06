//go:build darwin || linux

package scan

import (
	"runtime"
	"testing"
)

// ---- Platform / canonicalPlatform -------------------------------------------

func TestPlatform_ReturnsNonEmptyString(t *testing.T) {
	p := Platform()
	if p == "" {
		t.Error("Platform() returned empty string")
	}
}

func TestCanonicalPlatform_Darwin(t *testing.T) {
	// On macOS the running platform is darwin → "Darwin".
	// On Linux it's linux → "Linux".
	// We cannot fake runtime.GOOS, so we test the live value and ensure
	// it agrees with the exported Platform() wrapper.
	if Platform() != canonicalPlatform() {
		t.Error("Platform() and canonicalPlatform() disagree")
	}
}

func TestCanonicalPlatform_KnownValues(t *testing.T) {
	p := canonicalPlatform()
	switch runtime.GOOS {
	case "darwin":
		if p != "Darwin" {
			t.Errorf("canonicalPlatform() on darwin = %q, want %q", p, "Darwin")
		}
	case "linux":
		if p != "Linux" {
			t.Errorf("canonicalPlatform() on linux = %q, want %q", p, "Linux")
		}
	default:
		// On any other OS the function returns runtime.GOOS verbatim.
		if p != runtime.GOOS {
			t.Errorf("canonicalPlatform() on %q = %q, want %q", runtime.GOOS, p, runtime.GOOS)
		}
	}
}

// ---- RunAllChecksInto / RunAllChecks -----------------------------------------

// TestRunAllChecksInto_ProducesChecks verifies that RunAllChecksInto adds at
// least one check without panicking on the current platform.
func TestRunAllChecksInto_ProducesChecks(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	RunAllChecksInto(b)
	if b.Len() == 0 {
		t.Error("RunAllChecksInto produced 0 checks — expected at least one")
	}
}

// TestRunAllChecks_ReturnsResult verifies that RunAllChecks returns a non-zero
// Result (checks slice is non-nil) and each Check has a valid ID and status.
func TestRunAllChecks_ReturnsResult(t *testing.T) {
	r := RunAllChecks()
	if r.Checks == nil {
		t.Fatal("RunAllChecks returned nil Checks slice")
	}
	if len(r.Checks) == 0 {
		t.Error("RunAllChecks returned 0 checks — expected at least one")
	}
	for _, c := range r.Checks {
		if err := c.Validate(); err != nil {
			t.Errorf("invalid check in RunAllChecks result: %v", err)
		}
	}
}

// TestRunAllChecks_StatusValues verifies every check status is one of the
// four allowed values.
func TestRunAllChecks_StatusValues(t *testing.T) {
	r := RunAllChecks()
	for _, c := range r.Checks {
		if !c.Status.IsValid() {
			t.Errorf("check %s has invalid status %q", c.ID, c.Status)
		}
		if !c.Severity.IsValid() {
			t.Errorf("check %s has invalid severity %q", c.ID, c.Severity)
		}
	}
}
