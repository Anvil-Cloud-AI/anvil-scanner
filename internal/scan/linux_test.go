//go:build darwin || linux

package scan

import (
	"strings"
	"testing"
)

func TestRunLinuxChecks_NoopOnDarwin(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	RunLinuxChecks(b, "Darwin")
	if b.Len() != 0 {
		t.Errorf("expected 0 checks on Darwin, got %d", b.Len())
	}
}

// TestFW002_DefaultDeny exercises the ufw status string parsing.
func TestFW002_DefaultDeny_Pass(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	fw002DefaultDeny(b, "Status: active\nDefault: deny (incoming)\n")
	r := b.Build()
	if r.Checks[0].Status != StatusPass {
		t.Errorf("expected PASS for deny policy, got %s", r.Checks[0].Status)
	}
}

func TestFW002_DefaultDeny_Reject(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	fw002DefaultDeny(b, "Status: active\nDefault: reject (incoming)\n")
	r := b.Build()
	if r.Checks[0].Status != StatusPass {
		t.Errorf("expected PASS for reject policy, got %s", r.Checks[0].Status)
	}
}

func TestFW002_DefaultDeny_Fail(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	fw002DefaultDeny(b, "Status: active\nDefault: allow (incoming)\n")
	r := b.Build()
	if r.Checks[0].Status != StatusFail {
		t.Errorf("expected FAIL for allow policy, got %s", r.Checks[0].Status)
	}
}

// TestFW003_OpenClawPorts exercises port-rule parsing from ufw output.
func TestFW003_NoViolations(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	ufwOut := "Status: active\n22/tcp                     ALLOW       Anywhere\n"
	fw003OpenClawPorts(b, ufwOut)
	r := b.Build()
	if r.Checks[0].Status != StatusPass {
		t.Errorf("expected PASS when no OpenClaw ports open, got %s", r.Checks[0].Status)
	}
}

func TestFW003_UnrestrictedPort(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	// ufw status format: "18789           ALLOW       Anywhere"
	ufwOut := "Status: active\n18789                      ALLOW       Anywhere\n"
	fw003OpenClawPorts(b, ufwOut)
	r := b.Build()
	if r.Checks[0].Status != StatusWarn {
		t.Errorf("expected WARN for unrestricted OpenClaw port, got %s", r.Checks[0].Status)
	}
	if !strings.Contains(r.Checks[0].Detail, "18789") {
		t.Errorf("detail should name the offending port: %q", r.Checks[0].Detail)
	}
}

func TestFW003_RestrictedPort_NoViolation(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	// Port is allowed but only from a specific IP — not "Anywhere"
	ufwOut := "Status: active\n18789                      ALLOW       192.168.1.0/24\n"
	fw003OpenClawPorts(b, ufwOut)
	r := b.Build()
	if r.Checks[0].Status != StatusPass {
		t.Errorf("expected PASS when port restricted to specific IP, got %s", r.Checks[0].Status)
	}
}

// TestIptablesRuleRE ensures the regexp matches numbered rule lines.
func TestIptablesRuleRE(t *testing.T) {
	matches := []string{"1    ACCEPT", "  2  DROP", "10   LOG"}
	noMatches := []string{"Chain INPUT", "target     prot", ""}
	for _, line := range matches {
		if !iptablesRuleRE.MatchString(line) {
			t.Errorf("expected match for %q", line)
		}
	}
	for _, line := range noMatches {
		if iptablesRuleRE.MatchString(line) {
			t.Errorf("expected no match for %q", line)
		}
	}
}
