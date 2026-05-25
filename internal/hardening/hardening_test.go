//go:build darwin || linux

package hardening

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
)

// --- indexChecks / needsFix ---

func TestIndexChecks_BasicLookup(t *testing.T) {
	checks := []scan.Check{
		{ID: "SSH-006", Status: scan.StatusFail},
		{ID: "SSH-008", Status: scan.StatusWarn},
		{ID: "SSH-014", Status: scan.StatusPass},
	}
	idx := indexChecks(checks)
	if idx["SSH-006"] != scan.StatusFail {
		t.Errorf("SSH-006 want FAIL, got %v", idx["SSH-006"])
	}
	if idx["SSH-008"] != scan.StatusWarn {
		t.Errorf("SSH-008 want WARN, got %v", idx["SSH-008"])
	}
	if idx["SSH-014"] != scan.StatusPass {
		t.Errorf("SSH-014 want PASS, got %v", idx["SSH-014"])
	}
}

func TestNeedsFix_FailAndWarn(t *testing.T) {
	idx := map[string]scan.Status{
		"SSH-006": scan.StatusFail,
		"SSH-008": scan.StatusWarn,
		"SSH-014": scan.StatusPass,
		"SSH-015": scan.StatusSkip,
	}
	if !needsFix(idx, "SSH-006") {
		t.Error("FAIL should need fix")
	}
	if !needsFix(idx, "SSH-008") {
		t.Error("WARN should need fix")
	}
	if needsFix(idx, "SSH-014") {
		t.Error("PASS should not need fix")
	}
	if needsFix(idx, "SSH-015") {
		t.Error("SKIP should not need fix")
	}
	if needsFix(idx, "SSH-999") {
		t.Error("unknown check should not need fix")
	}
}

// --- rewriteSSHLines (pure text transformation, no I/O) ---

func TestRewriteSSHLines_ReplacesExistingDirective(t *testing.T) {
	lines := strings.Split("MaxAuthTries 6\nPermitRootLogin no\n", "\n")
	patches := map[string]struct{ canonical, value string }{
		"maxauthtries": {"MaxAuthTries", "4"},
	}
	out, replaced, toAppend := rewriteSSHLines(lines, patches)
	if !replaced["maxauthtries"] {
		t.Error("expected maxauthtries to be marked replaced")
	}
	if len(toAppend) != 0 {
		t.Errorf("unexpected toAppend: %v", toAppend)
	}
	if !strings.Contains(out, "MaxAuthTries 4") {
		t.Errorf("expected MaxAuthTries 4 in output:\n%s", out)
	}
	if strings.Contains(out, "MaxAuthTries 6") {
		t.Error("old value still present in output")
	}
}

func TestRewriteSSHLines_AppendsWhenMissing(t *testing.T) {
	lines := strings.Split("PermitRootLogin no\n", "\n")
	patches := map[string]struct{ canonical, value string }{
		"maxauthtries": {"MaxAuthTries", "4"},
	}
	out, replaced, toAppend := rewriteSSHLines(lines, patches)
	if replaced["maxauthtries"] {
		t.Error("should not be in replaced map — it was appended")
	}
	if len(toAppend) != 1 {
		t.Errorf("expected 1 appended directive, got %d", len(toAppend))
	}
	if !strings.Contains(out, "MaxAuthTries 4") {
		t.Errorf("expected MaxAuthTries 4 appended:\n%s", out)
	}
	if !strings.Contains(out, "# Added by anvil-scanner hardening") {
		t.Error("expected hardening comment block")
	}
}

func TestRewriteSSHLines_SkipsMatchBlock(t *testing.T) {
	src := "MaxAuthTries 6\nMatch User root\n  MaxAuthTries 2\n"
	lines := strings.Split(src, "\n")
	patches := map[string]struct{ canonical, value string }{
		"maxauthtries": {"MaxAuthTries", "4"},
	}
	out, replaced, _ := rewriteSSHLines(lines, patches)
	// The global MaxAuthTries should be replaced.
	if !replaced["maxauthtries"] {
		t.Error("expected global MaxAuthTries to be replaced")
	}
	// The Match-block line must remain unchanged.
	if !strings.Contains(out, "  MaxAuthTries 2") {
		t.Errorf("Match-block MaxAuthTries was altered:\n%s", out)
	}
}

func TestRewriteSSHLines_CommentsPreserved(t *testing.T) {
	src := "# SSH config\n# MaxAuthTries 10\nPermitRootLogin no\n"
	lines := strings.Split(src, "\n")
	patches := map[string]struct{ canonical, value string }{
		"maxauthtries": {"MaxAuthTries", "4"},
	}
	out, _, _ := rewriteSSHLines(lines, patches)
	if !strings.Contains(out, "# MaxAuthTries 10") {
		t.Error("comment line was removed or altered")
	}
}

func TestRewriteSSHLines_MultiplePatches(t *testing.T) {
	src := "MaxAuthTries 6\nX11Forwarding yes\n"
	lines := strings.Split(src, "\n")
	patches := map[string]struct{ canonical, value string }{
		"maxauthtries":  {"MaxAuthTries", "4"},
		"x11forwarding": {"X11Forwarding", "no"},
	}
	out, replaced, toAppend := rewriteSSHLines(lines, patches)
	if !replaced["maxauthtries"] || !replaced["x11forwarding"] {
		t.Errorf("replaced=%v", replaced)
	}
	if len(toAppend) != 0 {
		t.Errorf("unexpected appends: %v", toAppend)
	}
	if !strings.Contains(out, "MaxAuthTries 4") || !strings.Contains(out, "X11Forwarding no") {
		t.Errorf("output missing expected directives:\n%s", out)
	}
}

// --- patchSSHConfig (integration, requires sshd -t) ---

func writeTmpConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write tmp config: %v", err)
	}
	return p
}

func TestPatchSSHConfig_ReplacesExistingDirective(t *testing.T) {
	p := writeTmpConfig(t, "MaxAuthTries 6\nPermitRootLogin no\n")
	patches := map[string]struct{ canonical, value string }{
		"maxauthtries": {"MaxAuthTries", "4"},
	}
	changed, applied, err := patchSSHConfig(p, patches)
	if err != nil {
		t.Skipf("sshd -t not available: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true")
	}
	if len(applied) != 1 || applied[0] != "MaxAuthTries" {
		t.Errorf("applied=%v", applied)
	}
	data, _ := os.ReadFile(p)
	if !strings.Contains(string(data), "MaxAuthTries 4") {
		t.Errorf("expected MaxAuthTries 4, got:\n%s", string(data))
	}
	if strings.Contains(string(data), "MaxAuthTries 6") {
		t.Error("old value still present")
	}
}

// --- Result helper methods ---

func TestResult_Helpers(t *testing.T) {
	var r Result
	r.applied("SSH-006", "MaxAuthTries", "set to 4")
	r.skipped("SSH-008", "LoginGraceTime", "already 60")
	r.failed("SSH-014", "KexAlgorithms", "chmod error")

	if len(r.Applied) != 1 || r.Applied[0].CheckID != "SSH-006" {
		t.Errorf("applied: %+v", r.Applied)
	}
	if len(r.Skipped) != 1 || r.Skipped[0].Detail != "already 60" {
		t.Errorf("skipped: %+v", r.Skipped)
	}
	if len(r.Failed) != 1 || r.Failed[0].Name != "KexAlgorithms" {
		t.Errorf("failed: %+v", r.Failed)
	}
}
