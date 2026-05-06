//go:build darwin || linux

package backup

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ── defaultBackupRoot ─────────────────────────────────────────────────────────

// TestDefaultBackupRoot_ReturnsNonEmptyPathUnderHome verifies that
// defaultBackupRoot returns a non-empty path that is rooted inside the user's
// home directory.
func TestDefaultBackupRoot_ReturnsNonEmptyPathUnderHome(t *testing.T) {
	root, err := defaultBackupRoot()
	if err != nil {
		t.Fatalf("defaultBackupRoot() error: %v", err)
	}
	if root == "" {
		t.Fatal("defaultBackupRoot() returned empty string; want non-empty path")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("os.UserHomeDir() error: %v", err)
	}
	if !strings.HasPrefix(root, home) {
		t.Errorf("defaultBackupRoot() = %q; want path under home %q", root, home)
	}
}

// TestDefaultBackupRoot_ContainsAnvilScanner verifies that the returned path
// contains the expected ".anvil-scanner" directory component.
func TestDefaultBackupRoot_ContainsAnvilScanner(t *testing.T) {
	root, err := defaultBackupRoot()
	if err != nil {
		t.Fatalf("defaultBackupRoot() error: %v", err)
	}
	if !strings.Contains(root, ".anvil-scanner") {
		t.Errorf("defaultBackupRoot() = %q; want path containing '.anvil-scanner'", root)
	}
}

// TestDefaultBackupRoot_ContainsBackups verifies that the returned path contains
// the "backups" component — matching filepath.Join(home, ".anvil-scanner", "backups").
func TestDefaultBackupRoot_ContainsBackups(t *testing.T) {
	root, err := defaultBackupRoot()
	if err != nil {
		t.Fatalf("defaultBackupRoot() error: %v", err)
	}
	if !strings.HasSuffix(root, "backups") {
		t.Errorf("defaultBackupRoot() = %q; want path ending with 'backups'", root)
	}
}

// ── fmtFiles ──────────────────────────────────────────────────────────────────

// TestFmtFiles covers all pluralisation branches of fmtFiles.
func TestFmtFiles(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{0, "0 files"},
		{1, "1 file"},
		{2, "2 files"},
		{10, "10 files"},
		{100, "100 files"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			got := fmtFiles(tc.n)
			if got != tc.want {
				t.Errorf("fmtFiles(%d) = %q; want %q", tc.n, got, tc.want)
			}
		})
	}
}

// TestFmtFiles_NegativeDoesNotPanic verifies fmtFiles handles edge-case inputs
// without panicking.
func TestFmtFiles_NegativeDoesNotPanic(t *testing.T) {
	got := fmtFiles(-1)
	if got == "" {
		t.Error("fmtFiles(-1) returned empty string; want a non-empty result")
	}
}

// ── copyFile ──────────────────────────────────────────────────────────────────

// TestCopyFile_PreservesPermissions verifies that the destination file receives
// the same permission bits as the source (best-effort chmod).
func TestCopyFile_PreservesPermissions(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src.conf")
	dst := filepath.Join(tmp, "dst.conf")

	// Write with non-default permissions.
	if err := os.WriteFile(src, []byte("Port 22\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile() error: %v", err)
	}

	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("Stat dst: %v", err)
	}
	// copyFile always creates with 0o600, then chmod to src's mode.
	// On most systems 0o640 should be applied.
	if fi.Mode().Perm() != 0o640 {
		t.Errorf("dst permissions = %o; want %o", fi.Mode().Perm(), 0o640)
	}
}

// TestCopyFile_OverwritesExistingFile verifies that copyFile truncates and
// overwrites an existing destination file.
func TestCopyFile_OverwritesExistingFile(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src.txt")
	dst := filepath.Join(tmp, "dst.txt")

	if err := os.WriteFile(src, []byte("new content"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Pre-create dst with different content.
	if err := os.WriteFile(dst, []byte("old content that should be replaced"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile() error: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "new content" {
		t.Errorf("dst content = %q; want %q", got, "new content")
	}
}

// TestCopyFile_SymlinkAtDstIsReplaced verifies the TOCTOU guard: if a symlink
// exists at dst, copyFile removes it and writes a regular file.
func TestCopyFile_SymlinkAtDstIsReplaced(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "real.txt")
	target := filepath.Join(tmp, "target.txt")
	dst := filepath.Join(tmp, "link.txt")

	if err := os.WriteFile(src, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Create a symlink at dst pointing somewhere else.
	if err := os.WriteFile(target, []byte("original target"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, dst); err != nil {
		t.Fatal(err)
	}

	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile() error: %v", err)
	}

	// dst must now be a regular file with src's content, not a symlink.
	fi, err := os.Lstat(dst)
	if err != nil {
		t.Fatalf("Lstat dst: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Error("dst is still a symlink after copyFile; expected regular file")
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("ReadFile dst: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("dst content = %q; want %q", got, "hello")
	}

	// The original target must be unchanged.
	orig, _ := os.ReadFile(target)
	if string(orig) != "original target" {
		t.Errorf("original symlink target changed; got %q", orig)
	}
}

// ── reloadSSHD ────────────────────────────────────────────────────────────────

// TestReloadSSHD_DoesNotPanic verifies that reloadSSHD never panics regardless
// of whether sshd-related commands are available on the test system.
// It also verifies the function writes a non-empty completion message.
func TestReloadSSHD_DoesNotPanic(t *testing.T) {
	var buf bytes.Buffer
	// Must not panic.
	reloadSSHD(&buf)
	// On both Darwin and Linux the function always writes an "OK" line at the end.
	out := buf.String()
	switch runtime.GOOS {
	case "darwin":
		if !strings.Contains(out, "SSH daemon reloaded") {
			t.Errorf("reloadSSHD on darwin: expected 'SSH daemon reloaded', got: %q", out)
		}
	case "linux":
		if !strings.Contains(out, "SSH daemon reloaded") {
			t.Errorf("reloadSSHD on linux: expected 'SSH daemon reloaded', got: %q", out)
		}
	}
}

// ── removeFirewallRules ────────────────────────────────────────────────────────

// TestRemoveFirewallRules_DoesNotPanic verifies that removeFirewallRules never
// panics. On most CI hosts neither ufw nor pfctl will actually remove rules,
// but the function must still complete cleanly.
func TestRemoveFirewallRules_DoesNotPanic(t *testing.T) {
	var buf bytes.Buffer
	// Must not panic — firewall tools may or may not be present.
	removeFirewallRules(&buf)
	// No assertion on output: the function is best-effort and output is
	// conditional on which tools are installed. We only check for no panic.
}

// ── DoUninstall ────────────────────────────────────────────────────────────────

// TestDoUninstall_NoBackupsNoForceReturnsNil verifies that DoUninstall with no
// backup sessions and force=false returns nil and prints a warning.
func TestDoUninstall_NoBackupsNoForceReturnsNil(t *testing.T) {
	tmp := t.TempDir()
	overrideBackupRoot(t, tmp) // empty: no sessions

	var out bytes.Buffer
	// Provide "y" in input — but the function should exit early before prompting.
	err := DoUninstall(strings.NewReader("y\n"), &out, false)
	if err != nil {
		t.Fatalf("DoUninstall() error: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "WARNING") && !strings.Contains(output, "No backups") {
		t.Errorf("expected warning about no backups; got: %q", output)
	}
}

// TestDoUninstall_ForceWithNoBackupsProceedsWithConfirmation verifies that
// force=true proceeds past the no-backup check and prompts for confirmation.
func TestDoUninstall_ForceWithNoBackupsProceedsWithConfirmation(t *testing.T) {
	tmp := t.TempDir()
	overrideBackupRoot(t, tmp) // empty: no sessions

	var out bytes.Buffer
	// Input "n" to cancel at the confirmation prompt.
	err := DoUninstall(strings.NewReader("n\n"), &out, true)
	if err != nil {
		t.Fatalf("DoUninstall(force=true, confirm=n) error: %v", err)
	}
	output := out.String()
	// The confirmation prompt must appear.
	if !strings.Contains(output, "Continue?") {
		t.Errorf("expected confirmation prompt 'Continue?'; got: %q", output)
	}
}

// TestDoUninstall_CancelsOnNoConfirmation verifies that answering "n" to the
// confirmation prompt causes DoUninstall to return nil without restoring.
func TestDoUninstall_CancelsOnNoConfirmation(t *testing.T) {
	tmp := t.TempDir()
	overrideBackupRoot(t, tmp)

	// Create one session so force is not needed.
	sessionDir := filepath.Join(tmp, "2026-04-21_154300")
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	data := manifestData{
		Session: "2026-04-21_154300",
		Backups: []manifestEntry{
			{
				Original:    "/etc/ssh/sshd_config",
				Backup:      filepath.Join(sessionDir, "etc", "ssh", "sshd_config"),
				Description: "test",
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
			},
		},
	}
	raw, _ := json.MarshalIndent(data, "", "  ")
	if err := os.WriteFile(filepath.Join(sessionDir, "manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err := DoUninstall(strings.NewReader("n\n"), &out, false)
	if err != nil {
		t.Fatalf("DoUninstall() error on cancel: %v", err)
	}
	// Output must not contain a "Restored" completion message.
	output := out.String()
	if strings.Contains(output, "fully uninstalled") {
		t.Errorf("expected cancellation but got uninstall completion: %q", output)
	}
}

// TestDoUninstall_YesConfirmationRunsSteps verifies that confirming with "y"
// causes DoUninstall to execute all four steps and produce completion output.
func TestDoUninstall_YesConfirmationRunsSteps(t *testing.T) {
	tmp := t.TempDir()
	overrideBackupRoot(t, tmp)

	// Create a session with an empty backups list so RevertSession is called but
	// nothing actually needs system privileges to restore.
	sessionDir := filepath.Join(tmp, "2026-04-21_154300")
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	data := manifestData{Session: "2026-04-21_154300", Backups: nil}
	raw, _ := json.MarshalIndent(data, "", "  ")
	if err := os.WriteFile(filepath.Join(sessionDir, "manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err := DoUninstall(strings.NewReader("y\n"), &out, false)
	if err != nil {
		t.Fatalf("DoUninstall(confirm=y) error: %v", err)
	}
	output := out.String()

	for _, step := range []string{"Step 1", "Step 2", "Step 3", "Step 4"} {
		if !strings.Contains(output, step) {
			t.Errorf("DoUninstall output missing %q; full output: %q", step, output)
		}
	}
}

// TestDoUninstall_EmptyInputEOFReturnsNil verifies that EOF on the reader
// (simulating Ctrl-D) causes DoUninstall to return nil gracefully.
func TestDoUninstall_EmptyInputEOFReturnsNil(t *testing.T) {
	tmp := t.TempDir()
	overrideBackupRoot(t, tmp)

	// Create a session so the function reaches the confirmation prompt.
	sessionDir := filepath.Join(tmp, "2026-04-21_154300")
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	data := manifestData{Session: "2026-04-21_154300", Backups: nil}
	raw, _ := json.MarshalIndent(data, "", "  ")
	if err := os.WriteFile(filepath.Join(sessionDir, "manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	// Empty reader → scanner.Scan() immediately returns false (EOF).
	err := DoUninstall(strings.NewReader(""), &out, false)
	if err != nil {
		t.Fatalf("DoUninstall(EOF) error: %v", err)
	}
}

// ── DoRevert additional paths ─────────────────────────────────────────────────

// TestDoRevert_NoSessionsPrintsWarning verifies that DoRevert with an empty
// backup root prints a warning and returns nil.
func TestDoRevert_NoSessionsPrintsWarning(t *testing.T) {
	tmp := t.TempDir()
	overrideBackupRoot(t, tmp)

	var out bytes.Buffer
	err := DoRevert(strings.NewReader(""), &out)
	if err != nil {
		t.Fatalf("DoRevert() error: %v", err)
	}
	if !strings.Contains(out.String(), "WARNING") && !strings.Contains(out.String(), "No backup") {
		t.Errorf("expected no-sessions warning; got: %q", out.String())
	}
}

// TestDoRevert_InvalidSelectionCancels verifies that a non-numeric or
// out-of-range selection cancels gracefully.
func TestDoRevert_InvalidSelectionCancels(t *testing.T) {
	tmp := t.TempDir()
	overrideBackupRoot(t, tmp)

	sessionDir := filepath.Join(tmp, "2026-04-21_154300")
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	data := manifestData{
		Session: "2026-04-21_154300",
		Backups: []manifestEntry{
			{Original: "/etc/ssh/sshd_config", Backup: filepath.Join(sessionDir, "x"), Description: "t", Timestamp: ""},
		},
	}
	raw, _ := json.MarshalIndent(data, "", "  ")
	if err := os.WriteFile(filepath.Join(sessionDir, "manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input string
		want  string
	}{
		// 99 is out of range: the check 'choice > len(sessions)' fires -> WARNING.
		{"out of range high", "99\n", "WARNING"},
		// "abc" fails Sscanf; choice stays 0, which the code treats as cancel.
		{"non-numeric", "abc\n", "Cancelled"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := DoRevert(strings.NewReader(tc.input), &out); err != nil {
				t.Fatalf("DoRevert() error: %v", err)
			}
			if !strings.Contains(out.String(), tc.want) {
				t.Errorf("input %q: expected %q in output; got: %q", tc.input, tc.want, out.String())
			}
		})
	}
}

// TestDoRevert_EOFBeforeSelectionReturnsNil verifies that EOF before the user
// makes a selection returns nil gracefully.
func TestDoRevert_EOFBeforeSelectionReturnsNil(t *testing.T) {
	tmp := t.TempDir()
	overrideBackupRoot(t, tmp)

	sessionDir := filepath.Join(tmp, "2026-04-21_154300")
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	data := manifestData{Session: "2026-04-21_154300", Backups: nil}
	raw, _ := json.MarshalIndent(data, "", "  ")
	if err := os.WriteFile(filepath.Join(sessionDir, "manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := DoRevert(strings.NewReader(""), &out); err != nil {
		t.Fatalf("DoRevert(EOF) error: %v", err)
	}
}

// TestDoRevert_EmptySessionChosenReturnsWarning verifies that choosing a session
// whose backup list is empty emits a warning and returns nil.
func TestDoRevert_EmptySessionChosenReturnsWarning(t *testing.T) {
	tmp := t.TempDir()
	overrideBackupRoot(t, tmp)

	sessionDir := filepath.Join(tmp, "2026-04-21_154300")
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	data := manifestData{Session: "2026-04-21_154300", Backups: nil} // empty
	raw, _ := json.MarshalIndent(data, "", "  ")
	if err := os.WriteFile(filepath.Join(sessionDir, "manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	// Choose session 1 (the only session).
	if err := DoRevert(strings.NewReader("1\n"), &out); err != nil {
		t.Fatalf("DoRevert() error: %v", err)
	}
	if !strings.Contains(out.String(), "WARNING") {
		t.Errorf("expected WARNING for empty session; got: %q", out.String())
	}
}

// TestDoRevert_ConfirmNoCancels verifies that confirming with "n" after
// selecting a valid session cancels without reverting.
func TestDoRevert_ConfirmNoCancels(t *testing.T) {
	tmp := t.TempDir()
	overrideBackupRoot(t, tmp)

	sessionDir := filepath.Join(tmp, "2026-04-21_154300")
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	data := manifestData{
		Session: "2026-04-21_154300",
		Backups: []manifestEntry{
			{Original: "/etc/ssh/sshd_config", Backup: filepath.Join(sessionDir, "x"), Description: "test", Timestamp: ""},
		},
	}
	raw, _ := json.MarshalIndent(data, "", "  ")
	if err := os.WriteFile(filepath.Join(sessionDir, "manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	// Select session 1, then deny confirmation.
	if err := DoRevert(strings.NewReader("1\nn\n"), &out); err != nil {
		t.Fatalf("DoRevert() error on confirm=n: %v", err)
	}
	// Must not contain a "Restored" success message.
	if strings.Contains(out.String(), "Restored") {
		t.Errorf("expected no restore on confirm=n; got: %q", out.String())
	}
}

// ── NewManager ────────────────────────────────────────────────────────────────

// TestNewManager_UsesBackupRootFn verifies that NewManager delegates to
// backupRootFn and embeds the returned root in Manager.BackupRoot.
func TestNewManager_UsesBackupRootFn(t *testing.T) {
	tmp := t.TempDir()
	overrideBackupRoot(t, tmp)

	m, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	if m.BackupRoot != tmp {
		t.Errorf("BackupRoot = %q; want %q", m.BackupRoot, tmp)
	}
	if !strings.HasPrefix(m.SessionDir, tmp) {
		t.Errorf("SessionDir = %q; want it under %q", m.SessionDir, tmp)
	}
}

// TestNewManager_ErrorWhenBackupRootFails verifies that NewManager propagates
// an error returned by backupRootFn.
func TestNewManager_ErrorWhenBackupRootFails(t *testing.T) {
	orig := backupRootFn
	backupRootFn = func() (string, error) {
		return "", os.ErrPermission
	}
	t.Cleanup(func() { backupRootFn = orig })

	_, err := NewManager()
	if err == nil {
		t.Fatal("NewManager() returned nil; want error from failing backupRootFn")
	}
}
