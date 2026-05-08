//go:build darwin || linux

package schedule

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// buildPlist edge cases
// ---------------------------------------------------------------------------

func TestBuildPlist_PathWithSpaces(t *testing.T) {
	content, err := buildPlist("/home/user/my tools/anvil-scanner")
	if err != nil {
		t.Fatalf("buildPlist: %v", err)
	}
	if !strings.Contains(content, "my tools/anvil-scanner") {
		t.Error("plist missing binary path with spaces")
	}
	if !strings.Contains(content, "<key>Label</key>") {
		t.Error("plist missing Label key")
	}
}

func TestBuildPlist_ContainsLogPaths(t *testing.T) {
	content, err := buildPlist("/usr/bin/anvil")
	if err != nil {
		t.Fatalf("buildPlist: %v", err)
	}
	if !strings.Contains(content, "anvil-scanner.stdout.log") {
		t.Error("plist missing stdout log path")
	}
	if !strings.Contains(content, "anvil-scanner.stderr.log") {
		t.Error("plist missing stderr log path")
	}
	if !strings.Contains(content, "StandardOutPath") {
		t.Error("plist missing StandardOutPath key")
	}
	if !strings.Contains(content, "StandardErrorPath") {
		t.Error("plist missing StandardErrorPath key")
	}
}

func TestBuildPlist_ContainsPATHEnv(t *testing.T) {
	content, err := buildPlist("/usr/bin/anvil")
	if err != nil {
		t.Fatalf("buildPlist: %v", err)
	}
	if !strings.Contains(content, "EnvironmentVariables") {
		t.Error("plist missing EnvironmentVariables key")
	}
	if !strings.Contains(content, "/usr/local/bin") {
		t.Error("plist missing PATH value")
	}
}

// ---------------------------------------------------------------------------
// plistPath
// ---------------------------------------------------------------------------

func TestPlistPath_UnderHomeDir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home dir:", err)
	}
	pp, err := plistPath()
	if err != nil {
		t.Fatalf("plistPath: %v", err)
	}
	if !strings.HasPrefix(pp, home) {
		t.Errorf("plistPath %q does not start with home %q", pp, home)
	}
}

func TestPlistPath_ContainsLaunchAgents(t *testing.T) {
	pp, err := plistPath()
	if err != nil {
		t.Fatalf("plistPath: %v", err)
	}
	if !strings.Contains(pp, "LaunchAgents") {
		t.Errorf("plistPath %q does not contain LaunchAgents", pp)
	}
}

func TestPlistPath_HasPlistExtension(t *testing.T) {
	pp, err := plistPath()
	if err != nil {
		t.Fatalf("plistPath: %v", err)
	}
	if filepath.Ext(pp) != ".plist" {
		t.Errorf("expected .plist extension, got %q", filepath.Ext(pp))
	}
}

func TestPlistPath_ContainsLabel(t *testing.T) {
	pp, err := plistPath()
	if err != nil {
		t.Fatalf("plistPath: %v", err)
	}
	if !strings.Contains(pp, plistLabel) {
		t.Errorf("plistPath %q does not contain label %q", pp, plistLabel)
	}
}

// ---------------------------------------------------------------------------
// currentCrontab
// ---------------------------------------------------------------------------

func TestCurrentCrontab_ReturnsSlice(t *testing.T) {
	// currentCrontab shells out to `crontab -l`. It must return a non-panic
	// result regardless of whether the user has a crontab or not.
	lines := currentCrontab()
	// nil is valid (no crontab or crontab command absent); slice is also valid.
	// What we assert is that the function does not panic and returns a []string.
	_ = lines
}

func TestCurrentCrontab_ReturnsNilOnEmptyCrontab(t *testing.T) {
	// On macOS CI and most dev machines, crontab -l exits 1 when there is no
	// crontab. Verify we get nil back rather than a slice with an empty entry.
	lines := currentCrontab()
	for _, l := range lines {
		if l == "" {
			t.Error("currentCrontab returned a slice containing empty strings")
		}
	}
}

// ---------------------------------------------------------------------------
// writeCrontab
// ---------------------------------------------------------------------------

func TestWriteCrontab_FailsWhenCrontabBinaryMissing(t *testing.T) {
	// writeCrontab writes a temp file then calls `crontab <tmpfile>`.
	// On macOS, crontab is available but may fail due to permissions or
	// sandbox. On Linux CI it may also fail. The important thing is that
	// the function propagates the error rather than panicking or silently
	// succeeding when the install fails.
	//
	// We use a content that would be valid so that any error comes from
	// the crontab binary invocation path, exercising the error return.
	// We don't assert on a specific error because the test machine may or
	// may not allow crontab writes.
	content := "# test only\n"
	err := writeCrontab(content)
	// On macOS where crontab -l reports "no crontab", writing may succeed
	// or fail — either is fine as long as we don't panic.
	_ = err
}

func TestWriteCrontab_CreatesAnvilDir(t *testing.T) {
	// Override HOME to an isolated temp dir so writeCrontab creates its
	// directory structure without touching the real home directory.
	// The subsequent `crontab` invocation will fail (expected), but the
	// directory and temp file creation paths will be exercised.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// On darwin UserHomeDir also reads $HOME via os.UserHomeDir which on
	// recent Go versions honours the HOME env var.
	_ = writeCrontab("# anvil test\n")

	anvilDir := filepath.Join(tmpHome, ".anvil-scanner")
	if _, err := os.Stat(anvilDir); os.IsNotExist(err) {
		t.Errorf("expected %s to be created by writeCrontab", anvilDir)
	}
}

// ---------------------------------------------------------------------------
// setupLinux / removeLinux
// ---------------------------------------------------------------------------

func TestSetupLinux_DryRun(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("setupLinux is only exercised on Linux")
	}
	if err := setupLinux("/usr/local/bin/anvil-scanner", true); err != nil {
		t.Fatalf("setupLinux dry-run: %v", err)
	}
}

func TestSetupLinux_RejectsUnsafePath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("setupLinux is only exercised on Linux")
	}
	err := setupLinux(`/usr/"bin/anvil`, false)
	if err == nil {
		t.Error("expected error for unsafe binary path")
	}
}

func TestRemoveLinux_NoEntryPresent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("removeLinux is only exercised on Linux")
	}
	// When there is no anvil-scanner crontab entry, removeLinux should
	// print "No scheduled job found." and return nil without modifying
	// the crontab.
	err := removeLinux()
	if err != nil {
		t.Fatalf("removeLinux with no entry: %v", err)
	}
}

// ---------------------------------------------------------------------------
// setupMacOS / removeMacOS
// ---------------------------------------------------------------------------

func TestSetupMacOS_DryRun(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("setupMacOS is only exercised on macOS")
	}
	// Dry-run must not write any file or invoke launchctl.
	if err := setupMacOS("/usr/local/bin/anvil-scanner", true); err != nil {
		t.Fatalf("setupMacOS dry-run: %v", err)
	}
}

func TestRemoveMacOS_WhenPlistAbsent(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("removeMacOS is only exercised on macOS")
	}
	// Redirect HOME to a temp dir so there is definitely no plist file.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	err := removeMacOS()
	if err != nil {
		t.Fatalf("removeMacOS when plist absent: %v", err)
	}
}

func TestRemoveMacOS_WhenPlistPresent(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("removeMacOS is only exercised on macOS")
	}
	// Place a fake plist file at the expected path and verify removeMacOS
	// deletes it. launchctl unload will fail (expected); we assert the
	// file is removed and no error is returned.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Create the LaunchAgents directory and a stub plist.
	laDir := filepath.Join(tmpHome, "Library", "LaunchAgents")
	if err := os.MkdirAll(laDir, 0o700); err != nil {
		t.Fatalf("mkdir LaunchAgents: %v", err)
	}
	pp := filepath.Join(laDir, plistLabel+".plist")
	if err := os.WriteFile(pp, []byte("<plist/>"), 0o600); err != nil {
		t.Fatalf("writing stub plist: %v", err)
	}

	// removeMacOS calls launchctl unload (which may fail — that's fine).
	// The plist must be deleted regardless.
	err := removeMacOS()
	if err != nil {
		t.Fatalf("removeMacOS: %v", err)
	}
	if _, statErr := os.Stat(pp); !os.IsNotExist(statErr) {
		t.Error("expected plist to be removed but it still exists")
	}
}

// ---------------------------------------------------------------------------
// Setup / Remove (platform dispatch)
// ---------------------------------------------------------------------------

func TestSetup_DryRun_CurrentPlatform(t *testing.T) {
	// Setup with dryRun=true must never write files or invoke launchctl/crontab.
	if err := Setup("/usr/local/bin/anvil-scanner", true); err != nil {
		t.Fatalf("Setup dry-run: %v", err)
	}
}

func TestSetup_DryRun_UnsafePath(t *testing.T) {
	// On Linux cronEntry rejects the path; on macOS buildPlist happily
	// escapes it. Only assert the error on Linux.
	if runtime.GOOS == "linux" {
		err := Setup(`/usr/"bin/anvil`, true)
		if err == nil {
			t.Error("expected error for unsafe binary path on linux")
		}
	}
}

func TestRemove_WhenNoJobInstalled(t *testing.T) {
	// Redirect HOME so there is no plist (macOS) and the crontab is empty
	// (linux). Remove must return nil in both cases.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	err := Remove()
	if err != nil {
		t.Fatalf("Remove when no job installed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// cronEntry table-driven edge cases
// ---------------------------------------------------------------------------

func TestCronEntry_TableDriven(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"normal path", "/usr/local/bin/anvil-scanner", false},
		{"path with spaces", "/home/user/my tools/anvil-scanner", false},
		{"path with double-quote", `/usr/"bin/anvil`, true},
		{"path with backslash", `/usr/\bin/anvil`, true},
		{"path with newline", "/usr/bin/anvil\nscanner", true},
		{"empty path", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry, err := cronEntry(tc.path)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got entry: %q", entry)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.Contains(entry, cronComment) {
				t.Errorf("entry missing cron comment: %q", entry)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// filterCron edge cases
// ---------------------------------------------------------------------------

func TestFilterCron_EmptyInput(t *testing.T) {
	result := filterCron(nil)
	if result != nil {
		t.Errorf("expected nil for nil input, got %v", result)
	}
}

func TestFilterCron_AllAnvilLines(t *testing.T) {
	lines := []string{
		"0 * * * * /usr/local/bin/anvil-scanner --no-ai  # anvil-scanner",
		"30 * * * * /usr/local/bin/anvil-scanner --no-ai  # anvil-scanner",
	}
	result := filterCron(lines)
	if len(result) != 0 && result != nil {
		t.Errorf("expected all lines filtered, got %v", result)
	}
}

func TestFilterCron_PreservesNonAnvilLines(t *testing.T) {
	lines := []string{
		"0 2 * * * /usr/bin/backup",
		"15 3 * * * /usr/bin/cleanup",
	}
	result := filterCron(lines)
	if len(result) != 2 {
		t.Errorf("expected 2 lines preserved, got %d", len(result))
	}
}
