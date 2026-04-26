//go:build darwin || linux

package backup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- helpers ----------------------------------------------------------------

// newManagerInDir creates a Manager whose BackupRoot is inside dir.
func newManagerInDir(t *testing.T, dir string) *Manager {
	t.Helper()
	ts := time.Now().Format("2006-01-02_150405")
	m := &Manager{
		BackupRoot: filepath.Join(dir, "backups"),
		SessionDir: filepath.Join(dir, "backups", ts),
		sessionTS:  ts,
	}
	return m
}

// overrideBackupRoot temporarily redirects backupRootFn so ListSessions and
// NewManager use dir instead of the real ~/.anvil-scanner/backups.
func overrideBackupRoot(t *testing.T, dir string) {
	t.Helper()
	orig := backupRootFn
	backupRootFn = func() (string, error) { return dir, nil }
	t.Cleanup(func() { backupRootFn = orig })
}

// ---- Backup happy path ------------------------------------------------------

func TestBackup_HappyPath(t *testing.T) {
	tmp := t.TempDir()

	// Create a source file to back up.
	srcDir := filepath.Join(tmp, "etc", "ssh")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	srcFile := filepath.Join(srcDir, "sshd_config")
	if err := os.WriteFile(srcFile, []byte("Port 22\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := newManagerInDir(t, tmp)

	got := m.Backup(srcFile, "sshd_config before hardening")
	if !got {
		t.Fatal("Backup() returned false; want true")
	}

	// File must be present under the session dir.
	rel := strings.TrimPrefix(srcFile, "/")
	dest := filepath.Join(m.SessionDir, rel)
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("backed-up file not found at %s: %v", dest, err)
	}

	// Manifest must be written and parseable.
	manifestPath := filepath.Join(m.SessionDir, "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("manifest.json not found: %v", err)
	}
	var data manifestData
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("manifest.json unparseable: %v", err)
	}
	if len(data.Backups) != 1 {
		t.Fatalf("want 1 backup entry, got %d", len(data.Backups))
	}
	if data.Backups[0].Original != srcFile {
		t.Errorf("entry.Original = %q; want %q", data.Backups[0].Original, srcFile)
	}
	if data.Backups[0].Description != "sshd_config before hardening" {
		t.Errorf("entry.Description = %q; want %q", data.Backups[0].Description, "sshd_config before hardening")
	}

	// HasBackups and Summary must reflect the new entry.
	if !m.HasBackups() {
		t.Error("HasBackups() = false; want true")
	}
	summary := m.Summary()
	if !strings.Contains(summary, m.SessionDir) {
		t.Errorf("Summary() does not contain session dir: %q", summary)
	}
}

// ---- Backup returns false for missing file ----------------------------------

func TestBackup_MissingFile(t *testing.T) {
	tmp := t.TempDir()
	m := newManagerInDir(t, tmp)

	got := m.Backup(filepath.Join(tmp, "does-not-exist.conf"), "test")
	if got {
		t.Error("Backup() returned true for a missing file; want false")
	}
	if m.HasBackups() {
		t.Error("HasBackups() = true after backing up missing file; want false")
	}
}

// ---- RevertSession restores correctly ---------------------------------------

func TestRevertSession_RestoresCorrectly(t *testing.T) {
	tmp := t.TempDir()

	// Create the original file.
	origDir := filepath.Join(tmp, "originals")
	if err := os.MkdirAll(origDir, 0o755); err != nil {
		t.Fatal(err)
	}
	origFile := filepath.Join(origDir, "sshd_config")
	if err := os.WriteFile(origFile, []byte("Port 22\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Back it up.
	m := newManagerInDir(t, tmp)
	if !m.Backup(origFile, "test backup") {
		t.Fatal("Backup() returned false")
	}

	// Modify the original.
	if err := os.WriteFile(origFile, []byte("Port 2222\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Revert the session.
	restored, failed, err := RevertSession(m.SessionDir)
	if err != nil {
		t.Fatalf("RevertSession() error: %v", err)
	}
	if restored != 1 {
		t.Errorf("restored = %d; want 1", restored)
	}
	if failed != 0 {
		t.Errorf("failed = %d; want 0", failed)
	}

	// Original should be back to "Port 22".
	got, err := os.ReadFile(origFile)
	if err != nil {
		t.Fatalf("ReadFile after revert: %v", err)
	}
	if string(got) != "Port 22\n" {
		t.Errorf("file content after revert = %q; want %q", string(got), "Port 22\n")
	}
}

// ---- RevertSession rejects path traversal -----------------------------------

func TestRevertSession_RejectsPathTraversal(t *testing.T) {
	tmp := t.TempDir()

	// Create a session directory and a manifest with a backup path that
	// lives outside the session directory (path traversal).
	sessionDir := filepath.Join(tmp, "2026-04-21_154300")
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// The backup source listed in the manifest points OUTSIDE the session dir.
	outsideFile := filepath.Join(tmp, "outside.txt")
	if err := os.WriteFile(outsideFile, []byte("outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The restore destination.
	destFile := filepath.Join(tmp, "destination.txt")

	data := manifestData{
		Session: "2026-04-21_154300",
		Backups: []manifestEntry{
			{
				Original:    destFile,
				Backup:      outsideFile, // outside session dir — should be rejected
				Description: "path traversal attempt",
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
			},
		},
	}
	raw, _ := json.MarshalIndent(data, "", "  ")
	manifestPath := filepath.Join(sessionDir, "manifest.json")
	if err := os.WriteFile(manifestPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	restored, failed, err := RevertSession(sessionDir)
	if err != nil {
		t.Fatalf("RevertSession() unexpected error: %v", err)
	}
	if restored != 0 {
		t.Errorf("restored = %d; want 0 (traversal should be blocked)", restored)
	}
	if failed != 1 {
		t.Errorf("failed = %d; want 1", failed)
	}
	// Destination must NOT have been written.
	if _, err := os.Stat(destFile); err == nil {
		t.Error("destination file was created despite path traversal rejection")
	}
}

// ---- ListSessions returns newest-first, skips dirs without manifest ---------

func TestListSessions_NewestFirstAndSkipsMissingManifest(t *testing.T) {
	tmp := t.TempDir()
	overrideBackupRoot(t, tmp)

	sessions := []string{
		"2026-04-19_100000",
		"2026-04-20_120000",
		"2026-04-21_154300",
	}
	for _, s := range sessions {
		dir := filepath.Join(tmp, s)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		data := manifestData{Session: s, Backups: nil}
		raw, _ := json.MarshalIndent(data, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Add a dir WITHOUT a manifest — it must be skipped.
	noManifestDir := filepath.Join(tmp, "2026-04-22_000000")
	if err := os.MkdirAll(noManifestDir, 0o700); err != nil {
		t.Fatal(err)
	}

	got := ListSessions()

	if len(got) != 3 {
		t.Fatalf("ListSessions() returned %d sessions; want 3", len(got))
	}

	// Expect newest-first order.
	want := []string{
		filepath.Join(tmp, "2026-04-21_154300"),
		filepath.Join(tmp, "2026-04-20_120000"),
		filepath.Join(tmp, "2026-04-19_100000"),
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("sessions[%d] = %q; want %q", i, got[i], w)
		}
	}

	// The no-manifest dir must not appear.
	for _, s := range got {
		if s == noManifestDir {
			t.Errorf("ListSessions() included dir without manifest.json: %s", s)
		}
	}
}

// ---- DoRevert cancels on "0" input ------------------------------------------

func TestDoRevert_CancelsOnZero(t *testing.T) {
	tmp := t.TempDir()
	overrideBackupRoot(t, tmp)

	// Create one session with a manifest so the session list is non-empty.
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

	input := strings.NewReader("0\n")
	var out strings.Builder

	if err := DoRevert(input, &out); err != nil {
		t.Fatalf("DoRevert() error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Cancelled") {
		t.Errorf("expected cancellation message; got: %q", output)
	}
}

// ---- HasBackups and Summary when empty --------------------------------------

func TestManager_EmptySummary(t *testing.T) {
	tmp := t.TempDir()
	m := newManagerInDir(t, tmp)

	if m.HasBackups() {
		t.Error("HasBackups() = true on fresh Manager; want false")
	}
	got := m.Summary()
	if got != "No backups created this session." {
		t.Errorf("Summary() = %q; want %q", got, "No backups created this session.")
	}
}

// ---- copyFile: unwritable destination does not panic -------------------------

func TestCopyFile_UnwritableDest(t *testing.T) {
	tmp := t.TempDir()

	src := filepath.Join(tmp, "source.txt")
	if err := os.WriteFile(src, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create a destination directory with no write permission so
	// os.OpenFile(dst, ...) will fail.
	noWriteDir := filepath.Join(tmp, "noperm")
	if err := os.MkdirAll(noWriteDir, 0o555); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(noWriteDir, "out.txt")

	err := copyFile(src, dst)
	if err == nil {
		t.Error("copyFile to unwritable destination should return an error, got nil")
	}
}

// ---- RevertSession: no manifest returns (0,0,nil) ---------------------------

func TestRevertSession_NoManifest(t *testing.T) {
	tmp := t.TempDir()
	sessionDir := filepath.Join(tmp, "empty-session")
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		t.Fatal(err)
	}

	restored, failed, err := RevertSession(sessionDir)
	if err != nil {
		t.Fatalf("RevertSession() error: %v", err)
	}
	if restored != 0 || failed != 0 {
		t.Errorf("got (%d, %d); want (0, 0)", restored, failed)
	}
}
