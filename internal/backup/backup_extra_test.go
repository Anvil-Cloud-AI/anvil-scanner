//go:build darwin || linux

package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCopyFile_ContentPreserved verifies that a successful copy produces a
// destination file whose content is byte-for-byte identical to the source.
func TestCopyFile_ContentPreserved(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
	}{
		{"empty file", []byte{}},
		{"ascii text", []byte("Port 22\nPermitRootLogin no\n")},
		{"binary-ish content", []byte{0x00, 0xFF, 0x7F, 0x01, 0xAB, 0xCD}},
		{"unicode content", []byte("# Anvil Scanner config\nHost *\n  ServerAliveInterval 60\n")},
		{"single newline", []byte("\n")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			src := filepath.Join(tmp, "source.conf")
			dst := filepath.Join(tmp, "dest.conf")

			if err := os.WriteFile(src, tc.content, 0o644); err != nil {
				t.Fatalf("write source: %v", err)
			}

			if err := copyFile(src, dst); err != nil {
				t.Fatalf("copyFile() error: %v", err)
			}

			got, err := os.ReadFile(dst)
			if err != nil {
				t.Fatalf("ReadFile dest: %v", err)
			}
			if string(got) != string(tc.content) {
				t.Errorf("content mismatch: got %q, want %q", got, tc.content)
			}
		})
	}
}

// TestCopyFile_MissingSrcReturnsError verifies that copying a non-existent
// source returns a non-nil error whose message contains the source path.
func TestCopyFile_MissingSrcReturnsError(t *testing.T) {
	tmp := t.TempDir()

	tests := []struct {
		name string
		src  string
	}{
		{
			name: "absent file in temp dir",
			src:  filepath.Join(tmp, "does-not-exist.conf"),
		},
		{
			name: "deeply absent path",
			src:  filepath.Join(tmp, "a", "b", "c", "missing.conf"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dst := filepath.Join(tmp, "out.conf")

			err := copyFile(tc.src, dst)
			if err == nil {
				t.Fatalf("copyFile(%q, ...) = nil; want error", tc.src)
			}
			// Implementation wraps: fmt.Errorf("backup: open %s: %w", src, err)
			// so the src path must appear in the message.
			if !strings.Contains(err.Error(), tc.src) {
				t.Errorf("error %q does not contain src path %q", err.Error(), tc.src)
			}
		})
	}
}

// TestLoadManifest_CorruptJSON verifies that loadManifest returns a non-nil
// error for invalid JSON and that the error message contains the manifest path.
func TestLoadManifest_CorruptJSON(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"truncated JSON", `{"session":"2026-04-21","backups":[`},
		{"plain text", "this is not json at all"},
		{"empty file", ""},
		{"partial object", `{"session":}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			manifestPath := filepath.Join(tmp, "manifest.json")

			if err := os.WriteFile(manifestPath, []byte(tc.content), 0o600); err != nil {
				t.Fatalf("write manifest: %v", err)
			}

			_, err := loadManifest(manifestPath)
			if err == nil {
				t.Fatalf("loadManifest(%q) = nil; want error for corrupt content %q",
					manifestPath, tc.content)
			}
			// Implementation wraps: fmt.Errorf("backup: parse manifest %s: %w", path, err)
			// so the path must appear in the error message.
			if !strings.Contains(err.Error(), manifestPath) {
				t.Errorf("error %q does not contain manifest path %q",
					err.Error(), manifestPath)
			}
		})
	}
}

// TestLoadManifest_ValidJSON verifies the happy path: a well-formed manifest
// round-trips correctly through loadManifest.
func TestLoadManifest_ValidJSON(t *testing.T) {
	tmp := t.TempDir()
	manifestPath := filepath.Join(tmp, "manifest.json")

	// Synthetic manifest — fields: session (timestamp string), backups array with
	// original/backup (path strings), description (string), timestamp (RFC3339).
	content := `{"session":"2026-04-21_154300","backups":[{"original":"/etc/ssh/sshd_config","backup":"/home/user/.anvil-scanner/backups/2026-04-21_154300/etc/ssh/sshd_config","description":"sshd_config before hardening","timestamp":"2026-04-21T15:43:00Z"}]}`
	if err := os.WriteFile(manifestPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	data, err := loadManifest(manifestPath)
	if err != nil {
		t.Fatalf("loadManifest() unexpected error: %v", err)
	}
	if data.Session != "2026-04-21_154300" {
		t.Errorf("Session = %q; want %q", data.Session, "2026-04-21_154300")
	}
	if len(data.Backups) != 1 {
		t.Fatalf("Backups count = %d; want 1", len(data.Backups))
	}
	if data.Backups[0].Original != "/etc/ssh/sshd_config" {
		t.Errorf("Backups[0].Original = %q; want %q",
			data.Backups[0].Original, "/etc/ssh/sshd_config")
	}
}

// TestLoadManifest_MissingFile verifies that loadManifest returns an error
// when the file does not exist.
func TestLoadManifest_MissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-manifest.json")
	_, err := loadManifest(path)
	if err == nil {
		t.Fatal("loadManifest on missing file returned nil; want error")
	}
}
