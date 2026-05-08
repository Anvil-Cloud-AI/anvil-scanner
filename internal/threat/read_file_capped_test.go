//go:build darwin || linux

package threat

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestReadFileCapped_UnderCap verifies that when the file is smaller than the
// cap, the entire file content is returned without truncation.
func TestReadFileCapped_UnderCap(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		cap     int64
	}{
		{"ascii text well under cap", []byte("hello world\n"), 1024},
		{"empty file", []byte{}, 1024},
		{"binary content under cap", []byte{0x00, 0xFF, 0x7F, 0x01, 0xAB}, 1024},
		{"file exactly one byte under cap", bytes.Repeat([]byte("A"), 99), 100},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			path := filepath.Join(tmp, "under.dat")
			if err := os.WriteFile(path, tc.content, 0o644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			got, err := readFileCapped(path, tc.cap)
			if err != nil {
				t.Fatalf("readFileCapped() error = %v; want nil", err)
			}
			if !bytes.Equal(got, tc.content) {
				t.Errorf("readFileCapped() = %q; want %q", got, tc.content)
			}
		})
	}
}

// TestReadFileCapped_TruncatesToExactCap verifies that when the file is larger
// than the cap, readFileCapped returns exactly cap bytes — not cap+1 or cap-1.
func TestReadFileCapped_TruncatesToExactCap(t *testing.T) {
	tests := []struct {
		name string
		cap  int64
	}{
		{"cap 1", 1},
		{"cap 7", 7},
		{"cap 100", 100},
		{"cap 1023", 1023},
		{"cap 64 KiB", 64 * 1024},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			// File is always 3× the cap so it is definitely larger.
			content := bytes.Repeat([]byte("Z"), int(tc.cap*3))
			path := filepath.Join(tmp, "large.dat")
			if err := os.WriteFile(path, content, 0o644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			got, err := readFileCapped(path, tc.cap)
			if err != nil {
				t.Fatalf("readFileCapped() error = %v; want nil", err)
			}
			if int64(len(got)) != tc.cap {
				t.Errorf("readFileCapped() returned %d bytes; want exactly %d (cap)",
					len(got), tc.cap)
			}
			// Returned bytes must be the leading cap bytes of the file.
			if !bytes.Equal(got, content[:tc.cap]) {
				t.Errorf("readFileCapped() returned wrong leading bytes")
			}
		})
	}
}

// TestReadFileCapped_NonexistentFile verifies that a missing path produces a
// non-nil error.
func TestReadFileCapped_NonexistentFile(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"absent file in temp dir", filepath.Join(t.TempDir(), "no-such-file.dat")},
		{"deeply absent path", "/nonexistent/anvil/test/path/missing.dat"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readFileCapped(tc.path, 1024)
			if err == nil {
				t.Fatalf("readFileCapped(%q) = %q, nil; want error", tc.path, got)
			}
		})
	}
}
