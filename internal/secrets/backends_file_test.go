//go:build darwin || linux

package secrets

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

// ── loadFileKey / storeFileKey ────────────────────────────────────────────────

func TestStoreLoadFileKey_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.key")

	key := make([]byte, scryptKeyLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	if err := storeFileKey(path, key); err != nil {
		t.Fatalf("storeFileKey: %v", err)
	}

	got, err := loadFileKey(path)
	if err != nil {
		t.Fatalf("loadFileKey: %v", err)
	}
	if string(got) != string(key) {
		t.Errorf("key mismatch: got %x, want %x", got, key)
	}
}

func TestStoreFileKey_SetsPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.key")

	key := make([]byte, scryptKeyLen)
	rand.Read(key) //nolint:errcheck

	if err := storeFileKey(path, key); err != nil {
		t.Fatalf("storeFileKey: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file permissions: got %04o, want 0600", perm)
	}
}

func TestLoadFileKey_NotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.key")

	_, err := loadFileKey(path)
	if err == nil {
		t.Fatal("loadFileKey: expected error for non-existent file, got nil")
	}
}

func TestLoadFileKey_WrongLength(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.key")

	// Write a key that is too short (16 bytes instead of 32).
	if err := os.WriteFile(path, make([]byte, 16), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := loadFileKey(path)
	if err == nil {
		t.Fatal("loadFileKey: expected error for wrong-length key file, got nil")
	}
}

func TestLoadFileKey_TooLong(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "long.key")

	// Write 64 bytes — twice the expected key size.
	if err := os.WriteFile(path, make([]byte, 64), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := loadFileKey(path)
	if err == nil {
		t.Fatal("loadFileKey: expected error for over-length key file, got nil")
	}
}

func TestStoreFileKey_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.key")

	key1 := make([]byte, scryptKeyLen)
	rand.Read(key1) //nolint:errcheck
	if err := storeFileKey(path, key1); err != nil {
		t.Fatalf("first storeFileKey: %v", err)
	}

	key2 := make([]byte, scryptKeyLen)
	rand.Read(key2) //nolint:errcheck
	if err := storeFileKey(path, key2); err != nil {
		t.Fatalf("second storeFileKey: %v", err)
	}

	got, err := loadFileKey(path)
	if err != nil {
		t.Fatalf("loadFileKey after overwrite: %v", err)
	}
	if string(got) != string(key2) {
		t.Errorf("expected overwritten key2 to be loaded")
	}
}

// ── promptPassphrase via environment variable ─────────────────────────────────

func TestPromptPassphrase_EnvVar_NoConfirm(t *testing.T) {
	t.Setenv("ANVIL_SECRETS_PASSPHRASE", "my-test-passphrase-long")
	pw, err := promptPassphrase(false)
	if err != nil {
		t.Fatalf("promptPassphrase(confirm=false): %v", err)
	}
	if pw != "my-test-passphrase-long" {
		t.Errorf("got %q, want %q", pw, "my-test-passphrase-long")
	}
}

func TestPromptPassphrase_EnvVar_Confirm_LongEnough(t *testing.T) {
	t.Setenv("ANVIL_SECRETS_PASSPHRASE", "longerthantwelvecharacters")
	pw, err := promptPassphrase(true)
	if err != nil {
		t.Fatalf("promptPassphrase(confirm=true): %v", err)
	}
	if pw != "longerthantwelvecharacters" {
		t.Errorf("got %q, want %q", pw, "longerthantwelvecharacters")
	}
}

func TestPromptPassphrase_EnvVar_Confirm_TooShort(t *testing.T) {
	t.Setenv("ANVIL_SECRETS_PASSPHRASE", "short")
	_, err := promptPassphrase(true)
	if err == nil {
		t.Fatal("expected error for passphrase shorter than minPassphraseLen with confirm=true")
	}
}

func TestPromptPassphrase_EnvVar_ExactlyMinLength(t *testing.T) {
	// Build a passphrase exactly minPassphraseLen characters long.
	pw := make([]byte, minPassphraseLen)
	for i := range pw {
		pw[i] = 'a'
	}
	t.Setenv("ANVIL_SECRETS_PASSPHRASE", string(pw))

	got, err := promptPassphrase(true)
	if err != nil {
		t.Fatalf("promptPassphrase(confirm=true) at min length: %v", err)
	}
	if got != string(pw) {
		t.Errorf("passphrase mismatch")
	}
}

func TestPromptPassphrase_EnvVar_OneLessThanMin(t *testing.T) {
	pw := make([]byte, minPassphraseLen-1)
	for i := range pw {
		pw[i] = 'x'
	}
	t.Setenv("ANVIL_SECRETS_PASSPHRASE", string(pw))

	_, err := promptPassphrase(true)
	if err == nil {
		t.Fatal("expected error for passphrase one character below minimum")
	}
}

// ── validKeyNameRE ────────────────────────────────────────────────────────────

func TestValidKeyNameRE(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"uppercase letters", "CLAUDE_KEY", true},
		{"with numbers", "KEY123", true},
		{"underscore only", "_", true},
		{"all caps with underscore", "OPENAI_API_KEY", true},
		{"empty string", "", false},
		{"lowercase letters", "claude_key", false},
		{"hyphen", "CLAUDE-KEY", false},
		{"space", "CLAUDE KEY", false},
		{"dot", "CLAUDE.KEY", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := validKeyNameRE.MatchString(tc.input)
			if got != tc.want {
				t.Errorf("validKeyNameRE.MatchString(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// ── storeKeyringSecret input validation ───────────────────────────────────────

// TestStoreKeyringSecret_InvalidKeyName tests the guard that fires before any
// keyring call, so it works even without a system keyring daemon.
func TestStoreKeyringSecret_InvalidKeyName(t *testing.T) {
	err := storeKeyringSecret("invalid-name!", "value")
	if err == nil {
		t.Fatal("storeKeyringSecret: expected error for invalid key name, got nil")
	}
}

func TestStoreKeyringSecret_EmptyKeyName(t *testing.T) {
	err := storeKeyringSecret("", "value")
	if err == nil {
		t.Fatal("storeKeyringSecret: expected error for empty key name, got nil")
	}
}

// ── loadKeyringSecret input validation ────────────────────────────────────────

func TestLoadKeyringSecret_InvalidKeyName(t *testing.T) {
	val, ok := loadKeyringSecret("bad name!")
	if ok {
		t.Errorf("loadKeyringSecret: expected ok=false for invalid key name, got val=%q", val)
	}
}

func TestLoadKeyringSecret_EmptyKeyName(t *testing.T) {
	val, ok := loadKeyringSecret("")
	if ok {
		t.Errorf("loadKeyringSecret: expected ok=false for empty key name, got val=%q", val)
	}
}

// ── storeFileKey error path ───────────────────────────────────────────────────

func TestStoreFileKey_DirectoryReadOnly(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can write to read-only directories")
	}

	dir := t.TempDir()
	// Make the directory non-writable so WriteFile fails.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer os.Chmod(dir, 0o700) //nolint:errcheck

	path := filepath.Join(dir, "secrets.key")
	key := make([]byte, scryptKeyLen)

	err := storeFileKey(path, key)
	if err == nil {
		t.Fatal("expected error when writing key to read-only directory, got nil")
	}
}

// ── chooseDefaultBackend — exercises both branches ───────────────────────────

// TestChooseDefaultBackend_ReturnType documents the type contract: the returned
// string is one of the internal KDF constants, not necessarily a user-facing name.
func TestChooseDefaultBackend_ReturnType(t *testing.T) {
	got := chooseDefaultBackend()
	// Both return values are the internal KDF constants.
	if got != kdfKeyring && got != kdfScrypt {
		t.Errorf("chooseDefaultBackend() = %q; expected %q or %q", got, kdfKeyring, kdfScrypt)
	}
}
