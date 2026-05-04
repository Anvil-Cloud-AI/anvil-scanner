//go:build darwin || linux

package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

// ── parseEnvFile ──────────────────────────────────────────────────────────────

func TestParseEnvFile_ManagedKeys(t *testing.T) {
	input := `
# comment
CLAUDE_KEY=sk-abc123
OPENAI_KEY="openai-key-value"
GROK_KEY='grok-key-value'
UNKNOWN_KEY=should-be-ignored
AI_PROVIDER=anthropic
`
	got := parseEnvFile(input)

	cases := map[string]string{
		"CLAUDE_KEY":  "sk-abc123",
		"OPENAI_KEY":  "openai-key-value",
		"GROK_KEY":    "grok-key-value",
		"AI_PROVIDER": "anthropic",
	}
	for k, want := range cases {
		if v, ok := got[k]; !ok {
			t.Errorf("parseEnvFile: key %q not found", k)
		} else if v != want {
			t.Errorf("parseEnvFile: key %q = %q, want %q", k, v, want)
		}
	}
	if _, ok := got["UNKNOWN_KEY"]; ok {
		t.Error("parseEnvFile: UNKNOWN_KEY should have been filtered out")
	}
}

func TestParseEnvFile_EmptyInput(t *testing.T) {
	got := parseEnvFile("")
	if len(got) != 0 {
		t.Errorf("parseEnvFile: expected empty map, got %v", got)
	}
}

func TestParseEnvFile_OnlyComments(t *testing.T) {
	got := parseEnvFile("# just a comment\n# another comment\n")
	if len(got) != 0 {
		t.Errorf("parseEnvFile: expected empty map for comment-only input, got %v", got)
	}
}

func TestParseEnvFile_NoEqualsSign(t *testing.T) {
	// Lines without '=' should be silently skipped.
	got := parseEnvFile("CLAUDE_KEY\nOPENAI_KEY=valid\n")
	if _, ok := got["CLAUDE_KEY"]; ok {
		t.Error("parseEnvFile: key without '=' should be skipped")
	}
	if v, ok := got["OPENAI_KEY"]; !ok || v != "valid" {
		t.Errorf("parseEnvFile: OPENAI_KEY: got %q, want %q", v, "valid")
	}
}

func TestParseEnvFile_QuoteStripping(t *testing.T) {
	cases := []struct {
		line string
		want string
	}{
		{`CLAUDE_KEY="double-quoted"`, "double-quoted"},
		{`CLAUDE_KEY='single-quoted'`, "single-quoted"},
		{`CLAUDE_KEY=unquoted`, "unquoted"},
		// Mismatched quotes: the value should be returned as-is.
		{`CLAUDE_KEY="mismatched'`, `"mismatched'`},
	}
	for _, c := range cases {
		got := parseEnvFile(c.line)
		if v, ok := got["CLAUDE_KEY"]; !ok {
			t.Errorf("parseEnvFile(%q): key not found", c.line)
		} else if v != c.want {
			t.Errorf("parseEnvFile(%q): got %q, want %q", c.line, v, c.want)
		}
	}
}

func TestParseEnvFile_ValueWithEquals(t *testing.T) {
	// Values that contain '=' must be preserved correctly.
	input := "CLAUDE_KEY=abc=def\n"
	got := parseEnvFile(input)
	if v := got["CLAUDE_KEY"]; v != "abc=def" {
		t.Errorf("parseEnvFile: got %q, want %q", v, "abc=def")
	}
}

func TestParseEnvFile_BlankLines(t *testing.T) {
	input := "\n\n\nCLAUDE_KEY=val\n\n"
	got := parseEnvFile(input)
	if v := got["CLAUDE_KEY"]; v != "val" {
		t.Errorf("parseEnvFile: got %q, want %q", v, "val")
	}
}

// ── shredFile ─────────────────────────────────────────────────────────────────

func TestShredFile_RemovesFile(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "shred-test-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	path := tmp.Name()
	if _, err := tmp.WriteString("sensitive data here"); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}

	if err := shredFile(path); err != nil {
		t.Fatalf("shredFile: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("shredFile: expected file to be removed, got stat err: %v", err)
	}
}

func TestShredFile_NonExistentFile(t *testing.T) {
	// shredFile must return nil for a file that does not exist.
	path := filepath.Join(t.TempDir(), "does-not-exist.txt")
	if err := shredFile(path); err != nil {
		t.Errorf("shredFile on non-existent file: expected nil, got %v", err)
	}
}

func TestShredFile_EmptyFile(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "shred-empty-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	path := tmp.Name()
	if err := tmp.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}

	if err := shredFile(path); err != nil {
		t.Fatalf("shredFile on empty file: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("shredFile: empty file should be removed")
	}
}

// ── LoadSecrets with a temp encrypted container ───────────────────────────────

// TestLoadSecrets_EncryptedContainer creates an encrypted secrets.enc using
// the scrypt backend and verifies that LoadSecrets populates os.Environ with
// the managed keys stored inside.
func TestLoadSecrets_EncryptedContainer(t *testing.T) {
	const passphrase = "loadsecretstestpw" // well above the 12-char minimum

	t.Setenv("ANVIL_SECRETS_PASSPHRASE", passphrase)

	// Isolate home so the container lands in a temp dir, not ~/.anvil-scanner.
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	// Clear any pre-existing managed keys from the process environment so that
	// LoadSecrets has visible work to do.  Restore them in cleanup.
	origVals := make(map[string]string)
	for _, k := range ManagedKeys {
		origVals[k] = os.Getenv(k)
		os.Unsetenv(k) //nolint:errcheck
	}
	t.Cleanup(func() {
		for k, v := range origVals {
			if v != "" {
				os.Setenv(k, v) //nolint:errcheck
			} else {
				os.Unsetenv(k) //nolint:errcheck
			}
		}
	})

	// Write a source .env with two managed keys.
	srcEnv := filepath.Join(dir, "source.env")
	content := "CLAUDE_KEY=sk-load-secrets-test\nGROK_KEY=grok-load-test\n"
	if err := os.WriteFile(srcEnv, []byte(content), 0o600); err != nil {
		t.Fatalf("write source env: %v", err)
	}

	// Encrypt with the scrypt backend.
	if err := EncryptSecrets(srcEnv, "passphrase"); err != nil {
		t.Fatalf("EncryptSecrets: %v", err)
	}

	// Confirm the container exists.
	if _, err := os.Stat(encryptedSecrets()); err != nil {
		t.Fatalf("encrypted container not found after EncryptSecrets: %v", err)
	}

	// LoadSecrets must decrypt and populate os.Environ.
	loaded := LoadSecrets()

	if _, ok := loaded["CLAUDE_KEY"]; !ok {
		t.Error("LoadSecrets: CLAUDE_KEY not reported as loaded")
	}
	if _, ok := loaded["GROK_KEY"]; !ok {
		t.Error("LoadSecrets: GROK_KEY not reported as loaded")
	}

	// Values in the returned map must be masked.
	for k, v := range loaded {
		if v != "***" {
			t.Errorf("LoadSecrets: loaded[%q] = %q, expected masked value %q", k, v, "***")
		}
	}

	// The actual values must now be set in os.Environ.
	if got := os.Getenv("CLAUDE_KEY"); got != "sk-load-secrets-test" {
		t.Errorf("os.Getenv(CLAUDE_KEY): got %q, want %q", got, "sk-load-secrets-test")
	}
	if got := os.Getenv("GROK_KEY"); got != "grok-load-test" {
		t.Errorf("os.Getenv(GROK_KEY): got %q, want %q", got, "grok-load-test")
	}
}

// ── Smoke test: defer-zeroing does not corrupt the written output ─────────────

// TestDecryptSecrets_DeferZeroingDoesNotCorruptOutput verifies that the
// defer-based plaintext zeroing in DecryptSecrets fires AFTER writeSecureFile
// has completed, not before.  If the defer fired prematurely it would zero the
// []byte slice whose backing array had already been handed to the write path —
// producing a NUL-filled file instead of the original plaintext.
func TestDecryptSecrets_DeferZeroingDoesNotCorruptOutput(t *testing.T) {
	const passphrase = "smoketestpassword1"
	t.Setenv("ANVIL_SECRETS_PASSPHRASE", passphrase)

	dir := t.TempDir()
	t.Setenv("HOME", dir)

	// Clear managed keys so the test environment is clean; restore on cleanup.
	origVals := make(map[string]string)
	for _, k := range ManagedKeys {
		origVals[k] = os.Getenv(k)
		os.Unsetenv(k) //nolint:errcheck
	}
	t.Cleanup(func() {
		for k, v := range origVals {
			if v != "" {
				os.Setenv(k, v) //nolint:errcheck
			} else {
				os.Unsetenv(k) //nolint:errcheck
			}
		}
	})

	// Write a source .env with a known managed key value.
	srcEnv := filepath.Join(dir, "smoke-source.env")
	const wantValue = "sk-smoke-zero-test"
	if err := os.WriteFile(srcEnv, []byte("CLAUDE_KEY="+wantValue+"\n"), 0o600); err != nil {
		t.Fatalf("write source env: %v", err)
	}

	if err := EncryptSecrets(srcEnv, "passphrase"); err != nil {
		t.Fatalf("EncryptSecrets: %v", err)
	}

	destEnv := filepath.Join(dir, "smoke-decrypted.env")
	if err := DecryptSecrets(destEnv); err != nil {
		t.Fatalf("DecryptSecrets: %v", err)
	}

	raw, err := os.ReadFile(destEnv)
	if err != nil {
		t.Fatalf("read decrypted env: %v", err)
	}

	// If defer-zeroing fired before writeSecureFile returned the file would
	// contain NUL bytes — detect that explicitly.
	for i, b := range raw {
		if b == 0 {
			t.Fatalf("decrypted file contains NUL byte at offset %d — "+
				"defer zeroing may have fired before write completed", i)
		}
	}

	got := parseEnvFile(string(raw))
	if got["CLAUDE_KEY"] != wantValue {
		t.Errorf("CLAUDE_KEY = %q, want %q — defer zeroing may have corrupted the output",
			got["CLAUDE_KEY"], wantValue)
	}
}

// ── Encrypt/Decrypt round-trip via scrypt backend ─────────────────────────────

// TestEncryptDecryptRoundTrip_Scrypt exercises the full EncryptSecrets →
// DecryptSecrets path using a temporary home directory and the
// ANVIL_SECRETS_PASSPHRASE env var so no TTY prompt is needed.
func TestEncryptDecryptRoundTrip_Scrypt(t *testing.T) {
	const passphrase = "testpassphrase12"

	// Set the passphrase env var so promptPassphrase() does not block on stdin.
	t.Setenv("ANVIL_SECRETS_PASSPHRASE", passphrase)

	// Redirect the secrets directory into a temp dir so this test never
	// touches ~/.anvil-scanner.
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	// Write a source .env with at least one managed key.
	srcEnv := filepath.Join(dir, "source.env")
	content := "CLAUDE_KEY=sk-roundtrip-test\nAI_PROVIDER=anthropic\n"
	if err := os.WriteFile(srcEnv, []byte(content), 0o600); err != nil {
		t.Fatalf("write source env: %v", err)
	}

	// Encrypt. This shreds srcEnv on success.
	if err := EncryptSecrets(srcEnv, "passphrase"); err != nil {
		t.Fatalf("EncryptSecrets: %v", err)
	}

	// Source file must have been shredded.
	if _, err := os.Stat(srcEnv); !os.IsNotExist(err) {
		t.Error("EncryptSecrets: source .env file should have been shredded after encryption")
	}

	// Decrypt into a new destination file.
	destEnv := filepath.Join(dir, "decrypted.env")
	if err := DecryptSecrets(destEnv); err != nil {
		t.Fatalf("DecryptSecrets: %v", err)
	}

	data, err := os.ReadFile(destEnv)
	if err != nil {
		t.Fatalf("read decrypted env: %v", err)
	}

	got := parseEnvFile(string(data))
	if got["CLAUDE_KEY"] != "sk-roundtrip-test" {
		t.Errorf("round-trip CLAUDE_KEY: got %q, want %q", got["CLAUDE_KEY"], "sk-roundtrip-test")
	}
	if got["AI_PROVIDER"] != "anthropic" {
		t.Errorf("round-trip AI_PROVIDER: got %q, want %q", got["AI_PROVIDER"], "anthropic")
	}
}
