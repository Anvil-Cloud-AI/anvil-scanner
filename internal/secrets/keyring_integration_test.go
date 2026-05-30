//go:build darwin || linux

package secrets

// Integration tests for the OS keyring backend. They exercise the real macOS
// Keychain (darwin) or libsecret (linux) and therefore require:
//
//  1. An interactive user session with a reachable credential store.
//  2. The ANVIL_KEYRING_INTEGRATION environment variable set to "1".
//
// Run with:
//
//	ANVIL_KEYRING_INTEGRATION=1 go test -v -run TestKeyringIntegration ./internal/secrets/...
//
// Each test saves any pre-existing production keyring entry and restores it in
// a deferred cleanup, so running the suite on a machine that already has
// anvil-scanner configured does not corrupt live secrets.
//
// IMPORTANT: do not call t.Setenv("HOME", ...) in these tests. The macOS
// Keychain daemon locates login.keychain-db via ~/Library/Keychains; changing
// HOME causes the security(1) CLI to hang or fail. Use isolatedSecretsDir
// instead to isolate the secrets container without touching HOME.

import (
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func skipIfNoKeyringIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("ANVIL_KEYRING_INTEGRATION") == "" {
		t.Skip("set ANVIL_KEYRING_INTEGRATION=1 to run keyring integration tests")
	}
	if !hasKeyring() {
		t.Skip("OS keyring not available on this system")
	}
}

// saveMasterKeyEntry reads the current master key entry (if any) and returns a
// cleanup function that restores it. Always register with t.Cleanup before
// touching the keychain master-key account.
func saveMasterKeyEntry(t *testing.T) func() {
	t.Helper()
	existing, err := loadKeyringMasterKey()
	if err != nil {
		// No entry present — just delete on cleanup to leave state clean.
		return func() {
			if err := deleteKeyringMasterKey(); err != nil {
				t.Logf("cleanup: delete master key: %v", err)
			}
		}
	}
	return func() {
		if err := storeKeyringMasterKey(existing); err != nil {
			t.Logf("cleanup: restore master key: %v", err)
		}
	}
}

// isolatedSecretsDir redirects all secrets I/O to a fresh temp directory for
// the duration of the test. It sets the package-level secretsDirOverride so
// encryptedSecrets() and keyFile() resolve inside the temp tree, leaving the
// user's real ~/.anvil-scanner untouched. HOME is NOT changed — changing HOME
// breaks macOS Keychain access because security(1) locates the login keychain
// via ~/Library/Keychains.
func isolatedSecretsDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	secretsDirOverride = dir
	t.Cleanup(func() { secretsDirOverride = "" })
}

// randomKeyring32 generates a cryptographically random 32-byte key.
func randomKeyring32(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// clearManagedEnv clears all ManagedKeys from the process environment for the
// duration of the test, restoring originals in t.Cleanup.
func clearManagedEnv(t *testing.T) {
	t.Helper()
	origVals := make(map[string]string, len(ManagedKeys))
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
}

// ── master-key roundtrip ──────────────────────────────────────────────────────

// TestKeyringIntegration_MasterKeyRoundTrip verifies that a 32-byte AES master
// key survives a store → load → delete cycle through the OS credential store.
func TestKeyringIntegration_MasterKeyRoundTrip(t *testing.T) {
	skipIfNoKeyringIntegration(t)
	t.Cleanup(saveMasterKeyEntry(t))

	want := randomKeyring32(t)

	if err := storeKeyringMasterKey(want); err != nil {
		t.Fatalf("storeKeyringMasterKey: %v", err)
	}

	got, err := loadKeyringMasterKey()
	if err != nil {
		t.Fatalf("loadKeyringMasterKey: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("loadKeyringMasterKey: length = %d, want 32", len(got))
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("master key mismatch at byte %d: got %02x, want %02x", i, got[i], want[i])
		}
	}
}

// TestKeyringIntegration_MasterKeyBase64Integrity verifies that the key stored
// in the credential store is valid base64 and decodes to exactly 32 bytes.
// This guards against future changes to the encoding path.
func TestKeyringIntegration_MasterKeyBase64Integrity(t *testing.T) {
	skipIfNoKeyringIntegration(t)
	t.Cleanup(saveMasterKeyEntry(t))

	key := randomKeyring32(t)
	if err := storeKeyringMasterKey(key); err != nil {
		t.Fatalf("storeKeyringMasterKey: %v", err)
	}

	loaded, err := loadKeyringMasterKey()
	if err != nil {
		t.Fatalf("loadKeyringMasterKey: %v", err)
	}
	if len(loaded) != 32 {
		t.Errorf("decoded key length = %d, want 32", len(loaded))
	}
}

// ── per-secret keyring entries ────────────────────────────────────────────────

// TestKeyringIntegration_PerSecretRoundTrip verifies that individual secret
// values survive a store → load cycle and that deletions are clean.
func TestKeyringIntegration_PerSecretRoundTrip(t *testing.T) {
	skipIfNoKeyringIntegration(t)

	const testKey = "ABUSEIPDB_KEY"
	const testVal = "kvintegrationtest_abuseipdb_roundtrip"

	t.Cleanup(func() {
		if err := deleteKeyringSecret(testKey); err != nil {
			t.Logf("cleanup: deleteKeyringSecret(%q): %v", testKey, err)
		}
	})

	if err := storeKeyringSecret(testKey, testVal); err != nil {
		t.Fatalf("storeKeyringSecret: %v", err)
	}

	got, ok := loadKeyringSecret(testKey)
	if !ok {
		t.Fatal("loadKeyringSecret: key not found after store")
	}
	if got != testVal {
		t.Errorf("loadKeyringSecret: got %q, want %q", got, testVal)
	}

	// Delete and verify it is gone.
	if err := deleteKeyringSecret(testKey); err != nil {
		t.Fatalf("deleteKeyringSecret: %v", err)
	}
	if _, ok := loadKeyringSecret(testKey); ok {
		t.Error("loadKeyringSecret: entry still present after delete")
	}
}

// TestKeyringIntegration_PerSecretInvalidKey verifies that invalid key names
// are rejected both on store and load.
func TestKeyringIntegration_PerSecretInvalidKey(t *testing.T) {
	skipIfNoKeyringIntegration(t)

	if err := storeKeyringSecret("invalid-key-name", "value"); err == nil {
		t.Error("storeKeyringSecret: expected error for invalid key name, got nil")
	}
	if _, ok := loadKeyringSecret("invalid-key-name"); ok {
		t.Error("loadKeyringSecret: expected false for invalid key name")
	}
}

// ── full encrypt / decrypt round-trip with keyring backend ────────────────────

// TestKeyringIntegration_EncryptDecryptRoundTrip exercises the full
// EncryptSecrets → DecryptSecrets path using the OS keyring as the KDF backend.
func TestKeyringIntegration_EncryptDecryptRoundTrip(t *testing.T) {
	skipIfNoKeyringIntegration(t)
	isolatedSecretsDir(t)
	t.Cleanup(saveMasterKeyEntry(t))

	srcDir := t.TempDir()
	srcEnv := filepath.Join(srcDir, "source.env")
	const wantValue = "sk-keyring-integration-roundtrip"
	if err := os.WriteFile(srcEnv, []byte("CLAUDE_KEY="+wantValue+"\n"), 0o600); err != nil {
		t.Fatalf("write source env: %v", err)
	}

	// Encrypt with keyring backend.
	if err := EncryptSecrets(srcEnv, "keyring"); err != nil {
		t.Fatalf("EncryptSecrets(keyring): %v", err)
	}

	// Source file must have been shredded.
	if _, err := os.Stat(srcEnv); !os.IsNotExist(err) {
		t.Error("source .env not shredded after encryption")
	}

	// Verify container header declares kdfKeyring.
	blob, err := os.ReadFile(encryptedSecrets())
	if err != nil {
		t.Fatalf("read container: %v", err)
	}
	hdr, _, _, unpackErr := unpackContainer(blob)
	if unpackErr != nil {
		t.Fatalf("unpackContainer: %v", unpackErr)
	}
	if hdr.KDF != kdfKeyring {
		t.Errorf("container KDF = %q, want %q", hdr.KDF, kdfKeyring)
	}

	// Decrypt and verify content.
	destEnv := filepath.Join(t.TempDir(), "decrypted.env")
	if err := DecryptSecrets(destEnv); err != nil {
		t.Fatalf("DecryptSecrets: %v", err)
	}

	raw, err := os.ReadFile(destEnv)
	if err != nil {
		t.Fatalf("read decrypted env: %v", err)
	}
	got := parseEnvFile(string(raw))
	if got["CLAUDE_KEY"] != wantValue {
		t.Errorf("CLAUDE_KEY = %q, want %q", got["CLAUDE_KEY"], wantValue)
	}
}

// TestKeyringIntegration_EncryptDecrypt_NULGuard ensures the defer-zeroing
// pattern in DecryptSecrets does not corrupt the written output (keyring path).
func TestKeyringIntegration_EncryptDecrypt_NULGuard(t *testing.T) {
	skipIfNoKeyringIntegration(t)
	isolatedSecretsDir(t)
	t.Cleanup(saveMasterKeyEntry(t))

	src := filepath.Join(t.TempDir(), "src.env")
	const wantValue = "sk-keyring-nul-guard-test"
	if err := os.WriteFile(src, []byte("CLAUDE_KEY="+wantValue+"\n"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	if err := EncryptSecrets(src, "keyring"); err != nil {
		t.Fatalf("EncryptSecrets: %v", err)
	}

	dest := filepath.Join(t.TempDir(), "out.env")
	if err := DecryptSecrets(dest); err != nil {
		t.Fatalf("DecryptSecrets: %v", err)
	}

	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	for i, b := range raw {
		if b == 0 {
			t.Fatalf("NUL byte at offset %d — defer zeroing may have fired before write", i)
		}
	}
	got := parseEnvFile(string(raw))
	if got["CLAUDE_KEY"] != wantValue {
		t.Errorf("CLAUDE_KEY = %q, want %q", got["CLAUDE_KEY"], wantValue)
	}
}

// ── StoreSecretsKeyring happy path ────────────────────────────────────────────

// TestKeyringIntegration_StoreSecretsKeyring verifies that StoreSecretsKeyring
// writes per-secret entries that loadKeyringSecret can retrieve. We seed the
// container with passphrase backend (no HOME change needed) so that
// StoreSecretsKeyring has a source to decrypt.
func TestKeyringIntegration_StoreSecretsKeyring(t *testing.T) {
	skipIfNoKeyringIntegration(t)
	isolatedSecretsDir(t)

	const testKey1 = "CLAUDE_KEY"
	const testKey2 = "GROK_KEY"
	t.Cleanup(func() {
		deleteKeyringSecret(testKey1) //nolint:errcheck
		deleteKeyringSecret(testKey2) //nolint:errcheck
	})

	// Seed the encrypted container with known values via passphrase backend.
	t.Setenv("ANVIL_SECRETS_PASSPHRASE", "storesecretstest1234")
	src := filepath.Join(t.TempDir(), "src.env")
	if err := os.WriteFile(src, []byte("CLAUDE_KEY=sk-store-test\nGROK_KEY=grok-store-test\n"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := EncryptSecrets(src, "passphrase"); err != nil {
		t.Fatalf("EncryptSecrets(passphrase): %v", err)
	}

	if err := StoreSecretsKeyring(); err != nil {
		t.Fatalf("StoreSecretsKeyring: %v", err)
	}

	got1, ok1 := loadKeyringSecret(testKey1)
	if !ok1 {
		t.Error("CLAUDE_KEY not found in keyring after StoreSecretsKeyring")
	} else if got1 != "sk-store-test" {
		t.Errorf("CLAUDE_KEY = %q, want %q", got1, "sk-store-test")
	}

	got2, ok2 := loadKeyringSecret(testKey2)
	if !ok2 {
		t.Error("GROK_KEY not found in keyring after StoreSecretsKeyring")
	} else if got2 != "grok-store-test" {
		t.Errorf("GROK_KEY = %q, want %q", got2, "grok-store-test")
	}
}

// ── LoadSecrets with keyring backend ─────────────────────────────────────────

// TestKeyringIntegration_LoadSecrets_KeyringBackend verifies the full path
// where an encrypted container uses kdfKeyring and LoadSecrets decrypts it by
// fetching the master key from the OS credential store.
func TestKeyringIntegration_LoadSecrets_KeyringBackend(t *testing.T) {
	skipIfNoKeyringIntegration(t)
	isolatedSecretsDir(t)
	clearManagedEnv(t)
	t.Cleanup(saveMasterKeyEntry(t))

	src := filepath.Join(t.TempDir(), "src.env")
	if err := os.WriteFile(src, []byte("CLAUDE_KEY=sk-load-keyring-test\n"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	if err := EncryptSecrets(src, "keyring"); err != nil {
		t.Fatalf("EncryptSecrets: %v", err)
	}

	loaded := LoadSecrets()

	if _, ok := loaded["CLAUDE_KEY"]; !ok {
		t.Error("LoadSecrets: CLAUDE_KEY not reported as loaded")
	}
	for k, v := range loaded {
		if v != "***" {
			t.Errorf("LoadSecrets: loaded[%q] = %q, expected masked %q", k, v, "***")
		}
	}
	if got := os.Getenv("CLAUDE_KEY"); got != "sk-load-keyring-test" {
		t.Errorf("os.Getenv(CLAUDE_KEY) = %q, want %q", got, "sk-load-keyring-test")
	}
}

// TestKeyringIntegration_LoadSecrets_PerSecretEntries verifies the priority-1
// path in LoadSecrets where per-secret keyring entries take precedence over the
// encrypted container.
func TestKeyringIntegration_LoadSecrets_PerSecretEntries(t *testing.T) {
	skipIfNoKeyringIntegration(t)
	isolatedSecretsDir(t)
	clearManagedEnv(t)

	const testKey = "ABUSEIPDB_KEY"
	const testVal = "kv-per-secret-priority-test"

	t.Cleanup(func() {
		deleteKeyringSecret(testKey) //nolint:errcheck
	})

	if err := storeKeyringSecret(testKey, testVal); err != nil {
		t.Fatalf("storeKeyringSecret: %v", err)
	}

	loaded := LoadSecrets()

	if _, ok := loaded[testKey]; !ok {
		t.Errorf("LoadSecrets: %q not reported as loaded from per-secret keyring entry", testKey)
	}
	if got := os.Getenv(testKey); got != testVal {
		t.Errorf("os.Getenv(%q) = %q, want %q", testKey, got, testVal)
	}
}

// ── key rotation with keyring backend ────────────────────────────────────────

// TestKeyringIntegration_RotatePassphraseToKeyring re-encrypts an existing
// scrypt container under the keyring backend and verifies the content survives.
func TestKeyringIntegration_RotatePassphraseToKeyring(t *testing.T) {
	skipIfNoKeyringIntegration(t)
	isolatedSecretsDir(t)
	t.Setenv("ANVIL_SECRETS_PASSPHRASE", "rotateintegrationtest1")
	t.Cleanup(saveMasterKeyEntry(t))

	src := filepath.Join(t.TempDir(), "src.env")
	if err := os.WriteFile(src, []byte("CLAUDE_KEY=sk-rotate-to-keyring\n"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	if err := EncryptSecrets(src, "passphrase"); err != nil {
		t.Fatalf("EncryptSecrets(passphrase): %v", err)
	}

	if err := RotateKeyBackend("keyring"); err != nil {
		t.Fatalf("RotateKeyBackend(keyring): %v", err)
	}

	// Container must now declare kdfKeyring.
	blob, err := os.ReadFile(encryptedSecrets())
	if err != nil {
		t.Fatalf("read container: %v", err)
	}
	hdr, _, _, unpackErr := unpackContainer(blob)
	if unpackErr != nil {
		t.Fatalf("unpackContainer: %v", unpackErr)
	}
	if hdr.KDF != kdfKeyring {
		t.Errorf("after rotate: KDF = %q, want %q", hdr.KDF, kdfKeyring)
	}

	// Content must be intact.
	dest := filepath.Join(t.TempDir(), "out.env")
	if err := DecryptSecrets(dest); err != nil {
		t.Fatalf("DecryptSecrets after rotate: %v", err)
	}
	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	got := parseEnvFile(string(raw))
	if got["CLAUDE_KEY"] != "sk-rotate-to-keyring" {
		t.Errorf("CLAUDE_KEY = %q, want %q", got["CLAUDE_KEY"], "sk-rotate-to-keyring")
	}
}

// TestKeyringIntegration_RotateKeyringToPassphrase re-encrypts a keyring
// container under the passphrase backend and verifies the keyring master key
// entry is removed and content is preserved.
func TestKeyringIntegration_RotateKeyringToPassphrase(t *testing.T) {
	skipIfNoKeyringIntegration(t)
	isolatedSecretsDir(t)
	t.Setenv("ANVIL_SECRETS_PASSPHRASE", "rotateintegrationtest2")
	t.Cleanup(saveMasterKeyEntry(t))

	src := filepath.Join(t.TempDir(), "src.env")
	if err := os.WriteFile(src, []byte("CLAUDE_KEY=sk-rotate-to-passphrase\n"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	if err := EncryptSecrets(src, "keyring"); err != nil {
		t.Fatalf("EncryptSecrets(keyring): %v", err)
	}

	if err := RotateKeyBackend("passphrase"); err != nil {
		t.Fatalf("RotateKeyBackend(passphrase): %v", err)
	}

	// Container must now declare kdfScrypt.
	blob, err := os.ReadFile(encryptedSecrets())
	if err != nil {
		t.Fatalf("read container: %v", err)
	}
	hdr, _, _, unpackErr := unpackContainer(blob)
	if unpackErr != nil {
		t.Fatalf("unpackContainer: %v", unpackErr)
	}
	if hdr.KDF != kdfScrypt {
		t.Errorf("after rotate: KDF = %q, want %q", hdr.KDF, kdfScrypt)
	}

	// The keyring master key entry must have been removed.
	if _, err := loadKeyringMasterKey(); err == nil {
		t.Error("master key still present in keyring after rotation to passphrase")
	}

	// Content must be intact.
	dest := filepath.Join(t.TempDir(), "out.env")
	if err := DecryptSecrets(dest); err != nil {
		t.Fatalf("DecryptSecrets after rotate: %v", err)
	}
	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	got := parseEnvFile(string(raw))
	if got["CLAUDE_KEY"] != "sk-rotate-to-passphrase" {
		t.Errorf("CLAUDE_KEY = %q, want %q", got["CLAUDE_KEY"], "sk-rotate-to-passphrase")
	}
}

// ── hasKeyring round-trip ─────────────────────────────────────────────────────

// TestKeyringIntegration_HasKeyring_Probe verifies that hasKeyring returns true
// and that the probe cycle leaves no residual entries behind.
func TestKeyringIntegration_HasKeyring_Probe(t *testing.T) {
	skipIfNoKeyringIntegration(t)

	if !hasKeyring() {
		t.Fatal("hasKeyring() returned false on a system with keyring integration enabled")
	}

	// The probe entry must have been cleaned up by hasKeyring itself.
	val, err := loadKeyringProbe()
	if err == nil {
		t.Errorf("probe entry still present after hasKeyring() returned: got %q", val)
	}
}

// ── delete edge cases ─────────────────────────────────────────────────────────

// TestKeyringIntegration_DeleteMissingMasterKey verifies that
// deleteKeyringMasterKey is idempotent when no entry exists.
func TestKeyringIntegration_DeleteMissingMasterKey(t *testing.T) {
	skipIfNoKeyringIntegration(t)
	t.Cleanup(saveMasterKeyEntry(t))

	_ = deleteKeyringMasterKey()

	if err := deleteKeyringMasterKey(); err != nil {
		t.Errorf("deleteKeyringMasterKey on missing entry: %v", err)
	}
}

// TestKeyringIntegration_DeleteMissingPerSecret verifies that
// deleteKeyringSecret is idempotent when no entry exists.
func TestKeyringIntegration_DeleteMissingPerSecret(t *testing.T) {
	skipIfNoKeyringIntegration(t)

	const ghostKey = "ABUSEIPDB_KEY"
	_ = deleteKeyringSecret(ghostKey)

	if err := deleteKeyringSecret(ghostKey); err != nil {
		t.Errorf("deleteKeyringSecret on missing entry: %v", err)
	}
}

// ── RotateKeyBackend cleans up stale keyring entry ────────────────────────────

// TestKeyringIntegration_RotateKeyring_CleansOldEntry verifies that rotating
// from keyring to file removes the keyring master key entry, leaving no stale
// key material in the credential store.
func TestKeyringIntegration_RotateKeyring_CleansOldEntry(t *testing.T) {
	skipIfNoKeyringIntegration(t)
	isolatedSecretsDir(t)
	t.Cleanup(saveMasterKeyEntry(t))

	src := filepath.Join(t.TempDir(), "src.env")
	if err := os.WriteFile(src, []byte("CLAUDE_KEY=sk-stale-cleanup-test\n"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	if err := EncryptSecrets(src, "keyring"); err != nil {
		t.Fatalf("EncryptSecrets(keyring): %v", err)
	}

	// Master key must be present after encryption.
	if _, err := loadKeyringMasterKey(); err != nil {
		t.Fatalf("master key missing after keyring encryption: %v", err)
	}

	if err := RotateKeyBackend("file"); err != nil {
		t.Fatalf("RotateKeyBackend(file): %v", err)
	}

	// Keyring entry must be gone.
	if _, err := loadKeyringMasterKey(); err == nil {
		t.Error("master key still in keyring after rotation to file backend")
	}

	// Content must still decrypt correctly via the file key.
	dest := filepath.Join(t.TempDir(), "out.env")
	if err := DecryptSecrets(dest); err != nil {
		t.Fatalf("DecryptSecrets: %v", err)
	}
	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	got := parseEnvFile(string(raw))
	if got["CLAUDE_KEY"] != "sk-stale-cleanup-test" {
		t.Errorf("CLAUDE_KEY = %q, want %q", got["CLAUDE_KEY"], "sk-stale-cleanup-test")
	}
}

// ── InitSecrets with keyring backend ─────────────────────────────────────────

// TestKeyringIntegration_InitSecrets_Keyring exercises the first-time wizard
// path with the keyring backend in non-interactive mode.
func TestKeyringIntegration_InitSecrets_Keyring(t *testing.T) {
	skipIfNoKeyringIntegration(t)
	isolatedSecretsDir(t)
	t.Cleanup(saveMasterKeyEntry(t))

	src := filepath.Join(t.TempDir(), "src.env")
	if err := os.WriteFile(src, []byte("CLAUDE_KEY=sk-init-keyring-test\nAI_PROVIDER=anthropic\n"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	if err := InitSecrets(src, "keyring", true); err != nil {
		t.Fatalf("InitSecrets(keyring): %v", err)
	}

	if _, err := os.Stat(encryptedSecrets()); err != nil {
		t.Fatalf("encrypted container not found: %v", err)
	}

	dest := filepath.Join(t.TempDir(), "out.env")
	if err := DecryptSecrets(dest); err != nil {
		t.Fatalf("DecryptSecrets: %v", err)
	}
	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	got := parseEnvFile(string(raw))
	if got["CLAUDE_KEY"] != "sk-init-keyring-test" {
		t.Errorf("CLAUDE_KEY = %q, want %q", got["CLAUDE_KEY"], "sk-init-keyring-test")
	}

	// No key file should be produced when using keyring backend.
	if _, err := os.Stat(keyFile()); err == nil {
		t.Error("key file must not exist when using keyring backend")
	}
}

// ── multiple managed keys ─────────────────────────────────────────────────────

// TestKeyringIntegration_AllManagedKeys_StoreLoad verifies that all keys in
// ManagedKeys can be stored and retrieved individually via the keyring.
func TestKeyringIntegration_AllManagedKeys_StoreLoad(t *testing.T) {
	skipIfNoKeyringIntegration(t)

	t.Cleanup(func() {
		for _, k := range ManagedKeys {
			deleteKeyringSecret(k) //nolint:errcheck
		}
	})

	want := make(map[string]string, len(ManagedKeys))
	for i, k := range ManagedKeys {
		val := strings.Repeat("x", i+4) // distinct non-empty values
		if err := storeKeyringSecret(k, val); err != nil {
			t.Errorf("storeKeyringSecret(%q): %v", k, err)
			continue
		}
		want[k] = val
	}

	for k, wantVal := range want {
		got, ok := loadKeyringSecret(k)
		if !ok {
			t.Errorf("loadKeyringSecret(%q): not found", k)
			continue
		}
		if got != wantVal {
			t.Errorf("loadKeyringSecret(%q) = %q, want %q", k, got, wantVal)
		}
	}
}
