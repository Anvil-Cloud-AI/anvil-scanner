//go:build darwin || linux

package secrets

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	iexec "github.com/Anvil-Cloud-AI/anvil-scanner/internal/exec"
)

// ── OS keyring ────────────────────────────────────────────────────────────────

const (
	keyringService  = "anvil-scanner"
	keyringAccount  = "anvil_scanner_master_key"
	keyringDummyKey = "ANVILPROBE"
)

// storeKeyringMasterKey stores a base64-encoded 32-byte AES master key in
// the OS credential store.
func storeKeyringMasterKey(key []byte) error {
	encoded := base64.StdEncoding.EncodeToString(key)
	switch runtime.GOOS {
	case "darwin":
		r := iexec.Run("security", "add-generic-password",
			"-U",
			"-s", keyringService,
			"-a", keyringAccount,
			"-w", encoded,
		)
		if !r.Success() {
			return fmt.Errorf("secrets: keyring store failed (exit %d): %s", r.ExitCode, r.Stderr)
		}
		return nil
	default: // linux
		// secret-tool reads the value from stdin.
		ctx := context.Background()
		r := iexec.RunCtx(ctx, strings.NewReader(encoded+"\n"),
			"secret-tool", "store",
			"--label="+keyringService,
			"service", keyringService,
			"username", keyringAccount,
		)
		if !r.Success() {
			return fmt.Errorf("secrets: keyring store failed (exit %d): %s", r.ExitCode, r.Stderr)
		}
		return nil
	}
}

// loadKeyringMasterKey retrieves and base64-decodes the master key from the
// OS credential store.  Returns a descriptive error when the entry is absent.
func loadKeyringMasterKey() ([]byte, error) {
	var raw string
	switch runtime.GOOS {
	case "darwin":
		r := iexec.Run("security", "find-generic-password",
			"-s", keyringService,
			"-a", keyringAccount,
			"-w",
		)
		if !r.Success() {
			return nil, fmt.Errorf("secrets: keyring load failed (exit %d): %s", r.ExitCode, r.Stderr)
		}
		raw = strings.TrimSpace(r.Stdout)
	default: // linux
		r := iexec.Run("secret-tool", "lookup",
			"service", keyringService,
			"username", keyringAccount,
		)
		if !r.Success() {
			return nil, fmt.Errorf("secrets: keyring load failed (exit %d): %s", r.ExitCode, r.Stderr)
		}
		raw = strings.TrimSpace(r.Stdout)
	}

	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("secrets: keyring value is not valid base64: %w", err)
	}
	return key, nil
}

// deleteKeyringMasterKey removes the master key from the OS credential store.
// Returns nil when the entry was not present (best-effort semantic).
func deleteKeyringMasterKey() error {
	switch runtime.GOOS {
	case "darwin":
		r := iexec.Run("security", "delete-generic-password",
			"-s", keyringService,
			"-a", keyringAccount,
		)
		// exit 44 = "item not found" on macOS security(1) — treat as success.
		if r.ExitCode == 44 || r.Success() {
			return nil
		}
		return fmt.Errorf("secrets: keyring delete failed (exit %d): %s", r.ExitCode, r.Stderr)
	default: // linux
		r := iexec.Run("secret-tool", "clear",
			"service", keyringService,
			"username", keyringAccount,
		)
		// secret-tool clear exits 0 even when nothing was found.
		if r.Success() {
			return nil
		}
		return fmt.Errorf("secrets: keyring delete failed (exit %d): %s", r.ExitCode, r.Stderr)
	}
}

// hasKeyring probes the OS credential store by performing a dummy
// write → read → delete cycle.  Returns true only when all three
// operations succeed and the round-trip value is intact.
//
// This is the probe described in ADR-0002 §auto-selection.
func hasKeyring() bool {
	dummyKey := []byte(keyringDummyKey)

	if err := storeKeyringMasterKey(dummyKey); err != nil {
		return false
	}
	got, err := loadKeyringMasterKey()
	if err != nil {
		_ = deleteKeyringMasterKey()
		return false
	}
	_ = deleteKeyringMasterKey()
	return bytes.Equal(got, dummyKey)
}

// ── Passphrase backend ────────────────────────────────────────────────────────

// promptPassphrase reads a passphrase for encrypting or decrypting the
// secrets container.
//
// Priority:
//  1. ANVIL_SECRETS_PASSPHRASE environment variable (non-interactive).
//  2. Stdin prompt (interactive).
//
// When confirm is true (encrypt path) the passphrase must be at least
// minPassphraseLen characters long and the user must enter it twice.
//
// NOTE: stdin input is NOT hidden (no raw-mode / echo suppression).
// A future version should use golang.org/x/term.ReadPassword for echo-
// suppression; for now we use a plain bufio reader.
func promptPassphrase(confirm bool) (string, error) {
	// Env-var path — always wins, no prompts.
	if env := os.Getenv("ANVIL_SECRETS_PASSPHRASE"); env != "" {
		if confirm && len(env) < minPassphraseLen {
			return "", fmt.Errorf("secrets: passphrase must be at least %d characters", minPassphraseLen)
		}
		return env, nil
	}

	// Interactive stdin path.
	reader := bufio.NewReader(os.Stdin)

	fmt.Fprint(os.Stderr, "Enter secrets passphrase: ")
	pw, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("secrets: reading passphrase: %w", err)
	}
	pw = strings.TrimRight(pw, "\r\n")

	if confirm {
		if len(pw) < minPassphraseLen {
			return "", fmt.Errorf("secrets: passphrase must be at least %d characters", minPassphraseLen)
		}
		fmt.Fprint(os.Stderr, "Confirm passphrase: ")
		pw2, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("secrets: reading passphrase confirmation: %w", err)
		}
		pw2 = strings.TrimRight(pw2, "\r\n")
		if pw != pw2 {
			return "", errors.New("secrets: passphrases do not match")
		}
	}

	return pw, nil
}

// ── File backend ──────────────────────────────────────────────────────────────

// loadFileKey reads the raw 32-byte AES master key from keyFile.
func loadFileKey(keyFile string) ([]byte, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("secrets: read key file %s: %w", keyFile, err)
	}
	if len(data) != scryptKeyLen {
		return nil, fmt.Errorf("secrets: key file %s: expected %d bytes, got %d",
			keyFile, scryptKeyLen, len(data))
	}
	return data, nil
}

// storeFileKey writes the 32-byte AES master key to keyFile with 0600
// permissions.  The file is created if absent, truncated if present.
func storeFileKey(keyFile string, key []byte) error {
	if err := os.WriteFile(keyFile, key, 0600); err != nil {
		return fmt.Errorf("secrets: write key file %s: %w", keyFile, err)
	}
	return nil
}

// ── Per-secret keyring helpers ────────────────────────────────────────────────

// storeKeyringSecret stores an individual secret value (e.g. a raw API key)
// in the OS credential store under account "<keyringAccount>/<name>".
// This is distinct from storeKeyringMasterKey: the master key entry holds the
// AES encryption key for the container, while per-secret entries hold the
// plaintext secret values directly (useful for tools that read the keyring
// without going through the container).
func storeKeyringSecret(name, value string) error {
	account := keyringAccount + "/" + name
	switch runtime.GOOS {
	case "darwin":
		r := iexec.Run("security", "add-generic-password",
			"-U",
			"-s", keyringService,
			"-a", account,
			"-w", value,
		)
		if !r.Success() {
			return fmt.Errorf("secrets: store keyring secret %q (exit %d): %s", name, r.ExitCode, r.Stderr)
		}
		return nil
	default: // linux
		ctx := context.Background()
		r := iexec.RunCtx(ctx, strings.NewReader(value+"\n"),
			"secret-tool", "store",
			"--label="+keyringService+"/"+name,
			"service", keyringService,
			"username", account,
		)
		if !r.Success() {
			return fmt.Errorf("secrets: store keyring secret %q (exit %d): %s", name, r.ExitCode, r.Stderr)
		}
		return nil
	}
}

// loadKeyringSecret retrieves an individual secret value from the OS credential
// store.  Returns ("", false) when the entry is absent.
func loadKeyringSecret(name string) (string, bool) {
	account := keyringAccount + "/" + name
	switch runtime.GOOS {
	case "darwin":
		r := iexec.Run("security", "find-generic-password",
			"-s", keyringService,
			"-a", account,
			"-w",
		)
		if !r.Success() {
			return "", false
		}
		return strings.TrimSpace(r.Stdout), true
	default: // linux
		r := iexec.Run("secret-tool", "lookup",
			"service", keyringService,
			"username", account,
		)
		if !r.Success() {
			return "", false
		}
		return strings.TrimSpace(r.Stdout), true
	}
}

// ── Backend selection ─────────────────────────────────────────────────────────

// chooseDefaultBackend returns "keyring" when the OS credential store is
// available and functional, otherwise "scrypt" (passphrase-derived).
// The "file" backend is never auto-selected; it must be requested explicitly
// via --init-secrets --backend file.
func chooseDefaultBackend() string {
	if hasKeyring() {
		return kdfKeyring
	}
	return kdfScrypt
}
