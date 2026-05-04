//go:build darwin || linux

package secrets

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ManagedKeys is the set of environment variable names that the secrets
// package tracks.  Only these keys are loaded from the encrypted container
// and written to per-secret keyring entries.
var ManagedKeys = []string{
	"CLAUDE_KEY", "OPENAI_KEY", "GROK_KEY", "ABUSEIPDB_KEY",
	"AI_PROVIDER", "AI_MODEL", "OLLAMA_URL", "XAI_API_URL",
}

// ValidBackends is the set of user-facing backend names accepted by
// EncryptSecrets, InitSecrets, and RotateKeyBackend.
var ValidBackends = []string{"keyring", "passphrase", "file"}

// passphraseEnvVar is the environment variable that can supply a passphrase
// without a TTY prompt (useful in CI / headless environments).
const passphraseEnvVar = "ANVIL_SECRETS_PASSPHRASE" //nolint:gosec

// ── path helpers ─────────────────────────────────────────────────────────────

func secretsDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".anvil-scanner")
}

func encryptedSecrets() string {
	return filepath.Join(secretsDir(), "secrets.enc")
}

func keyFile() string {
	return filepath.Join(secretsDir(), "secrets.key")
}

// PlaintextEnv is the conventional plaintext .env path (repo root).
// It is not used by tests directly; exported for CLI consumers.
var PlaintextEnv = func() string {
	// Walk up from the executable location is fragile; use cwd as a
	// reasonable default, matching the Python behaviour.
	cwd, _ := os.Getwd()
	return filepath.Join(cwd, ".env")
}()

// ── public API ────────────────────────────────────────────────────────────────

// EncryptSecrets reads plaintext from sourceEnvFile, derives or generates a
// 32-byte master key using the chosen backend, encrypts the payload with
// AES-256-GCM, and writes a versioned container to encryptedSecrets().
// The source file is shredded after a successful write.
func EncryptSecrets(sourceEnvFile string, backend string) error {
	plain, err := os.ReadFile(sourceEnvFile)
	if err != nil {
		return fmt.Errorf("secrets: read source file: %w", err)
	}

	// Normalise and validate backend.
	backend, err = resolveBackend(backend)
	if err != nil {
		return err
	}

	// Refuse keyring backend when running as root (root's keyring is empty
	// on every supported platform).
	if backend == kdfKeyring && os.Getuid() == 0 {
		return errors.New(
			"secrets: keyring backend unavailable as root — " +
				"root's OS keyring is empty; re-run without sudo or choose 'passphrase'",
		)
	}

	// Ensure the secrets directory exists.
	if err := os.MkdirAll(secretsDir(), 0o700); err != nil {
		return fmt.Errorf("secrets: create secrets dir: %w", err)
	}

	// Generate/derive the master key and build the container header.
	var masterKey []byte
	var hdr containerHeader
	hdr.Cipher = cipherAES256GCM
	hdr.Created = time.Now().UTC().Format(time.RFC3339)
	hdr.KDF = backend

	switch backend {
	case kdfKeyring:
		masterKey = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, masterKey); err != nil {
			return fmt.Errorf("secrets: generate keyring master key: %w", err)
		}
		if err := storeKeyringMasterKey(masterKey); err != nil {
			return fmt.Errorf("secrets: store keyring master key: %w", err)
		}

	case kdfScrypt:
		passphrase, err := promptPassphrase(true)
		if err != nil {
			return fmt.Errorf("secrets: prompt passphrase: %w", err)
		}
		if len(passphrase) < minPassphraseLen {
			return fmt.Errorf("secrets: passphrase too short (need ≥ %d chars)", minPassphraseLen)
		}
		salt := make([]byte, scryptSaltLen)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return fmt.Errorf("secrets: generate scrypt salt: %w", err)
		}
		masterKey, err = deriveKeyScrypt(passphrase, salt, scryptN, scryptR, scryptP)
		if err != nil {
			return fmt.Errorf("secrets: derive scrypt key: %w", err)
		}
		hdr.Salt = base64.StdEncoding.EncodeToString(salt)
		hdr.N = scryptN
		hdr.R = scryptR
		hdr.P = scryptP

	case kdfFile:
		fmt.Fprintln(os.Stderr, "WARNING: file backend — the key will live on disk next to the ciphertext.")
		fmt.Fprintln(os.Stderr, "  Prefer 'keyring' or 'passphrase' for better security.")
		masterKey = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, masterKey); err != nil {
			return fmt.Errorf("secrets: generate file master key: %w", err)
		}
		if err := storeFileKey(keyFile(), masterKey); err != nil {
			return fmt.Errorf("secrets: write key file: %w", err)
		}
	}

	// Encrypt.
	ciphertext, err := encryptAES256GCM(masterKey, plain)
	// Zero the master key as soon as encryption is done.
	for i := range masterKey {
		masterKey[i] = 0
	}
	if err != nil {
		return fmt.Errorf("secrets: encrypt: %w", err)
	}

	// Pack container and write atomically.
	blob, err := packContainer(hdr, ciphertext)
	if err != nil {
		return fmt.Errorf("secrets: pack container: %w", err)
	}
	if err := writeSecureFile(encryptedSecrets(), blob); err != nil {
		return fmt.Errorf("secrets: write container: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Encrypted secrets → %s  (backend: %s)\n", encryptedSecrets(), backendLabel(backend))

	// Shred the plaintext source.
	if err := shredFile(sourceEnvFile); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: could not shred %s — delete it manually!\n", sourceEnvFile)
	} else {
		fmt.Fprintf(os.Stderr, "Plaintext %s shredded and removed.\n", sourceEnvFile)
	}

	// Informational hints per backend.
	switch backend {
	case kdfKeyring:
		fmt.Fprintln(os.Stderr, "Master key stored in OS keyring. No key material is on disk.")
	case kdfScrypt:
		fmt.Fprintln(os.Stderr, "Master key is derived from your passphrase on every decrypt.")
		fmt.Fprintf(os.Stderr, "For CI/headless use, set the %s environment variable.\n", passphraseEnvVar)
	case kdfFile:
		fmt.Fprintf(os.Stderr, "Legacy key file: %s (0600). Back it up somewhere safe.\n", keyFile())
	}
	return nil
}

// DecryptSecrets reads the secrets container from encryptedSecrets(), loads
// the master key from the appropriate backend, and writes the plaintext to
// destEnvFile with 0600 permissions.
func DecryptSecrets(destEnvFile string) error {
	blob, err := os.ReadFile(encryptedSecrets())
	if err != nil {
		return fmt.Errorf("secrets: read container: %w", err)
	}

	hdr, ciphertext, legacy, err := unpackContainer(blob)
	if err != nil {
		return fmt.Errorf("secrets: unpack container: %w", err)
	}
	if legacy {
		fmt.Fprintln(os.Stderr,
			"WARNING: legacy secrets layout detected (Fernet/Python container).")
		fmt.Fprintln(os.Stderr,
			"  Migrate: anvil-scanner --rotate-key-backend passphrase")
		return errors.New("secrets: legacy container cannot be decrypted by this binary")
	}

	masterKey, err := loadMasterKeyForHeader(hdr)
	if err != nil {
		return err
	}
	defer func() {
		for i := range masterKey {
			masterKey[i] = 0
		}
	}()

	plain, err := decryptAES256GCM(masterKey, ciphertext)
	if err != nil {
		return fmt.Errorf("secrets: decrypt: %w", err)
	}

	if err := writeSecureFile(destEnvFile, plain); err != nil {
		return fmt.Errorf("secrets: write plaintext: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Decrypted secrets → %s\n", destEnvFile)
	return nil
}

// LoadSecrets loads managed secrets into os.Environ from available sources
// (per-key keyring, encrypted container, plaintext .env) in priority order.
// It returns a map of the keys it loaded, with values masked as "***".
func LoadSecrets() map[string]string {
	loaded := make(map[string]string)

	// 1. Per-secret keyring entries (if keyring is available).
	if hasKeyring() {
		for _, key := range ManagedKeys {
			if _, ok := os.LookupEnv(key); ok {
				continue // env vars always win
			}
			if val, ok := loadKeyringSecret(key); ok {
				if err := os.Setenv(key, val); err != nil {
					fmt.Fprintf(os.Stderr, "WARNING: could not set %s: %v\n", key, err)
				} else {
					loaded[key] = "***"
				}
			}
		}
	}

	// 2. Encrypted container.
	if _, err := os.Stat(encryptedSecrets()); err == nil {
		blob, err := os.ReadFile(encryptedSecrets())
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: could not read %s: %v\n", encryptedSecrets(), err)
		} else {
			hdr, ciphertext, legacy, unpackErr := unpackContainer(blob)
			if unpackErr != nil {
				fmt.Fprintf(os.Stderr, "WARNING: malformed secrets container: %v\n", unpackErr)
			} else {
				if legacy {
					fmt.Fprintln(os.Stderr,
						"WARNING: legacy secrets layout detected — migrate with --rotate-key-backend")
				} else {
					// Warn if root + keyring backend (root's keyring is empty).
					if os.Getuid() == 0 && hdr != nil && hdr.KDF == kdfKeyring {
						fmt.Fprintln(os.Stderr,
							"WARNING: running as root but container uses keyring backend — decryption may fail.")
					}
					masterKey, keyErr := loadMasterKeyForHeader(hdr)
					if keyErr != nil {
						fmt.Fprintf(os.Stderr,
							"WARNING: could not load master key: %v\n", keyErr)
						fmt.Fprintln(os.Stderr,
							"Scan will proceed WITHOUT API keys — results may be incomplete.")
					} else {
						plain, decErr := decryptAES256GCM(masterKey, ciphertext)
						for i := range masterKey {
							masterKey[i] = 0
						}
						if decErr != nil {
							fmt.Fprintf(os.Stderr,
								"WARNING: decryption failed: %v\n", decErr)
						} else {
							for k, v := range parseEnvFile(string(plain)) {
								if _, ok := os.LookupEnv(k); !ok {
									if err := os.Setenv(k, v); err != nil {
										fmt.Fprintf(os.Stderr, "WARNING: could not set %s: %v\n", k, err)
									} else {
										loaded[k] = "***"
									}
								}
							}
							for i := range plain {
								plain[i] = 0
							}
						}
					}
				}
			}
		}
	}

	// 3. Fallback to plaintext .env in current directory.
	if len(loaded) == 0 {
		dotenv := filepath.Join(func() string { d, _ := os.Getwd(); return d }(), ".env")
		if data, err := os.ReadFile(dotenv); err == nil {
			for k, v := range parseEnvFile(string(data)) {
				if _, ok := os.LookupEnv(k); !ok {
					if err := os.Setenv(k, v); err != nil {
						fmt.Fprintf(os.Stderr, "WARNING: could not set %s: %v\n", k, err)
					} else {
						loaded[k] = "***"
					}
				}
			}
			if len(loaded) > 0 {
				fmt.Fprintln(os.Stderr, "Tip: prefer encrypted storage over plaintext .env files.")
				fmt.Fprintln(os.Stderr, "  Run: anvil-scanner --init-secrets")
			}
		}
	}

	return loaded
}

// InitSecrets is the first-time wizard: pick a backend (prompting on a TTY
// unless nonInteractive is true or backend is given), validate, and call
// EncryptSecrets.  If encryptedSecrets() already exists and we're interactive,
// the user is asked to confirm.
func InitSecrets(sourceEnvFile, backend string, nonInteractive bool) error {
	// Determine the source file.
	src := sourceEnvFile
	if src == "" {
		src = PlaintextEnv
	}

	// Pick backend if not specified.
	if backend == "" {
		if !nonInteractive && isTerminal() {
			backend = askBackendChoice()
		}
		if backend == "" {
			backend = chooseDefaultBackend()
		}
	}

	// Validate backend.
	if !isValidBackend(backend) {
		return fmt.Errorf("secrets: unknown backend %q (valid: %s)", backend, strings.Join(ValidBackends, ", "))
	}

	// Refuse keyring-as-root early.
	if (backend == "keyring" || backend == kdfKeyring) && os.Getuid() == 0 {
		return errors.New(
			"secrets: keyring backend requires a per-user credential store; " +
				"re-run without sudo or choose 'passphrase'",
		)
	}

	fmt.Fprintf(os.Stderr, "Selected backend: %s\n", backend)

	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("secrets: source file not found: %s — copy config.example.env and fill in your values first", src)
	}

	// Prompt before overwriting an existing container.
	if _, err := os.Stat(encryptedSecrets()); err == nil {
		fmt.Fprintf(os.Stderr, "WARNING: existing %s will be overwritten.\n", encryptedSecrets())
		if !nonInteractive && isTerminal() {
			fmt.Fprint(os.Stderr, "  Proceed? [y/N] ")
			var resp string
			fmt.Fscanln(os.Stdin, &resp)
			resp = strings.ToLower(strings.TrimSpace(resp))
			if resp != "y" && resp != "yes" {
				fmt.Fprintln(os.Stderr, "Aborted.")
				return nil
			}
		}
	}

	if err := EncryptSecrets(src, backend); err != nil {
		return err
	}

	// Shred stale key file when moving off file backend.
	resolvedBackend, _ := resolveBackend(backend)
	if resolvedBackend != kdfFile {
		if _, err := os.Stat(keyFile()); err == nil {
			if shErr := shredFile(keyFile()); shErr == nil {
				fmt.Fprintf(os.Stderr,
					"Removed stale %s — master key no longer needs to live on disk.\n", keyFile())
			}
		}
	}
	return nil
}

// RotateKeyBackend re-encrypts the existing secrets container under a new
// backend.  The original plaintext is kept in a temp file that is shredded
// in a defer regardless of success or failure.
func RotateKeyBackend(target string) error {
	if !isValidBackend(target) {
		return fmt.Errorf("secrets: unknown backend %q (valid: %s)", target, strings.Join(ValidBackends, ", "))
	}

	if _, err := os.Stat(encryptedSecrets()); err != nil {
		return fmt.Errorf("secrets: no encrypted secrets at %s — run --init-secrets first", encryptedSecrets())
	}

	// Decrypt current container into memory.
	blob, err := os.ReadFile(encryptedSecrets())
	if err != nil {
		return fmt.Errorf("secrets: read container: %w", err)
	}
	hdr, ciphertext, legacy, err := unpackContainer(blob)
	if err != nil {
		return fmt.Errorf("secrets: unpack container: %w", err)
	}
	if legacy {
		return errors.New("secrets: cannot rotate a legacy (Python/Fernet) container — decrypt it manually first")
	}

	oldKDF := ""
	if hdr != nil {
		oldKDF = hdr.KDF
	}

	masterKey, err := loadMasterKeyForHeader(hdr)
	if err != nil {
		return fmt.Errorf("secrets: load current master key: %w", err)
	}
	plain, err := decryptAES256GCM(masterKey, ciphertext)
	for i := range masterKey {
		masterKey[i] = 0
	}
	if err != nil {
		return fmt.Errorf("secrets: decrypt current container: %w", err)
	}

	// Ensure the secrets directory exists before creating a temp file in it.
	if err := os.MkdirAll(secretsDir(), 0o700); err != nil {
		return fmt.Errorf("secrets: create secrets dir: %w", err)
	}

	// Write plaintext to a temp file and shred it in a defer.
	tmp, err := os.CreateTemp(secretsDir(), ".rotate-*.env")
	if err != nil {
		return fmt.Errorf("secrets: create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = shredFile(tmpPath)
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("secrets: chmod temp file: %w", err)
	}
	if _, err := tmp.Write(plain); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("secrets: write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("secrets: close temp file: %w", err)
	}
	// Clear plaintext bytes immediately after writing.
	for i := range plain {
		plain[i] = 0
	}

	// Re-encrypt under the new backend.
	if err := EncryptSecrets(tmpPath, target); err != nil {
		return fmt.Errorf("secrets: re-encrypt: %w", err)
	}

	// Clean up old backend's key material.
	resolvedTarget, _ := resolveBackend(target)
	if oldKDF == kdfFile && resolvedTarget != kdfFile {
		if _, statErr := os.Stat(keyFile()); statErr == nil {
			if shErr := shredFile(keyFile()); shErr == nil {
				fmt.Fprintf(os.Stderr, "Removed stale %s.\n", keyFile())
			}
		}
	}
	if oldKDF == kdfKeyring && resolvedTarget != kdfKeyring {
		if delErr := deleteKeyringMasterKey(); delErr == nil {
			fmt.Fprintln(os.Stderr, "Removed old master key from OS keyring.")
		}
	}

	fmt.Fprintf(os.Stderr, "Rotation complete. Backend is now: %s\n", target)
	return nil
}

// StoreSecretsKeyring loads secrets from the container (or plaintext .env)
// and stores each managed key as a per-secret keyring entry so that tools
// reading the OS credential store directly can find them by name.
func StoreSecretsKeyring() error {
	if !hasKeyring() {
		return errors.New("secrets: no usable keyring backend detected on this system")
	}

	// Collect secrets from encrypted container first.
	secretMap := make(map[string]string)
	if _, err := os.Stat(encryptedSecrets()); err == nil {
		blob, err := os.ReadFile(encryptedSecrets())
		if err == nil {
			hdr, ciphertext, legacy, unpackErr := unpackContainer(blob)
			if unpackErr == nil && !legacy {
				if masterKey, keyErr := loadMasterKeyForHeader(hdr); keyErr == nil {
					if plain, decErr := decryptAES256GCM(masterKey, ciphertext); decErr == nil {
						for i := range masterKey {
							masterKey[i] = 0
						}
						secretMap = parseEnvFile(string(plain))
						for i := range plain {
							plain[i] = 0
						}
					}
				}
			}
		}
	}

	// Fall back to plaintext .env if we got nothing from the container.
	if len(secretMap) == 0 {
		dotenv := filepath.Join(func() string { d, _ := os.Getwd(); return d }(), ".env")
		if data, err := os.ReadFile(dotenv); err == nil {
			secretMap = parseEnvFile(string(data))
		}
	}

	if len(secretMap) == 0 {
		return errors.New("secrets: no secrets found — create a .env or run --init-secrets first")
	}

	var stored int
	var lastErr error
	for k, v := range secretMap {
		if err := storeKeyringSecret(k, v); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: could not store %s in keyring: %v\n", k, err)
			lastErr = err
			continue
		}
		stored++
	}
	if stored == 0 {
		return fmt.Errorf("secrets: no secrets could be stored in keyring: %w", lastErr)
	}
	fmt.Fprintf(os.Stderr, "Stored %d secret(s) in system keyring.\n", stored)
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// parseEnvFile parses an .env-format string and returns a map containing only
// the managed keys.  It skips blank lines, comment lines, and lines without
// an '=' separator.  Surrounding single or double quotes are stripped from
// values.
func parseEnvFile(text string) map[string]string {
	managed := make(map[string]bool, len(ManagedKeys))
	for _, k := range ManagedKeys {
		managed[k] = true
	}

	result := make(map[string]string)
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		k := strings.TrimSpace(line[:idx])
		v := strings.TrimSpace(line[idx+1:])
		if !managed[k] {
			continue
		}
		// Strip surrounding matching quotes.
		if len(v) >= 2 && v[0] == v[len(v)-1] && (v[0] == '"' || v[0] == '\'') {
			v = v[1 : len(v)-1]
		}
		if k != "" {
			result[k] = v
		}
	}
	return result
}

// shredFile overwrites path with zeros, syncs, closes, then removes it.
// Returns nil if the file does not exist.
func shredFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("secrets: shred open %s: %w", path, err)
	}

	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("secrets: shred stat %s: %w", path, err)
	}

	size := info.Size()
	if size > 0 {
		zeros := make([]byte, size)
		if _, err := f.WriteAt(zeros, 0); err != nil {
			_ = f.Close()
			return fmt.Errorf("secrets: shred write %s: %w", path, err)
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return fmt.Errorf("secrets: shred sync %s: %w", path, err)
		}
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("secrets: shred close %s: %w", path, err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("secrets: shred remove %s: %w", path, err)
	}
	return nil
}

// writeSecureFile writes data to path atomically (via a .tmp sibling) with
// 0600 permissions.
func writeSecureFile(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("secrets: open tmp file %s: %w", tmp, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("secrets: write tmp file %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("secrets: sync tmp file %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("secrets: close tmp file %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("secrets: rename %s → %s: %w", tmp, path, err)
	}
	return nil
}

// loadMasterKeyForHeader loads the 32-byte master key from the appropriate
// backend based on the container header.
func loadMasterKeyForHeader(hdr *containerHeader) ([]byte, error) {
	if hdr == nil {
		return nil, errors.New("secrets: nil container header")
	}
	switch hdr.KDF {
	case kdfKeyring:
		key, err := loadKeyringMasterKey()
		if err != nil {
			return nil, fmt.Errorf("secrets: load keyring master key: %w", err)
		}
		return key, nil

	case kdfScrypt:
		saltRaw, err := base64.StdEncoding.DecodeString(hdr.Salt)
		if err != nil {
			return nil, fmt.Errorf("secrets: decode scrypt salt: %w", err)
		}
		passphrase, err := promptPassphrase(false)
		if err != nil {
			return nil, fmt.Errorf("secrets: prompt passphrase: %w", err)
		}
		if passphrase == "" {
			return nil, errors.New("secrets: empty passphrase; cannot decrypt")
		}
		n, r, p := hdr.N, hdr.R, hdr.P
		if n == 0 {
			n = scryptN
		}
		if r == 0 {
			r = scryptR
		}
		if p == 0 {
			p = scryptP
		}
		key, err := deriveKeyScrypt(passphrase, saltRaw, n, r, p)
		if err != nil {
			return nil, fmt.Errorf("secrets: derive scrypt key: %w", err)
		}
		return key, nil

	case kdfFile:
		key, err := loadFileKey(keyFile())
		if err != nil {
			return nil, fmt.Errorf("secrets: load file key: %w", err)
		}
		return key, nil

	default:
		return nil, fmt.Errorf("secrets: unknown KDF %q in container header", hdr.KDF)
	}
}

// resolveBackend normalises and validates a user-supplied backend string.
// "passphrase" is mapped to kdfScrypt ("scrypt") to match the container
// header KDF label while keeping the user-facing flag intuitive.
// An empty backend is auto-selected via chooseDefaultBackend().
func resolveBackend(backend string) (string, error) {
	if backend == "" {
		return chooseDefaultBackend(), nil
	}
	switch backend {
	case "keyring":
		return kdfKeyring, nil
	case "passphrase":
		return kdfScrypt, nil
	case "file":
		return kdfFile, nil
	// Also accept internal KDF names directly (used by RotateKeyBackend).
	case kdfScrypt:
		return kdfScrypt, nil
	default:
		return "", fmt.Errorf("secrets: unknown backend %q (valid: %s)", backend, strings.Join(ValidBackends, ", "))
	}
}

// backendLabel converts an internal KDF name back to its user-facing label.
func backendLabel(kdf string) string {
	switch kdf {
	case kdfScrypt:
		return "passphrase"
	default:
		return kdf
	}
}

// isValidBackend reports whether b is one of the user-facing ValidBackends.
func isValidBackend(b string) bool {
	for _, v := range ValidBackends {
		if b == v {
			return true
		}
	}
	return false
}

// isTerminal reports whether os.Stdin is an interactive terminal.
func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// askBackendChoice displays a menu and returns the user's selection.
func askBackendChoice() string {
	fmt.Fprintln(os.Stderr, "Choose where to store the master key:")
	fmt.Fprintln(os.Stderr, "  [1] keyring    (OS keyring — recommended)")
	fmt.Fprintln(os.Stderr, "  [2] passphrase (scrypt-derived — good for servers)")
	fmt.Fprintln(os.Stderr, "  [3] file       (key on disk — NOT recommended)")
	fmt.Fprint(os.Stderr, "  Choice [1/2/3]: ")
	var choice string
	fmt.Fscanln(os.Stdin, &choice)
	switch strings.TrimSpace(choice) {
	case "1":
		return "keyring"
	case "2":
		return "passphrase"
	case "3":
		return "file"
	default:
		return chooseDefaultBackend()
	}
}
