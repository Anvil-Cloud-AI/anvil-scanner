// Package secrets implements the encrypted secrets store. It is the
// Go port of python/anvil_scanner/secrets.py.
//
// Structure (planned):
//
//   - container.go: on-disk container format (header + ciphertext).
//     Once shipped, the format is a compatibility promise.
//     ADR-0002 (docs/adr/0002-secrets-container-format.md) must be
//     written before this package is implemented.
//   - backends.go: key-backend abstraction. Backends: OS keyring
//     (darwin keychain, linux secret-service), passphrase-derived
//     (argon2id), file-based (restricted mode 0600).
//
// The root keyring refusal (cli.py behavior) lives in cmd/anvil-scanner
// rather than here — this package does not know the user identity.
package secrets
