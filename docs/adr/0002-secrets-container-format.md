# ADR-0002 — Secrets Container Format

**Status**: Accepted  
**Date**: 2026-04-21  
**Author**: Anvil Cloud AI

---

## Context

The Python reference implementation (`python/anvil_scanner/secrets.py`) encrypts API keys and
sensitive configuration using the `cryptography` library's Fernet primitive (AES-128-CBC +
HMAC-SHA256). The Go rewrite cannot use Fernet without a third-party package that reimplements
the full Fernet spec, and Fernet is considered legacy — AES-256-GCM is the modern standard.

The container file (`~/.anvil-scanner/secrets.enc`) must carry enough metadata to select the
correct key backend and cipher at decrypt time, and the format must be a stability promise once
shipped: existing user containers must continue to work across versions.

---

## Decision

### On-disk container layout

```
ANVILSEC\n               9-byte magic + newline
1\n                      version line (ASCII digit + newline)
{"kdf":"...","cipher":"aes256gcm",...}\n   single-line JSON header + newline
<raw ciphertext bytes>   nonce-prefixed AES-256-GCM ciphertext
```

#### Header fields

| Field | Required | Values | Notes |
|-------|----------|--------|-------|
| `kdf` | yes | `"keyring"`, `"scrypt"`, `"file"` | Key derivation/storage backend |
| `cipher` | yes (Go containers) | `"aes256gcm"` | Absent = legacy Fernet container |
| `created` | yes | RFC 3339 UTC string | Audit trail only |
| `salt` | scrypt only | base64-std string | 16 random bytes, base64-encoded |
| `n` | scrypt only | int | scrypt N (must be power of 2, 2¹⁴–2²⁰) |
| `r` | scrypt only | int | scrypt r (1–64) |
| `p` | scrypt only | int | scrypt p (1–3) |

#### Ciphertext encoding (AES-256-GCM)

The ciphertext stored after the header is `nonce || GCM_ciphertext || GCM_tag`:
- nonce: 12 random bytes
- ciphertext + tag: standard AES-256-GCM output (tag appended by Go's `crypto/cipher`)

#### Legacy Fernet detection

A container that lacks the `"cipher"` header field (or has `"cipher":"fernet"`) was produced by
the Python implementation. The Go implementation detects these and prints a migration hint rather
than attempting to decrypt, since implementing Fernet would require a third-party package:

```
Legacy secrets container (Fernet) detected.
Migrate using the Python tool:
  anvil-scanner --init-secrets   # re-encrypts under new format
```

### Key backends

Three backends map to the `kdf` header value:

#### `keyring` — OS credential store (recommended)
- macOS: `security` CLI (`add-generic-password` / `find-generic-password`)
- Linux: `secret-tool` CLI (GNOME Keyring / KWallet)
- The 32-byte AES master key is stored base64-encoded under service `anvil-scanner`,
  account `anvil_scanner_master_key`
- If the keyring subprocess is unavailable, fall back to `passphrase`

#### `scrypt` — passphrase-derived key (good for servers/CI)
- KDF: `hashlib.scrypt`-compatible parameters via `golang.org/x/crypto/scrypt`
- Default: N=32768 (2¹⁵), r=8, p=1 (≈32 MiB RAM, ≈100 ms on modern hardware)
- Salt: 16 random bytes, stored in header
- Passphrase: read from `ANVIL_SECRETS_PASSPHRASE` env var, else stdin prompt
- Min passphrase length: 12 characters

#### `file` — key on disk (legacy, opt-in only)
- 32-byte AES key written to `~/.anvil-scanner/secrets.key` with `0600` permissions
- Never auto-selected; only available via explicit `--init-secrets --backend file`
- Printed warning at encrypt time

### Auto-selection (`keyring` if available, else `passphrase`)

The `keyring` backend is auto-selected when the `security` CLI (macOS) or `secret-tool`
(Linux) subprocess succeeds a probe write+read. Otherwise `passphrase` is used.

### Scrypt parameter validation (DoS guard)

A malicious or corrupted container header could coerce the Go process into OOM by specifying
`N=2^30`. The Go implementation validates N/r/p before running scrypt:

| Parameter | Min | Max |
|-----------|-----|-----|
| N | 2¹⁴ (power-of-2 required) | 2²⁰ |
| r | 1 | 64 |
| p | 1 | 3 |

### Secret loading priority

```
1. Existing os.Environ values (always win — never overwrite)
2. Per-secret keyring entries (for secrets stored via --store-keyring)
3. Decrypted secrets.enc container
4. Plaintext .env file (fallback with migration warning)
```

### Managed secret keys

The following environment variable names are managed by this package:

```
CLAUDE_KEY, OPENAI_KEY, GROK_KEY, ABUSEIPDB_KEY,
AI_PROVIDER, AI_MODEL, OLLAMA_URL, XAI_API_URL
```

### Security invariants

- `secrets.enc` written with `0600` permissions
- `secrets.key` written with `0600` permissions
- Header size capped at 4096 bytes (prevents header-bloat DoS during parse)
- Salt size capped at 1024 bytes
- Plaintext .env shredded (overwrite with zeros, then delete) after successful encryption
- Keyring backend refused when `os.Getuid() == 0` (root's keyring ≠ user's keyring)
- Rotation uses a `finally`-style defer to shred any temporary .env written during rotation

---

## Consequences

- Go containers are **not** directly readable by the Python implementation (different cipher)
- Python containers are **not** decryptable by Go (Fernet not implemented in Go)
- Migration path: use Python to rotate to passphrase, export plaintext, re-encrypt with Go
- `golang.org/x/crypto` is added as the only external dependency (scrypt)
- The container format is a compatibility promise from v1.0 onward; version bumps require a new ADR
