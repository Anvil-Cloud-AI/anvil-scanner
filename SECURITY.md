# Security

## Reporting Vulnerabilities

If you discover a security vulnerability in anvil-scanner, please report it responsibly:

- **Email:** security@anvil-scanner.io
- **Do NOT** open a public GitHub issue for security vulnerabilities

We will acknowledge receipt within 48 hours and aim to release a fix within 7 days for critical issues.

## Security Audit History

Anvil-secure has undergone multiple rounds of security review. All findings have been remediated.

### Round 1 — 2026-03-13 (Pre-delivery)
- **Scope:** CLI tool + API backend
- **Findings:** 3 critical, 4 high, 6 medium — all fixed
- **Key fixes:** Unbounded prompt field, webhook error handling, report file permissions

### Round 2 — 2026-03-16
- **Scope:** Full codebase re-audit post-fixes
- **Findings:** 3 critical, 5 high, 8 medium — all fixed
- **Key fixes:** API key hashing upgraded (unsalted SHA-256 → HMAC-SHA256 with salt), database rollback discipline, public IP validation, atomic file operations, silent failure elimination

### Round 3 — 2026-03-17
- **Scope:** Public CLI repo (post API separation), two passes
- **Pass 1 findings:** 1 critical (XSS), 3 high, 3 medium — all fixed
- **Pass 2 findings:** 1 critical (IoC XSS), 4 high, 3 medium — all fixed
- **Key fixes:** HTML escaping for all external data in reports, backup source path traversal guard, IPv6 firewall rule support, TOCTOU-safe report writes, gateway token leak removed, keyring error logging, atomic pf.conf writes, proper exception typing in decryption

### Round 4 — 2026-03-18 (Bandit SAST)
- **Scope:** `anvil-scanner.py` — 4,247 lines scanned
- **Findings:** 0 critical, 0 high, 0 medium, 9 low (all expected false positives)
- **Low-severity items:** `subprocess` import (B404), `xml.sax.saxutils` import (B406), partial-path subprocess calls (B607), `subprocess.run` without `shell=True` (B603 ×2), empty-string token comparison (B105), `try/except/continue` in filesystem walk (B112), HTML hex color codes misidentified as passwords (B105 ×2)
- **Result:** Clean — no action required

## Automated Security Scanning

The following tools run on every push and pull request:

- **[Bandit](https://bandit.readthedocs.io/)** — Python-specific SAST (static application security testing)
- **[CodeQL](https://codeql.github.com/)** — GitHub's semantic code analysis with security-extended queries
- **[Dependabot](https://docs.github.com/en/code-security/dependabot)** — Automated dependency vulnerability monitoring
- **Dependency Review** — Blocks PRs that introduce high-severity vulnerable dependencies

Current status: **0 high-severity, 0 medium-severity** findings across all automated scans.

## Security Design Principles

- **No `shell=True`** — All subprocess calls use argument lists to prevent command injection
- **SSRF validation** — Ollama URL validated against localhost-only allowlist
- **Atomic file operations** — System config files (sshd_config, pf.conf, manifests) written via temp + rename
- **Secret management** — API keys stored via OS keyring (GNOME Keyring, macOS Keychain), encrypted file, or environment variable; no plaintext secrets on disk
- **HTML escaping** — All external data in reports passes through `html.escape()`
- **Path validation** — Backup restore validates both source (inside session dir) and destination (managed path prefixes)
- **TLS everywhere** — All external API calls use `ssl.create_default_context()`
- **No hardcoded credentials** — All secrets loaded from env vars, keyring, or encrypted store
