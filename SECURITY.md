# Security

## Reporting Vulnerabilities

If you discover a security vulnerability in anvil-scanner, please report it responsibly:

- **Email:** security@anvilcloud.ai
- **Do NOT** open a public GitHub issue for security vulnerabilities

We will acknowledge receipt within 48 hours and aim to release a fix within 7 days for critical issues.

## Automated Security Scanning

The following tools run on every push and pull request (see `.github/workflows/go-ci.yml`):

- **[gosec](https://github.com/securego/gosec)** — Go-specific SAST; outputs SARIF uploaded to GitHub Security
- **[govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)** — scans against the Go vulnerability database
- **[staticcheck](https://staticcheck.io/)** (`honnef.co/go/tools`) — extended static analysis beyond `go vet`
- **[semgrep](https://semgrep.dev/)** — SAST with `p/golang`, `p/owasp-top-ten`, and `p/secrets` rulesets; outputs SARIF
- **`go test -race ./...`** — full test suite with race detector runs on every push (Ubuntu + macOS)
- **`go vet ./...`** — standard Go static analysis
- **[Dependabot](https://docs.github.com/en/code-security/dependabot)** — automated Go module and GitHub Actions dependency monitoring

## Scan Results — v1.0.0 (2026-05-06)

### govulncheck

```
No vulnerabilities found.
```

Zero known vulnerabilities across all direct and transitive dependencies.

### staticcheck

Zero findings. All `SA` (correctness), `S` (simple), and `U` (unused code) checks pass cleanly.

### gosec

43 findings flagged, all reviewed and triaged:

| Rule | Severity | Count | Status |
|------|----------|-------|--------|
| G304 — file path via variable | MEDIUM | 9 | Accepted: all paths are constructed internally from trusted inputs, not from user input |
| G115 — integer overflow conversion | MEDIUM | 21 | Accepted: `len()` returns `int` in Go; gosec conservatively flags `uint→int` casts that cannot overflow |
| G306 — file write with 0644 | MEDIUM | 1 | Accepted: `pf.conf` is a world-readable system config file; 0644 is correct and annotated `#nosec` |
| G104 — unhandled `Close()` error | LOW | 12 | Accepted: `Close()` on a file opened for reading after `io.ReadAll` cannot return meaningful data |

**0 HIGH-severity findings. 0 unreviewed MEDIUM findings.**

## Security Design Principles

- **No shell injection** — All subprocess calls use argument lists (`exec.Command(binary, args...)`), never string interpolation
- **SSRF protection** — All outbound HTTP uses a custom transport that validates resolved IPs against RFC-1918, loopback, link-local, CGNAT, ULA, and NAT64 ranges; Ollama is restricted to localhost only
- **Memory caps** — All file reads use `io.LimitReader`; subprocess stdout/stderr capped at 1 MB
- **Atomic file writes** — System config files (`sshd_config`, `pf.conf`, manifests) written via temp-file + rename
- **Secret management** — API keys stored via OS keyring (macOS Keychain / GNOME Keyring), AES-256-GCM encrypted file with scrypt KDF, or environment variable; no plaintext secrets on disk
- **Key zeroing** — Encryption key material explicitly zeroed via `defer` after use
- **HTML escaping** — All external data in HTML reports passes through `html.EscapeString`
- **Path validation** — Backup restore validates source paths are inside the session directory and destinations are managed path prefixes
- **Cron injection guard** — Schedule entries reject characters that can break crontab syntax (`"`, `\`, newlines)
- **TLS everywhere** — All external API calls use Go's `crypto/tls` with default certificate verification; no `InsecureSkipVerify`
- **No hardcoded credentials** — All secrets loaded from environment variables, OS keyring, or encrypted store at runtime
