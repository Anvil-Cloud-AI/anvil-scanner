# Audit Log

Running record of scan results and external security reviews for anvil-scanner. Each release and periodic re-scan gets an entry below, newest first.

## How to read this log

Entries come in three types:

- **Release** — full scan cycle around a tagged release, gating the tag.
- **Periodic** — unscheduled re-scan triggered by a dependency bump, upstream CVE disclosure, or other notable event between releases.
- **Incident** — a confirmed vulnerability in anvil-scanner itself, with link to advisory, triage timeline, and fix commit.

Every entry records: date, scope, toolchain, findings by severity, and fix references.

---

## 2026-05-06 — Release v1.0.0 (initial public release)

**Type:** Release

**Date:** 2026-05-06

**Scope:** Full public repo at first OSS release tag. Go rewrite complete; all check IDs ported from behavioral spec. Python reference implementation deleted.

**Toolchain:**

- `go test -race ./...` — full test suite with race detector (Ubuntu + macOS matrix)
- `go vet ./...` — standard Go static analysis
- staticcheck (`honnef.co/go/tools`) — SA/S/U checks
- gosec — Go-specific SAST, SARIF output uploaded to GitHub Security
- govulncheck — Go vulnerability database scan
- semgrep `p/golang` + `p/owasp-top-ten` + `p/secrets` — SARIF output

**Results:**

- go test: all packages pass, race detector clean
- go vet: 0 findings
- staticcheck: 0 findings
- govulncheck: 0 known vulnerable dependencies
- gosec: 43 findings, all triaged (see SECURITY.md for breakdown)
- semgrep: 0 findings

**Notable pre-release hardening:**

- Every subprocess call site reviewed: explicit argument lists only, no shell interpolation.
- HTML escaping (`html.EscapeString`) applied to every external-data field in report output.
- SSRF protection: custom transport validates resolved IPs against RFC-1918, loopback, link-local, CGNAT, ULA, and NAT64 ranges.
- Memory caps: all file reads use `io.LimitReader`; subprocess stdout/stderr capped at 1 MB.
- Atomic file writes: system config files written via temp-file + rename.
- Cron injection guard: schedule entries reject characters that break crontab syntax.
- Key zeroing: encryption key material explicitly zeroed via `defer` after use.

**Fix commits:** See [v1.0.0 tag](https://github.com/Anvil-Cloud-AI/anvil-scanner/releases/tag/v1.0.0)

---

<!-- Template for future entries — copy, fill, prepend above the previous entry.

## YYYY-MM-DD — Release vX.Y.Z
**Type:** Release | Periodic | Incident
**Date:**
**Scope:**
**Toolchain:**
**Results:**
- go test:
- go vet:
- staticcheck:
- govulncheck:
- gosec:
- semgrep:
**Remediation summary:**
**Fix commits:**
**Advisories published:** (link to any GHSAs if Incident)

-->
