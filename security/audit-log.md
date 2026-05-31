# Audit Log

Running record of scan results and external security reviews for anvil-scanner. Each release and periodic re-scan gets an entry below, newest first.

## How to read this log

Entries come in three types:

- **Release** — full scan cycle around a tagged release, gating the tag.
- **Periodic** — unscheduled re-scan triggered by a dependency bump, upstream CVE disclosure, or other notable event between releases.
- **Incident** — a confirmed vulnerability in anvil-scanner itself, with link to advisory, triage timeline, and fix commit.

Every entry records: date, scope, toolchain, findings by severity, and fix references.

---

## 2026-05-31 — Periodic deep security review & hardening pass (post-v1.0.0)

**Type:** Periodic

**Date:** 2026-05-31

**Scope:** Full manual deep security audit of the entire codebase (main branch, post v1.0.0) against the project's own five core security rules (AGENTS.md / CLAUDE.md) plus the standard automated SAST suite. Review covered all subprocess execution, file I/O boundaries, outbound HTTP, privileged uninstall/revert paths, secret handling, HTML output, and centralization of security primitives. Triggered by explicit request for comprehensive review after the initial public release stabilized.

**Toolchain:**
- `go test -race ./...` (full matrix, clean)
- `go vet ./...` (clean)
- `staticcheck ./...` (via normal CI gates on main — clean prior to this pass)
- `gosec` (via CI + manual review of all remaining `#nosec` / `//nolint` sites)
- `govulncheck ./...` (via CI — no vulnerable call-graph paths)
- `semgrep` (p/golang + p/owasp-top-ten + p/secrets, via CI)
- Extensive manual code review, data-flow tracing for SSRF/TOCTOU/privilege boundaries, and cross-package consistency audit

**Results:**
- All automated CI gates green on main at start of review.
- Manual deep review identified 3 high-severity gaps and multiple medium items not caught by SAST tools (primarily around privileged best-effort paths and duplicated security boundary logic):
  - **High:** Raw `os/exec.Command` + direct `os.ReadFile`/`os.WriteFile`/`os.Remove` in uninstall paths (`internal/backup/backup.go`: `removeFirewallRules`, `reloadSSHD`). These bypassed all five project security rules on privileged cleanup code.
  - **High:** `TelemetryClient` in `internal/safehttp` documented as SSRF-guarded but actually instantiated an unguarded `*http.Transport`.
  - **High/Medium:** Large duplicated `ssrfSafeTransport` + private-IP CIDR logic in `internal/ai/ai.go` (plus stray `webintel.go` community intel fetch code that had been accidentally committed).
- Numerous lower-severity consistency and defense-in-depth issues also addressed (see remediation summary).
- Zero unreviewed high-severity findings after remediation. All changes followed TDD where new logic was added and full `-race` / `go vet` verification.

**Remediation summary:**
- Created `internal/safehttp` package as the single source of truth for outbound HTTP clients: `SafeClient`, `LocalhostOnlyClient` (strict for Ollama), `TelemetryClient`, and `IsPrivateIP` with dial-time `net.Dialer.Control` enforcement. Migrated every call site (ai providers, threat intel feeds, OpenClaw, telemetry, schedule).
- Fully migrated uninstall/revert privileged operations in `internal/backup` to `internal/exec` helpers (`RunElevated`, `ReadFileElevated`, `WriteFileElevated` with atomic temp+rename). Added `io.LimitReader` guard to `loadManifest`.
- Deleted ~80 lines of duplicated transport code from `internal/ai`; removed the stray webintel fetch entirely.
- Earlier rounds in the same cycle (fail2ban post-restart polling, authoritative `sshd -T` effective config, macOS `socketfilterfw` firewall detection, launchctl fallback for Remote Login, etc.) also landed with corresponding test and report updates.
- All HTML external data continues to use `html.EscapeString`; all config writes remain atomic; all file reads bounded.

**Fix commits:** Multiple security-hardening PRs and direct main-line commits, May 2026 (safehttp centralization, backup uninstall migration, AI transport cleanup, plus supporting SSH/macOS/fail2ban robustness work). Full history available via `git log --since="2026-05-01"`.

**Notes:** This pass deliberately touched "working" privileged paths (uninstall) knowing it would require a full re-test cycle on Ubuntu (sudo) + macOS. Post-fix manual testing on both platforms is required before the next release tag.

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
