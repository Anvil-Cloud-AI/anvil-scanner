# Audit Log

Running record of scan results and external security reviews for anvil-scanner. Each release and periodic re-scan gets an entry below, newest first.

## How to read this log

Entries come in three types:

- **Release** — full scan cycle around a tagged release, gating the tag.
- **Periodic** — unscheduled re-scan triggered by a dependency bump, upstream CVE disclosure, or other notable event between releases.
- **Incident** — a confirmed vulnerability in anvil-scanner itself, with link to advisory, triage timeline, and fix commit.

Every entry records: date, scope, toolchain, findings by severity, and fix references.

---

## 2026-06-09 — Pre-merge deep review: Windows port (feat/windows-checks)

**Type:** Periodic

**Date:** 2026-06-09

**Scope:** Pre-merge security review of branch `feat/windows-checks` diff vs `origin/main` (~1,002 LOC across 28 files). New code: `internal/scan/scan_windows.go`, `windows_checks.go`, `windows_firewall.go` (Windows-tagged collectors that shell out to PowerShell and `reg.exe` via `internal/exec`); `windows_checks_parse.go`, `windows_firewall_parse.go`, `sku.go` (pure parsers, un-tagged); `sku_windows.go`, `fileowner_windows.go` (Windows stubs); `cmd/anvil-scanner/main_windows.go` (Windows entry point); build-tag broadening on `internal/container`, `internal/openclaw`, `internal/threat` (adding `|| windows`); `.github/workflows/go-ci.yml` (added `windows-latest` runner, removed `branches: [main]` restriction from `pull_request` trigger). Six specific areas assessed: (1) command/argument injection in PowerShell and reg.exe collectors; (2) untrusted PowerShell JSON output parsing; (3) privilege — read-only / no-admin assertion; (4) XSS in the HTML report for WIN-* check data; (5) CI trigger change risk; (6) secrets, SSRF, crypto, info-leak in error strings.

**Toolchain:**

Native (darwin, default platform):
- `go vet ./...` — 0 findings
- `staticcheck ./...` — 0 findings
- `gosec -quiet ./...` — 40 findings, all pre-existing (same set as the 2026-06-04 entry); **0 findings in any new Windows file**
- `govulncheck ./...` — 4 standard-library advisories (GO-2026-5039 `net/textproto`, GO-2026-5037 `crypto/x509`, GO-2026-4971 `net`, GO-2026-4918 `net/http`), all pre-existing and fixed in go1.26.3/go1.26.4 (local toolchain is go1.26.2); confirmed pre-existing by stashing the branch and re-running on `main`; none introduced by this branch
- `go test ./...` — all 13 packages pass; new Windows parser unit tests (`TestParseFirewallProfiles`, `TestEvalFirewallProfiles`, `TestParseDefenderStatus`, `TestEvalDefender`, `TestParseAndEvalSMB1`, `TestEvalRDP`, `TestParseRDPConfigNulls`, `TestParseUACEnabled`, `TestEvalUAC`, `TestParseServiceDisabled`, `TestParseInstallationType`) all pass on darwin

Windows cross-target (SAST tools skip windows-tagged code by default — this is the required workaround):
- `GOOS=windows GOARCH=amd64 go vet ./...` — 0 findings
- `GOOS=windows GOARCH=amd64 staticcheck ./...` — 0 findings
- `GOOS=windows GOARCH=amd64 go build ./...` — clean (confirms windows-tagged code compiles without error)

Note: `gosec` does not support cross-OS GOOS targeting for windows-tagged code via the environment variable; the darwin-native run above skips `//go:build windows` files. Runtime execution on a live Windows host is covered by `windows_integration_test.go` (`TestWindowsChecksIntegration`) running on the `windows-latest` GitHub Actions runner added in this branch.

**Results:**

- **No CRITICAL findings.**
- **No HIGH findings.**
- **No MEDIUM findings.**
- 1 LOW / informational finding (functional gap, no security impact — see below).
- All six assessed areas verified clean.

Detailed findings:

1. **Command/argument injection — CLEAN.** Every PowerShell invocation uses `iexec.Run("powershell", "-NoProfile", "-NonInteractive", "-Command", command)` where `command` is a Go string literal (backtick raw string or concatenation of string literals only — verified at `windows_checks.go:36,54,72,93,114` and `windows_firewall.go:18`). The `reg.exe` call in `sku_windows.go:12` uses explicit static argv elements. No user-controlled data flows into any command argument: every `check*` function accepts only a `*CheckBuilder`, and the call graph from `main_windows.go` is `RunAllChecksInto(b)` → `check*(b)` with no CLI flag values passed through.

2. **Untrusted output parsing — CLEAN.** All PowerShell JSON is decoded through `encoding/json.Unmarshal` into typed structs. The custom `jbool.UnmarshalJSON` returns a `nil` error in all cases, converting unknown input safely to `false`; a nil `json.RawMessage` also decodes safely to `false` (string conversion of nil is `""`, matched by `case "false", "":` in `rawJSONToBool`). Pointer fields (`rdpConfig.DenyTS`, `rdpConfig.NLA`, `uacConfig.EnableLUA`) decode JSON `null` to `nil` correctly and are nil-checked before dereference. The `parseServiceDisabled` function uses `json.RawMessage` + `strconv.Atoi` to handle numeric/string `StartType` values safely. Output is bounded by the pre-existing 1 MiB exec cap in `internal/exec.limitedWriter` (`maxExecOutputBytes = 1*1024*1024`), which applies to all `iexec.Run` calls including the new ones. No `unsafe`, no reflection, no deserialization outside `encoding/json`.

3. **Privilege — CLEAN.** None of the `check*` functions call `iexec.RunElevated`, `exec.WriteFileElevated`, `os.Remove`, or any write API. All subprocess calls are read-only PowerShell queries (`Get-MpComputerStatus`, `Get-SmbServerConfiguration`, `Get-NetFirewallProfile`, `Get-Service`, registry `Get-ItemProperty`) and a `reg query` (read). No UAC-elevation path is implemented in this branch, consistent with the stated design intent. `fileowner_windows.go` is a stub returning 0; it performs no I/O.

4. **Report / XSS — CLEAN.** WIN-* check fields (`ID`, `Name`, `Detail`, `Severity`, `Status`) are produced by the parser layer as controlled Go constants and strings derived from the bounded, typed JSON decode. In the HTML report, Priority Findings (the only section where WIN-* checks can surface — see below) passes every field through `e()` (`html.EscapeString`) at `html.go:195` (`detail := e(f.Detail)`), `201` (`e(string(f.ID))`, `e(f.Name)`), `202` (`e(strings.ToUpper(string(f.Severity)))`). Report files are written with `0o600` permissions. One functional gap noted: `catOrder` in `html.go:36` does not include `"WIN"`, so WIN-* checks are grouped into `cats["WIN"]` during `renderExtendedChecks` but are never rendered in the Extended Hardening Checks table. They DO appear in the Priority Findings section (which iterates all `d.Checks`) and they are counted in the status-pill totals and the "N checks" header. This is a UX inconsistency (WIN failures visible in priority section but absent from the system detail table), not a security issue. Noted for the team.

5. **CI trigger change — LOW RISK.** Removing `branches: [main]` from `pull_request` means CI runs on PRs targeting any branch, enabling CI validation for stacked feature branches. With `pull_request` (not `pull_request_target`), fork PRs run in a restricted context with no access to repository secrets. The workflow uses no repository secrets at all (confirmed: no `secrets.*` references, no `GITHUB_TOKEN` beyond the implicit read-only token). The two jobs that do use elevated permissions (`gosec`, `semgrep`) only request `security-events: write` to upload SARIF results — standard and appropriate. No secret exposure risk. Adding `windows-latest` to the build matrix increases CI cost and surface area slightly, but introduces no security concern.

6. **Secrets, SSRF, crypto, info-leak — CLEAN.** No hardcoded credentials or tokens in any new file. No outbound network calls in the new Windows code. No cryptographic operations. Error strings surface PowerShell/registry error text in `Check.Detail` fields (e.g., "could not read Terminal Server registry keys") — these are user-visible but contain only static tool-provided error context, not secret material or internal paths. The `fmt.Sprintf("Detected %s", DetectWindowsSKU())` in `scan_windows.go:26` interpolates only the `WindowsSKU.String()` return value, which is one of three controlled constants.

**Remediation summary:**

No security fixes required. The functional gap (WIN-* checks absent from the Extended Hardening Checks table) is informational and should be addressed in a follow-up by adding `"WIN"` to `catOrder` and a corresponding entry in `catLabels` in `internal/report/html.go`.

**Fix commits:** N/A — no security issues found. Branch `feat/windows-checks` is clear for merge from a security standpoint pending normal code review.

**Notes:** The govulncheck stdlib advisories (GO-2026-5039, GO-2026-5037, GO-2026-4971, GO-2026-4918) are pre-existing and require a Go toolchain bump to ≥1.26.4. This is a repo-wide action tracked separately. Runtime execution of the Windows integration test (`TestWindowsChecksIntegration`) requires the `windows-latest` CI runner; local analysis on darwin using cross-target `GOOS=windows` vet/staticcheck/build is the best available substitute for static analysis of windows-tagged code.

---

## 2026-06-04 — Pre-merge deep review: container scanning feature

**Type:** Periodic

**Date:** 2026-06-04

**Scope:** Pre-merge security review of branch `feat/container-scanning` (PR #9), which adds the `internal/container` package (runtime hardening across docker/podman + image CVE scanning via grype/trivy + registry scanning via `--scan-image`), the report Containers section, and the OpenClaw structural-check refactor. Review covered the full branch diff vs `main` (~1,400 LOC): all new subprocess execution (`docker`/`podman` ps & inspect, `grype`/`trivy` invocation), untrusted-data parsing (scanner + inspect JSON), the new HTML/JSON report surfaces, the `--scan-image` user-input boundary, and resource/cancellation handling. Triggered by explicit pre-merge request.

**Toolchain:**
- `go test -race ./...` — full suite, clean
- `go vet ./...` — clean
- `staticcheck ./internal/container/... ./internal/report/... ./cmd/...` — 0 findings
- `gosec` (v2, on changed packages) — 4 findings, **all pre-existing** (report write-path `G304` in `report.go` WriteHTML/WriteJSON to a user-specified output path; telemetry `os.ReadFile`/`resp.Body.Close` in `telemetry.go`); **0 in the new `internal/container` code**
- `govulncheck ./...` — 4 Go **standard-library** advisories (GO-2026-5039 net/textproto, GO-2026-5037 crypto/x509, GO-2026-4971 net, GO-2026-4918 net/http), all repo-wide and fixed in go1.26.3/1.26.4 (local toolchain is go1.26.2); none introduced by this branch and none reached from `internal/container`
- Two independent manual adversarial reviews (`security-reviewer` agent), pre- and post-fix, with data-flow tracing for argument injection, XSS, untrusted-JSON handling, SSRF, and context cancellation

**Results:**
- **No CRITICAL findings.** No HIGH findings remaining after remediation.
- First adversarial pass (during development) flagged 2 HIGH issues — both fixed and re-verified:
  - **High:** Argument injection — a `--scan-image` ref (or container ID from `ps`) beginning with `-` could be reinterpreted as a grype/trivy/`inspect` flag (e.g. trivy `--output`/`--username`). Closed by `ValidateImageRef` (anchored allowlist `^[A-Za-z0-9][A-Za-z0-9_.\-/:@]*$` + leading-dash guard + 512-char cap) **and** passing every external ref/ID after a `--` argv separator.
  - **High:** Scanner subprocess ignored the parent (signal) context — Ctrl-C wouldn't cancel an in-flight image pull. Fixed by threading `ctx` through `ScanImages`→`scanOne`.
- Second (independent, post-fix) pass confirmed all prior fixes hold (separators, regexp anchoring, HTML escaping of every report field, 1 MiB exec output cap, safe JSON decoding, timeout/cancel behavior) and found 1 MEDIUM + minor items, now addressed.
- gosec/staticcheck/govulncheck surfaced nothing new in the feature code.

**Remediation summary:**
- **MEDIUM** — image refs discovered from `docker/podman ps` previously bypassed `ValidateImageRef` (only `--scan-image` refs were validated). Now every ref is validated in `ScanImages` before reaching the scanner; an invalid runtime-derived ref is recorded as a skipped `ImageScan.Error` rather than executed.
- **LOW** — `CONTAINER-003` (root-user check) missed `root:group` / `root:0` forms; now splits on `:` and inspects the user half, so root expressed with a group is still flagged. Tests added.
- **LOW** — added a `ctx.Err()` guard between sequential image scans so a cancelled run stops promptly instead of launching another subprocess.
- **INFO/accepted** — grype/trivy perform their own registry network I/O outside the `internal/safehttp` SSRF guard; this is inherent to delegating to an external scanner and is mitigated by ref validation + documented on the `--scan-image` flag and in the README ("only pass trusted references"). No code change.
- **Deferred (not this branch):** `internal/exec` sets `TimedOut` only on `DeadlineExceeded`, so parent-context cancellation is reported as a generic failure rather than a timeout — diagnostic-only, shared code, tracked separately. Go toolchain bump to ≥1.26.4 to clear the stdlib govulncheck advisories — repo-wide, handled outside this PR.
- All new external data in the report passes through `html.EscapeString`; per-image CVE rows capped (200) to bound report size; all subprocess calls use explicit argument lists (no shell).

**Fix commits:** Branch `feat/container-scanning` (PR #9) — feature + in-development HIGH fixes in `fe455e7`; post-review MEDIUM/LOW remediations in the follow-up commit on the same branch.

**Notes:** SAST tools (gosec, govulncheck, staticcheck) were installed locally for this pass since CI normally provides them; semgrep was not run locally (CI `p/golang` + `p/owasp-top-ten` + `p/secrets` gates still apply on the PR). Re-confirm CI is green before merge.

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
