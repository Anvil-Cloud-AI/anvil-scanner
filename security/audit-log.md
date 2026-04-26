# Audit Log

Running record of scan results and external security reviews for the anvil-scanner public OSS release. Each release and periodic scan gets an entry below, newest first.

## How to read this log

Entries come in three types:

- **Release** — full scan cycle around a tagged release, gating the tag.
- **Periodic** — unscheduled re-scan triggered by a dependency bump, upstream CVE disclosure, or other notable event between releases.
- **Incident** — a confirmed vulnerability in anvil-scanner itself, with link to advisory, triage timeline, and fix commit.

Every entry records: date, scope, toolchain, findings by severity, and fix references.

---

## 2026-04-21 — Clean-sheet Go rewrite decided; launch delayed; Python moved to `python/`

**Type:** Periodic (pre-release)

**Date:** 2026-04-21

**Scope:** Reversal of the earlier 2026-04-21 decision (ship Python v1.0.0, phase a Go migration as v2.0 over 8–12 weeks). After two rounds of pushback from Dave — first on the "don't want Python long-term" framing, then on the proposal to build Go clean-sheet from the feature list rather than do a migration — we're switching to a clean-sheet Go rewrite inside this same repo and delaying v1.0.0 until Go feature-parity. The Python code stays in the repo as a behavioral reference (not published, not installed, not maintained past cut-over). The existing 380-test suite is the specification; Go tests will be written native to Go idioms. No equivalence harness, no two-language maintenance window, no PyPI deprecation story — all three are problems we only had because we'd committed to shipping Python first.

**Toolchain:**

- pytest (380 passed, 2 skipped — baseline preserved after Python moved to `python/` subdir)
- ruff (58 findings — baseline preserved)
- bandit with `python/.bandit` config (10 medium, 9 high — all previously triaged)
- Go toolchain: not yet installed in CI; compile verification deferred to Dave's local machine pending Phase 1

**Changes:**

- **ADR-0001 rewritten.** Status flipped from Proposed to Accepted. Decision replaced: was "ship Python v1.0.0, phased migration over 8–12 weeks post-launch with equivalence harness + `--use-legacy` flag + PyPI deprecation window"; is now "clean-sheet Go rewrite inside this repo, delay launch 4–6 weeks, Python becomes reference-only, delete `python/` tree in the commit that tags v1.0.0." Added Option D (clean-sheet Go, delay launch) as the chosen path. Removed the equivalence-harness machinery and the Python→Go module mapping. Added a new "Repo Layout (post-transition)" section, collapsed the phased plan from 4 phases over 12 weeks to 5 phases over 6 weeks. Rewrote the "Trade-off Analysis" to include the Go-vs-Rust comparison that Dave asked about explicitly ("is go the best language for this project?") and the rationale for delaying launch rather than shipping-then-migrating.
- **`docs/porting-checklist.md` added.** All 37 check IDs enumerated: FW-001/002/003 (firewall), MACOS-001 through MACOS-008 (incl. FileVault at medium/WARN), RPI-001 through RPI-012 (Raspberry Pi), SSH-000/006/008/014/015/016/021/023/024/029/030/041/042/043. Each row has a status checkbox, severity, and a Python source reference. Ancillary features (HTML report, JSON report, AI analysis with NO_PROVIDER handling, threat intel, secrets store, pre-scan AI preflight, backup/snapshot/restore, root keyring refusal, telemetry) are listed separately. Priority-Findings promotion rules and status taxonomy are written down so a Go implementer can match them without reading Python source. `python/tests/test_refactor_guardrails.py` + `python/tests/test_anvil_scanner.py` are called out as the files to read first for behavioral contracts.
- **Python moved to `python/` subdirectory.** `anvil_scanner/` → `python/anvil_scanner/`, `tests/` → `python/tests/`, `anvil-scanner.py` → `python/anvil-scanner.py`, `pytest.ini` → `python/pytest.ini`, `requirements.txt` → `python/requirements.txt`, `.bandit` → `python/.bandit`, `install.sh` → `python/install.sh`. The pytest suite still runs green from the new location; CI workflow paths updated to match. `vulndb/` (shared vulnerability data) and `backend/` (separate FastAPI service) stay at the repo root unchanged.
- **Go scaffold at repo root.** `go.mod` with module path `github.com/Anvil-Cloud-AI/anvil-scanner`, `cmd/anvil-scanner/main.go` hello-world stub, `internal/` package stubs for scan/report/ai/threat/secrets/openclaw/backup/exec/hardening each with a `doc.go` documenting the responsibility, `.goreleaser.yml` stub ready for Phase 1 hardening, `.gitignore` updated for Go build artifacts. Phase 0 of the ADR plan is now complete.

**Tests added:** None this session. Phase 1 of the Go plan opens with `internal/scan/` check-builder tests; those land with the foundation work.

**Fix references:** Session of 2026-04-21, following Dave's "what if we setup a clean repo and just build the go app" and "no, let's just delay launch and get it done" decisions after a detailed comparison of ship-then-migrate vs clean-sheet.

---

## 2026-04-21 — Package rename (anvil-secure → anvil-scanner) + Go migration ADR + SSH gate finalized

**Type:** Periodic (pre-release)

**Date:** 2026-04-21

**Scope:** Three linked pieces of pre-launch cleanup. (1) Finish the SSH-gate work started 2026-04-19 so the file-permission checks (SSH-041/042/043) also drop when Remote Login is off on macOS, plus write the test class that locks the gate down. (2) Rename the project from `anvil-secure` to `anvil-scanner` across the tree — "scanner" describes what the tool actually does and leaves namespace room for future `anvil-*` siblings (`anvil-remediate`, `anvil-monitor`, etc.). (3) Capture the "ship Python now, Go rewrite as v2" decision as ADR-0001 so the migration direction is on paper rather than implicit.

**Toolchain:**

- pytest (375 passed, 2 skipped — matches pre-rename baseline exactly)
- ruff (58 findings — matches baseline)
- bandit with `.bandit` config (10 medium, 9 high — all previously triaged)

**Changes:**

- **SSH file-permission checks gated on `ssh_enabled`.** The original 2026-04-19 gate wrapped SSH-006 through SSH-030 (the directive-parsing checks) but left SSH-041 (`~/.ssh` and `authorized_keys` permissions), SSH-042 (`sshd_config` ownership/permissions), and SSH-043 (`ssh_host_*_key` file permissions) running unconditionally. Those three still emitted SKIP rows on a macOS machine with Remote Login off — stale `/etc/ssh/sshd_config` permissions are irrelevant security-wise when sshd isn't listening. Wrapped all three in the existing `if ssh_enabled:` block in `scanner.py::extended_scan`, so now the entire SSH section disappears rather than leaving a tail of SKIP noise.
- **Package rename sweep.** `anvil_secure/` → `anvil_scanner/` (package directory), `anvil-secure.py` → `anvil-scanner.py` (entry point), `tests/test_anvil_secure.py` → `tests/test_anvil_scanner.py`, plus text substitution across 37 tracked files for `anvil_secure` / `anvil-secure` / `Anvil Secure` / `ANVIL_SECURE`. Covers: Python imports, CLI invocations, docs, README, OSS_COMMERCIAL_PLAN, SECURITY.md, PI_TESTING.md, security/ docs, install.sh, `.bandit`, `.gitignore`, `.secrets.baseline`, `.github/workflows/security.yml`, `vulndb/update.py`, `config.example.env`. Also adjusted user-visible defaults: report output directory is now `~/anvil-scanner-reports/` (was `~/anvil-secure-reports/`); report filename template is now `anvil-scanner-YYYY-MM-DD*.html`; GitHub reference in `reporting.py` now points at `Anvil-Cloud-AI/anvil-scanner`. Nothing was published to PyPI under `anvil-secure`, so the rename is zero-break for external users. Existing report files in a user's `~/anvil-secure-reports/` are unaffected; new reports land in the new directory.
- **ADR-0001: Python → Go migration plan.** New `docs/adr/0001-go-migration.md`. Documents the three options considered (stay Python + pipx install, PyInstaller single-file Python binary, Go rewrite), the recommendation (ship v1.0.0 Python, execute a 4-phase Go port over 8–12 weeks as v2.0), module mapping for all 11 Python modules to proposed Go packages, a JSON-over-stdio plugin protocol to replace the implicit Python-import plugin boundary, an "equivalence harness" de-risking step for the port itself, and the sunset plan for the PyPI package. Proposed, not yet accepted.

**Tests added:** `tests/test_refactor_guardrails.py` gained `TestSshChecksSkippedWhenDisabled` (5 tests): (a) Darwin + `remote_login_enabled=False` → zero SSH-* checks in `extended_scan` output, (b) same scenario specifically verifies SSH-041, SSH-042, SSH-043 are absent (regression guard against the pre-fix behavior), (c) Darwin + `remote_login_enabled=True` → SSH-* checks run, (d) Darwin with the key missing entirely (unknown state) → SSH-* checks run (conservative), (e) Linux → SSH-* checks always run regardless of `ssh_config` hints (the gate is macOS-only).

**Fix references:** Session of 2026-04-21, continuing Dave's 2026-04-19 ask ("drop the ssh findings when ssh isn't enabled") and his 2026-04-21 ask ("we need to rewrite that to be anvil-scanner").

---

## 2026-04-19 — Report redesign + FileVault suggestion + SSH gate (initial) + word-wrap fix

**Type:** Periodic (pre-release)

**Date:** 2026-04-19

**Scope:** Four UX-focused changes to the HTML scan report after Dave's first live-machine scans surfaced readability and severity-calibration issues: (1) port the modern report redesign from `mockups/report-redesign-v2.html` into `reporting.py` with scroll-spy tab highlighting, (2) fix word-wrap in the OpenClaw Security ID column where long dotted IDs were shattering character-by-character, (3) downgrade FileVault (MACOS-002) from critical/FAIL to medium/WARN when off — it's a suggestion not a mandate, and promoting it into Priority Findings was producing false urgency, (4) start dropping SSH findings on macOS when Remote Login is off (directive checks completed this day; file-permission checks SSH-041/042/043 finished 2026-04-21).

**Toolchain:**

- pytest (362 → 375 passed, 2 skipped — 13 new tests across redesign + FileVault classes)
- ruff (66 → 58 findings — net improvement)
- bandit with `.bandit` config (unchanged, baseline preserved)

**Changes:**

- **Modern report redesign ported.** Graphite palette, CSS custom properties in `:root` (--bg-0, --accent, etc.), sticky topbar with `backdrop-filter: blur(10px)`, brand-mark gradient badge replacing the 🔐 emoji, typography tune across headers and body, and a sticky subnav under the topbar with anchored tabs to each report section (Summary / Priority / System / OpenClaw / Threats / AI). All existing class names preserved (`.sc`, `.ring`, `.pp`, `.wbox`, `.ovbox`, `.ai-fail`, `.ai-skip`, `.ai-disclaimer`) so no downstream HTML callers broke.
- **Scroll-spy tab highlighting.** Dave specifically asked for the subnav tab of the currently-visible section to be highlighted while scrolling. Implemented as an IntersectionObserver on `[data-nav-section]` wrappers with `rootMargin: '-120px 0px -60% 0px'` — a section "activates" when it crosses into the top 40% of the viewport, accounting for the sticky header. Click handlers on the subnav links also force the `.active` class immediately so the highlight doesn't lag the scroll. Degrades gracefully if `IntersectionObserver` is unavailable.
- **Conditional subnav rendering.** Only render tabs for sections that exist in the current report (Priority / OpenClaw / Threats are conditional on findings present; Summary / System / AI are always rendered).
- **OpenClaw Security ID column word-wrap fix.** Long dotted IDs like `security.exposure.open_groups_with_runtime_or_fs` were breaking character-by-character inside the old 80px column because `td code` carried `word-break: break-all`. Dropped `word-break: break-all` from the `td code, .finding code` rule and widened the ID column to 220px. IDs now wrap at sensible breakpoints (dots / underscores) or stay on one line. Same 220px width applied to the SSH Configuration directive column for the same reason.
- **FileVault (MACOS-002) downgraded to medium/WARN when off.** Dave's feedback: there are legitimate reasons to run without FileVault (CI runners, shared dev Macs, key-management overhead) and flagging it critical promotes it into Priority Findings where it produces false urgency. Changed: `fdesetup` not available → SKIP; FileVault on → PASS; FileVault off → WARN with copy that frames it as a suggestion ("consider enabling FileVault for at-rest data protection (suggested, not required)"). Severity changed from critical to medium so the Priority Findings filter (`FAIL/WARN + critical/high`) no longer catches it. FileVault on still PASSes as before.
- **SSH gate — first pass.** Added `ssh_enabled = not (plat == "Darwin" and ssh_cfg_for_gate.get("remote_login_enabled") is False)` at the head of `extended_scan`'s SSH block. When `ssh_enabled` is False, skipped SSH-006 through SSH-030 (all directive-parsing checks). Intentionally no "SSH checks skipped" SKIP row — the SSH Configuration section already surfaces "Remote Login: disabled" so the user knows why it's gone. Gate only fires on Darwin because `remote_login_enabled` is a macOS-only flag; Linux and unknown-state Darwin continue running the full SSH suite. File-permission checks SSH-041/042/043 remained outside the gate in this pass — finished 2026-04-21.

**Tests added:** `tests/test_refactor_guardrails.py` gained `TestReportRedesignSubnavAndScrollSpy` (8 tests on subnav rendering, anchor targets, section ID wrappers, IntersectionObserver inclusion, conditional Priority / Threats tab rendering, CSS custom properties presence, and brand-mark replacing the emoji) and `TestFileVaultIsSuggestionNotCritical` (5 tests: FileVault off → WARN, severity is medium not critical, detail reads as suggestion, FileVault on still PASSes, does not bubble into Priority Findings end-to-end).

**Fix references:** Session of 2026-04-19. Continued and completed 2026-04-21 (SSH-041/042/043 gating, new test class).

---

## 2026-04-19 — AI analysis: Ollama-first fallback + loud failure + disclaimer

**Type:** Periodic (pre-release)

**Date:** 2026-04-19

**Scope:** Redesign the `--ai-analysis` provider-detection and failure-surfacing path after Dave's first live AI scan produced a muted "openai not installed" line in the HTML report with no actionable next step. The underlying chain: sudo'd `--init-secrets` seeded an empty master-key, so `load_secrets()` returned nothing useful, so no cloud key was in env, so `_detect_provider()` silently defaulted to Ollama, which wasn't running, which produced a terse error that rendered as a grey single-line mute in the report. Ship a user-visible version of this by (a) making the provider order Ollama-first with an explicit probe, (b) introducing a NO_PROVIDER sentinel so "nothing works" is a first-class return value, (c) loud red banner in the report with structured remediation, and (d) an inline AI-inconsistency disclaimer alongside any generated AI content.

**Toolchain:**

- pytest (362 passed, 2 skipped)
- ruff (0 net new findings on modified files; baseline 45 → 45)
- bandit with `.bandit` config (0 findings)

**Changes:**

- **Ollama-first provider order with reachability probe.** `_detect_provider()` now goes: explicit `AI_PROVIDER` env → 500 ms GET probe to Ollama's `/api/tags` (loopback only, validated by `_validate_ollama_url`) → `CLAUDE_KEY` / `OPENAI_KEY` / `GROK_KEY` → `AI_PROVIDER_NONE`. Rationale: if the user has Ollama running locally, they get AI narrative for free, no BYOK needed, and scan data never leaves the machine. The probe has no failure penalty — any exception returns False and falls through to the key-based path.
- **`AI_PROVIDER_NONE` sentinel.** New return value from `_detect_provider()` when nothing is available. Previously the code silently fell back to Ollama and then failed late with a network error; now `ai_risk_analysis()` short-circuits on NONE and returns a structured `{error, remediation}` dict so the report can render a first-class loud empty state.
- **Preflight in `cli.py` before the scan starts.** `_preflight_ai_provider()` runs `_detect_provider()` plus a cheap `__import__()` probe for the provider's SDK (catches the "key is set but `anthropic` / `openai` package not in this venv" trap), then emits a loud terminal error with full remediation copy before the 30-second scan begins instead of at the end.
- **Structured multi-line remediation copy.** `_missing_package_remediation(pkg, key_env)` generates a 5-option remediation block with the recommended fix first (use the `anvil-scanner` wrapper so the bundled venv is picked up) and ad-hoc `pip install` as a later fallback. Copy also advertises Ollama (`ollama serve`) as a local-inference alternative for users who'd rather not touch cloud keys.
- **Three visually distinct AI-section states in the HTML report.** Red-left `role="alert"` banner on failure (with the structured remediation rendered as a bulleted list), dashed-border muted callout on `--no-ai` / default-off skip, normal overview + cards on success. Before this pass, all three rendered as the same muted grey line and Dave couldn't tell from a report whether `--ai-analysis` was passed or whether it was passed and silently failed.
- **Inline AI-inconsistency disclaimer.** New `.ai-disclaimer` callout (yellow-left accent, visually distinct from both the alert banner and the success cards) appended to the AI Risk Analysis section whenever AI content is shown — success and error-with-remediation both get it, the skip empty-state does not (no AI content to disclaim). Copy calls out that LLM output is probabilistic, can miss issues / invent details / recommend changes that don't fit the environment, and instructs the user to verify critical findings against raw scan data and official docs before acting. The page footer already carried a generic "AI-generated analysis may be inaccurate" line; this surfaces the warning next to the AI output itself where it actually gets read.

**Tests added:** `tests/test_anvil_scanner.py` — rewrote `TestDetectProvider` (6 existing tests patched to stub `_ollama_reachable=False`, 4 new tests for probe-skip-on-explicit-provider, Ollama-reachable-beats-CLAUDE_KEY, Ollama-reachable-no-keys, NO_PROVIDER-when-nothing-works), new `TestOllamaReachable` (6 tests on the probe's success/timeout/connection-refused/non-2xx/generic-error paths), new `TestAiNoProviderShortCircuit` (4 tests including a structured-remediation assertion for the "openai SDK missing" case). `tests/test_refactor_guardrails.py` — rewrote `TestAiAnalysisProviderDetection`, new `TestReportAiSectionStates` (7 tests covering skip / error / success rendering plus the three disclaimer cases: shown-on-success, shown-on-error, hidden-on-skip), new `TestPreflightAiProvider` (5 tests including two `builtins.__import__`-mocking tests for the Dave-on-system-Python scenario).

**Fix references:** Session of 2026-04-19 (continuation of the same day's sudo/keyring entry below).

---

## 2026-04-19 — Baselining removal + sudo/keyring UX layer

**Type:** Periodic (pre-release)

**Date:** 2026-04-19

**Scope:** Two pre-launch adjustments surfaced during final readiness review: (1) retire the in-tree file-baselining / config-drift tracker, (2) close the "I ran it with sudo and now my scans don't work" UX hole around the OS keyring backend.

**Toolchain:**

- pytest (335 passed, 2 skipped)
- ruff `--select S` (0 findings on modified files)
- bandit with `.bandit` config (0 findings on modified files)

**Changes:**

- **Retire the file-baselining feature.** Removed the per-host SHA-256 baseline of `/etc/ufw/ufw.conf`, `/etc/ssh/sshd_config`, `/etc/fail2ban/jail.local`, and friends. Anyone with a real posture requirement already runs a dedicated FIM tool (AIDE, osquery file_events, Tripwire, Wazuh) and duplicating that check inside anvil-scanner added persistent bloat to every exported report without meaningful coverage. Gone from the code: `_hash_file`, `_get_file_mtime`, `_create_baseline`, `_update_baseline`, `_check_config_drift`, the `_BASELINES_DIR` / `_BASELINE_FILE` constants, the `--baseline` CLI flag, the `drift_html` section in `reporting.py`, the drift-prompt augmentation in `ai_analysis.py`, and the three `_update_baseline(...)` call sites in `hardening.py` after ufw / sshd / fail2ban apply. No migration required — on-disk baseline files under `~/.anvil-scanner/baselines/` are ignored by the new code and can be deleted by the user at leisure.
- **Informational root nudge on non-root-requiring commands.** Running `./anvil-scanner.py --scan` or `--init-secrets` (or any command other than `--harden` / `--uninstall` / `--revert`) under `sudo` now prints a short advisory explaining that OpenClaw installs tend to live in user directories and scanning as root can hide user-scope findings while scattering output across two homes. The nudge dwells for 3 seconds (Ctrl-C exits cleanly with status 130) and then continues — it is informational, not a blocker.
- **`--no-sudo-warning` flag + `ANVIL_NO_SUDO_WARNING=1` env var.** Power users who have audited the trade-off and intentionally want to run scans as root can suppress the nudge via the flag or the env var. Documented in the flag's help text.
- **Hard refusal in `--init-secrets` for the keyring backend under sudo.** Selecting backend `[1] keyring` while `os.geteuid() == 0` now refuses the operation with a specific explanation: the OS credential store is per-user, so a keyring seeded by root is unreachable to the user account that'll run later scans. The refusal offers two paths forward (drop sudo and re-run, or pick `[2] passphrase` / `[3] file` which work regardless of EUID). Closes the previously-silent "created keyring entry as root, normal scans can't find it" failure mode.
- **One-shot advisory in `load_secrets()` when the container wants keyring but we're root.** Mirror of the above for inherited installs — if an existing `secrets.enc` header declares `backend=keyring` and the current process is root, we print a single advisory (latched behind `_ROOT_KEYRING_HINT_SHOWN`) before attempting the keyring lookup. The lookup still runs; this just tells the user what the probable failure reason is before the error surfaces.
- **Fix: `--scan --ai-analysis` was never calling `load_secrets()`.** AI analysis requires the provider key decrypted from `secrets.enc`, but the `--scan` path only decrypted secrets when `--threat-intel` was also set. Dave hit this in live use: AI scan produced no results because the provider key was never loaded. Added a `load_secrets()` call on the `--scan --ai-analysis` path. Root cause was a missed branch when `--threat-intel` and `--ai-analysis` were split into separate flags earlier in the v1 prep.

**Tests added:** `tests/test_anvil_scanner.py` gained three new classes — `TestWarnIfRootForUserOp` (9 tests covering the root-nudge flow, flag suppression, env-var suppression, Ctrl-C exit code, and non-root no-op), `TestInitSecretsRootKeyringRefusal` (3 tests on the `init_secrets` refusal copy and return value), `TestMaybeWarnRootKeyring` (5 tests on the one-shot latch and per-process reset). `tests/test_refactor_guardrails.py` dropped the duplicate `test_parser_accepts_baseline_flag`. Removed: `test_prompt_includes_drift_when_detected`, `test_prompt_no_drift_section_when_clean`, `test_baseline_flag`, and the entire `TestHashFile` class (all covered features that no longer exist).

**Fix references:** Session of 2026-04-19.

---

## 2026-04-18 — macOS report polish (no-fail2ban + SSH state)

**Type:** Periodic (pre-release)

**Date:** 2026-04-18

**Scope:** Small reporting tweaks surfaced by a live macOS test run (2026-04-18T05:22:32 report).

**Toolchain:**

- pytest (319 passed, 2 skipped)
- ruff `--select S` (0 findings on modified files)
- bandit with `.bandit` config (0 findings)

**Changes:**

- **Drop fail2ban section on macOS.** fail2ban is Linux-only; the HTML report's "🚫 fail2ban" section rendered three red rows on macOS (installed/running/active jails all "No"/"none") which was misleading rather than informative. The section is now conditional on `platform` — omitted entirely on Darwin.
- **Replace "unknown" SSH directive rows on macOS.** Apple ships `/etc/ssh/sshd_config` with every directive commented out unless Remote Login is enabled, so `PermitRootLogin` and `PasswordAuthentication` both rendered as "unknown" — two unhelpful rows. `_get_ssh_config()` now probes `systemsetup -getremotelogin` on macOS and sets `remote_login_enabled`. The SSH Configuration section renders:
  - Remote Login off → single informative row ("SSH server is off on this Mac, System Settings → General → Sharing → Remote Login") with no directive noise.
  - Remote Login on → an "enabled" banner row plus the actual directive rows (which are now meaningful).
  - Service state indeterminate (e.g. non-admin user where both directives are also "unknown") → a single "could not determine service state" row with a prompt to re-run with sudo.
- **Fix table overflow in HTML reports.** A 5-column table like the OpenClaw Security section was letting its Severity column render outside the section border when the Detail column contained long unbroken strings (remediation URLs, commands like `cd $OPENCLAW_SRC && git pull && make install`, unwrapped Fix: instructions). Added `table-layout:fixed` on the base `table` rule (so explicit `<th style="width:…">` widths are honoured and unwidthed columns share the remainder), `word-break:break-word; overflow-wrap:anywhere` on `th`/`td` (so long tokens wrap within cells), `overflow-x:auto` on `section` as a safety valve for any remaining overflow, and a `td code` rule that lets inline code wrap rather than force column expansion. Added a `test_tables_have_overflow_guards` test that checks the CSS guards are present in the rendered report.
- **Fix misleading "0 passed" pill on the OpenClaw Security section.** OpenClaw's `security audit --json` emits *findings* only (things to act on), never PASS rows — so the pill strip at the top of this section was always displaying "0 passed" alongside whatever counts OpenClaw actually reported. Two changes: (1) rename the heading from "(N checks)" → "(N findings)" to match what the wrapper actually produces; (2) add `hide_empty=True` to `_status_pills()` and pass it only from the OpenClaw section so zero-count pills are suppressed. The Extended Hardening Checks section is unchanged and still shows all five pills regardless of zero counts, because that section legitimately emits PASS entries.

**Tests added:**

- `tests/test_refactor_guardrails.py::TestMacOSReporting` (6 tests covering Darwin-omits-fail2ban, Linux-keeps-fail2ban, remote-login-off/on/unknown rendering, and Linux SSH rendering unchanged).
- `tests/test_anvil_scanner.py::TestMacosRemoteLoginProbe` (6 tests on the `_macos_remote_login_enabled()` helper: not-mac short-circuit, missing systemsetup, on/off parsing, non-admin non-zero exit, unexpected output).

**Fix references:** Session of 2026-04-18.

---

## 2026-04-17 — Pre-release hardening: secrets storage + OpenClaw pivot

**Type:** Periodic (pre-release)

**Date:** 2026-04-17

**Scope:** Launch-prep pass addressing two known pre-launch issues before cutting the first public tag.

**Toolchain:**

- pytest (307 passed, 2 skipped)
- ruff (0 findings on modified files)
- bandit (0 findings on modified files)
- Independent security review agent covering `anvil_scanner/secrets.py`

**Changes:**

- **OpenClaw pivot.** Replaced the hand-rolled `_check_openclaw_config()` check queue and the `docs/findings/openclaw/` per-check pages with a thin wrapper around `openclaw security audit --json`. OpenClaw is authoritative on its own config surface; anvil-scanner no longer maintains a parallel ruleset. The wrapper fails soft — if OpenClaw is missing, the audit times out, the binary returns non-zero, or the JSON is garbled, the scan emits a single SKIP finding and continues. Net delete: ~1,400 lines of drifting parallel checks.
- **OpenClaw install-channel awareness.** The wrapper now fingerprints the user's install (`npm` / `brew` / `source` / `unknown`) and uses that to rewrite OpenClaw's generic "run `openclaw update`" remediation into the actual upgrade command for the user's channel. Findings are stamped with `source: "openclaw:<channel>:<version>"`. No version-gap FAIL is ever emitted; the npm release train intentionally trails source and nagging every scan would erode signal on real findings.
- **Secrets-storage hardening.** Addressed the "key lives next to ciphertext" weakness by introducing a versioned container format (magic + version + JSON header + Fernet token) and three key backends: `keyring` (OS keyring; no key material on disk), `passphrase` (scrypt-derived from a ≥12-char passphrase, stdlib only), and `file` (legacy, retained with a big warning). Legacy headerless pairs still decrypt with a one-shot migration hint. New CLI: `--init-secrets` wizard + `--rotate-key-backend` atomic cross-backend re-encrypt.
- **Secrets security-review remediation.** An independent review of the secrets rewrite flagged CRITICAL / HIGH / MEDIUM issues; all addressed in this pass:
  - scrypt parameters (N/r/p) are bounds-checked before invocation (N in [2^14, 2^20] and must be power-of-2; r ≤ 64; p ≤ 3) to defeat DoS via adversarial container headers.
  - Container headers are capped at 4096 bytes with `kdf` schema validation at unpack time rather than lazily at key-load.
  - Salt bytes are size-capped (≤1024) and base64-length-gated before decode.
  - `rotate_key_backend` is wrapped in try/finally: the temporary plaintext env file is shredded on every exit path (success, early return, exception), and the in-memory plaintext binding is dropped to shorten GC residency.
  - `encrypt_secrets` drops `plain` and `master_key` bindings immediately after the Fernet encrypt call.

**Tests added:** `tests/test_secrets_backends.py` (54 tests: container format, scrypt KDF, per-backend round-trip, legacy compat, rotation, parameter validation, header schema); new test classes in `tests/test_anvil_scanner.py` for install-channel detection and remediation tailoring (24 tests).

**Fix references:** Session of 2026-04-17. See `OSS_COMMERCIAL_PLAN.md` §0 for full launch-readiness status.

---

## TBD — Release v1.0.0 (initial public release baseline)

**Type:** Release

**Date:** *(to be filled on tag)*

**Scope:** Full public repo at first OSS release tag.

**Toolchain:**

- `go test ./...` (workflow: [`.github/workflows/go-ci.yml`](../.github/workflows/go-ci.yml) `build` job)
- `go vet ./...` (workflow: [`.github/workflows/go-ci.yml`](../.github/workflows/go-ci.yml) `build` job)
- staticcheck (workflow: [`.github/workflows/go-ci.yml`](../.github/workflows/go-ci.yml) `lint` job)
- gosec SAST, SARIF output (workflow: [`.github/workflows/go-ci.yml`](../.github/workflows/go-ci.yml) `gosec` job)
- govulncheck (workflow: [`.github/workflows/go-ci.yml`](../.github/workflows/go-ci.yml) `govulncheck` job)
- semgrep `p/golang` + `p/owasp-top-ten` + `p/secrets`, SARIF output (workflow: [`.github/workflows/go-ci.yml`](../.github/workflows/go-ci.yml) `semgrep` job)

**Results:**

- go test: *(N tests passing — fill on tag)*
- go vet: 0 findings
- staticcheck: 0 findings
- gosec: 0 findings
- govulncheck: 0 known vulnerable dependencies
- semgrep: 0 findings

**Notable pre-release remediation:**

- Every subprocess call site reviewed: explicit argument lists only, no shell interpolation. Each `// #nosec` marker has a rationale comment.
- HTML escaping (`html.EscapeString`) applied to every external-data field surfaced in report output.
- Upgrade-recommendation strings written to point at "latest available version" rather than hardcoded target versions (avoids stale guidance between releases).
- OpenClaw version detection hardened against `openclaw --version` / path variance across install channels.
- HTML report rendering hardened with defensive field access on every finding to prevent panics on shape drift.

**Fix commits:** *(link to release tag and comparison when public)*

---

<!-- Template for future entries — copy, fill, prepend above the previous entry.

## YYYY-MM-DD — Release vX.Y.Z
**Type:** Release | Periodic | Incident
**Date:**
**Scope:**
**Toolchain:**
**Results:**
- Bandit:
- Ruff (S-category):
- pip-audit:
- detect-secrets:
- pytest:
- CodeQL:
**Remediation summary:**
**Fix commits:**
**Advisories published:** (link to any GHSAs if Incident)

-->
