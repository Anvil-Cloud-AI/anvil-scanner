# ADR-0001: Rewrite anvil-scanner in Go (clean-sheet, delay v1.0.0)

**Status:** Accepted
**Date:** 2026-04-21
**Deciders:** Dave Moore (david.moore@anvilcloud.ai)

---

## Context

`anvil-scanner` is a local-first security hardening CLI for macOS and Linux. The existing implementation is Python 3.10+ at roughly 6,722 lines across 11 modules, with 380 passing tests:

| Module | LOC | Responsibility |
|---|---:|---|
| `scanner.py` | 1,267 | Core + extended hardening checks (SSH, FileVault, macOS/Linux) |
| `threat_intel.py` | 1,256 | CVE feed parsing, advisory matching |
| `reporting.py` | 1,010 | HTML + JSON report generation (embedded template) |
| `secrets.py` | 1,005 | Encrypted secrets store (container format, key backends) |
| `ai_analysis.py` | 397 | Anthropic/Ollama provider adapter, risk summary |
| `hardening.py` | 385 | Pre-check policy evaluation |
| `core.py` | 384 | Command dispatch, subprocess helpers |
| `cli.py` | 362 | argparse entry point |
| `openclaw_audit.py` | 359 | OpenClaw config + runtime audit |
| `backup.py` | 284 | Config snapshot + restore |

The Python implementation was originally scheduled to ship as v1.0.0 within weeks. Python distribution requires the user to manage an interpreter and virtualenv — either directly, via `pipx`, or via `pip install --user --break-system-packages`. This produces three frictions that matter for a security tool:

1. **First-run cost.** A security tool is judged in the first 90 seconds. `pip install` plus interpreter discovery plus dependency resolution is a worse experience than `curl | sh` followed by a single static binary.
2. **Support surface.** Python version drift (system Python on macOS, `externally-managed-environment` errors on modern Debian), venv activation confusion, `pip install --break-system-packages` warnings we have to pre-empt in docs.
3. **Ecosystem expectation.** Every adjacent OSS security tool — trivy, grype, gitleaks, kube-bench, nuclei, falco, cosign — ships as a single static Go binary. Users have formed that expectation.

The workload is a poor fit for Python's strengths. The scanner and hardening modules are almost entirely shelling out to OS commands (`fdesetup`, `launchctl`, `sshd -T`, `systemctl`, `dpkg`, `stat`, `find`) and parsing text output. There is no numpy / pandas / ML dependency anchoring us. The Python-strong dependency — the official Anthropic SDK — is a thin wrapper around one POST endpoint for our usage and ports trivially to a direct HTTP client.

Dave's stated motivations, in order:

1. "could we migrate this to Go and get away from using venvs?"
2. "I don't want Python long-term" (preferring to resolve the install-UX story before v1.0.0 is promoted to users).
3. "what if instead of trying to move the existing python, what if we setup a clean repo and just build the go app using the requirements/features we've already put together?"
4. "no, let's just delay launch and get it done."
5. "is go the best language for this project?" — and after discussion: "alright, do it with go."

### Constraints

- **No public Python release.** The Python implementation has never been published to PyPI. There are no existing users to migrate. There is no compatibility promise to preserve.
- **The Python code is valuable as a specification, not as a transition target.** The 380-test suite encodes the behavioral contract (severity calibration, SSH gating, priority-finding promotion rules, parsing edge cases). The Go rewrite treats those tests as the spec; Go tests are written native to Go idioms rather than translated 1:1.
- **Small team.** Single-digit contributor count. The rewrite cost falls on the same people.
- **AI summary keeps working.** Claude integration is a flagship feature from day one.

---

## Decision

**Rewrite `anvil-scanner` in Go as a clean-sheet implementation inside this same repo, and delay the v1.0.0 launch accordingly.**

Concretely:

1. **Python code moves to `python/`** as reference-only. It is not published, not installed by users, and not maintained past the cut-over. It exists so (a) porters can diff against a working implementation, and (b) the test suite can be consulted as behavioral spec.
2. **Go becomes the repo root.** `go.mod`, `cmd/anvil-scanner/`, `internal/`, `.goreleaser.yml` all live at the root. The published `anvil-scanner` binary is the Go binary.
3. **No equivalence harness.** We don't need byte-for-byte agreement with Python output — we never shipped it. Port features to Go, write Go-native tests against the same behavioral requirements the Python tests describe, and delete the Python implementation once the check coverage matches.
4. **v1.0.0 slips** to when the Go build passes the porting checklist (see `docs/porting-checklist.md`). Target window: 4–6 weeks from this decision.

This was not the initial recommendation. The original version of this ADR proposed shipping Python v1.0.0 and phasing a Go migration as a v2.0 effort over 8–12 weeks. Dave pushed back twice:

- First pushback: "why ship something we don't want long-term?" — a fair point. Shipping a Python v1 means locking in a Python install-UX public API, a Python-era documentation corpus, and a user base that will complain when v2.0 changes the install path.
- Second pushback: "what if we just build clean in Go from the feature list we already have?" — cuts the equivalence-harness work entirely and eliminates the maintenance tax of running two implementations in parallel.

Both points land. The clean-sheet rewrite with a delayed launch is materially simpler than ship-then-migrate: no two-language release pipeline, no compatibility promise between Python v1 and Go v2, no PyPI deprecation window, no "which binary do I run" confusion.

---

## Options Considered

### Option A — Stay Python, ship as-is (pipx-first)

| Dimension | Assessment |
|---|---|
| Complexity | Low (status quo) |
| Cost | ~0 dev effort |
| Install UX | Fair — `pipx install` hides the venv but still requires a Python interpreter |
| Binary size / startup | ~50 MB with deps / ~300 ms cold start |
| Long-term fit | Poor — commits us to a distribution model we've already decided we don't want |

**Verdict.** Rejected. Dave is explicit that he doesn't want Python long-term, and users form first impressions on v1. Shipping v1 on a distribution model we plan to abandon makes the v2 transition harder, not easier.

### Option B — PyInstaller / shiv single-file Python binary

| Dimension | Assessment |
|---|---|
| Complexity | Medium — PyInstaller is finicky per-platform |
| Cost | 1–2 weeks setup + ongoing maintenance |
| Install UX | Good — one file, chmod +x, run |
| Binary size / startup | 30–50 MB / 400–800 ms |
| Supply-chain story | Weak — interpreter + stdlib baked in, attestations can't cover the bundled stdlib |

**Verdict.** Rejected. A 40MB opaque blob is a poor look for a tool whose pitch is "audit your security posture." Community has largely abandoned this pattern for serious tools — ruff rewrote to Rust, many orgs fell back to pipx. This is a defensible intermediate step but a dead-end.

### Option C — Go rewrite as a v2.0 follow-on (the original proposal)

| Dimension | Assessment |
|---|---|
| Complexity | High — real rewrite plus two-language maintenance during transition |
| Cost | 8–12 weeks focused engineering, plus equivalence-harness tax |
| Install UX | Excellent (eventually) |
| Transition pain | Real — PyPI deprecation window, CLI flag compat, two docs trees |

**Verdict.** Rejected in favor of Option D. The equivalence harness, the `--use-legacy` flag, the PyPI deprecation window, and the parallel release pipelines were all solving problems we only have because we committed to shipping Python v1 first. Cutting that commitment collapses the complexity.

### Option D — Clean-sheet Go rewrite, delay launch (recommended and chosen)

| Dimension | Assessment |
|---|---|
| Complexity | Medium — single-language rewrite, no compatibility harness |
| Cost | 4–6 weeks focused engineering |
| Install UX | Excellent — `curl -L ... -o anvil-scanner && chmod +x` from day one |
| Binary size / startup | ~8–12 MB / ~15 ms |
| Distribution channels | GitHub releases, Homebrew, apt/deb, Docker scratch, Winget (future) |
| Supply-chain story | Strong — `go.sum`, SLSA attestations, cosign signatures, reproducible builds via goreleaser |
| Transition pain | None — Python was never public |

**Pros.** Single static binary per `GOOS/GOARCH`. Native cross-compile from one build host. Goreleaser + cosign + GitHub attestations is the industry-standard release pipeline. `os/exec`, `io/fs`, `path/filepath.Glob`, `html/template` map 1:1 to what the scanner actually does. Stronger security posture for a security tool (no interpreter attack surface, no `pickle`, no transitive pip supply chain). Compiler catches a whole class of bugs Python misses at runtime. No equivalence harness — the Python tests are the spec, not a regression oracle. No two-language maintenance window. Users never see Python.

**Cons.** The 4–6 week window is pessimistic about parallelism and optimistic about nothing going wrong. Likely actual range is 5–8 weeks. Launch slips vs original v1.0.0 plan. Loss of REPL iteration speed. No official Anthropic Go SDK as of the planning date — we'll call the HTTP API directly (~150 LOC).

---

## Trade-off Analysis

**Why Go specifically, not Rust?** Go wins on maintainability for a team this size. Rust's safety benefits are larger on memory-bounded workloads or parsers for untrusted input; `anvil-scanner` is a subprocess-driven reporting tool where Go's simpler model pays off in faster onboarding and easier contribution from the OSS community. Rust would also cost 2–4 weeks of team ramp. Go is the right pragmatic answer; Rust is the right answer if this were a kernel module, a network-facing parser, or a long-running daemon handling untrusted inputs in-process. The adjacent ecosystem — trivy, grype, gitleaks, cosign, kube-bench, falco — is overwhelmingly Go, which matters for contribution and for user expectations about tool behavior.

**Why not Zig / Deno / Bun / other?** Ecosystem risk. Go's stdlib + goreleaser + cosign is battle-tested for security-tool distribution. The novelty tax on anything else isn't worth paying for our use case.

**Why delay launch instead of shipping Python v1 + following with Go v2?** Three reasons. First, shipping v1 in a distribution model we've already decided to abandon locks in a user base whose next experience is a migration. Second, the equivalence harness and `--use-legacy` flag that Option C required are pure overhead we avoid by never shipping Python. Third, a launch slip of 4–6 weeks is recoverable; a bad first impression on install UX is not.

**What happens to the Python code?** It moves to `python/` as reference. Tests stay runnable so we can consult them as behavioral spec during the port. Once the Go build passes `docs/porting-checklist.md`, the `python/` tree is deleted in the same commit that tags v1.0.0.

---

## Repo Layout (post-transition)

```
anvil-scanner/                          # repo root = Go module
  go.mod / go.sum
  cmd/
    anvil-scanner/main.go               # CLI entry point
  internal/
    scan/                                # check engine + platform checks
      checks.go                          # CheckBuilder, status/severity types
      ssh.go                             # SSH-000..SSH-043
      macos.go                           # MACOS-001..MACOS-008
      linux.go                           # FW-001..FW-003 + distro specifics
      rpi.go                             # RPI-001..RPI-012
    hardening/                           # policy evaluation
    report/
      html.go                            # html/template, go:embed
      json.go                            # JSON output
      template.html                      # embedded report template
      assets/                            # CSS + scroll-spy JS (go:embed)
    ai/
      provider.go                        # provider interface + precedence
      anthropic.go                       # direct HTTP client
      ollama.go                          # Ollama HTTP client
    threat/                              # CVE feed + advisory matching
    secrets/
      container.go                       # on-disk container format
      backends.go                        # keyring / file / env backends
    openclaw/                            # OpenClaw audit (reference plugin)
    backup/                              # snapshot + restore
    exec/                                # subprocess helpers
  .goreleaser.yml
  .github/workflows/
    go-ci.yml                            # test + vet + staticcheck on PR
    release.yml                          # goreleaser + cosign on tag
  docs/
    adr/
      0001-go-migration.md               # this file
      0002-secrets-container-format.md   # on-disk spec (to be written)
    porting-checklist.md                 # the 37-check spec
    plugin-protocol.md                   # subprocess plugin contract
  python/                                # REFERENCE ONLY, deleted at v1.0.0
    anvil_scanner/                       # current implementation
    tests/                                # 380 tests — the behavioral spec
    requirements.txt
    pytest.ini
  vulndb/                                 # shared vulnerability data (unchanged)
  backend/                                # separate FastAPI service (unchanged)
```

`vulndb/` and `backend/` are separate concerns and are untouched by this transition.

---

## Porting Notes

Detail lives in `docs/porting-checklist.md`; highlights here:

- **`reporting.py` embedded HTML template** → `template.html` + `go:embed`. Scroll-spy JS + CSS port as string literals — no semantic translation needed.
- **`ai_analysis.py` Anthropic SDK** → direct HTTP POST to `/v1/messages`, ~150 LOC including retry and NO_PROVIDER sentinel handling. Preserve Ollama-first precedence: Ollama > CLAUDE_KEY > OPENAI_KEY > GROK_KEY > NONE.
- **Dynamic `add()` helper in `extended_scan`** → `CheckBuilder` struct with typed methods: `.Pass(id, name, detail, sev)`, `.Fail(...)`, `.Warn(...)`, `.Skip(...)`. Cleaner than the Python closure pattern.
- **`_parse_sshd_config()` regex** → `regexp` package, same patterns.
- **SSH gating** — the `ssh_enabled` gate (Darwin + remote_login_enabled=False ⇒ all SSH checks skipped, including SSH-041/042/043 file permissions) is the highest-impact behavioral contract to preserve. `python/tests/test_refactor_guardrails.py::TestSshChecksSkippedWhenDisabled` is the spec.
- **FileVault is WARN, not FAIL** — severity medium, downgraded 2026-04-19. Does not promote to Priority Findings.
- **Priority Findings filter** — `status ∈ {FAIL, WARN}` AND `severity ∈ {critical, high}`. Medium never promotes.
- **`run_cmd()` subprocess wrapper** → `exec.CommandContext` with same timeout/stdout/stderr/returncode shape.

---

## Plugin Protocol

Subprocess plugins over a JSON-stdio contract:

```
anvil-scanner → spawns → /usr/local/share/anvil-scanner/plugins/<name>
stdin:  JSON { "platform": "Darwin", "scan_result": {...} }
stdout: JSON { "checks": [{"id":"...","status":"PASS",...}, ...] }
```

Why subprocess and not Go plugins (`.so`)? Go's `plugin` package is Linux-only in practice, doesn't work cross-version, and complicates cross-compilation. Subprocess wins on three dimensions: (1) plugins can be written in any language, (2) plugin crashes can't take down the scanner, (3) each plugin binary can be signed independently. Protocol overhead is negligible for a tool that invokes plugins a handful of times per run.

OpenClaw becomes the reference plugin — a small Go binary that replaces `openclaw_audit.py`, shipped alongside the main binary in the same release. The plugin protocol is specified in `docs/plugin-protocol.md` (to be written before OpenClaw is ported).

---

## Consequences

### What becomes easier

- **Install UX from day one.** `brew install anvil-scanner` or `curl -L ... | sh`. No Python, no venv, no dependency resolution. This is the motivating change.
- **Release pipeline.** Goreleaser produces signed darwin-arm64, darwin-amd64, linux-amd64, linux-arm64 binaries plus Homebrew tap updates in one `git tag` → CI run.
- **Startup latency.** ~300ms → ~15ms matters for users who run the tool in CI or pre-commit hooks.
- **Cross-compilation.** Users can embed `anvil-scanner` in a Docker scratch image or a GitHub Action runner trivially.
- **Security posture.** No interpreter, no pip supply chain, attestable builds, reproducible builds.
- **Contribution surface.** Go's strict formatting + stdlib-heavy style lowers the review bar for OSS contributions. Most adjacent security tool contributors already know Go.
- **No two-language maintenance.** Everything we'd have to keep coherent during a migration (docs, tests, CLI flags, report format) is only ever in one language.

### What becomes harder

- **Iteration speed during development.** Compile cycle vs Python's REPL. Mitigated by `go test -run` and `go run`.
- **AI path.** We maintain our own Anthropic HTTP client. Low cost but it's a thing.
- **Dynamic config.** Any place the Python version uses reflection or dict-shaped data must move to `struct` types — generally an improvement but a rewrite cost.
- **Launch date.** Slips 4–6 weeks (realistic: 5–8).

### What we'll need to revisit

- **Plugin API stability.** Once we commit to the subprocess JSON protocol, changes become breaking for any external plugin authors. Plan a v1 plugin protocol freeze before GA.
- **Secrets container format.** The on-disk format is a forward-compatibility promise once we ship. ADR-0002 specifies the wire format before `secrets/` is ported.
- **HTML report structure.** The scroll-spy subnav and priority-findings section have specific DOM expectations encoded in `python/tests/test_refactor_guardrails.py::TestReportRedesignSubnavAndScrollSpy`. Port these as Go template snapshot tests.

---

## Phased Plan

### Phase 0 — Transition (this week)

- Move Python to `python/` subdirectory.
- Scaffold Go module at repo root: `go.mod`, `cmd/anvil-scanner/main.go`, `internal/<pkg>/doc.go` stubs, `.goreleaser.yml` stub.
- Update `.gitignore` for Go artifacts.
- Update `README.md` with the transition explanation.
- Python CI stays green against `python/` paths so the spec tests keep running.

### Phase 1 — Go foundation (week 1)

- `internal/exec/` subprocess wrapper with `CommandContext` + timeout.
- `internal/scan/` check builder + status/severity types + result aggregation.
- `cmd/anvil-scanner/` argparse equivalent via `flag` or `cobra`.
- Unit tests for the check builder.
- CI: `go test ./...`, `go vet`, `staticcheck`, `gosec`. Matrix: darwin-arm64, darwin-amd64, linux-amd64, linux-arm64.

### Phase 2 — Platform checks (weeks 2–3)

- `internal/scan/ssh.go` — the largest and most tested surface. SSH gating contract is the single most important behavior to preserve.
- `internal/scan/macos.go` — MACOS-001 through MACOS-008.
- `internal/scan/linux.go` — FW-001 through FW-003, distro-specific checks.
- `internal/scan/rpi.go` — RPI-001 through RPI-012.
- `internal/hardening/` — policy evaluation.

### Phase 3 — Report + AI + ancillaries (weeks 4–5)

- `internal/report/` HTML + JSON, including sticky subnav + scroll-spy + priority findings.
- `internal/ai/` Anthropic HTTP + Ollama + provider precedence + NO_PROVIDER loud-failure banner.
- `internal/threat/` CVE feed parsing + advisory matching.
- `internal/secrets/` after ADR-0002 is written.
- `internal/openclaw/` as reference plugin.
- `internal/backup/` snapshot + restore.

### Phase 4 — v1.0.0 GA (week 6)

- Porting checklist fully green.
- Release pipeline signs + notarizes macOS builds, produces SLSA attestations.
- Homebrew tap live. Apt repo live.
- Delete `python/` tree. Tag `v1.0.0`.

---

## Action Items

1. [x] Move Python to `python/` subdirectory. (done Phase 0)
2. [x] Scaffold Go module at repo root with `go.mod`, `cmd/`, `internal/` stubs. (done Phase 0)
3. [ ] Open `docs/adr/0002-secrets-container-format.md` before porting `secrets.py` — pin the on-disk format.
4. [ ] Author `docs/plugin-protocol.md` before OpenClaw is ported — avoid locking in an accidental protocol.
5. [ ] Set up goreleaser + cosign signing in Phase 1 alongside foundation work — validate the release pipeline before we need to depend on it.
6. [ ] Keep `python/` CI job green throughout the port so the behavioral spec stays executable.
7. [ ] Delete `python/` in the same commit that tags `v1.0.0`.

---

## References

- Porting checklist: `docs/porting-checklist.md` — 37 check IDs + ancillary features
- Reference Python source: `python/anvil_scanner/` (6,722 LOC, 11 modules)
- Reference test suite: `python/tests/` (380 tests as of 2026-04-21) — behavioral spec
- Related follow-on: `docs/adr/0002-secrets-container-format.md` (to be written) — on-disk format
- Related follow-on: `docs/plugin-protocol.md` (to be written) — subprocess plugin contract
- Launch plan: `OSS_COMMERCIAL_PLAN.md` (needs revision to reflect slipped date + Go-only distribution)
