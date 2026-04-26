# Scanners

Catalog of every security scanner that runs on anvil-scanner, what it checks, where it's configured, and how to reproduce each check locally.

If you just want the one-shot command to reproduce CI on your laptop, skip to [Reproduce CI locally](#reproduce-ci-locally).

## What runs on every push

| Scanner        | Purpose                                     | Config / Workflow                                                       | Blocks merge on                          |
| -------------- | ------------------------------------------- | ----------------------------------------------------------------------- | ---------------------------------------- |
| `go test`      | Full test suite (Ubuntu + macOS matrix)     | [`.github/workflows/go-ci.yml`](../.github/workflows/go-ci.yml) `build` job | Any test failure                     |
| `go vet`       | Standard Go static analysis                 | [`.github/workflows/go-ci.yml`](../.github/workflows/go-ci.yml) `build` job | Any vet finding                      |
| staticcheck    | Extended static checks beyond `go vet`      | [`.github/workflows/go-ci.yml`](../.github/workflows/go-ci.yml) `lint` job  | Any finding                          |
| gosec          | Go SAST — insecure patterns, subprocess use, TLS | [`.github/workflows/go-ci.yml`](../.github/workflows/go-ci.yml) `gosec` job | Any finding (SARIF uploaded)        |
| govulncheck    | Go vulnerability database scan              | [`.github/workflows/go-ci.yml`](../.github/workflows/go-ci.yml) `govulncheck` job | Any known vulnerable module    |
| semgrep        | SAST with `p/golang`, `p/owasp-top-ten`, `p/secrets` | [`.github/workflows/go-ci.yml`](../.github/workflows/go-ci.yml) `semgrep` job | Any finding (SARIF uploaded, `continue-on-error`) |
| Dependabot     | Go module + GitHub Actions advisory monitor | [`.github/dependabot.yml`](../.github/dependabot.yml)                  | N/A — opens PRs, doesn't gate           |

The `build`, `lint`, `gosec`, `govulncheck`, and `semgrep` jobs are all defined in [`.github/workflows/go-ci.yml`](../.github/workflows/go-ci.yml). SARIF results from gosec and semgrep are uploaded to the GitHub Security tab via `github/codeql-action/upload-sarif`.

## Reproduce CI locally

One-shot block — run from repo root:

```bash
# 1. Install scanners (first time only)
go install honnef.co/go/tools/cmd/staticcheck@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
# semgrep requires Python: pip install semgrep

# 2. Run the same checks CI runs
go test ./...
go vet ./...
staticcheck ./...
gosec -fmt sarif -out gosec.sarif ./...
govulncheck ./...
semgrep ci --sarif --output semgrep.sarif \
  --config p/golang --config p/owasp-top-ten --config p/secrets
```

If all commands exit 0, you'd pass the push-time gates. SARIF uploads are GitHub-side only.

## Per-scanner detail

### go test

Runs the full test suite on every push across Ubuntu and macOS. Security-relevant test coverage includes subprocess arg-list enforcement, HTML escaping, path traversal guards, TOCTOU-safe writes, SSRF validators, and secrets container round-trips.

- **Run:** `go test ./...`
- **Race detection:** Run locally with `go test -race ./...` for extra coverage.

### go vet

Standard Go static analyzer built into the toolchain. Catches suspicious constructs: misuse of `sync/atomic`, incorrect format strings, unreachable code, etc.

- **Run:** `go vet ./...`

### staticcheck

Extended static analysis from `honnef.co/go/tools`. Goes beyond `go vet` with checks for deprecated API usage, unnecessary type conversions, unreachable code paths, and style issues that indicate bugs.

- **Install:** `go install honnef.co/go/tools/cmd/staticcheck@latest`
- **Run:** `staticcheck ./...`
- **Inline suppression:** `//nolint:staticcheck // <one-line rationale>` on the offending line. Rationale is mandatory.

### gosec

Go-specific SAST that scans the AST for known-insecure patterns: subprocess calls with `shell=true`, hardcoded credentials, weak hash functions, insecure TLS configs, G104 (unhandled errors), path traversal, etc.

- **Workflow job:** `gosec` in `.github/workflows/go-ci.yml`
- **Run:** `gosec -fmt sarif -out gosec.sarif ./...`
- **Output:** SARIF file uploaded to GitHub Security tab.
- **Inline suppression:** `// #nosec G<ID> -- <rationale>` on the offending line. Rationale is mandatory — no bare `#nosec`.

### govulncheck

Scans the module graph and call graph against the Go vulnerability database (`vuln.go.dev`). Only reports vulnerabilities in packages that are actually called, not just imported transitively.

- **Workflow job:** `govulncheck` in `.github/workflows/go-ci.yml`
- **Run:** `govulncheck ./...`
- **Fail condition:** Any known vulnerability in a transitively-reachable call path.
- **Remediation:** Bump the module version in `go.mod` / `go.sum` to a non-vulnerable version, re-run govulncheck, re-run the full test suite.

### semgrep

SAST with three rulesets:
- `p/golang` — Go-idiomatic patterns (nil checks, defer misuse, goroutine leaks)
- `p/owasp-top-ten` — OWASP Top 10 categories
- `p/secrets` — hard-coded API keys, tokens, credentials

- **Workflow job:** `semgrep` in `.github/workflows/go-ci.yml` (runs in `semgrep/semgrep` container)
- **Run:** `semgrep ci --sarif --output semgrep.sarif`
- **`continue-on-error`:** `true` — semgrep findings are surfaced via SARIF but don't hard-block the workflow at this time. Triage findings under the Security tab.
- **Output:** SARIF file uploaded to GitHub Security tab.

### Dependabot

Opens PRs against `go.mod` (Go modules) and workflow `actions/` pins when upstream advisories land. Does not block anything by itself; govulncheck is the gate for vulnerability regressions.

- **Config:** [`.github/dependabot.yml`](../.github/dependabot.yml)

## Interpretation guide

**Before suppressing any finding:**

1. Reproduce locally so you understand what triggered it.
2. Write out the rationale in plain prose before choosing a suppression syntax. If the rationale is hard to write, the finding is probably real.
3. Prefer narrow suppressions: a single-line `// #nosec G<ID> -- rationale` beats a file-wide or package-wide skip.
4. Put the comment *on* the suppressed line — never below, never elsewhere in the file.

**When a scanner is wrong:**

Scanners produce false positives. That's expected. But the right response is always (a) document why it's wrong with a rationale comment, (b) prefer the narrowest suppression, (c) mention it in the next `audit-log.md` entry if it's a pattern worth remembering. Never silently widen a skip list.

**When findings should escalate:**

If a scan catches something that was previously suppressed, unsuppress it and re-triage from scratch — scanner rules and the code around a suppression both evolve. Old rationale comments are hypotheses, not proofs.

## Related docs

- [audit-log.md](audit-log.md) — Running record of scan results by release.
- [disclosure-policy.md](disclosure-policy.md) — How to report a vulnerability that slipped past these scanners.
- [threat-model.md](threat-model.md) — What these scanners can and can't catch.
