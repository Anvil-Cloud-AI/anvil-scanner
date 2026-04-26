# Scanners

Catalog of every security scanner that runs on anvil-scanner, what it checks, where it's configured, and how to reproduce each check locally.

If you just want the one-shot command to reproduce CI on your laptop, skip to [Reproduce CI locally](#reproduce-ci-locally).

## What runs on every push

| Scanner          | Purpose                                | Config                                                        | Blocks merge on                    |
| ---------------- | -------------------------------------- | ------------------------------------------------------------- | ---------------------------------- |
| bandit           | Python SAST (AST pattern rules)        | [`.bandit`](../.bandit)                                       | Any medium+ severity finding       |
| ruff `--select S` | Security lint (flake8-bandit ruleset)  | [`pyproject.toml`](../pyproject.toml) `[tool.ruff.lint]`      | Any un-suppressed S-rule finding   |
| pip-audit        | Dependency CVE check                   | [`requirements.txt`](../requirements.txt) (pinned)            | Any HIGH or CRITICAL CVE           |
| detect-secrets   | Secret scanner (delta vs. baseline)    | [`.secrets.baseline`](../.secrets.baseline)                   | Any secret not already in baseline |
| pytest           | Unit + integration tests               | [`pytest.ini`](../pytest.ini)                                 | Any test failure                   |
| CodeQL           | Semantic dataflow (GitHub-hosted)      | [`.github/workflows/codeql.yml`](../.github/workflows/codeql.yml), `security-extended` | Any finding in `security-extended` query pack |
| Dependabot       | Upstream advisory monitor              | [`.github/dependabot.yml`](../.github/dependabot.yml)         | N/A — opens PRs, doesn't gate      |

The bandit and pip-audit jobs are wired in [`.github/workflows/security.yml`](../.github/workflows/security.yml). CodeQL lives in its own workflow so it can run on its own schedule.

## Reproduce CI locally

One-shot block — run from repo root:

```bash
# 1. Install scanners
pip install bandit ruff pip-audit detect-secrets pytest

# 2. Run the same checks CI runs
bandit -c .bandit -r anvil_scanner vulndb -ll
ruff check --select S anvil_scanner vulndb
pip-audit -r requirements.txt
detect-secrets scan --baseline .secrets.baseline
pytest
```

If all five exit 0, you'd pass the push-time gates. CodeQL runs GitHub-side only; a local approximation is `codeql database create` + `codeql database analyze --format=sarif-latest`, but there's no requirement to reproduce it locally.

## Per-scanner detail

### bandit

Python-specific SAST that scans the AST for known-insecure patterns (subprocess with `shell=True`, hardcoded passwords, weak hashes, insecure SSL contexts, etc.).

- **Config:** [`.bandit`](../.bandit)
- **Run:** `bandit -c .bandit -r anvil_scanner vulndb -ll`
- **Severity filter:** `-ll` means report LOW and above; CI fails on MEDIUM+ via `-ll` plus manual review of LOW.
- **File-wide skips** (in `.bandit`): B108, B104, B310 — each with a rationale comment explaining why the pattern is a scanning target, not a vulnerability. Re-read the `.bandit` header before adding to this list.
- **Inline suppression:** `# nosec B<ID>  # <one-line rationale>` on the offending line. Rationale comment is mandatory — no bare `# nosec`.

### ruff (S-category)

Ruff ships the flake8-bandit rules as the `S` prefix. Faster than bandit and catches a mostly-overlapping but non-identical set.

- **Config:** `[tool.ruff.lint]` in `pyproject.toml`, `select = ["S"]` (plus other lint rules).
- **Run:** `ruff check --select S anvil_scanner vulndb`
- **Inline suppression:** `# noqa: S<ID>  # <rationale>` on the offending line.
- **File-level suppression:** `# ruff: noqa: S<ID>` as the first line of the file, with a header comment explaining why the whole file is exempt (e.g., `cli.py`, `threat_intel.py`, `ai_analysis.py`, `vulndb/update.py` for S310 — all urllib calls validated against allowlists or hard-coded well-known endpoints).
- **Double-suppression:** When bandit *and* ruff both flag a line, both markers go on the same line: `# nosec B310  # noqa: S310  # <rationale>`.

### pip-audit

Cross-references `requirements.txt` pins against the OSV and PyPI advisory databases.

- **Run:** `pip-audit -r requirements.txt`
- **Fail condition:** CI fails on HIGH or CRITICAL CVEs. MEDIUM and below open a follow-up issue but don't block the push.
- **Remediation:** Bump the pin in `requirements.txt` to a non-vulnerable version, re-run pip-audit, re-run the full test suite (dep bumps have caused test failures before). If a fix isn't available upstream, add a justified ignore via `pip-audit --ignore-vuln <ID>` and document the decision in `audit-log.md`.

### detect-secrets

Scans for high-entropy strings and known credential patterns (AWS keys, private keys, JWT tokens, etc.). Uses a committed baseline so only *new* secrets fail CI.

- **Baseline:** [`.secrets.baseline`](../.secrets.baseline)
- **Run (delta scan, what CI does):** `detect-secrets scan --baseline .secrets.baseline`
- **Audit baseline entries:** `detect-secrets audit .secrets.baseline` — interactive tool for marking entries as true or false positives.
- **Update the baseline after a legitimate new false positive:** `detect-secrets scan --baseline .secrets.baseline --update` then `detect-secrets audit .secrets.baseline` to mark the new entry, then commit the updated baseline.

Known documented false positives in the current baseline:

- `/etc/passwd` — scanning-target path, not a password file reference.
- `PasswordAuthentication` — SSH directive name used in test fixtures and hardening checks.
- Docker-compose placeholder strings (`changeme`, `example`) in development-only templates.

If a real secret lands in a commit, rotate the credential first, then patch the repo (either `git filter-repo` for pre-release history or a documented rotation note in `audit-log.md` for post-release).

### pytest

Not a security scanner per se, but the security posture depends on the test suite catching regressions in the hardened code paths (subprocess arg-list enforcement, HTML escaping, path traversal guards, TOCTOU-safe writes, SSRF validators).

- **Run:** `pytest`
- **Coverage targets of note:** `anvil_scanner/reporting.py` (HTML escaping), `anvil_scanner/scanner.py` (subprocess calls, path validation), `anvil_scanner/threat_intel.py` (URL allowlist, CVE matching), `anvil_scanner/keyring_helpers.py` (secret storage).

### CodeQL

GitHub-hosted semantic analysis. Runs the `security-extended` query pack, which includes everything in `security` plus dataflow queries for injection and tainted-data propagation.

- **Workflow:** [`.github/workflows/codeql.yml`](../.github/workflows/codeql.yml)
- **Triggers:** push to `main`, pull requests, weekly schedule.
- **Output:** Alerts appear under the repo's Security tab. Alerts are triaged the same way as any other finding — either fixed, dismissed with `won't fix` and written justification, or marked `false positive` with a comment.

### Dependabot

Opens PRs against `requirements.txt` (and `actions/` versions in workflow files) when upstream advisories land. Does not block anything by itself; pip-audit is the gate.

- **Config:** [`.github/dependabot.yml`](../.github/dependabot.yml)

## Interpretation guide

**Before suppressing any finding:**

1. Reproduce locally so you understand what triggered it.
2. Write out the rationale in plain prose before choosing a suppression syntax. If the rationale is hard to write, the finding is probably real.
3. Prefer narrow suppressions: a single-line `# nosec B<ID>  # rationale` beats a file-wide skip; a file-wide skip beats a global `.bandit` skip.
4. Every global skip added to `.bandit` or file-level `# ruff: noqa` header requires a comment explaining why the entire scope is exempt.
5. Put the comment *above* or *on* the suppressed line — never below, never elsewhere in the file.

**When a scanner is wrong:**

Scanners produce false positives. That's expected. But the right response is always (a) document why it's wrong with a rationale comment, (b) prefer the narrowest suppression, (c) mention it in the next `audit-log.md` entry if it's a pattern worth remembering. Never silently widen a skip list.

**When findings should escalate:**

If a scan catches something that was previously suppressed, unsuppress it and re-triage from scratch — scanner rules and the code around a suppression both evolve. Old rationale comments are hypotheses, not proofs.

## Related docs

- [audit-log.md](audit-log.md) — Running record of scan results by release.
- [disclosure-policy.md](disclosure-policy.md) — How to report a vulnerability that slipped past these scanners.
- [threat-model.md](threat-model.md) — What these scanners can and can't catch.
