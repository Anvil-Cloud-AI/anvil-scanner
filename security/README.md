# Security

This folder documents anvil-scanner's security practices, scan history, and disclosure process.

Anvil-Secure is a defensive security scanner and hardening tool. Because it makes security claims about *other* systems, it holds itself to the same standard: every push runs through bandit SAST, ruff S-category lint, pip-audit, detect-secrets, and pytest; results are logged in [audit-log.md](audit-log.md) with zero high-severity findings as the release gate.

## Contents

- **[audit-log.md](audit-log.md)** — Running ledger of scan results and external security reviews. Each release and periodic re-scan gets an entry, newest first.
- **[scanners.md](scanners.md)** — What runs on every push and the exact commands to reproduce each check locally.
- **[disclosure-policy.md](disclosure-policy.md)** — How to responsibly report a vulnerability. Contact, SLA, scope, safe-harbor language.
- **[threat-model.md](threat-model.md)** — What anvil-scanner defends against, what it explicitly does not, and what it trusts.

## Reporting a vulnerability

Email: **security@anvilcloud.ai**

Please do *not* file a public GitHub issue for security vulnerabilities. GitHub's Security tab on this repository also accepts private advisory reports.

Full policy, SLA, and safe-harbor terms: [disclosure-policy.md](disclosure-policy.md).

## Posture

- All subprocess calls use list-form arguments with `shell=False`; no user-controlled shell interpolation.
- All external data rendered in HTML reports passes through `html.escape()`.
- Release artifacts are signed (Ed25519); verification steps are published alongside each release.
- Dependencies are pinned in `requirements.txt`; `pip-audit` runs on every push and blocks merges on CRITICAL/HIGH CVEs.
- Secrets are never stored in plaintext on disk: keyring (GNOME Keyring / macOS Keychain), encrypted file, or environment variable only.
- The vulnerability database shipped in `vulndb/` is in-tree and reviewable; live updates will be signed bundles (roadmap).

For the full trust model, see [threat-model.md](threat-model.md).
