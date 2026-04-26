# Vulnerability Disclosure Policy

How to report a security vulnerability in anvil-scanner, what happens after you do, and the safe-harbor commitments we make to good-faith researchers.

## Report a vulnerability

**Email:** security@anvilcloud.ai

**GitHub:** The Security tab on this repository accepts private advisory reports via GitHub Security Advisories. This is the preferred channel because it keeps the conversation in one place and automates GHSA publication.

**Do not** file a public GitHub issue for a suspected security vulnerability. Public issues are indexed immediately, which is bad for everyone.

### What to include

A good report contains:

- A clear description of the vulnerability and the affected version(s) / commit SHA.
- Steps to reproduce — minimal proof-of-concept is ideal. A command-line invocation or a sanitized input file beats a paragraph of description.
- Impact: what can an attacker do, and what preconditions do they need?
- Your name or handle as you'd like it to appear in the advisory, or a note that you'd prefer to remain anonymous.

Reports in any language are accepted; we'll respond in English.

## What happens next

We commit to the following SLA for reports sent to `security@anvilcloud.ai` or filed via GitHub Security Advisories:

| Stage                                | Target                                     |
| ------------------------------------ | ------------------------------------------ |
| Initial acknowledgement              | Within 48 hours                            |
| Triage and severity assessment       | Within 5 business days                     |
| Fix for CRITICAL-severity issues     | Within 7 days of triage                    |
| Fix for HIGH-severity issues         | Within 30 days of triage                   |
| Fix for MEDIUM- and LOW-severity     | Next regular release cycle                 |
| Public advisory (GHSA) publication   | Coordinated with reporter, at or after fix |

If we can't meet these targets — because the issue is deep, or the fix is risky, or we need to coordinate with upstream — we'll tell you why and propose a revised timeline. Silence is not a disclosure strategy.

## Severity

We use CVSS 3.1 for severity scoring and publish the vector in every advisory. The qualitative bands we use:

- **CRITICAL** — Remote unauthenticated code execution, credential exfiltration, or full bypass of a core security control (subprocess sandboxing, secret storage, TLS validation, path validation).
- **HIGH** — Authenticated RCE, privilege escalation within the tool's own process model, or exposure of material user data.
- **MEDIUM** — Logic bugs that weaken a security claim without immediately breaking it, or DoS with meaningful impact.
- **LOW** — Hardening improvements, minor information disclosure with no user-data impact, edge-case misbehavior.

## Scope

**In scope** — the code shipped in this repository:

- `anvil_scanner/` — scanner, hardening, reporting, CLI.
- `vulndb/` — in-tree CVE and advisory data, updater script, signing verification.
- Release artifacts (signed tarballs / wheels published from this repo).
- Documentation and examples that could mislead users into an insecure configuration.

**Out of scope:**

- Anvil Cloud AI's commercial products (backend API, dashboard, desktop app) — report those via the same email; we'll route internally.
- Third-party dependencies — report upstream first. If the dependency is pinned in `requirements.txt` and the fix requires our action, we still want to know.
- Social engineering of Anvil Cloud AI staff, physical attacks, and DoS against infrastructure we don't own.
- Findings from automated scanners with no demonstrated impact path — please include a working proof-of-concept.
- Missing security headers on marketing pages, SPF / DMARC configuration on non-production domains, and similar low-impact issues on ancillary properties.

If you're unsure whether something is in scope, email us and ask. Being wrong in good faith does not forfeit safe harbor.

## Safe harbor

We will not pursue legal action, pursue administrative action (including DMCA takedowns), or support law-enforcement action against researchers who:

- Make a good-faith effort to avoid privacy violations, service disruption, and destruction of data.
- Report the vulnerability promptly and do not exploit it beyond what's necessary to demonstrate impact.
- Give us reasonable time to fix before public disclosure, per the SLA above.
- Do not access, modify, or exfiltrate data that isn't your own. Test against your own deployment of anvil-scanner.

Testing techniques that are explicitly *not* authorized under this safe harbor:

- Denial-of-service testing against Anvil Cloud AI infrastructure or other users.
- Automated vulnerability scanning against hosts you don't own, even if anvil-scanner itself would scan them.
- Social engineering of Anvil Cloud AI employees, contractors, or customers.
- Physical access attempts against Anvil Cloud AI facilities.

This policy is adapted in spirit from [disclose.io's core terms](https://disclose.io/). We are not currently affiliated with or certified by disclose.io, but we aim to be consistent with their norms.

## Recognition

We do not currently run a paid bug bounty.

We do maintain a thank-you section in each GHSA advisory and in the release notes of the version that fixes the reported issue. If you'd prefer no public credit, tell us in the report and we'll leave you out.

## Coordinated disclosure

We'll coordinate public disclosure with you. Our default flow:

1. Fix lands in `main` and is cut into a patch release.
2. GHSA advisory is drafted privately and shared with the reporter for accuracy review.
3. On the agreed-upon publication date — usually the release date or shortly after — the GHSA goes public and a CVE is requested through GitHub's CNA.
4. The release notes link to the advisory; the `audit-log.md` entry links both.

If you need a specific embargo window (e.g., you're presenting the finding at a conference), tell us as early as possible. We'll do our best to align.

## Encryption

If you need to send sensitive details encrypted, ask for our current PGP key in your initial email and we'll respond with the key fingerprint through a second channel. We're a small team; end-to-end encryption isn't the default and we'd rather not pretend otherwise.

## Related docs

- [audit-log.md](audit-log.md) — Where confirmed vulnerabilities get logged as Incident entries once fixed.
- [threat-model.md](threat-model.md) — What we treat as in-scope threats and why.
- [scanners.md](scanners.md) — The automated checks that catch routine issues before they ship.
