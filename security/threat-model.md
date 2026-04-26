# Threat Model

What anvil-scanner defends against, what it explicitly does not, and what it trusts. This document is the canonical answer to "is anvil-scanner enough?" — the honest answer is "for these threats, yes; for these others, no, and here's what you'd pair it with."

## What anvil-scanner is

A defensive security scanner and hardening tool that runs on Linux and macOS hosts (including Raspberry Pi), targeting OpenClaw deployments and general system posture. It scans the host, queries advisory feeds, correlates findings with the in-tree vulnerability database, and produces an HTML report plus actionable fix suggestions. It optionally applies hardening changes (SSH config, packet filter rules, file permissions) under explicit user control.

It runs as an unprivileged process by default. Hardening actions that require root prompt for elevation and are always atomic (temp-file + rename).

## In-scope threats

These are the threats anvil-scanner is designed to catch and either report, fix, or flag for the operator.

### Host posture drift
- Missing or weak SSH configuration (password auth enabled, root login allowed, weak MACs / KEXes).
- World-writable system config files, weak permissions on secrets directories.
- Firewall rules that expose services to the public internet unintentionally.
- Container runtimes with insecure defaults (privileged containers, mounted docker socket, host networking where not needed).

### Vulnerable software
- OpenClaw versions with known CVEs present in `vulndb/openclaw-gateway.json`.
- System packages with upstream CVE disclosures matched against installed versions.
- Dependency CVEs in anvil-scanner's own `requirements.txt` (caught by pip-audit in CI, not at runtime on the target host).

### Indicators of compromise (best-effort)
- Suspicious files in well-known staging paths (`/tmp`, `/dev/shm`, `/var/tmp`, user home caches).
- Services bound to all interfaces that are typically loopback-only.
- Known-bad IPs in active connections cross-referenced against AbuseIPDB / CISA KEV / Shodan InternetDB.

IoC detection is best-effort and intentionally conservative — we optimize for low false-positive rate over recall. See "What we don't claim" below.

### Anvil-secure's own attack surface
- Command injection via subprocess — prevented by list-form arguments and `shell=False` everywhere.
- SSRF via the Ollama integration — prevented by a loopback-only URL allowlist.
- XSS in HTML reports — prevented by `html.escape()` on every external-data field.
- Path traversal in backup / restore — prevented by source-inside-session and destination-in-managed-prefix validation.
- TOCTOU on config-file writes — prevented by temp + rename with fsync.
- Secret exposure — secrets never written to plaintext on disk; keyring, encrypted file, or env var only.

Every push through CI gates on bandit, ruff `--select S`, pip-audit, detect-secrets, and pytest with zero un-suppressed high-severity findings as the release bar. See [scanners.md](scanners.md).

## Out of scope — what anvil-scanner does not protect against

Being explicit here is a feature, not a hedge. If any of the following match your threat model, you need controls that anvil-scanner does not provide.

### Active adversary already on the host
If an attacker has persistent root on the target at scan time, they can tamper with the kernel, with `/proc`, with command output, with the vulndb files, or with anvil-scanner itself before or during the scan. We trust the host we're scanning. Mitigations you'd layer on: immutable boot, secure boot, remote attestation, out-of-band scanning from a known-good management host.

### Kernel-level rootkits and firmware implants
Out of scope by design. We scan userspace. Kernel modules, UEFI implants, SMM payloads, and baseband-level compromise are not detectable by anvil-scanner and we make no claim otherwise.

### Zero-days and unpublished advisories
We match against `vulndb/` (refreshed from published feeds) and upstream advisory databases. A vulnerability that has not been disclosed cannot be in either. The value we provide is fast, correct correlation of *public* advisories against a host's actual software inventory.

### Supply-chain attacks on dependencies
pip-audit catches CVEs in what we pin. It does not catch typosquats, compromised upstream accounts that haven't been reported, or build-time tampering. SBOMs and signed release artifacts (roadmap) narrow this, but we do not claim full supply-chain defense.

### Physical access
Evil-maid attacks, cold-boot attacks, JTAG, BMC compromise — out of scope. Full-disk encryption and physical controls are the right layer.

### Active network adversary
We assume TLS endpoints are who they claim to be via the system trust store. If you need to defend against state-level MITM on advisory-feed traffic, you want a stronger pinning / transparency-log strategy than we currently implement.

### Application-layer vulnerabilities in OpenClaw itself
We scan *for* OpenClaw CVEs by version correlation. We do not pentest a running OpenClaw deployment. That's a different class of tool and a different authorization model.

### The commercial backend and dashboard
The open-source scanner in this repository is one component. The managed backend API, the web dashboard, and the desktop app are separate products under separate threat models documented privately. Security reports against those are welcome via the same disclosure channel; routing is handled internally.

## Trust assumptions

anvil-scanner trusts:

- **The host operating system.** The kernel, libc, and core utilities report accurate state. If they lie, we lie.
- **The Python interpreter.** We trust CPython's standard library behaviors — `ssl.create_default_context()` returns a properly configured context, `subprocess.run(..., shell=False)` doesn't interpret a shell, `html.escape()` escapes the five dangerous characters.
- **Signed release artifacts.** Users who install from source and skip signature verification get the posture they configure. We document the verification step for every release.
- **Advisory feeds over TLS** with the system trust store (CISA KEV, Shodan InternetDB, AbuseIPDB, GitHub Security Advisories, PyPI advisories). We do not pin certificates for these sources today.
- **The user's decision to elevate.** Hardening actions that require `sudo` are opt-in and display what they'll change before executing. We trust the operator to review.
- **The in-tree `vulndb/` contents.** The files are reviewable at commit time; this is their integrity story today. Signed advisory bundles are on the roadmap.

## What we don't claim

- We don't claim zero false positives — IoC detection in particular trades recall for precision, and real intrusions have patterns that only look suspicious in context.
- We don't claim zero false negatives — scanning is a sampling operation; "anvil-scanner found nothing" is not the same as "there's nothing to find."
- We don't claim completeness across operating systems — Linux and macOS (including Raspberry Pi) are our supported targets. Windows, BSDs, and embedded RTOSes are not supported today.
- We don't claim defense against novel or targeted attacks. The scanner catches what it knows how to look for.

## Data handling

- **Telemetry:** The open-source scanner does not phone home by default. Any outbound network traffic from a scan originates from explicit advisory-feed lookups (CISA KEV, Shodan InternetDB, AbuseIPDB, GitHub Security Advisories) or from the optional AI analysis integration (Anthropic API or a user-configured local Ollama endpoint).
- **Report files:** HTML reports and JSON scan artifacts are written under a session directory with `0700` ownership. They may contain hostnames, IP addresses, file paths, installed-package lists, and any IoC matches. They do not contain secrets read from keyring storage.
- **AI analysis (optional):** If enabled, the scan summary is sent to the configured LLM endpoint. The summary redacts absolute paths and obvious hostnames before transmission. Users opting in should treat the LLM endpoint as a data-processing subcontractor and configure accordingly.
- **Secrets:** API keys and tokens are stored via OS keyring (GNOME Keyring, macOS Keychain), an encrypted file at rest, or an environment variable. Never plaintext on disk. See [README.md](README.md) for the full list.

## When the model changes

Threat models age. Add an entry to [audit-log.md](audit-log.md) whenever:

- A new threat moves from out-of-scope to in-scope (feature addition).
- A trust assumption is narrowed or broadened (e.g., advisory-feed signing is added — trust narrows).
- A previously-silent assumption is discovered and documented.

We'd rather admit the shape of the model than let it drift in silence.

## Related docs

- [README.md](README.md) — Folder index and posture summary.
- [scanners.md](scanners.md) — What runs on every push.
- [disclosure-policy.md](disclosure-policy.md) — How to report a vulnerability, SLA, safe harbor.
- [audit-log.md](audit-log.md) — Running record of scan results.
