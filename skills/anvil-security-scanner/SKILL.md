---
name: anvil-security-scanner
description: Host security scanning, OpenClaw-specific auditing, and automated hardening for OpenClaw deployments. Includes upcoming container scanning for OpenClaw images.
version: 0.1.0
metadata:
  openclaw:
    requires:
      bins:
        - docker
    emoji: "🛡️"
    homepage: https://github.com/Anvil-Cloud-AI/anvil-scanner
    description: |
      Professional-grade security scanner and hardening tool purpose-built for people running OpenClaw.

      Key capabilities:
      - Deep host security scanning (SSH, firewall, services, updates, etc.)
      - Native integration with `openclaw security audit` — surfaces OpenClaw findings in the same report
      - Container security auditing specifically for OpenClaw containers (privileged mode, port exposure, mounts, etc.)
      - One-command hardening (`--harden`) for SSH crypto, firewalls, and fail2ban
      - Full backup + `--uninstall` so all changes can be safely reverted
      - Optional AI risk analysis (local Ollama or cloud providers)
      - Threat intelligence (Shodan, AbuseIPDB, CISA KEV, local IoCs)

      Especially valuable for OpenClaw users because it understands OpenClaw's container model and can audit the actual containers your agents run in.

      Container scanning support is actively being expanded.
---

# Anvil Scanner — Security for OpenClaw

**Anvil Scanner** is a standalone, security-first CLI tool designed for OpenClaw operators who want visibility and control over the security of their hosts and containers.

## When to use this skill

Use this when the user wants to:
- Understand the security posture of the machine running OpenClaw
- Audit the security of OpenClaw containers themselves
- Apply safe, reversible hardening to SSH, firewalls, or fail2ban
- Get a combined view of traditional host security + OpenClaw-specific findings
- Have a professional security report (HTML + JSON) with optional AI analysis

## Core Commands

```bash
# Full security scan (recommended)
sudo anvil-scanner

# Scan without AI analysis
sudo anvil-scanner --no-ai

# Apply hardening (SSH ciphers, firewall rules, fail2ban, etc.)
sudo anvil-scanner --harden

# Revert all changes made by anvil-scanner
sudo anvil-scanner --uninstall

# Schedule regular scans
anvil-scanner --schedule
```

## OpenClaw Integration

Anvil Scanner automatically:
1. Runs `openclaw security audit --json` (if OpenClaw is installed)
2. Correlates those findings with CVEs and threat intel
3. Performs additional container-level checks on any running `ghcr.io/openclaw/openclaw` containers (privileged mode, exposed ports, sensitive mounts, etc.)

**Container scanning is a major focus area** and is actively being expanded.

## Output

- Beautiful HTML report (great for sharing or archiving)
- Machine-readable JSON
- Optional AI-generated risk narrative and prioritized recommendations

## Important Notes for Agents

- Most powerful operations require `sudo`.
- Always recommend the user reviews the HTML report.
- The tool has excellent `--uninstall` support — changes are safe to experiment with.
- It follows very strict security practices itself (explicit command arguments, no shell injection, bounded I/O, SSRF-safe networking).

## Installation

See the official releases: https://github.com/Anvil-Cloud-AI/anvil-scanner/releases

Pre-built static binaries are available for macOS (Intel + Apple Silicon) and Linux (amd64 + arm64).

---

**This skill exists to help OpenClaw users discover and effectively use Anvil Scanner as a companion security tool.**