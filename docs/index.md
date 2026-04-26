# Anvil-Secure Hardening Guides

Plain-English security guides for every check category. Each guide explains *why* a setting matters and gives step-by-step instructions to fix it — no security expertise required.

---

## Guides

| Guide | Description |
|-------|-------------|
| [SSH Hardening](ssh-hardening.md) | Secure your SSH server: authentication limits, encryption settings, key/file permissions, and a complete hardened sshd_config example |
| [Kernel Hardening](kernel-hardening.md) | Linux kernel sysctl settings for network attack prevention, ASLR, and restricting information leakage — includes a complete sysctl.conf snippet |
| [Filesystem Security](filesystem-security.md) | Secure /tmp mounts, find world-writable files, audit SUID/SGID binaries, and set safe default umask values |
| [User & Auth Hardening](user-auth-hardening.md) | Fix empty passwords, remove rogue root accounts, enforce password aging and complexity with PAM, and set up account lockout |
| [macOS Hardening](macos-hardening.md) | macOS-specific guide: SIP, FileVault, Gatekeeper, Application Firewall, Remote Login, screen sharing, and firmware password |
| [Fail2ban Setup](fail2ban-setup.md) | Install and configure fail2ban to automatically block brute-force attacks on SSH and OpenClaw — includes exact jail configs |
| [OpenClaw Security](openclaw-security.md) | Secure your OpenClaw deployment: block ports with ufw, set up an nginx reverse proxy, use encrypted secrets, and API key best practices |
| [OpenClaw Plugin Protocol](plugin-protocol.md) | How anvil-scanner integrates with OpenClaw: subprocess protocol, JSON finding schema, install-channel detection, severity mapping, and report integration |

---

## Quick Reference: Check ID to Guide

| Check IDs | Guide |
|-----------|-------|
| SSH-006 through SSH-043 | [SSH Hardening](ssh-hardening.md) |
| KERN-001 through KERN-011 | [Kernel Hardening](kernel-hardening.md) |
| FS-001 through FS-005 | [Filesystem Security](filesystem-security.md) |
| AUTH-001 through AUTH-005 | [User & Auth Hardening](user-auth-hardening.md) |
| MACOS-001 through MACOS-008 | [macOS Hardening](macos-hardening.md) |

For OpenClaw configuration checks, anvil-scanner delegates to OpenClaw's own
`openclaw security audit --json` and surfaces the findings verbatim. Each
finding includes remediation text sourced from OpenClaw; for deeper guidance
see the [OpenClaw security docs](https://docs.openclaw.ai/security).

---

## About Anvil-Secure

Anvil-Secure is an open-source security scanner for Linux and macOS systems. It checks hundreds of configuration settings against CIS Benchmarks and other industry standards, then generates a prioritized report with specific recommendations.

- [GitHub Repository](https://github.com/Anvil-Cloud-AI/anvil-scanner)
- [README](../README.md)
