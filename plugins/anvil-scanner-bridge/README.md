# Anvil Scanner Bridge Plugin for OpenClaw

This is a native OpenClaw plugin that exposes Anvil Scanner's powerful security and hardening capabilities as first-class tools that OpenClaw agents can call.

## Why this exists

OpenClaw users benefit enormously from strong host and container security visibility. Anvil Scanner is purpose-built for this use case:

- Excellent native integration with `openclaw security audit`
- Dedicated security auditing of OpenClaw containers
- One-command, reversible hardening
- Professional reporting + optional AI analysis

Instead of agents having to tell users "run this CLI tool", this plugin lets agents directly invoke high-value security actions.

## Tools Provided

- `run_security_scan` — Full host + OpenClaw + threat intel scan
- `audit_openclaw_containers` — Focused security checks on running OpenClaw containers
- `apply_hardening` — Apply SSH/firewall/fail2ban hardening (with dry-run support)
- `revert_anvil_changes` — Safely undo all previous hardening changes

## Installation (once published)

```bash
openclaw plugins install @anvil-cloud-ai/anvil-scanner-bridge
```

Or via ClawHub:

```bash
clawhub package install @anvil-cloud-ai/anvil-scanner-bridge
```

## Configuration

Add to your OpenClaw config:

```json
{
  "plugins": {
    "anvil-scanner": {
      "binaryPath": "anvil-scanner",
      "defaultSudo": true,
      "timeoutSeconds": 180
    }
  }
}
```

## Publishing to ClawHub

```bash
clawhub package publish . --dry-run
clawhub package publish .
```

## Status

Early bridge implementation. The long-term vision is tighter integration (possibly native Rust/Go components or direct library usage).

Container scanning improvements in the main Anvil Scanner project will directly benefit this plugin.
