# anvil-security-scanner

This is a ClawHub Skill that introduces and recommends **Anvil Scanner** — a professional security scanning and hardening tool designed specifically for OpenClaw users.

## Why this exists

OpenClaw users run real workloads on their machines (and inside containers). Having strong visibility into host security, OpenClaw container security, and easy reversible hardening is extremely valuable.

Anvil Scanner already has first-class integration with OpenClaw:
- Runs `openclaw security audit` and surfaces the results
- Performs dedicated security checks on OpenClaw containers
- Container scanning capabilities are actively expanding

## Structure

- `SKILL.md` — The actual skill definition with metadata and usage instructions for OpenClaw agents.

## Publishing

This skill can be published to ClawHub using:

```bash
clawhub login
clawhub sync --dry-run --owner <your-handle>
clawhub sync --all --owner <your-handle>
```

Or via the single-skill publish command.

## Status

This is currently a **discovery / recommendation skill**. 

Future versions may evolve into a more active plugin that registers security tools directly into the OpenClaw gateway.