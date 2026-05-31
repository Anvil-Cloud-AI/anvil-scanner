# Anvil Scanner

Turnkey security hardening scanner for OpenClaw deployments.
Single static binary — no Python, no virtualenv, no `pip install`.
**Supports Linux (Ubuntu/Debian) and macOS (Intel + Apple Silicon), Raspberry Pi.**

---

> **⚠️ DISCLAIMER — READ BEFORE USE**
>
> Anvil Scanner is provided **as-is, without warranty of any kind**, express or implied.
>
> - This tool performs **best-effort** security checks based on common hardening guidelines. It does **not** guarantee that your system is secure, fully hardened, or protected against all threats.
> - Security hardening is a **continuous process**. Passing all checks does not mean your system is safe. Failing checks does not mean you are actively compromised.
> - **AI-generated analysis** (risk scores, recommendations, overviews) is produced by a language model and may be **inaccurate, incomplete, or inappropriate** for your specific environment. Always verify recommendations with a qualified security professional before acting on them.
> - Applying hardening actions (firewall rules, SSH config changes, system updates) **may disrupt running services** or lock you out of your system. Always test in a non-production environment first and ensure you have an alternative access method (console, recovery mode) before making changes.
> - The authors and contributors of Anvil Scanner **accept no liability** for any damage, data loss, service disruption, security breach, or other consequences arising from the use or misuse of this tool.
> - This tool is **not a substitute** for professional security audits, penetration testing, or compliance reviews.
>
> **Use at your own risk.**

---

## Features

- **Host scanning** — open ports, SSH config, pending updates, running services
- **AI risk analysis** — risk score (1–10) + recommendations (Ollama, Claude, OpenAI, Grok)
- **Firewall checks** — `ufw` on Linux, `pf` + Application Firewall on macOS
- **SSH hardening checks** — 44 checks covering config, algorithms, permissions
- **Threat intelligence** — Shodan, AbuseIPDB, local IoC scanning, CVE exposure, CISA KEV
- **OpenClaw audit** — runs `openclaw security audit`, maps findings to checks, tailors remediation by install channel (npm / brew / source)
- **Encrypted secrets store** — AES-256-GCM container with keyring, passphrase, or file backends
- **Scheduling** — `launchd` plist on macOS, `crontab` on Linux
- **Backup & revert** — every modified system file is snapshotted before any change

---

## Installation

### Pre-built binaries (recommended)

Download the latest release for your platform from the [GitHub Releases](https://github.com/Anvil-Cloud-AI/anvil-scanner/releases) page.

```bash
# macOS (Apple Silicon)
curl -L https://github.com/Anvil-Cloud-AI/anvil-scanner/releases/latest/download/anvil-scanner_darwin_arm64.tar.gz | tar xz
sudo mv anvil-scanner /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/Anvil-Cloud-AI/anvil-scanner/releases/latest/download/anvil-scanner_darwin_amd64.tar.gz | tar xz
sudo mv anvil-scanner /usr/local/bin/

# Linux (amd64)
curl -L https://github.com/Anvil-Cloud-AI/anvil-scanner/releases/latest/download/anvil-scanner_linux_amd64.tar.gz | tar xz
sudo mv anvil-scanner /usr/local/bin/

# Linux (arm64 / Raspberry Pi)
curl -L https://github.com/Anvil-Cloud-AI/anvil-scanner/releases/latest/download/anvil-scanner_linux_arm64.tar.gz | tar xz
sudo mv anvil-scanner /usr/local/bin/
```

### Build from source

Requires Go 1.25+.

```bash
go install github.com/Anvil-Cloud-AI/anvil-scanner/cmd/anvil-scanner@latest
```

---

## Configuration

Set your AI provider key as an environment variable (pick one):

```bash
export CLAUDE_KEY="your_anthropic_api_key"
export OPENAI_KEY="your_openai_api_key"
export GROK_KEY="your_xai_api_key"
# Or use Ollama — free, local, no key needed
```

AI provider detection order: **Ollama** (local) → `CLAUDE_KEY` → `OPENAI_KEY` → `GROK_KEY` → none (AI skipped with a visible banner).

For long-lived or headless setups, encrypt keys at rest instead:

```bash
# First-time setup — interactive wizard
anvil-scanner --init-secrets

# Encrypt a .env file into the container
anvil-scanner --encrypt /path/to/.env

# Decrypt to inspect or edit
anvil-scanner --decrypt /tmp/secrets-check.env

# Move to a different backend later
anvil-scanner --rotate-key-backend keyring
```

**Key backends:**

| Backend | How the master key is stored | Best for |
|---------|------------------------------|----------|
| `keyring` | OS keyring (Keychain / secret-tool) — no key on disk | Desktops |
| `passphrase` | Derived via scrypt each run; honours `ANVIL_SECRETS_PASSPHRASE` env var | Headless / CI |
| `file` | Written to `~/.anvil-scanner/secrets.key` | Legacy / compatibility |

---

## Privilege escalation

**Run Anvil Scanner as your regular user — not with sudo.**

The scanner warns when invoked as root and some checks behave incorrectly under sudo (see macOS note below). Checks that need root access and don't have it show `SKIP`, which is expected.

| Operation | How privileges are handled |
|-----------|---------------------------|
| Scan (default) | Run as your user. Root-only checks (`/etc/shadow`, kernel parameters) show `SKIP` if not elevated — that's fine for most use cases. |
| `--harden` | Run as your user. The tool prompts for your password when it needs to modify system files. |
| `--revert` / `--uninstall` | Run with `sudo` — these restore files to system paths and require root. |
| `--schedule` / `--unschedule` | No elevation needed — installs to your user crontab or launchd agent. |
| Threat intel | No elevation needed — network lookups only. |

**macOS note:** The Remote Login check (`MACOS-005`) uses `systemsetup`, which must run as an admin user in a normal session — it fails when invoked as root via `sudo`. If you run the scanner with `sudo`, MACOS-005 will be skipped and SSH checks will run regardless of whether Remote Login is actually enabled, producing findings for an SSH server that may not be running. Running without `sudo` avoids this.

---

## Usage

```bash
# Full scan — host + OpenClaw + threat intelligence + AI analysis (most common)
anvil-scanner

# Skip threat intelligence
anvil-scanner --no-threat-intel

# Skip AI analysis
anvil-scanner --no-ai

# Skip OpenClaw audit
anvil-scanner --no-openclaw

# Write HTML report to a specific path
anvil-scanner --html /tmp/report.html

# Write JSON report to a specific path
anvil-scanner --json-output /tmp/report.json

# Print JSON report to stdout (for piping)
anvil-scanner --json

# Apply hardening fixes (prompts for password when needed)
anvil-scanner --harden

# Schedule hourly scan
anvil-scanner --schedule

# Preview what --schedule would configure
anvil-scanner --schedule-dry-run

# Remove scheduled scan
anvil-scanner --unschedule

# Restore files from a backup session (interactive)
sudo anvil-scanner --revert

# Remove all anvil-scanner changes and backups
sudo anvil-scanner --uninstall

# Force uninstall even when no backups found
sudo anvil-scanner --uninstall --force

# Send anonymised scan summary to Anvil telemetry (opt-in)
anvil-scanner --telemetry

# Print version
anvil-scanner --version

# Secrets management (run as your normal user — keyring backend requires a non-root session)
anvil-scanner --init-secrets --backend keyring
anvil-scanner --store-keyring
```

---

## Threat Intelligence

Runs by default. Disable with `--no-threat-intel`. Results appear in the HTML report's **Threat Intelligence** section and are factored into the AI risk score.

| Check | Source | API key required |
|-------|--------|-----------------|
| Shodan InternetDB | Open ports, CVEs, tags for your public IP | No |
| AbuseIPDB | Abuse confidence score + report history | Optional (`ABUSEIPDB_KEY`) |
| Local IoC scan | Suspicious cron jobs, crypto miners, C2 tools, SSH persistence, auth log anomalies | No |
| CVE exposure | Installed packages cross-referenced against known CVEs | No |
| CISA KEV | Installed packages cross-referenced against CISA's Known Exploited Vulnerabilities catalog | No |

---

## Environment Variables

| Variable | Required for | Default | Description |
|----------|-------------|---------|-------------|
| `CLAUDE_KEY` | AI (Claude) | — | Anthropic API key |
| `OPENAI_KEY` | AI (OpenAI) | — | OpenAI API key |
| `GROK_KEY` | AI (Grok) | — | xAI API key |
| `ABUSEIPDB_KEY` | AbuseIPDB check | — | Free key from [abuseipdb.com](https://www.abuseipdb.com) |
| `AI_PROVIDER` | Provider override | auto-detect | `ollama`, `claude`, `openai`, or `grok` |
| `AI_MODEL` | Model override | per-provider default | Override the default model |
| `ANVIL_TELEMETRY` | Telemetry | `0` | Set to `1` to enable (same as `--telemetry`) |
| `ANVIL_SECRETS_PASSPHRASE` | Secrets (passphrase backend) | — | Passphrase for unattended decryption in CI |
| `OLLAMA_URL` | Ollama endpoint | `http://localhost:11434` | Override the local Ollama server URL |
| `XAI_API_URL` | Grok endpoint | `https://api.x.ai/v1` | Override the xAI API base URL |

---

## Platform Support

| Feature | Linux (Ubuntu/Debian) | macOS | Raspberry Pi OS |
|---------|----------------------|-------|-----------------|
| Port scanning | `ss` / `netstat` | `lsof` | `ss` / `netstat` |
| Pending updates | `apt list --upgradable` | `brew outdated` + `softwareupdate` | `apt list --upgradable` |
| Firewall checks | `ufw` / `iptables` | `pf` + App Firewall | `ufw` / `iptables` |
| SSH checks | ✅ 44 checks | ✅ (gated on Remote Login) | ✅ |
| macOS-specific | — | SIP, FileVault, Gatekeeper, Firmware PW | — |
| Raspberry Pi checks | — | — | ✅ 12 checks |
| AI risk analysis | ✅ | ✅ | ✅ |
| HTML / JSON reports | ✅ | ✅ | ✅ |
| Scheduling | `crontab` | `launchd` plist | `crontab` |
| Secrets store | ✅ | ✅ | ✅ |

---

## Backup & Revert

Anvil Scanner snapshots every system file it modifies **before** making any changes.

```
~/.anvil-scanner/backups/YYYY-MM-DD_HHMMSS/
├── manifest.json
└── etc/
    └── ssh/
        └── sshd_config
```

To restore from a backup session:

```bash
sudo anvil-scanner --revert
```

This lists available sessions, shows what each backed up, and prompts for confirmation before restoring.

To restore a single file manually:

```bash
cp ~/.anvil-scanner/backups/2026-04-26_120000/etc/ssh/sshd_config /etc/ssh/sshd_config
systemctl restart sshd
```

To remove all changes and clean up completely:

```bash
sudo anvil-scanner --uninstall
```

---

## Data Sources

| Data | Source | License |
|------|--------|---------|
| OpenClaw CVE advisory database | [jgamblin/OpenClawCVEs](https://github.com/jgamblin/OpenClawCVEs) (fetched at runtime, updated hourly) | MIT — Copyright 2026 [Jerry Gamblin](https://github.com/jgamblin) |

---

## Security Notes

- No `shell=True` — all subprocesses use explicit argument lists
- Credentials loaded from env vars or the encrypted secrets container — never hardcoded
- `sshd -t` validates config syntax before any SSH service restart
- Secrets container uses AES-256-GCM with scrypt KDF; master key never touches disk in keyring mode

---

## License

[Business Source License 1.1](LICENSE) — free for internal use on OpenClaw deployments you own or operate. Converts to Apache 2.0 on 2030-03-28.

Commercial licensing: [licensing@anvilcloud.ai](mailto:licensing@anvilcloud.ai)
