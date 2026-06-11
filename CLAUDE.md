# anvil-scanner — Project Guide

Security hardening scanner for macOS, Linux, Raspberry Pi, and Windows 11 / Windows Server. Produces structured scan results and an HTML report with optional AI risk narrative (on Unix platforms).

## Build and Run

```bash
go build ./cmd/anvil-scanner
./anvil-scanner --scan
```

## Test

```bash
go test ./...                   # all packages
go test -race ./...             # with race detector
go test ./internal/scan/...     # single package
```

## Architecture

```
cmd/anvil-scanner/
  main.go               CLI entry point on Unix (main_linux.go, main_darwin.go tagged)
  main_windows.go       Tier-0 placeholder Windows entry point (read-only scan + reports only)
internal/
  scan/
    scan.go             CheckBuilder + Unix orchestration
    scan_windows.go     Windows orchestration (runAllChecksInto)
    *_windows.go        Windows-tagged check collectors (firewall, defender, SMBv1, RDP, UAC, update)
    windows_*.go        Windows-specific parsers and evaluators
  report/               HTML + JSON report generation (go:embed template, shared by all platforms)
  ai/                   Anthropic / Ollama / OpenAI / Grok provider adapters (Unix only)
  threat/               CVE feed, CISA KEV, AbuseIPDB, IoC detection (Unix only)
  container/            Container runtime hardening (docker/podman) + image CVE scan (Unix only)
  secrets/              AES-256-GCM encrypted store (keyring / file / env backends; Unix only)
  openclaw/             OpenClaw audit wrapper (subprocess JSON protocol; Unix only)
  backup/               Config snapshot + restore (Unix only)
  exec/                 Subprocess helpers with timeout + memory caps (cross-platform)
  schedule/             Cron / launchd scheduling (Unix only)
  hardening/            Pre-check policy evaluation (Unix only)
```

**Windows vs Unix:**
- Windows build uses `//go:build windows` tags on Windows-specific files
- Unix builds use default platform detection (`runtime.GOOS`)
- `main_windows.go` is a minimal placeholder: runs Windows checks, writes HTML/JSON reports; no hardening, AI, threat intel, OpenClaw, container scanning, secrets, scheduling, or backup/revert
- Shared `report` package generates identical HTML/JSON format across all platforms

## Key Conventions

- All subprocess calls use explicit argument lists — no shell interpolation.
- All file reads use `io.LimitReader`; subprocess stdout/stderr capped at 1 MB.
- System config writes go through temp-file + rename (atomic).
- External data in HTML reports passes through `html.EscapeString`.
- Outbound HTTP uses an SSRF-safe transport that rejects RFC-1918 and loopback IPs (except Ollama, which is localhost-only).

## Check IDs

| Prefix | Platform | Notes |
|--------|----------|-------|
| SSH-   | Linux / macOS / Raspberry Pi | SSH server hardening (44 checks) |
| MACOS- | macOS only | SIP, FileVault, Gatekeeper, etc. |
| FW-    | Linux | ufw / iptables firewall |
| RPI-   | Raspberry Pi | Raspberry Pi specific |
| OC-    | Linux / macOS / Raspberry Pi | OpenClaw security audit findings |
| CONTAINER- | Linux / macOS | Container runtime hardening (docker/podman) + image CVE rollup |
| WIN-   | Windows 11 / Windows Server | Windows hardening checks (read-only, no admin required) |
| WIN-000 | Windows | Informational: detected SKU (Windows 11 Client vs Server) |
| WIN-FW-001 | Windows | Windows Defender Firewall enabled (all profiles) |
| WIN-AV-001 | Windows | Microsoft Defender Antivirus + real-time protection |
| WIN-SMB-001 | Windows | SMBv1 server protocol disabled |
| WIN-RDP-001 | Windows | Remote Desktop disabled or requires Network Level Authentication |
| WIN-UAC-001 | Windows | User Account Control enabled |
| WIN-UPD-001 | Windows | Windows Update service not disabled |
