# anvil-scanner — Project Guide

Security hardening scanner for macOS, Linux, and Raspberry Pi. Produces structured scan results and an HTML report with optional AI risk narrative.

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
cmd/anvil-scanner/      CLI entry point (main.go, flag parsing, telemetry)
internal/
  scan/                 CheckBuilder + all platform checks (SSH, macOS, Linux, RPi)
  report/               HTML + JSON report generation (go:embed template)
  ai/                   Anthropic / Ollama / OpenAI / Grok provider adapters
  threat/               CVE feed, CISA KEV, AbuseIPDB, IoC detection
  container/            Container runtime hardening (docker/podman) + image CVE scan (grype/trivy)
  secrets/              AES-256-GCM encrypted store (keyring / file / env backends)
  openclaw/             OpenClaw audit wrapper (subprocess JSON protocol)
  backup/               Config snapshot + restore
  exec/                 Subprocess helpers with timeout + memory caps
  schedule/             Cron / launchd scheduling
  hardening/            Pre-check policy evaluation
```

## Key Conventions

- All subprocess calls use explicit argument lists — no shell interpolation.
- All file reads use `io.LimitReader`; subprocess stdout/stderr capped at 1 MB.
- System config writes go through temp-file + rename (atomic).
- External data in HTML reports passes through `html.EscapeString`.
- Outbound HTTP uses an SSRF-safe transport that rejects RFC-1918 and loopback IPs (except Ollama, which is localhost-only).

## Check IDs

| Prefix | Platform |
|--------|----------|
| SSH-   | All platforms (SSH hardening) |
| MACOS- | macOS only |
| FW-    | Linux firewall |
| RPI-   | Raspberry Pi |
| OC-    | OpenClaw audit |
| CONTAINER- | Container runtime hardening (all containers, docker/podman) + image CVE rollup |
