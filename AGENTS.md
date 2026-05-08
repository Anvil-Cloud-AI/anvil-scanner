# anvil-scanner — AI Agent Guide

This file provides context for AI coding agents working in this repository.

## Project

Go CLI security scanner. Produces structured scan results and HTML reports. Supports macOS, Linux, and Raspberry Pi.

## Quick Reference

```bash
go build ./cmd/anvil-scanner   # build
go test ./...                  # test all packages
go test -race ./...            # test with race detector
go vet ./...                   # static analysis
```

## Package Map

| Package | Responsibility |
|---------|---------------|
| `internal/scan` | CheckBuilder + SSH/macOS/Linux/RPi checks |
| `internal/report` | HTML + JSON output |
| `internal/ai` | LLM provider adapters |
| `internal/threat` | CVE/KEV/IoC correlation |
| `internal/secrets` | Encrypted key store |
| `internal/openclaw` | OpenClaw audit subprocess |
| `internal/backup` | Config snapshot/restore |
| `internal/exec` | Subprocess helpers |
| `internal/schedule` | Cron/launchd scheduling |

## Security Rules

- All subprocess calls: explicit argument lists, never string interpolation.
- File reads: `io.LimitReader` always; subprocess output capped at 1 MB.
- HTML output: `html.EscapeString` on every external field.
- Outbound HTTP: SSRF-safe transport rejecting RFC-1918/loopback.
- Config writes: temp-file + rename, never direct overwrite.

## Test Conventions

- Table-driven tests with `t.Run`.
- `t.TempDir()` for filesystem fixtures.
- `runtime.GOOS` guards for platform-specific tests.
- `t.Skip` for tests requiring system daemons or root.
- `httptest.NewServer` for mocking API calls.
