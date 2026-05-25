# QA Testing Guide — v1.0.0

Manual test checklist for macOS, Ubuntu, and Raspberry Pi.  
Run every section on each platform unless the platform column says otherwise.

**Download the release binary before starting:**

```bash
# macOS (Apple Silicon)
curl -L https://github.com/Anvil-Cloud-AI/anvil-scanner/releases/download/v1.0.0/anvil-scanner_1.0.0_darwin_arm64.tar.gz | tar xz
chmod +x anvil-scanner

# macOS (Intel)
curl -L https://github.com/Anvil-Cloud-AI/anvil-scanner/releases/download/v1.0.0/anvil-scanner_1.0.0_darwin_amd64.tar.gz | tar xz
chmod +x anvil-scanner

# Ubuntu / Raspberry Pi (ARM64)
curl -L https://github.com/Anvil-Cloud-AI/anvil-scanner/releases/download/v1.0.0/anvil-scanner_1.0.0_linux_arm64.tar.gz | tar xz
chmod +x anvil-scanner

# Ubuntu (x86_64)
curl -L https://github.com/Anvil-Cloud-AI/anvil-scanner/releases/download/v1.0.0/anvil-scanner_1.0.0_linux_amd64.tar.gz | tar xz
chmod +x anvil-scanner
```

---

## 1. Binary Basics

| # | Command | Expected | macOS | Ubuntu | RPi |
|---|---------|----------|-------|--------|-----|
| 1.1 | `./anvil-scanner --version` | Prints `anvil-scanner 1.0.0`, exits 0 | ☐ | ☐ | ☐ |
| 1.2 | `./anvil-scanner -v` | Same as above | ☐ | ☐ | ☐ |
| 1.3 | `./anvil-scanner --help` | Prints usage, exits 0 (not 1) | ☐ | ☐ | ☐ |
| 1.4 | `./anvil-scanner --invalid-flag` | Error message on stderr, exits non-0 | ☐ | ☐ | ☐ |
| 1.5 | Verify checksum: `sha256sum anvil-scanner` matches `checksums.txt` | Checksums match | ☐ | ☐ | ☐ |

---

## 2. Basic Scan

Run without any flags as a normal (non-root) user.

```bash
./anvil-scanner --no-ai --no-openclaw
```

| # | What to verify | macOS | Ubuntu | RPi |
|---|----------------|-------|--------|-----|
| 2.1 | Prints `Anvil Scanner 1.0.0 — hardening scan` | ☐ | ☐ | ☐ |
| 2.2 | Prints platform name (e.g. `Platform: macOS 14.x`) | ☐ | ☐ | ☐ |
| 2.3 | Prints check summary line (`X total ✅ Y passed ❌ Z failed`) | ☐ | ☐ | ☐ |
| 2.4 | Prints `HTML report written to: ~/anvil-scanner-reports/anvil-scanner-YYYY-MM-DD...html` | ☐ | ☐ | ☐ |
| 2.5 | HTML file exists at that path and opens in a browser | ☐ | ☐ | ☐ |
| 2.6 | HTML report contains the platform name and at least one check result | ☐ | ☐ | ☐ |
| 2.7 | Exits 0 | ☐ | ☐ | ☐ |

---

## 3. Root Warning

```bash
sudo ./anvil-scanner --no-ai --no-openclaw
```

| # | What to verify | macOS | Ubuntu | RPi |
|---|----------------|-------|--------|-----|
| 3.1 | Prints `⚠  WARNING: Running as root.` on stderr | ☐ | ☐ | ☐ |
| 3.2 | Mentions your actual username via `detected sudo from user: <name>` | ☐ | ☐ | ☐ |
| 3.3 | HTML report is written to **your** home dir, not `/root/` | ☐ | ☐ | ☐ |
| 3.4 | Report file is owned by your user, not root | ☐ | ☐ | ☐ |

---

## 4. Output Flags

### 4.1 `--html <path>`

```bash
./anvil-scanner --no-ai --no-openclaw --html /tmp/test-report.html
```

| # | What to verify | macOS | Ubuntu | RPi |
|---|----------------|-------|--------|-----|
| 4.1.1 | HTML written to `/tmp/test-report.html` (not default dir) | ☐ | ☐ | ☐ |
| 4.1.2 | File is valid HTML (opens in browser) | ☐ | ☐ | ☐ |

### 4.2 `--json` (stdout)

```bash
./anvil-scanner --no-ai --no-openclaw --json > /tmp/report.json
```

| # | What to verify | macOS | Ubuntu | RPi |
|---|----------------|-------|--------|-----|
| 4.2.1 | `/tmp/report.json` contains valid JSON (`python3 -m json.tool /tmp/report.json`) | ☐ | ☐ | ☐ |
| 4.2.2 | Progress output (platform, summary) went to **stderr**, not stdout | ☐ | ☐ | ☐ |
| 4.2.3 | HTML report is still written to the default dir | ☐ | ☐ | ☐ |

### 4.3 `--json-output <path>`

```bash
./anvil-scanner --no-ai --no-openclaw --json-output /tmp/report2.json
```

| # | What to verify | macOS | Ubuntu | RPi |
|---|----------------|-------|--------|-----|
| 4.3.1 | `/tmp/report2.json` exists and is valid JSON | ☐ | ☐ | ☐ |
| 4.3.2 | Progress printed to stdout (not suppressed) | ☐ | ☐ | ☐ |
| 4.3.3 | HTML report also written to default dir | ☐ | ☐ | ☐ |

### 4.4 Combined output flags

```bash
./anvil-scanner --no-ai --no-openclaw --json --json-output /tmp/r.json --html /tmp/r.html > /tmp/stdout.json
```

| # | What to verify | macOS | Ubuntu | RPi |
|---|----------------|-------|--------|-----|
| 4.4.1 | `/tmp/stdout.json` — valid JSON (from `--json`) | ☐ | ☐ | ☐ |
| 4.4.2 | `/tmp/r.json` — valid JSON (from `--json-output`) | ☐ | ☐ | ☐ |
| 4.4.3 | `/tmp/r.html` — valid HTML (from `--html`) | ☐ | ☐ | ☐ |
| 4.4.4 | All three files have the same `platform` field | ☐ | ☐ | ☐ |

---

## 5. AI Flags

### 5.1 `--no-ai`

```bash
./anvil-scanner --no-ai --no-openclaw --html /tmp/no-ai.html
```

| # | What to verify | macOS | Ubuntu | RPi |
|---|----------------|-------|--------|-----|
| 5.1.1 | No AI provider message printed | ☐ | ☐ | ☐ |
| 5.1.2 | HTML report has AI section marked as skipped | ☐ | ☐ | ☐ |

### 5.2 No AI provider available (no keys, no Ollama)

```bash
env -i HOME=$HOME ./anvil-scanner --no-openclaw --html /tmp/no-provider.html
```

| # | What to verify | macOS | Ubuntu | RPi |
|---|----------------|-------|--------|-----|
| 5.2.1 | Prints `ℹ  No AI provider available` | ☐ | ☐ | ☐ |
| 5.2.2 | Scan continues and completes (does not abort) | ☐ | ☐ | ☐ |
| 5.2.3 | HTML report flags AI section as unavailable | ☐ | ☐ | ☐ |

---

## 6. Threat Intel (on by default; `--no-threat-intel` to skip)

Requires internet access. Run without API keys first.

```bash
./anvil-scanner --no-ai --no-openclaw --html /tmp/threat.html
```

| # | What to verify | macOS | Ubuntu | RPi |
|---|----------------|-------|--------|-----|
| 6.1 | Prints `Running threat intelligence scan...` | ☐ | ☐ | ☐ |
| 6.2 | Prints IoC summary (`✅ No local IoC indicators found` or count) | ☐ | ☐ | ☐ |
| 6.3 | Prints CVE check result | ☐ | ☐ | ☐ |
| 6.4 | Scan completes even without API keys (Shodan/AbuseIPDB skip gracefully) | ☐ | ☐ | ☐ |
| 6.5 | HTML report has Threat Intel section populated | ☐ | ☐ | ☐ |

---

## 7. Schedule Flags

### 7.1 Dry run (safe — no changes)

```bash
./anvil-scanner --schedule-dry-run
```

| # | What to verify | macOS | Ubuntu | RPi |
|---|----------------|-------|--------|-----|
| 7.1.1 | Prints what would be installed (plist path on macOS, crontab entry on Linux) | ☐ | ☐ | ☐ |
| 7.1.2 | No actual plist/crontab created | ☐ | ☐ | ☐ |
| 7.1.3 | Exits 0 | ☐ | ☐ | ☐ |

### 7.2 Install schedule

```bash
./anvil-scanner --schedule
```

| # | What to verify | macOS | Ubuntu | RPi |
|---|----------------|-------|--------|-----|
| 7.2.1 | macOS: plist created at `~/Library/LaunchAgents/ai.anvilcloud.anvil-scanner.plist` | ☐ | — | — |
| 7.2.2 | Linux: crontab entry appears in `crontab -l` | — | ☐ | ☐ |
| 7.2.3 | macOS: `launchctl list | grep anvil` shows job loaded | ☐ | — | — |

### 7.3 Remove schedule

```bash
./anvil-scanner --unschedule
```

| # | What to verify | macOS | Ubuntu | RPi |
|---|----------------|-------|--------|-----|
| 7.3.1 | macOS: plist removed, job no longer in `launchctl list` | ☐ | — | — |
| 7.3.2 | Linux: crontab entry removed from `crontab -l` | — | ☐ | ☐ |
| 7.3.3 | Exits 0 | ☐ | ☐ | ☐ |

---

## 8. Revert & Uninstall

> **Note:** These flags are only meaningful after a scan has made changes that were backed up.

### 8.1 `--revert` with no backups

```bash
./anvil-scanner --revert
```

| # | What to verify | macOS | Ubuntu | RPi |
|---|----------------|-------|--------|-----|
| 8.1.1 | Prints warning that no backup sessions are available | ☐ | ☐ | ☐ |
| 8.1.2 | Exits gracefully (not a crash) | ☐ | ☐ | ☐ |

### 8.2 `--uninstall` with no backups

```bash
./anvil-scanner --uninstall
```

| # | What to verify | macOS | Ubuntu | RPi |
|---|----------------|-------|--------|-----|
| 8.2.1 | Prompts for confirmation before doing anything | ☐ | ☐ | ☐ |
| 8.2.2 | `n` cancels cleanly | ☐ | ☐ | ☐ |

### 8.3 `--force` warning without `--uninstall`

```bash
./anvil-scanner --force
```

| # | What to verify | macOS | Ubuntu | RPi |
|---|----------------|-------|--------|-----|
| 8.3.1 | Prints `Warning: --force has no effect without --uninstall` on stderr | ☐ | ☐ | ☐ |
| 8.3.2 | Scan continues normally | ☐ | ☐ | ☐ |

---

## 9. Secrets Flags

### 9.1 `--backend` warning without companion

```bash
./anvil-scanner --backend keyring
```

| # | What to verify | macOS | Ubuntu | RPi |
|---|----------------|-------|--------|-----|
| 9.1.1 | Prints `Warning: --backend has no effect without --init-secrets or --encrypt` | ☐ | ☐ | ☐ |
| 9.1.2 | Scan continues normally | ☐ | ☐ | ☐ |

### 9.2 `--encrypt` / `--decrypt` round-trip

```bash
# Create a test .env file
echo 'OPENAI_KEY=sk-test-1234\nSHODAN_KEY=test-abc' > /tmp/test.env

# Encrypt using passphrase backend
./anvil-scanner --encrypt /tmp/test.env --backend passphrase

# Decrypt back
./anvil-scanner --decrypt /tmp/test-decrypted.env

# Verify round-trip
diff /tmp/test.env /tmp/test-decrypted.env
```

| # | What to verify | macOS | Ubuntu | RPi |
|---|----------------|-------|--------|-----|
| 9.2.1 | Encrypt prompts for passphrase (twice for confirmation) | ☐ | ☐ | ☐ |
| 9.2.2 | Encrypted container created at `~/.anvil-scanner/secrets.enc` | ☐ | ☐ | ☐ |
| 9.2.3 | Decrypt prompts for passphrase (once) | ☐ | ☐ | ☐ |
| 9.2.4 | Decrypted file matches original | ☐ | ☐ | ☐ |

### 9.3 `--rotate-key-backend`

```bash
./anvil-scanner --rotate-key-backend passphrase
```

| # | What to verify | macOS | Ubuntu | RPi |
|---|----------------|-------|--------|-----|
| 9.3.1 | If no container exists: returns an informative error | ☐ | ☐ | ☐ |
| 9.3.2 | If container exists: prompts for new passphrase and re-encrypts | ☐ | ☐ | ☐ |

---

## 10. Signal Handling

```bash
./anvil-scanner &
sleep 2
kill -INT $!
```

| # | What to verify | macOS | Ubuntu | RPi |
|---|----------------|-------|--------|-----|
| 10.1 | Process terminates cleanly (no panic/stack trace) | ☐ | ☐ | ☐ |
| 10.2 | Exits non-0 or 0 (either is acceptable; no hung process) | ☐ | ☐ | ☐ |

---

## 11. Platform-Specific Checks

### 11.1 macOS only

Run a full scan and open the HTML report. Verify these check IDs are present:

| Check ID | Description | Present in report |
|----------|-------------|------------------|
| MACOS-001 | System Integrity Protection (SIP) | ☐ |
| MACOS-002 | FileVault disk encryption | ☐ |
| MACOS-003 | Gatekeeper | ☐ |
| MACOS-004 | Application Firewall | ☐ |
| MACOS-005 | Remote Login (SSH) | ☐ |
| MACOS-006 | Screen Sharing | ☐ |
| MACOS-007 | Auto Login | ☐ |
| MACOS-008 | Firmware Password (Intel Macs only) | ☐ |

Verify at least one check shows PASS or WARN (not all SKIP).

### 11.2 Linux (Ubuntu + RPi)

| Check ID | Description | Ubuntu | RPi |
|----------|-------------|--------|-----|
| FW-001 | UFW firewall enabled | ☐ | ☐ |
| SSH-006 | PermitRootLogin | ☐ | ☐ |
| SSH-007 | PasswordAuthentication | ☐ | ☐ |
| AUTH-001 | Empty password accounts | ☐ | ☐ |

### 11.3 Raspberry Pi only

Run on an actual RPi device. Verify these check IDs are present in the report:

| Check ID | Description | Present |
|----------|-------------|---------|
| RPI-001 | Default `pi` user present | ☐ |
| RPI-002 | Default password unchanged | ☐ |
| RPI-003 | SSH enabled with default password | ☐ |
| RPI-004 | GPU memory split | ☐ |
| RPI-005 | Camera/serial interfaces | ☐ |

---

## 12. SSH Checks (All Platforms)

Run a scan and verify these check IDs appear in the report:

| Check ID | Description | macOS | Ubuntu | RPi |
|----------|-------------|-------|--------|-----|
| SSH-006 | PermitRootLogin | ☐ | ☐ | ☐ |
| SSH-007 | PasswordAuthentication | ☐ | ☐ | ☐ |
| SSH-009 | Protocol version | ☐ | ☐ | ☐ |
| SSH-040 | Authorized keys file permissions | ☐ | ☐ | ☐ |
| SSH-041 | `~/.ssh` directory permissions | ☐ | ☐ | ☐ |
| SSH-043 | Known hosts file | ☐ | ☐ | ☐ |

---

## 13. Report Quality

Open the HTML report in a browser and visually verify:

| # | What to check | macOS | Ubuntu | RPi |
|---|---------------|-------|--------|-----|
| 13.1 | Page loads without console errors | ☐ | ☐ | ☐ |
| 13.2 | Platform name displayed correctly in header | ☐ | ☐ | ☐ |
| 13.3 | Timestamp is current (today's date/time) | ☐ | ☐ | ☐ |
| 13.4 | Check results section has pass/fail/warn badges | ☐ | ☐ | ☐ |
| 13.5 | No raw HTML entities visible (e.g., `&lt;` instead of `<`) | ☐ | ☐ | ☐ |
| 13.6 | Open ports section populated (or shows "none detected") | ☐ | ☐ | ☐ |
| 13.7 | SSH directives section populated | ☐ | ☐ | ☐ |

---

## 14. Telemetry (Optional)

Only test if you want telemetry to fire — this sends data to Anvil's endpoint.

```bash
./anvil-scanner --no-ai --no-openclaw --telemetry
```

| # | What to verify | macOS | Ubuntu | RPi |
|---|----------------|-------|--------|-----|
| 14.1 | Prints `Submitting telemetry...` | ☐ | ☐ | ☐ |
| 14.2 | Completes without error | ☐ | ☐ | ☐ |

Alternatively, verify via env var:

```bash
ANVIL_TELEMETRY=1 ./anvil-scanner --no-ai --no-openclaw
```

---

## Issues Found

Record any failures here:

| Platform | Flag / Feature | Observed behavior | Expected behavior |
|----------|---------------|-------------------|-------------------|
| | | | |
| | | | |
| | | | |

---

## Sign-off

| Platform | Tester | Date | Result |
|----------|--------|------|--------|
| macOS (Apple Silicon) | | | ☐ PASS  ☐ FAIL |
| macOS (Intel) | | | ☐ PASS  ☐ FAIL |
| Ubuntu | | | ☐ PASS  ☐ FAIL |
| Raspberry Pi | | | ☐ PASS  ☐ FAIL |
