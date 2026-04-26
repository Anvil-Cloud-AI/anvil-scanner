# Anvil-Secure Plugin Protocol: OpenClaw Integration

This document specifies how anvil-scanner integrates with OpenClaw as an auditing plugin.  It covers the subprocess protocol, the JSON finding schema, install-channel detection, severity mapping, error handling, and how findings surface in reports.

**Implementation**: `internal/openclaw/openclaw.go`  
**Reference**: `python/anvil_scanner/openclaw_audit.py`

---

## Overview

Anvil-scanner treats OpenClaw as an optional, self-describing plugin.  When OpenClaw is present on `PATH`, anvil-scanner invokes `openclaw security audit --json` as a subprocess, translates the returned findings into standard `scan.Check` values, and includes them in the HTML and JSON reports under a dedicated "OpenClaw" section.

If OpenClaw is absent, times out, or returns unexpected output, a single `SKIP` check is recorded and the broader scan continues.  OpenClaw is never a hard dependency.

Use `--no-openclaw` to suppress the audit entirely.

---

## Install-Channel Detection

Before running the audit, anvil-scanner probes the install channel to generate useful, channel-specific remediation text.

### How it works

1. `openclaw --version` is executed (5-second timeout).  If exit code is `-1` (binary not on `PATH`), the channel is `unknown`.
2. `which openclaw` is executed to resolve the binary's absolute path.
3. The path is lower-cased and forward-slash-normalised, then matched against marker strings:

| Priority | Channel | Path markers |
|----------|---------|--------------|
| 1 | `npm` | `/node_modules/`, `/.npm/`, `/npm/`, `/yarn/global/`, `/pnpm/global/` |
| 2 | `brew` | `/cellar/`, `/opt/homebrew/`, `/home/linuxbrew/`, `/usr/local/opt/` |
| 3 | `source` | Version string contains `-dev`, `-rc`, `-alpha`, `-beta`, or `+g` |
| 4 | `unknown` | No markers matched |

### Source stamp

Every finding produced by the OpenClaw integration is tagged with a source stamp appended to its `Remediation` field:

```
Source: openclaw:<channel>:<version>
```

Examples:
- `Source: openclaw:brew:2025.4.1`
- `Source: openclaw:npm:2025.3.0`
- `Source: openclaw:source:2025.5.0-dev+g3a1b2c`
- `Source: openclaw:unknown:?`

This stamp is displayed as a release-channel badge in the HTML report so users can see which installation served the audit.

---

## Subprocess Protocol

### Command

```
openclaw security audit --json
```

- **Timeout**: 30 seconds
- **Working directory**: inherited from anvil-scanner
- **Stdin**: none
- **Expected exit code**: 0

### Success response

On success, OpenClaw writes a JSON object to stdout:

```json
{
  "findings": [
    {
      "checkId":     "OC-CFG-001",
      "title":       "Gateway binds to 0.0.0.0",
      "severity":    "critical",
      "detail":      "OpenClaw gateway listens on all interfaces. Restrict to 127.0.0.1.",
      "remediation": "Set bind_address = 127.0.0.1 in openclaw.json and restart the service."
    }
  ]
}
```

Anvil-scanner parses `findings` as an array of finding objects (see schema below).  An empty `findings` array is valid and produces no checks.

---

## Finding JSON Schema

Each element of the `findings` array must conform to:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `checkId` | string | yes | Stable identifier, e.g. `OC-CFG-001` |
| `title` | string | yes | Short human-readable name |
| `severity` | string | yes | `"critical"`, `"warn"`, or `"info"` (case-insensitive) |
| `detail` | string | no | Explanation of the finding |
| `remediation` | string | no | Fix instructions (may contain generic "update openclaw" text — see below) |

---

## Severity Mapping

OpenClaw severities are mapped to anvil-scanner `Status` and `Severity` values:

| OpenClaw severity | Status | Severity | Appears in Priority Findings? |
|-------------------|--------|----------|-------------------------------|
| `critical` | `FAIL` | `critical` | Yes (FAIL + critical) |
| `warn` | `WARN` | `medium` | No (medium never promotes) |
| `info` | `PASS` | `low` | No |
| anything else | `SKIP` | `low` | No |

The **Priority Findings** rule (`status ∈ {FAIL, WARN} AND severity ∈ {critical, high}`) means only `critical`-severity OpenClaw findings surface at the top of the report.  `warn` findings appear in the extended checks table but not the priority list.

---

## Remediation Tailoring

Generic "please update OpenClaw" remediation text is rewritten to the channel-specific upgrade command before storing the finding:

| Channel | Upgrade command |
|---------|----------------|
| `npm` | `npm update -g openclaw` |
| `brew` | `brew upgrade openclaw` |
| `source` | `cd $OPENCLAW_SRC && git pull && make install` |
| `unknown` | `see https://openclaw.io/install for upgrade instructions` |

Trigger phrases that activate tailoring (case-insensitive, substring match):
- `run \`openclaw update\``
- `run openclaw update`
- `openclaw update`
- `update openclaw`
- `upgrade openclaw`

Only the first matching trigger in the remediation string is replaced.  Unrelated text is passed through unchanged.

---

## Error Handling and SKIP Conditions

All error conditions produce exactly **one `SKIP` check** with ID `OC-AUDIT-000` and name `OpenClaw security audit`.  This ensures the broader scan always completes and the report clearly shows why no OpenClaw findings are present.

| Condition | SKIP detail |
|-----------|-------------|
| Binary not on `PATH` | `openclaw not found on PATH; skipping OpenClaw configuration audit. Install OpenClaw or add it to PATH to enable this check.` |
| Subprocess timed out | `openclaw security audit timed out after 30s` (npm channel appends a warm-up hint) |
| Exit code `-1` (post-install check) | `openclaw not found on PATH` |
| Non-zero exit code | `openclaw security audit exited <N>: <first 200 chars of stderr>` |
| Malformed JSON | `could not parse openclaw audit output as JSON` |
| `findings` key absent | `openclaw audit returned no findings list` |

The `npm` channel appends an additional note on timeout:
> *(npm installs can be slow to warm up on the first run of the day; rerun once and see if it resolves)*

---

## Report Integration

### HTML report

OpenClaw findings appear in a dedicated **OpenClaw Audit** section, rendered after the main hardening checks.  The section is only included when at least one non-SKIP finding exists.  Each finding shows its ID, title, status badge, severity, and detail (including the tailored remediation and source stamp).

The subnav tab **"OpenClaw"** is only added when the section has content.

### JSON report

OpenClaw findings are NOT included in the top-level `checks` array or `priority_findings`.  They are available as `oc_checks` in the full report data but the current JSON schema (`--json`) focuses on hardening checks only.  This may be extended in a future version.

### Terminal output

```
Running OpenClaw security audit... 7 finding(s)
```

Or, when OpenClaw is not installed:

```
Running OpenClaw security audit... (skipped — openclaw not installed)
```

---

## OpenClaw's End of the Contract

This document specifies what anvil-scanner expects from `openclaw security audit --json`.  OpenClaw must:

1. Write a valid JSON object with a `"findings"` array to stdout on exit code 0.
2. Write diagnostic text to stderr (not stdout) on failure.
3. Exit within 30 seconds.
4. Use only the severity values `"critical"`, `"warn"`, and `"info"`.
5. Provide stable `checkId` values so HTML anchors remain linkable across versions.

Breaking any of these produces a SKIP with an explanatory message rather than a hard failure, so users always get a complete scan report.

---

## Extending the Protocol (Future)

The protocol is intentionally minimal.  Proposed extensions (tracked separately):

- `"category"` field on findings for grouping in the report
- `"cve"` array for findings that correspond to known CVEs
- `"remediation_url"` for deep links into OpenClaw's own documentation
- `"fixed_in"` version string to indicate when a finding was resolved
- A `version` field at the top level of the audit payload for schema versioning
