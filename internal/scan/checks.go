// Package scan implements the check engine and platform-specific
// hardening checks. It is the Go port of python/anvil_scanner/scanner.py.
//
// The primary types exported here are Status, Severity, Check, and
// CheckBuilder. Platform-specific files (ssh.go, macos.go, linux.go,
// rpi.go) will land in subsequent phases and use CheckBuilder to
// register results.
//
// See docs/porting-checklist.md for the full check inventory and
// python/anvil_scanner/scanner.py for the reference implementation.
package scan

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Status is the result of a single check. The Python reference uses
// exactly four values and nothing else; we preserve that taxonomy.
//
// See docs/porting-checklist.md § "Status values".
type Status string

const (
	StatusPass Status = "PASS"
	StatusFail Status = "FAIL"
	StatusWarn Status = "WARN"
	StatusSkip Status = "SKIP"
)

// IsValid reports whether s is one of the four allowed statuses.
// A Status read from JSON or from a plugin subprocess should be
// validated before use.
func (s Status) IsValid() bool {
	switch s {
	case StatusPass, StatusFail, StatusWarn, StatusSkip:
		return true
	}
	return false
}

// Severity is the policy-assigned severity for a check. It is fixed
// per check-ID regardless of result status — e.g. the FileVault
// check always has Severity=SeverityMedium; only its Status varies.
//
// The Priority Findings promotion rule (hardening package) uses
// the pair (Status, Severity) together.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// IsValid reports whether s is one of the four allowed severities.
func (s Severity) IsValid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return true
	}
	return false
}

// rank returns a sort-friendly integer for severity (higher = worse).
// Not exported — callers should use explicit comparisons via the
// constants, not magic numbers.
func (s Severity) rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}

// Check is one row of the scan result. It matches the JSON shape
// that the Python reference emits, so downstream consumers (the
// HTML/JSON report, plugin subprocesses, and the public JSON
// schema) don't have to care whether Python or Go produced the
// output.
//
// Field tags use snake_case to stay wire-compatible with the
// Python output. Do NOT rename fields on the wire without a
// coordinated schema bump — the JSON schema is part of the
// v1.0.0 compatibility promise.
type Check struct {
	// ID is the check identifier (e.g. "SSH-041", "MACOS-002").
	// See docs/porting-checklist.md for the authoritative list.
	ID string `json:"id"`

	// Name is a short human-readable title shown in reports.
	Name string `json:"name"`

	// Status is the outcome: PASS, FAIL, WARN, or SKIP.
	Status Status `json:"status"`

	// Severity is the policy-assigned severity.
	Severity Severity `json:"severity"`

	// Detail is the longer-form explanation: what was checked,
	// what was observed, and (for non-PASS outcomes) what the
	// user should do. Kept as free-form string for now; the
	// report layer handles formatting.
	Detail string `json:"detail,omitempty"`

	// Remediation is an optional hint with a concrete command
	// or config change. Empty when the detail already says it.
	Remediation string `json:"remediation,omitempty"`

	// Timestamp is when the check ran. Useful when scan results
	// are spliced together from a plugin subprocess running on
	// a different wall-clock.
	Timestamp time.Time `json:"timestamp,omitempty"`
}

// Validate returns nil if the Check is shaped well enough to emit,
// or a descriptive error otherwise. Call this before serializing
// scan output — the JSON schema assumes ID is non-empty and
// Status/Severity are in range.
func (c Check) Validate() error {
	switch {
	case strings.TrimSpace(c.ID) == "":
		return fmt.Errorf("check: empty ID")
	case !c.Status.IsValid():
		return fmt.Errorf("check %s: invalid status %q", c.ID, c.Status)
	case !c.Severity.IsValid():
		return fmt.Errorf("check %s: invalid severity %q", c.ID, c.Severity)
	}
	return nil
}

// Result is the aggregate output of a scan — a flat list of Check
// records plus summary counts.
type Result struct {
	Checks  []Check   `json:"checks"`
	Started time.Time `json:"started"`
	Ended   time.Time `json:"ended"`
}

// Count returns the number of checks in the result with the given
// status. Convenience helper for reports and tests.
func (r Result) Count(s Status) int {
	n := 0
	for _, c := range r.Checks {
		if c.Status == s {
			n++
		}
	}
	return n
}

// MarshalJSON is defined explicitly so the summary counts (pass,
// fail, warn, skip) appear alongside the raw check list. The Python
// JSON output includes these for consumers that want a quick
// overview without iterating the full check list.
func (r Result) MarshalJSON() ([]byte, error) {
	type raw Result // avoid recursion
	summary := struct {
		raw
		Summary struct {
			Pass int `json:"pass"`
			Fail int `json:"fail"`
			Warn int `json:"warn"`
			Skip int `json:"skip"`
		} `json:"summary"`
	}{raw: raw(r)}
	summary.Summary.Pass = r.Count(StatusPass)
	summary.Summary.Fail = r.Count(StatusFail)
	summary.Summary.Warn = r.Count(StatusWarn)
	summary.Summary.Skip = r.Count(StatusSkip)
	return json.Marshal(summary)
}

// CheckBuilder is the fluent helper platform checks use to emit
// results. It replaces the Python `add()` closure pattern in
// scanner.py::extended_scan with a typed API that the compiler can
// catch misuse of.
//
// Usage (sketch):
//
//	b := scan.NewBuilder(scan.WithClock(now))
//	b.Pass("SSH-000", "sshd_config readable", "file exists and is readable", scan.SeverityHigh)
//	b.Skip("SSH-006", "MaxAuthTries ≤ 4", "SSH is not enabled", scan.SeverityMedium)
//	result := b.Build()
//
// The builder is NOT goroutine-safe. Scans are sequential by design —
// concurrent subprocess invocations would produce inconsistent
// wall-clock telemetry and would complicate audit logging. If a
// future phase needs parallelism, wrap this in a mutex at that call
// site rather than baking sync.Mutex into the common type.
type CheckBuilder struct {
	checks []Check
	now    func() time.Time
}

// BuilderOption configures a CheckBuilder at construction time.
type BuilderOption func(*CheckBuilder)

// WithClock injects a custom time source. Intended for tests that
// need deterministic Timestamp values.
func WithClock(clock func() time.Time) BuilderOption {
	return func(b *CheckBuilder) { b.now = clock }
}

// NewBuilder constructs a CheckBuilder with the given options.
func NewBuilder(opts ...BuilderOption) *CheckBuilder {
	b := &CheckBuilder{now: time.Now}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// add is the internal workhorse for Pass/Fail/Warn/Skip. Keeping
// the four public methods thin and typed makes check-site code
// self-documenting at the expense of a little surface area here.
func (b *CheckBuilder) add(id, name, detail string, status Status, sev Severity) {
	b.checks = append(b.checks, Check{
		ID:        id,
		Name:      name,
		Detail:    detail,
		Status:    status,
		Severity:  sev,
		Timestamp: b.now(),
	})
}

// Pass records a passing check.
func (b *CheckBuilder) Pass(id, name, detail string, sev Severity) {
	b.add(id, name, detail, StatusPass, sev)
}

// Fail records a failing check.
func (b *CheckBuilder) Fail(id, name, detail string, sev Severity) {
	b.add(id, name, detail, StatusFail, sev)
}

// Warn records a warning — something worth knowing about but not
// a hard failure. FileVault-off on macOS is the canonical example.
func (b *CheckBuilder) Warn(id, name, detail string, sev Severity) {
	b.add(id, name, detail, StatusWarn, sev)
}

// Skip records a check that wasn't run. The detail should explain
// why (missing binary, platform mismatch, feature disabled, etc.)
// so users don't mistake SKIP for a silent pass.
func (b *CheckBuilder) Skip(id, name, detail string, sev Severity) {
	b.add(id, name, detail, StatusSkip, sev)
}

// WithRemediation sets the remediation hint on the most recently
// added check. It's separate from Pass/Fail/Warn/Skip so the common
// case (no remediation) stays a single readable call.
//
// If called before any check has been added it is a no-op — the
// remediation text is silently dropped.
func (b *CheckBuilder) WithRemediation(text string) *CheckBuilder {
	if len(b.checks) == 0 {
		return b
	}
	b.checks[len(b.checks)-1].Remediation = text
	return b
}

// Build returns the accumulated Result. After calling Build, the
// builder should not be reused.
func (b *CheckBuilder) Build() Result {
	return Result{
		Checks: b.checks,
		// Started/Ended are the caller's responsibility — the
		// builder doesn't know when scanning began. The main
		// scan entry point sets these around the full run.
	}
}

// Len returns the number of checks accumulated so far. Useful for
// tests and for progress reporting during long scans.
func (b *CheckBuilder) Len() int { return len(b.checks) }
