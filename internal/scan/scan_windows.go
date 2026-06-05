//go:build windows

package scan

import (
	"fmt"
	"time"
)

// This file is a Tier-0 Windows placeholder. The Unix scan orchestration in
// scan.go calls into macOS/Linux/RPi-specific runners that do not exist on
// Windows. Until real Windows hardening checks are implemented, the Windows
// build emits a single SKIP placeholder so the report pipeline runs end to
// end and produces a coherent (empty-of-findings) result.

// Platform returns the canonical platform name on Windows.
func Platform() string {
	return "Windows"
}

// RunAllChecksInto populates b with the Windows placeholder check set. For
// Tier-0 this is a single SKIP entry; real Windows checks land in a later phase.
func RunAllChecksInto(b *CheckBuilder) {
	b.Skip(
		"WIN-000",
		"Windows checks (placeholder)",
		fmt.Sprintf("Windows hardening checks not yet implemented (detected %s)", DetectWindowsSKU()),
		SeverityMedium,
	)
}

// RunAllChecks executes all hardening checks for the current platform and
// returns an aggregated Result. On Windows this yields the SKIP placeholder.
func RunAllChecks() Result {
	b := NewBuilder(WithClock(func() time.Time { return time.Now().UTC() }))
	RunAllChecksInto(b)
	return b.Build()
}
