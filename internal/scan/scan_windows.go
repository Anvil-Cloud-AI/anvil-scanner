//go:build windows

package scan

import (
	"fmt"
	"time"
)

// This file orchestrates the Windows hardening checks. The Unix scan
// orchestration in scan.go calls into macOS/Linux/RPi-specific runners that do
// not exist on Windows, so Windows has its own RunAllChecksInto here.

// Platform returns the canonical platform name on Windows.
func Platform() string {
	return "Windows"
}

// RunAllChecksInto populates b with the Windows hardening checks. WIN-000 is an
// informational entry recording the detected SKU (Windows 11 Client vs Server),
// followed by the individual WIN-* checks. More checks are added as they land.
func RunAllChecksInto(b *CheckBuilder) {
	b.Pass(
		"WIN-000",
		"Windows platform detected",
		fmt.Sprintf("Detected %s", DetectWindowsSKU()),
		SeverityLow,
	)
	checkWindowsFirewall(b)
}

// RunAllChecks executes all hardening checks for the current platform and
// returns an aggregated Result. On Windows this yields the SKIP placeholder.
func RunAllChecks() Result {
	b := NewBuilder(WithClock(func() time.Time { return time.Now().UTC() }))
	RunAllChecksInto(b)
	return b.Build()
}
