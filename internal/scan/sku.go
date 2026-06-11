package scan

import "strings"

// WindowsSKU distinguishes the two Windows product families anvil-scanner
// targets: Windows 11 (Client — the default target) and Windows Server.
// Later phases use this so a check can apply to one SKU and SKIP on the other.
//
// The type and its parser live in an unconstrained file (no build tag) so the
// pure parsing logic is unit-testable on any platform; the actual registry
// read that feeds it lives in sku_windows.go.
type WindowsSKU int

const (
	SKUUnknown WindowsSKU = iota
	SKUClient
	SKUServer
)

func (s WindowsSKU) String() string {
	switch s {
	case SKUClient:
		return "Windows Client"
	case SKUServer:
		return "Windows Server"
	default:
		return "Unknown Windows SKU"
	}
}

// parseInstallationType maps the registry InstallationType value
// (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\InstallationType) to a
// WindowsSKU. "Client" → Windows 11/10 desktop; "Server" / "Server Core" →
// Windows Server. "Server" is checked first so "Server Core" classifies as
// Server. Pure function — no I/O — so it is testable on any platform.
func parseInstallationType(regOutput string) WindowsSKU {
	lower := strings.ToLower(regOutput)
	switch {
	case strings.Contains(lower, "server"):
		return SKUServer
	case strings.Contains(lower, "client"):
		return SKUClient
	default:
		return SKUUnknown
	}
}
