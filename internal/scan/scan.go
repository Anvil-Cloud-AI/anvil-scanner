//go:build darwin || linux

package scan

import (
	"runtime"
	"time"
)

// Platform returns the canonical platform name used by all check runners.
func Platform() string {
	return canonicalPlatform()
}

// RunAllChecksInto populates b with all platform-appropriate hardening checks
// except RPI (Linux-only, requires DetectRPI). On Linux, callers should follow
// up with DetectRPI + RunRPIChecks.
func RunAllChecksInto(b *CheckBuilder) {
	platform := canonicalPlatform()
	RunMacOSChecks(b, platform)
	RunLinuxChecks(b, platform)

	var remoteLogin *bool
	if platform == "Darwin" {
		remoteLogin = MacOSRemoteLoginEnabled()
	}
	RunSSHChecks(b, platform, remoteLogin)
}

// RunAllChecks executes all hardening checks for the current platform and
// returns an aggregated Result. On Linux, RPI checks are excluded — use
// RunAllChecksInto + DetectRPI + RunRPIChecks for full coverage.
func RunAllChecks() Result {
	b := NewBuilder(WithClock(func() time.Time { return time.Now().UTC() }))
	RunAllChecksInto(b)
	return b.Build()
}

func canonicalPlatform() string {
	switch runtime.GOOS {
	case "darwin":
		return "Darwin"
	case "linux":
		return "Linux"
	default:
		return runtime.GOOS
	}
}
