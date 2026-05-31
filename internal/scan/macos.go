//go:build darwin || linux

package scan

import (
	"strconv"
	"strings"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/exec"
)

// RunMacOSChecks executes MACOS-001 through MACOS-008 and adds results
// to b. It is a no-op on non-Darwin platforms — callers must check the
// platform before calling, or call it unconditionally and it returns
// early. All subprocess invocations go through internal/exec so they
// respect the global timeout and return structured results.
func RunMacOSChecks(b *CheckBuilder, platform string) {
	if platform != "Darwin" {
		return
	}

	macos001SIP(b)
	macos002FileVault(b)
	macos003Gatekeeper(b)
	macos004Firewall(b)
	macos005RemoteLogin(b)
	macos006ScreenSharing(b)
	macos007AutoLogin(b)
	macos008FirmwarePassword(b)
}

// macos001SIP — System Integrity Protection.
// csrutil(8) reports "System Integrity Protection status: enabled."
// PASS when enabled, FAIL when explicitly disabled, SKIP when csrutil
// is unavailable.
func macos001SIP(b *CheckBuilder) {
	res := exec.Run("csrutil", "status")
	switch {
	case res.ExitCode == -1: // binary not found
		b.Skip("MACOS-001", "System Integrity Protection (SIP)",
			"csrutil not available", SeverityCritical)
	case res.Success() && strings.Contains(strings.ToLower(res.Stdout), "enabled"):
		b.Pass("MACOS-001", "System Integrity Protection (SIP)",
			strings.TrimSpace(res.Stdout), SeverityCritical)
	default:
		b.Fail("MACOS-001", "System Integrity Protection (SIP)",
			strings.TrimSpace(res.Stdout), SeverityCritical)
	}
}

// macos002FileVault — Full disk encryption.
//
// FileVault is a *suggestion*, not a mandatory hardening item.
// Off → WARN (not FAIL) + severity medium so it does NOT promote to
// Priority Findings. This is the canonical FileVault calibration rule
// (downgraded 2026-04-19).
//
// Behavioral contract: FileVault absence is a suggestion (medium severity),
// never promoted to a critical priority finding.
func macos002FileVault(b *CheckBuilder) {
	res := exec.Run("fdesetup", "status")
	out := strings.TrimSpace(res.Stdout)
	switch {
	case res.ExitCode == -1:
		b.Skip("MACOS-002", "FileVault (full disk encryption)",
			"fdesetup not available", SeverityMedium)
	case res.Success() && strings.Contains(strings.ToLower(out), "on"):
		b.Pass("MACOS-002", "FileVault (full disk encryption)",
			out, SeverityMedium)
	default:
		b.Warn("MACOS-002", "FileVault (full disk encryption)",
			out+" — consider enabling FileVault for at-rest data protection (suggested, not required).",
			SeverityMedium)
	}
}

// macos003Gatekeeper — Application signing enforcement.
// spctl --status reports "assessments enabled" when on.
func macos003Gatekeeper(b *CheckBuilder) {
	res := exec.Run("spctl", "--status")
	out := strings.TrimSpace(res.Stdout)
	switch {
	case res.ExitCode == -1:
		b.Skip("MACOS-003", "Gatekeeper enabled",
			"spctl not available", SeverityHigh)
	case res.Success() && strings.Contains(strings.ToLower(out), "enabled"):
		b.Pass("MACOS-003", "Gatekeeper enabled", out, SeverityHigh)
	default:
		b.Fail("MACOS-003", "Gatekeeper enabled", out, SeverityHigh)
	}
}

// macos004Firewall — Application Layer Firewall.
// globalstate: 0 = off, 1 = on (block all incoming), 2 = on (allow
// signed). Any value ≥ 1 is PASS.
func macos004Firewall(b *CheckBuilder) {
	res := exec.Run("defaults", "read",
		"/Library/Preferences/com.apple.alf", "globalstate")
	if !res.Success() {
		b.Skip("MACOS-004", "macOS Firewall enabled",
			"Could not read firewall preferences", SeverityHigh)
		return
	}
	out := strings.TrimSpace(res.Stdout)
	state, err := strconv.Atoi(out)
	if err != nil {
		b.Warn("MACOS-004", "macOS Firewall enabled",
			"Unexpected firewall state: "+out, SeverityHigh)
		return
	}
	if state >= 1 {
		b.Pass("MACOS-004", "macOS Firewall enabled",
			"Firewall globalstate = "+out, SeverityHigh)
	} else {
		b.Fail("MACOS-004", "macOS Firewall enabled",
			"Firewall is disabled (globalstate = 0)", SeverityHigh)
	}
}

// macos005RemoteLogin — SSH server toggle.
// PASS when off (Remote Login disabled), WARN when on (intentional SSH
// access is fine but worth flagging), SKIP only when we truly cannot
// determine the state.
//
// When run under sudo, systemsetup often fails. We fall back to checking
// whether the com.openssh.sshd launchd job is loaded. This is not 100%
// perfect but is good enough to avoid the noisy "status unknown" path
// in the report when Remote Login is actually enabled.
func macos005RemoteLogin(b *CheckBuilder) {
	res := exec.Run("systemsetup", "-getremotelogin")
	out := strings.TrimSpace(res.Stdout)

	if res.Success() && !strings.Contains(out, "administrator access") {
		lower := strings.ToLower(out)
		if strings.Contains(lower, "off") {
			b.Pass("MACOS-005", "Remote Login (SSH) restricted",
				"Remote Login is Off", SeverityMedium)
		} else {
			b.Warn("MACOS-005", "Remote Login (SSH) restricted",
				"Remote Login is enabled — verify this is intentional",
				SeverityMedium)
		}
		return
	}

	// Fallback: check if the sshd job is loaded via launchctl.
	// This works better under sudo.
	launchRes := exec.Run("launchctl", "list", "com.openssh.sshd")
	if launchRes.Success() {
		// If the job is listed, Remote Login is effectively enabled.
		b.Warn("MACOS-005", "Remote Login (SSH) restricted",
			"Remote Login appears to be enabled (detected via launchctl)",
			SeverityMedium)
		return
	}

	// Still can't tell.
	b.Skip("MACOS-005", "Remote Login (SSH) restricted",
		"Could not determine Remote Login state (systemsetup requires a non-root admin session; launchctl fallback also inconclusive)",
		SeverityMedium)
}

// macos006ScreenSharing — Screen sharing service.
// launchctl list com.apple.screensharing exits non-zero when the
// service is not loaded → PASS. ExitCode -1 means launchctl is absent
// (not a macOS system or run without a user session) → SKIP.
func macos006ScreenSharing(b *CheckBuilder) {
	res := exec.Run("launchctl", "list", "com.apple.screensharing")
	switch {
	case res.ExitCode == -1:
		b.Skip("MACOS-006", "Screen sharing disabled",
			"launchctl not available — cannot check screen sharing status", SeverityMedium)
	case res.ExitCode != 0:
		b.Pass("MACOS-006", "Screen sharing disabled",
			"Screen sharing service not loaded", SeverityMedium)
	default:
		b.Warn("MACOS-006", "Screen sharing disabled",
			"Screen sharing service appears to be loaded — verify this is intentional",
			SeverityMedium)
	}
}

// macos007AutoLogin — Automatic login at boot.
// FAIL when autoLoginUser is set, PASS when the key is absent (rc != 0
// means the defaults key doesn't exist).
// Note: Python source uses severity "medium"; the porting checklist
// lists "critical". Following the Python reference implementation here.
func macos007AutoLogin(b *CheckBuilder) {
	res := exec.Run("defaults", "read",
		"/Library/Preferences/com.apple.loginwindow", "autoLoginUser")
	if res.ExitCode != 0 {
		b.Pass("MACOS-007", "Automatic login disabled",
			"No autoLoginUser set (automatic login is disabled)", SeverityMedium)
	} else {
		raw := strings.Map(func(r rune) rune {
			if r < 32 || r == 127 {
				return -1
			}
			return r
		}, strings.TrimSpace(res.Stdout))
		b.Fail("MACOS-007", "Automatic login disabled",
			"Automatic login enabled for user: "+raw,
			SeverityMedium)
	}
}

// macos008FirmwarePassword — Intel-only firmware password.
// SKIP on Apple Silicon (arm64) with an explanatory message pointing
// to Activation Lock as the equivalent control.
func macos008FirmwarePassword(b *CheckBuilder) {
	archRes := exec.Run("uname", "-m")
	arch := strings.TrimSpace(archRes.Stdout)

	if !strings.Contains(arch, "x86_64") {
		b.Skip("MACOS-008", "Firmware password set (Intel)",
			"Apple Silicon Mac — firmware password N/A (use Activation Lock instead)",
			SeverityMedium)
		return
	}

	res := exec.Run("firmwarepasswd", "-check")
	out := strings.TrimSpace(res.Stdout)
	switch {
	case res.ExitCode == -1:
		b.Skip("MACOS-008", "Firmware password set (Intel)",
			"firmwarepasswd not available (may need root)", SeverityMedium)
	case res.Success() && strings.Contains(strings.ToLower(out), "yes"):
		b.Pass("MACOS-008", "Firmware password set (Intel)", out, SeverityMedium)
	default:
		b.Warn("MACOS-008", "Firmware password set (Intel)", out, SeverityMedium)
	}
}
