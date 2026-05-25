//go:build darwin || linux

package hardening

import (
	"fmt"
	"runtime"
	"strings"

	iexec "github.com/Anvil-Cloud-AI/anvil-scanner/internal/exec"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
)

// applyLinuxFirewall enables ufw and sets a default-deny inbound policy (FW-001, FW-002).
func applyLinuxFirewall(idx map[string]scan.Status, r *Result) {
	if runtime.GOOS != "linux" {
		return
	}

	if needsFix(idx, "FW-001") {
		res := iexec.Run("ufw", "--force", "enable")
		if res.Success() {
			r.applied("FW-001", "Firewall (ufw) enabled", "ufw --force enable")
		} else {
			r.failed("FW-001", "Firewall (ufw) enabled",
				fmt.Sprintf("ufw enable failed: %s", strings.TrimSpace(res.Stderr+res.Stdout)))
		}
	}

	if needsFix(idx, "FW-002") {
		res := iexec.Run("ufw", "default", "deny", "incoming")
		if res.Success() {
			r.applied("FW-002", "Default deny inbound", "ufw default deny incoming")
		} else {
			r.failed("FW-002", "Default deny inbound",
				fmt.Sprintf("ufw default deny failed: %s", strings.TrimSpace(res.Stderr+res.Stdout)))
		}
	}
}

// applyMacOSFirewall enables the macOS application firewall (MACOS-004).
func applyMacOSFirewall(idx map[string]scan.Status, r *Result) {
	if runtime.GOOS != "darwin" {
		return
	}

	if !needsFix(idx, "MACOS-004") {
		return
	}

	const sfwPath = "/usr/libexec/ApplicationFirewall/socketfilterfw"
	res := iexec.Run(sfwPath, "--setglobalstate", "on")
	if res.Success() {
		r.applied("MACOS-004", "macOS Firewall enabled", "socketfilterfw --setglobalstate on")
	} else {
		r.failed("MACOS-004", "macOS Firewall enabled",
			fmt.Sprintf("socketfilterfw failed: %s", strings.TrimSpace(res.Stderr+res.Stdout)))
	}
}
