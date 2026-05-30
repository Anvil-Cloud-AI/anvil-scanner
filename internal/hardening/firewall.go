//go:build darwin || linux

package hardening

import (
	"fmt"
	osexec "os/exec"
	"runtime"
	"strings"

	iexec "github.com/Anvil-Cloud-AI/anvil-scanner/internal/exec"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
)

// applyLinuxFirewall enables ufw and sets a default-deny inbound policy
// (FW-001, FW-002).  If ufw is not installed, it is installed first via
// apt-get (Debian/Ubuntu only).
func applyLinuxFirewall(idx map[string]scan.Status, r *Result) {
	if runtime.GOOS != "linux" {
		return
	}

	if !needsFix(idx, "FW-001") && !needsFix(idx, "FW-002") {
		return
	}

	// Install ufw if it's missing.  Without this, ufw enable/default below
	// fails silently with "command not found" on minimal Ubuntu installs.
	installedNow := false
	if _, err := osexec.LookPath("ufw"); err != nil {
		if !aptInstall("ufw", "FW-001", "Firewall (ufw) enabled", r) {
			return
		}
		installedNow = true
	}

	if needsFix(idx, "FW-001") {
		res := iexec.RunElevated("ufw", "--force", "enable")
		detail := "ufw --force enable"
		if installedNow {
			detail = "installed ufw via apt-get; " + detail
		}
		if res.Success() {
			r.applied("FW-001", "Firewall (ufw) enabled", detail)
		} else {
			r.failed("FW-001", "Firewall (ufw) enabled",
				fmt.Sprintf("ufw enable failed: %s", strings.TrimSpace(res.Stderr+res.Stdout)))
		}
	}

	if needsFix(idx, "FW-002") {
		res := iexec.RunElevated("ufw", "default", "deny", "incoming")
		if res.Success() {
			r.applied("FW-002", "Default deny inbound", "ufw default deny incoming")
		} else {
			r.failed("FW-002", "Default deny inbound",
				fmt.Sprintf("ufw default deny failed: %s", strings.TrimSpace(res.Stderr+res.Stdout)))
		}
	}
}

// aptInstall installs pkg via apt-get and records the outcome on r under the
// given check ID.  Returns true on success, false on failure (failure already
// recorded).  No-op for non-apt distros — those record a failed action so the
// user gets a clear message.
func aptInstall(pkg, checkID, name string, r *Result) bool {
	if _, err := osexec.LookPath("apt-get"); err != nil {
		r.failed(checkID, name,
			fmt.Sprintf("%s not installed and apt-get is unavailable — install manually for your distro", pkg))
		return false
	}
	// `apt-get update` is best-effort: on stale package lists a fresh sync
	// avoids "Unable to locate package" failures.  Ignore non-fatal errors.
	_ = iexec.RunElevated("apt-get", "update", "-qq")
	res := iexec.RunElevated("apt-get", "install", "-y", pkg)
	if !res.Success() {
		r.failed(checkID, name,
			fmt.Sprintf("apt-get install %s failed: %s", pkg, strings.TrimSpace(res.Stderr+res.Stdout)))
		return false
	}
	return true
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
	res := iexec.RunElevated(sfwPath, "--setglobalstate", "on")
	if res.Success() {
		r.applied("MACOS-004", "macOS Firewall enabled", "socketfilterfw --setglobalstate on")
	} else {
		r.failed("MACOS-004", "macOS Firewall enabled",
			fmt.Sprintf("socketfilterfw failed: %s", strings.TrimSpace(res.Stderr+res.Stdout)))
	}
}
