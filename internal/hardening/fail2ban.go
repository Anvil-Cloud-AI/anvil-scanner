//go:build darwin || linux

package hardening

import (
	"fmt"
	"os"
	osexec "os/exec"
	"runtime"
	"strings"

	iexec "github.com/Anvil-Cloud-AI/anvil-scanner/internal/exec"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
)

// jailLocalPath is the standard fail2ban local override.  jail.conf ships
// with the package; jail.local takes precedence and survives upgrades.
const jailLocalPath = "/etc/fail2ban/jail.local"

// jailMarker identifies files we previously wrote.  Used to make rewrite
// idempotent — we update our own config to ship fixes, but never clobber a
// hand-edited jail.local.
const jailMarker = "# Managed by anvil-scanner --harden."

// jailLocalContent is a conservative starting point: 5 failed attempts in
// 10 minutes triggers a 1-hour ban on sshd.  Users can tune later in the
// same file.
//
// backend = systemd is required on modern Ubuntu (22.04+) and most current
// systemd distros — /var/log/auth.log is no longer written by default, so
// the default file backend silently produces an inactive jail.  Reading
// from the systemd journal works on every systemd host that runs sshd.
const jailLocalContent = `# Managed by anvil-scanner --harden.
# Customise freely; subsequent --harden runs leave this file alone.
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
ignoreip = 127.0.0.1/8 ::1
backend  = systemd

[sshd]
enabled = true
`

// applyFail2ban ensures fail2ban is installed, the sshd jail is enabled,
// and the service is running (F2B-001).
func applyFail2ban(idx map[string]scan.Status, r *Result) {
	if runtime.GOOS != "linux" {
		return
	}
	if !needsFix(idx, "F2B-001") {
		return
	}

	installedNow := false
	if _, err := osexec.LookPath("fail2ban-client"); err != nil {
		if !aptInstall("fail2ban", "F2B-001", "fail2ban service", r) {
			return
		}
		installedNow = true
	}

	// Decide whether to write jail.local:
	//   - file missing  → write
	//   - we wrote it before (marker present) → overwrite (lets us ship fixes)
	//   - user-authored (no marker) → leave alone, never clobber customisations
	wroteJail := false
	shouldWrite := false
	if _, statErr := os.Stat(jailLocalPath); os.IsNotExist(statErr) {
		shouldWrite = true
	} else if existing, readErr := iexec.ReadFileElevated(jailLocalPath); readErr == nil {
		if strings.Contains(string(existing), jailMarker) {
			shouldWrite = true
		}
	}
	if shouldWrite {
		if err := iexec.WriteFileElevated(jailLocalPath, []byte(jailLocalContent), "0644"); err != nil {
			r.failed("F2B-001", "fail2ban service",
				fmt.Sprintf("write %s: %v", jailLocalPath, err))
			return
		}
		wroteJail = true
	}

	// Enable + start (or restart, if it was already running with old config).
	enableRes := iexec.RunElevated("systemctl", "enable", "--now", "fail2ban")
	if !enableRes.Success() {
		r.failed("F2B-001", "fail2ban service",
			fmt.Sprintf("systemctl enable --now fail2ban: %s", strings.TrimSpace(enableRes.Stderr+enableRes.Stdout)))
		return
	}
	if wroteJail {
		// Pick up the new jail.  Restart is safer than reload across versions.
		if restartRes := iexec.RunElevated("systemctl", "restart", "fail2ban"); !restartRes.Success() {
			r.failed("F2B-001", "fail2ban service",
				fmt.Sprintf("systemctl restart fail2ban failed after writing jail.local: %s — config is likely invalid, run: sudo systemctl status fail2ban",
					strings.TrimSpace(restartRes.Stderr+restartRes.Stdout)))
			return
		}
	}

	// Verify with systemctl is-active.  Earlier versions tried polling
	// `fail2ban-client status` for a stricter "daemon is serving requests"
	// signal, but that requires root/fail2ban-group access — for non-root
	// hardening runs it failed every time and reported a spurious failure
	// against a service that had actually come up fine.  systemctl tracks
	// the same Type=forking unit state and works without elevation.
	activeRes := iexec.Run("systemctl", "is-active", "fail2ban")
	if strings.TrimSpace(activeRes.Stdout) != "active" {
		jr := iexec.RunElevated("journalctl", "-u", "fail2ban", "-n", "20", "--no-pager")
		journal := strings.TrimSpace(jr.Stdout)
		if len(journal) > 400 {
			journal = "..." + journal[len(journal)-400:]
		}
		r.failed("F2B-001", "fail2ban service",
			fmt.Sprintf("service did not reach active state — check: sudo systemctl status fail2ban\n%s", journal))
		return
	}

	var details []string
	if installedNow {
		details = append(details, "installed fail2ban via apt-get")
	}
	if wroteJail {
		details = append(details, "wrote "+jailLocalPath+" with sshd jail enabled")
	}
	details = append(details, "enabled + started fail2ban service (verified active)")
	r.applied("F2B-001", "fail2ban service", strings.Join(details, "; "))
}
