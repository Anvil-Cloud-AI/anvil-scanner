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

// jailLocalContent is a conservative starting point: 5 failed attempts in
// 10 minutes triggers a 1-hour ban on sshd.  Users can tune later in the
// same file.
const jailLocalContent = `# Managed by anvil-scanner --harden.
# Customise freely; subsequent --harden runs leave this file alone.
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5

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
		if !aptInstall("fail2ban", "F2B-001", "fail2ban active", r) {
			return
		}
		installedNow = true
	}

	// Write jail.local only if it's missing — never clobber user customisations.
	wroteJail := false
	if _, statErr := os.Stat(jailLocalPath); os.IsNotExist(statErr) {
		if err := iexec.WriteFileElevated(jailLocalPath, []byte(jailLocalContent), "0644"); err != nil {
			r.failed("F2B-001", "fail2ban active",
				fmt.Sprintf("write %s: %v", jailLocalPath, err))
			return
		}
		wroteJail = true
	}

	// Enable + start (or restart, if it was already running with old config).
	enableRes := iexec.RunElevated("systemctl", "enable", "--now", "fail2ban")
	if !enableRes.Success() {
		r.failed("F2B-001", "fail2ban active",
			fmt.Sprintf("systemctl enable --now fail2ban: %s", strings.TrimSpace(enableRes.Stderr+enableRes.Stdout)))
		return
	}
	if wroteJail {
		// Pick up the new jail.  Restart is safer than reload across versions.
		_ = iexec.RunElevated("systemctl", "restart", "fail2ban")
	}

	var details []string
	if installedNow {
		details = append(details, "installed fail2ban via apt-get")
	}
	if wroteJail {
		details = append(details, "wrote "+jailLocalPath+" with sshd jail enabled")
	}
	details = append(details, "enabled + started fail2ban service")
	r.applied("F2B-001", "fail2ban active", strings.Join(details, "; "))
}
