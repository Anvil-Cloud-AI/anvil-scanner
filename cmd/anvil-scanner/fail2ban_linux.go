//go:build linux

package main

import (
	"regexp"
	"strings"

	iexec "github.com/Anvil-Cloud-AI/anvil-scanner/internal/exec"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/report"
)

var jailListRE = regexp.MustCompile(`Jail list:\s*(.+)`)

func collectFail2ban() *report.Fail2banInfo {
	installed := iexec.Run("which", "fail2ban-client").Success()
	info := &report.Fail2banInfo{Installed: installed}
	if !installed {
		return info
	}
	// Use systemctl is-active (works without root) for the run state.
	// fail2ban-client status would also work but requires root or being
	// in the fail2ban group, which made the report claim Running=false
	// for non-root scans against a healthy service.
	activeRes := iexec.Run("systemctl", "is-active", "fail2ban")
	info.Running = strings.TrimSpace(activeRes.Stdout) == "active"
	if !info.Running {
		return info
	}
	// Best-effort jail list — may fail without root permission to the
	// fail2ban socket.  Absence does not change Running.
	res := iexec.Run("fail2ban-client", "status")
	if res.Success() {
		if m := jailListRE.FindStringSubmatch(res.Stdout); m != nil {
			for _, j := range strings.Split(m[1], ",") {
				if j = strings.TrimSpace(j); j != "" {
					info.Jails = append(info.Jails, j)
				}
			}
		}
	}
	return info
}
