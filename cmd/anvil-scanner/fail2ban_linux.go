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
	res := iexec.Run("fail2ban-client", "status")
	info.Running = res.Success()
	if info.Running {
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
