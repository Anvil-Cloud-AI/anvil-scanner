//go:build darwin || linux

package scan

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/exec"
)

// openclawPorts is the set of well-known OpenClaw network ports. Rules
// allowing these from "Anywhere" in ufw are flagged by FW-003.
var openclawPorts = []string{"18789", "18791", "9090", "19001"}

// iptablesRuleRE matches numbered iptables rule lines (lines starting
// with a digit). Used to count active rules in the FW-001 fallback.
var iptablesRuleRE = regexp.MustCompile(`^\s*\d+`)

// RunLinuxChecks executes FW-001 through FW-003 and adds results to b.
// It is a no-op on non-Linux platforms.
func RunLinuxChecks(b *CheckBuilder, platform string) {
	if platform != "Linux" {
		return
	}
	fw001, ufwOut := fw001Firewall(b)
	if fw001 {
		fw002DefaultDeny(b, ufwOut)
		fw003OpenClawPorts(b, ufwOut)
	}
}

// fw001Firewall checks whether a firewall is active. Returns (true, ufwOut)
// when ufw is active so FW-002/003 can reuse the already-fetched status
// output. Returns (false, "") in all other cases — FW-002/003 are
// dependent on ufw being active and are silently skipped otherwise,
// matching the Python reference behavior.
func fw001Firewall(b *CheckBuilder) (ufwActive bool, ufwOut string) {
	ufwRes := exec.Run("ufw", "status")

	if ufwRes.Success() {
		if strings.Contains(ufwRes.Stdout, "Status: active") {
			b.Pass("FW-001", "Firewall (ufw) enabled",
				"ufw is active", SeverityCritical)
			return true, ufwRes.Stdout
		}
		b.Fail("FW-001", "Firewall (ufw) enabled",
			"ufw is installed but not active. Run: sudo ufw enable",
			SeverityCritical)
		return false, ""
	}

	// ufw unavailable — try iptables fallback
	iptRes := exec.Run("iptables", "-L", "-n", "--line-numbers")
	if iptRes.Success() && strings.Contains(iptRes.Stdout, "Chain INPUT") {
		ruleCount := 0
		for _, line := range strings.Split(iptRes.Stdout, "\n") {
			if iptablesRuleRE.MatchString(line) {
				ruleCount++
			}
		}
		if ruleCount > 0 {
			b.Pass("FW-001", "Firewall (iptables) enabled",
				fmt.Sprintf("iptables active with %d rule(s) — ufw not installed", ruleCount),
				SeverityCritical)
		} else {
			b.Warn("FW-001", "Firewall enabled",
				"iptables present but no custom rules. Install ufw: sudo apt install ufw",
				SeverityCritical)
		}
	} else {
		b.Fail("FW-001", "Firewall enabled",
			"No firewall detected (ufw not installed, iptables empty or unavailable). "+
				"Install and enable: sudo apt install ufw && sudo ufw enable",
			SeverityCritical)
	}
	return false, ""
}

// fw002DefaultDeny checks whether ufw's default inbound policy is deny
// or reject. Only called when ufw is confirmed active.
func fw002DefaultDeny(b *CheckBuilder, ufwOut string) {
	if strings.Contains(ufwOut, "Default: deny (incoming)") ||
		strings.Contains(ufwOut, "Default: reject (incoming)") {
		b.Pass("FW-002", "Default deny inbound",
			"ufw default policy denies incoming traffic", SeverityHigh)
	} else {
		b.Fail("FW-002", "Default deny inbound",
			"ufw default incoming policy is not deny/reject. Run: sudo ufw default deny incoming",
			SeverityHigh)
	}
}

// fw003OpenClawPorts checks whether ufw rules allow OpenClaw ports from
// "Anywhere" (unrestricted). Only called when ufw is confirmed active.
func fw003OpenClawPorts(b *CheckBuilder, ufwOut string) {
	var violations []string
	for _, line := range strings.Split(ufwOut, "\n") {
		for _, port := range openclawPorts {
			if strings.Contains(line, port) &&
				strings.Contains(line, "ALLOW") &&
				strings.Contains(line, "Anywhere") {
				violations = append(violations,
					fmt.Sprintf("Port %s allows traffic from anywhere", port))
			}
		}
	}
	if len(violations) > 0 {
		b.Warn("FW-003", "OpenClaw ports restricted in firewall",
			"Firewall allows OpenClaw ports from any source: "+
				strings.Join(violations, "; ")+
				". Restrict to trusted IPs: sudo ufw allow from <IP> to any port <PORT>",
			SeverityHigh)
	} else {
		b.Pass("FW-003", "OpenClaw ports restricted in firewall",
			"No unrestricted OpenClaw port rules detected", SeverityHigh)
	}
}
