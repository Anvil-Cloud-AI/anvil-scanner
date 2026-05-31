//go:build darwin || linux

package scan

import (
	"fmt"
	osexec "os/exec"
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

// RunLinuxChecks executes FW-001 through FW-003 and F2B-001 and adds results to b.
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
	f2b001Fail2ban(b)
}

// f2b001Fail2ban checks whether fail2ban is installed and the sshd jail is
// active.
//
// Install state and run state are checked separately so non-root scans
// produce accurate results:
//
//   - Installed via LookPath (definitive, no permissions needed)
//   - Running via `systemctl is-active fail2ban` (no root needed)
//   - sshd jail via `fail2ban-client status` (requires root — best-effort
//     introspection; absence is reported as a soft note, not a fail)
//
// Prior versions used `fail2ban-client status` as the running check, which
// returned non-zero on permission denied for non-root users — so the scan
// reported "service not running" for a service that was actually fine.
func f2b001Fail2ban(b *CheckBuilder) {
	if _, err := osexec.LookPath("fail2ban-client"); err != nil {
		b.Fail("F2B-001", "fail2ban service",
			"fail2ban not installed — SSH brute-force protection unavailable. "+
				"Install and enable: sudo apt install fail2ban && sudo systemctl enable --now fail2ban",
			SeverityHigh)
		return
	}

	activeRes := exec.Run("systemctl", "is-active", "fail2ban")
	if strings.TrimSpace(activeRes.Stdout) != "active" {
		b.Fail("F2B-001", "fail2ban service",
			"fail2ban installed but the service is not running. "+
				"Enable and start: sudo systemctl enable --now fail2ban",
			SeverityHigh)
		return
	}

	// Service is up.  Try to introspect jails — requires fail2ban socket
	// access (root or fail2ban group), so silently tolerate failure.
	jailsRes := exec.Run("fail2ban-client", "status")
	switch {
	case jailsRes.Success() && strings.Contains(jailsRes.Stdout, "sshd"):
		b.Pass("F2B-001", "fail2ban service",
			"fail2ban running with sshd jail enabled", SeverityHigh)
	case jailsRes.Success():
		b.Warn("F2B-001", "fail2ban service",
			"fail2ban is running but no sshd jail is active. "+
				"Enable the sshd jail in /etc/fail2ban/jail.local",
			SeverityHigh)
	default:
		// Couldn't introspect jails (typically permission denied).  Service
		// is active per systemd, so this is a PASS — re-run under sudo if
		// the user wants the jail breakdown.
		b.Pass("F2B-001", "fail2ban service",
			"fail2ban service is active (re-run with sudo to introspect jails)",
			SeverityHigh)
	}
}

// fw001Firewall checks whether a firewall is active. Returns (true, ufwOut)
// when ufw is active so FW-002/003 can reuse the already-fetched status
// output. Returns (false, "") in all other cases — FW-002/003 are
// dependent on ufw being active and are silently skipped otherwise,
// matching the Python reference behavior.
//
// Install state and runtime state are checked separately so we can give an
// accurate verdict even on non-root scans (where `ufw status` errors out
// with "you need to be root").  Order:
//
//  1. binary on PATH? if no → fall through to iptables
//  2. `ufw status verbose` works? prefer this — it gives us the default
//     policy line FW-002 needs
//  3. `systemctl is-active ufw` (no root required) → still a definitive
//     answer for FW-001, but we lose the verbose output so FW-002/003 skip
func fw001Firewall(b *CheckBuilder) (ufwActive bool, ufwOut string) {
	if _, err := osexec.LookPath("ufw"); err == nil {
		// `ufw status verbose` is required to see the default policy line
		// ("Default: deny (incoming), allow (outgoing), ...").  Plain
		// `ufw status` only shows active/inactive and rules — FW-002 has
		// no chance of passing without the verbose output.
		ufwRes := exec.Run("ufw", "status", "verbose")
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

		// ufw is installed but we couldn't read its status (typically
		// "you need to be root").  systemctl is-active works without root.
		sysRes := exec.Run("systemctl", "is-active", "ufw")
		switch strings.TrimSpace(sysRes.Stdout) {
		case "active":
			b.Pass("FW-001", "Firewall (ufw) enabled",
				"ufw service is active (re-run scan with sudo to also check FW-002 default policy and FW-003 port rules)",
				SeverityCritical)
			return false, "" // no verbose output → FW-002/003 are skipped
		case "inactive", "failed":
			b.Fail("FW-001", "Firewall (ufw) enabled",
				"ufw is installed but the service is not active. Run: sudo ufw enable",
				SeverityCritical)
			return false, ""
		}
		// systemctl had no idea either — fall through to iptables / final FAIL.
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
