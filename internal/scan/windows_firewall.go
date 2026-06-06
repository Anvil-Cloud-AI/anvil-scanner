//go:build windows

package scan

import iexec "github.com/Anvil-Cloud-AI/anvil-scanner/internal/exec"

// checkWindowsFirewall reports whether Windows Defender Firewall is enabled for
// every profile (Domain/Private/Public). WIN-FW-001. Applies to both Client and
// Server SKUs. Read-only — no elevation required.
//
// Uses PowerShell's Get-NetFirewallProfile with JSON output rather than
// `netsh advfirewall`, because netsh's "State ON/OFF" text is localized whereas
// the JSON Enabled field is not.
func checkWindowsFirewall(b *CheckBuilder) {
	const id = "WIN-FW-001"
	const name = "Windows Defender Firewall enabled (all profiles)"

	r := iexec.Run("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress")
	if !r.Success() {
		b.Skip(id, name, "could not query firewall profiles (Get-NetFirewallProfile failed)", SeverityCritical)
		return
	}

	profiles, err := parseFirewallProfiles(r.Stdout)
	if err != nil {
		b.Skip(id, name, err.Error(), SeverityCritical)
		return
	}

	status, detail := evalFirewallProfiles(profiles)
	switch status {
	case StatusPass:
		b.Pass(id, name, detail, SeverityCritical)
	case StatusFail:
		b.Fail(id, name, detail, SeverityCritical)
	default:
		b.Skip(id, name, detail, SeverityCritical)
	}
}
