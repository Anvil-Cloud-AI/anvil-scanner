//go:build windows

package scan

import iexec "github.com/Anvil-Cloud-AI/anvil-scanner/internal/exec"

// This file holds the windows-tagged collectors for the read-only WIN-* checks.
// Each runs a PowerShell query and delegates the verdict to a pure evaluator in
// windows_checks_parse.go (unit-tested on any platform). All are read-only and
// need no elevation.

// ps runs a PowerShell command non-interactively and returns the exec Result.
func ps(command string) iexec.Result {
	return iexec.Run("powershell", "-NoProfile", "-NonInteractive", "-Command", command)
}

// emitResult records a (status, detail) verdict on b under the given id/name/sev.
func emitResult(b *CheckBuilder, id, name string, sev Severity, status Status, detail string) {
	switch status {
	case StatusPass:
		b.Pass(id, name, detail, sev)
	case StatusFail:
		b.Fail(id, name, detail, sev)
	case StatusWarn:
		b.Warn(id, name, detail, sev)
	default:
		b.Skip(id, name, detail, sev)
	}
}

// checkWindowsDefenderAV — WIN-AV-001. Defender may be absent on some Server
// configurations; that surfaces as a SKIP rather than a failure.
func checkWindowsDefenderAV(b *CheckBuilder) {
	const id = "WIN-AV-001"
	const name = "Microsoft Defender Antivirus and real-time protection enabled"
	r := ps(`Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json -Compress`)
	if !r.Success() {
		b.Skip(id, name, "Get-MpComputerStatus unavailable (Defender not present on this host?)", SeverityHigh)
		return
	}
	av, rtp, err := parseDefenderStatus(r.Stdout)
	if err != nil {
		b.Skip(id, name, err.Error(), SeverityHigh)
		return
	}
	status, detail := evalDefender(av, rtp)
	emitResult(b, id, name, SeverityHigh, status, detail)
}

// checkWindowsSMBv1 — WIN-SMB-001.
func checkWindowsSMBv1(b *CheckBuilder) {
	const id = "WIN-SMB-001"
	const name = "SMBv1 server protocol disabled"
	r := ps(`Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol | ConvertTo-Json -Compress`)
	if !r.Success() {
		b.Skip(id, name, "Get-SmbServerConfiguration unavailable", SeverityHigh)
		return
	}
	enabled, err := parseSMB1Enabled(r.Stdout)
	if err != nil {
		b.Skip(id, name, err.Error(), SeverityHigh)
		return
	}
	status, detail := evalSMB1(enabled)
	emitResult(b, id, name, SeverityHigh, status, detail)
}

// checkWindowsRDP — WIN-RDP-001. Reads RDP enablement and NLA from the registry.
func checkWindowsRDP(b *CheckBuilder) {
	const id = "WIN-RDP-001"
	const name = "Remote Desktop disabled, or requires Network Level Authentication"
	r := ps(`[pscustomobject]@{` +
		`DenyTS=(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections;` +
		`NLA=(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication` +
		`} | ConvertTo-Json -Compress`)
	if !r.Success() {
		b.Skip(id, name, "could not read Terminal Server registry keys", SeverityHigh)
		return
	}
	cfg, err := parseRDPConfig(r.Stdout)
	if err != nil {
		b.Skip(id, name, err.Error(), SeverityHigh)
		return
	}
	status, detail := evalRDP(cfg)
	emitResult(b, id, name, SeverityHigh, status, detail)
}

// checkWindowsUAC — WIN-UAC-001.
func checkWindowsUAC(b *CheckBuilder) {
	const id = "WIN-UAC-001"
	const name = "User Account Control (UAC) enabled"
	r := ps(`[pscustomobject]@{` +
		`EnableLUA=(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA` +
		`} | ConvertTo-Json -Compress`)
	if !r.Success() {
		b.Skip(id, name, "could not read UAC registry key", SeverityHigh)
		return
	}
	cfg, err := parseUACEnabled(r.Stdout)
	if err != nil {
		b.Skip(id, name, err.Error(), SeverityHigh)
		return
	}
	status, detail := evalUAC(cfg)
	emitResult(b, id, name, SeverityHigh, status, detail)
}

// checkWindowsUpdate — WIN-UPD-001. Flags the Windows Update service being
// Disabled (which silently blocks security updates).
func checkWindowsUpdate(b *CheckBuilder) {
	const id = "WIN-UPD-001"
	const name = "Windows Update service not disabled"
	r := ps(`Get-Service wuauserv | Select-Object Status,StartType | ConvertTo-Json -Compress`)
	if !r.Success() {
		b.Skip(id, name, "could not query the Windows Update service", SeverityMedium)
		return
	}
	disabled, err := parseServiceDisabled(r.Stdout)
	if err != nil {
		b.Skip(id, name, err.Error(), SeverityMedium)
		return
	}
	status, detail := evalUpdateService(disabled)
	emitResult(b, id, name, SeverityMedium, status, detail)
}
