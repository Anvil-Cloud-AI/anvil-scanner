package scan

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// jbool tolerates the several ways PowerShell's ConvertTo-Json renders a
// boolean across OS/version: native bool, number (1/0), or string
// ("True"/"False"). Reuses rawJSONToBool from windows_firewall_parse.go.
type jbool bool

func (b *jbool) UnmarshalJSON(data []byte) error {
	*b = jbool(rawJSONToBool(json.RawMessage(data)))
	return nil
}

// --- WIN-AV-001: Microsoft Defender Antivirus ---

type defenderStatus struct {
	AntivirusEnabled          jbool `json:"AntivirusEnabled"`
	RealTimeProtectionEnabled jbool `json:"RealTimeProtectionEnabled"`
}

// parseDefenderStatus parses `Get-MpComputerStatus | Select-Object
// AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json`.
func parseDefenderStatus(jsonOut string) (av, rtp bool, err error) {
	s := strings.TrimSpace(jsonOut)
	if s == "" {
		return false, false, fmt.Errorf("empty Get-MpComputerStatus output")
	}
	var d defenderStatus
	if err := json.Unmarshal([]byte(s), &d); err != nil {
		return false, false, fmt.Errorf("parse defender status: %w", err)
	}
	return bool(d.AntivirusEnabled), bool(d.RealTimeProtectionEnabled), nil
}

func evalDefender(av, rtp bool) (Status, string) {
	switch {
	case !av:
		return StatusFail, "Microsoft Defender Antivirus is disabled"
	case !rtp:
		return StatusFail, "Defender real-time protection is disabled — enable with: Set-MpPreference -DisableRealtimeMonitoring $false"
	default:
		return StatusPass, "Defender Antivirus and real-time protection are enabled"
	}
}

// --- WIN-SMB-001: SMBv1 server protocol ---

type smbConfig struct {
	EnableSMB1Protocol jbool `json:"EnableSMB1Protocol"`
}

// parseSMB1Enabled parses `Get-SmbServerConfiguration | Select-Object
// EnableSMB1Protocol | ConvertTo-Json`.
func parseSMB1Enabled(jsonOut string) (bool, error) {
	s := strings.TrimSpace(jsonOut)
	if s == "" {
		return false, fmt.Errorf("empty Get-SmbServerConfiguration output")
	}
	var c smbConfig
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		return false, fmt.Errorf("parse SMB config: %w", err)
	}
	return bool(c.EnableSMB1Protocol), nil
}

func evalSMB1(enabled bool) (Status, string) {
	if enabled {
		return StatusFail, "SMBv1 server protocol is enabled (legacy, exploitable) — disable with: Set-SmbServerConfiguration -EnableSMB1Protocol $false"
	}
	return StatusPass, "SMBv1 server protocol is disabled"
}

// --- WIN-RDP-001: Remote Desktop + Network Level Authentication ---

type rdpConfig struct {
	// DenyTS is fDenyTSConnections: 1 = RDP disabled, 0 = enabled, nil = unset.
	DenyTS *int `json:"DenyTS"`
	// NLA is UserAuthentication on RDP-Tcp: 1 = NLA required, 0 = not, nil = unset.
	NLA *int `json:"NLA"`
}

// parseRDPConfig parses the pscustomobject {DenyTS, NLA} emitted by the RDP
// collector. Null registry values decode to nil pointers.
func parseRDPConfig(jsonOut string) (rdpConfig, error) {
	s := strings.TrimSpace(jsonOut)
	if s == "" {
		return rdpConfig{}, fmt.Errorf("empty RDP registry output")
	}
	var c rdpConfig
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		return rdpConfig{}, fmt.Errorf("parse RDP config: %w", err)
	}
	return c, nil
}

func evalRDP(c rdpConfig) (Status, string) {
	// Default (key unset) is fDenyTSConnections=1 → RDP off.
	rdpDisabled := c.DenyTS == nil || *c.DenyTS == 1
	if rdpDisabled {
		return StatusPass, "Remote Desktop (RDP) is disabled"
	}
	if c.NLA != nil && *c.NLA == 1 {
		return StatusPass, "RDP is enabled with Network Level Authentication required"
	}
	return StatusFail, "RDP is enabled without Network Level Authentication — require NLA in System Properties → Remote, or set UserAuthentication=1"
}

// --- WIN-UAC-001: User Account Control ---

type uacConfig struct {
	EnableLUA *int `json:"EnableLUA"`
}

func parseUACEnabled(jsonOut string) (uacConfig, error) {
	s := strings.TrimSpace(jsonOut)
	if s == "" {
		return uacConfig{}, fmt.Errorf("empty UAC registry output")
	}
	var c uacConfig
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		return uacConfig{}, fmt.Errorf("parse UAC config: %w", err)
	}
	return c, nil
}

func evalUAC(c uacConfig) (Status, string) {
	// EnableLUA default is 1 (UAC on) when the value is unset.
	if c.EnableLUA != nil && *c.EnableLUA == 0 {
		return StatusFail, "User Account Control (UAC) is disabled — set HKLM\\...\\Policies\\System\\EnableLUA=1 and reboot"
	}
	return StatusPass, "User Account Control (UAC) is enabled"
}

// --- WIN-UPD-001: Windows Update service ---

type serviceConfig struct {
	StartType json.RawMessage `json:"StartType"`
}

// parseServiceDisabled parses `Get-Service <svc> | Select-Object Status,StartType
// | ConvertTo-Json` and reports whether StartType is Disabled. ConvertTo-Json
// may render the ServiceStartMode enum as a string ("Disabled") or its numeric
// value (4 = Disabled), so both are handled.
func parseServiceDisabled(jsonOut string) (disabled bool, err error) {
	s := strings.TrimSpace(jsonOut)
	if s == "" {
		return false, fmt.Errorf("empty Get-Service output")
	}
	var c serviceConfig
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		return false, fmt.Errorf("parse service config: %w", err)
	}
	raw := strings.Trim(strings.TrimSpace(string(c.StartType)), `"`)
	if strings.EqualFold(raw, "Disabled") {
		return true, nil
	}
	if n, convErr := strconv.Atoi(raw); convErr == nil && n == 4 {
		return true, nil
	}
	return false, nil
}

func evalUpdateService(disabled bool) (Status, string) {
	if disabled {
		return StatusFail, "Windows Update service (wuauserv) is Disabled — set it to Manual/Automatic so security updates can install"
	}
	return StatusPass, "Windows Update service (wuauserv) is not disabled"
}
