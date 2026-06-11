package scan

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// firewallProfile is one Windows Defender Firewall profile (Domain/Private/Public).
type firewallProfile struct {
	Name    string
	Enabled bool
}

// parseFirewallProfiles parses the JSON emitted by
// `Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json`.
//
// ConvertTo-Json emits a JSON array for multiple profiles but a bare object
// when only one is returned, and the Enabled field can render as a bool, a
// number (1/0), or a string ("True"/"False") depending on the PowerShell / OS
// version — so it is decoded tolerantly. Pure function (no I/O) so it is unit
// testable on any platform; the actual PowerShell call lives in the
// windows-tagged collector.
func parseFirewallProfiles(jsonOut string) ([]firewallProfile, error) {
	trimmed := strings.TrimSpace(jsonOut)
	if trimmed == "" {
		return nil, fmt.Errorf("empty firewall profile output")
	}

	type rawProfile struct {
		Name    string          `json:"Name"`
		Enabled json.RawMessage `json:"Enabled"`
	}

	var raws []rawProfile
	if trimmed[0] == '[' {
		if err := json.Unmarshal([]byte(trimmed), &raws); err != nil {
			return nil, fmt.Errorf("parse firewall profiles: %w", err)
		}
	} else {
		var one rawProfile
		if err := json.Unmarshal([]byte(trimmed), &one); err != nil {
			return nil, fmt.Errorf("parse firewall profile: %w", err)
		}
		raws = []rawProfile{one}
	}

	out := make([]firewallProfile, 0, len(raws))
	for _, r := range raws {
		out = append(out, firewallProfile{Name: r.Name, Enabled: rawJSONToBool(r.Enabled)})
	}
	return out, nil
}

// rawJSONToBool interprets true/false, 1/0, or "True"/"False" as a bool.
func rawJSONToBool(raw json.RawMessage) bool {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	switch strings.ToLower(s) {
	case "true":
		return true
	case "false", "":
		return false
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n != 0
	}
	return false
}

// evalFirewallProfiles returns the check status and human-readable detail for
// the parsed profiles: PASS only when every profile is enabled.
func evalFirewallProfiles(profiles []firewallProfile) (Status, string) {
	if len(profiles) == 0 {
		return StatusSkip, "no firewall profiles reported"
	}
	var disabled []string
	for _, p := range profiles {
		if !p.Enabled {
			disabled = append(disabled, p.Name)
		}
	}
	if len(disabled) == 0 {
		return StatusPass, fmt.Sprintf("Windows Defender Firewall enabled for all %d profile(s)", len(profiles))
	}
	return StatusFail, fmt.Sprintf(
		"Windows Defender Firewall disabled for profile(s): %s — enable with: Set-NetFirewallProfile -Profile %s -Enabled True",
		strings.Join(disabled, ", "), strings.Join(disabled, ","))
}
