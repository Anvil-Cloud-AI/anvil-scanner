package scan

import "testing"

func TestParseFirewallProfiles(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		wantLen     int
		wantEnabled map[string]bool
		wantErr     bool
	}{
		{
			name:        "array with bool enabled",
			in:          `[{"Name":"Domain","Enabled":true},{"Name":"Private","Enabled":false},{"Name":"Public","Enabled":true}]`,
			wantLen:     3,
			wantEnabled: map[string]bool{"Domain": true, "Private": false, "Public": true},
		},
		{
			name:        "array with numeric enabled (1/0)",
			in:          `[{"Name":"Domain","Enabled":1},{"Name":"Public","Enabled":0}]`,
			wantLen:     2,
			wantEnabled: map[string]bool{"Domain": true, "Public": false},
		},
		{
			name:        "array with string enabled",
			in:          `[{"Name":"Domain","Enabled":"True"},{"Name":"Public","Enabled":"False"}]`,
			wantLen:     2,
			wantEnabled: map[string]bool{"Domain": true, "Public": false},
		},
		{
			name:        "single object (one profile)",
			in:          `{"Name":"Public","Enabled":true}`,
			wantLen:     1,
			wantEnabled: map[string]bool{"Public": true},
		},
		{"empty", "", 0, nil, true},
		{"garbage", "not json", 0, nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseFirewallProfiles(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tc.wantLen {
				t.Fatalf("len = %d, want %d", len(got), tc.wantLen)
			}
			for _, p := range got {
				if want, ok := tc.wantEnabled[p.Name]; ok && p.Enabled != want {
					t.Errorf("%s enabled = %v, want %v", p.Name, p.Enabled, want)
				}
			}
		})
	}
}

func TestEvalFirewallProfiles(t *testing.T) {
	tests := []struct {
		name     string
		profiles []firewallProfile
		want     Status
	}{
		{"all enabled passes", []firewallProfile{{"Domain", true}, {"Private", true}, {"Public", true}}, StatusPass},
		{"one disabled fails", []firewallProfile{{"Domain", true}, {"Public", false}}, StatusFail},
		{"all disabled fails", []firewallProfile{{"Domain", false}}, StatusFail},
		{"none reported skips", nil, StatusSkip},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, detail := evalFirewallProfiles(tc.profiles)
			if got != tc.want {
				t.Errorf("status = %v, want %v", got, tc.want)
			}
			if detail == "" {
				t.Error("expected non-empty detail")
			}
		})
	}
}
