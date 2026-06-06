package scan

import "testing"

func intp(i int) *int { return &i }

func TestParseDefenderStatus(t *testing.T) {
	av, rtp, err := parseDefenderStatus(`{"AntivirusEnabled":true,"RealTimeProtectionEnabled":false}`)
	if err != nil || !av || rtp {
		t.Fatalf("av=%v rtp=%v err=%v", av, rtp, err)
	}
	if _, _, err := parseDefenderStatus(""); err == nil {
		t.Error("expected error on empty input")
	}
}

func TestEvalDefender(t *testing.T) {
	cases := []struct {
		av, rtp bool
		want    Status
	}{
		{true, true, StatusPass},
		{true, false, StatusFail},
		{false, true, StatusFail},
		{false, false, StatusFail},
	}
	for _, c := range cases {
		if got, _ := evalDefender(c.av, c.rtp); got != c.want {
			t.Errorf("evalDefender(%v,%v) = %v, want %v", c.av, c.rtp, got, c.want)
		}
	}
}

func TestParseAndEvalSMB1(t *testing.T) {
	on, err := parseSMB1Enabled(`{"EnableSMB1Protocol":true}`)
	if err != nil || !on {
		t.Fatalf("on=%v err=%v", on, err)
	}
	if got, _ := evalSMB1(true); got != StatusFail {
		t.Errorf("SMBv1 enabled should FAIL, got %v", got)
	}
	if got, _ := evalSMB1(false); got != StatusPass {
		t.Errorf("SMBv1 disabled should PASS, got %v", got)
	}
	// numeric encoding (0 = false)
	off, _ := parseSMB1Enabled(`{"EnableSMB1Protocol":0}`)
	if off {
		t.Error("0 should decode to false")
	}
}

func TestEvalRDP(t *testing.T) {
	cases := []struct {
		name string
		cfg  rdpConfig
		want Status
	}{
		{"rdp disabled (deny=1)", rdpConfig{DenyTS: intp(1)}, StatusPass},
		{"rdp unset defaults disabled", rdpConfig{}, StatusPass},
		{"rdp enabled with NLA", rdpConfig{DenyTS: intp(0), NLA: intp(1)}, StatusPass},
		{"rdp enabled no NLA", rdpConfig{DenyTS: intp(0), NLA: intp(0)}, StatusFail},
		{"rdp enabled NLA unset", rdpConfig{DenyTS: intp(0)}, StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, _ := evalRDP(c.cfg); got != c.want {
				t.Errorf("evalRDP = %v, want %v", got, c.want)
			}
		})
	}
}

func TestParseRDPConfigNulls(t *testing.T) {
	cfg, err := parseRDPConfig(`{"DenyTS":null,"NLA":null}`)
	if err != nil || cfg.DenyTS != nil || cfg.NLA != nil {
		t.Fatalf("expected nil pointers, got %+v err=%v", cfg, err)
	}
}

func TestParseUACEnabled(t *testing.T) {
	cfg, err := parseUACEnabled(`{"EnableLUA":1}`)
	if err != nil || cfg.EnableLUA == nil || *cfg.EnableLUA != 1 {
		t.Fatalf("got %+v err=%v, want EnableLUA=1", cfg, err)
	}
	nullCfg, err := parseUACEnabled(`{"EnableLUA":null}`)
	if err != nil || nullCfg.EnableLUA != nil {
		t.Fatalf("got %+v err=%v, want nil EnableLUA", nullCfg, err)
	}
	if _, err := parseUACEnabled(""); err == nil {
		t.Error("expected error on empty input")
	}
}

func TestEvalUAC(t *testing.T) {
	if got, _ := evalUAC(uacConfig{EnableLUA: intp(1)}); got != StatusPass {
		t.Errorf("EnableLUA=1 should PASS, got %v", got)
	}
	if got, _ := evalUAC(uacConfig{EnableLUA: intp(0)}); got != StatusFail {
		t.Errorf("EnableLUA=0 should FAIL, got %v", got)
	}
	if got, _ := evalUAC(uacConfig{}); got != StatusPass {
		t.Errorf("unset EnableLUA should default to PASS, got %v", got)
	}
}

func TestParseServiceDisabled(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"string Disabled", `{"Status":1,"StartType":"Disabled"}`, true},
		{"numeric 4 = Disabled", `{"Status":1,"StartType":4}`, true},
		{"string Automatic", `{"Status":4,"StartType":"Automatic"}`, false},
		{"numeric 3 = Manual", `{"Status":1,"StartType":3}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseServiceDisabled(c.in)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if got != c.want {
				t.Errorf("disabled = %v, want %v", got, c.want)
			}
		})
	}
	if got, _ := evalUpdateService(true); got != StatusFail {
		t.Errorf("disabled service should FAIL, got %v", got)
	}
	if got, _ := evalUpdateService(false); got != StatusPass {
		t.Errorf("enabled service should PASS, got %v", got)
	}
}
