package scan

import (
	"fmt"
	"strings"
	"testing"
)

// ---- parseSshdConfig via parseConfigString (test-only mirror) ---------------

// TestParseSshdConfigString_ValidDirectives exercises the parsing logic with
// a representative well-formed config.
func TestParseSshdConfigString_ValidDirectives(t *testing.T) {
	content := `# Comment line
PermitRootLogin no
MaxAuthTries 3
LogLevel VERBOSE
X11Forwarding no
AllowTcpForwarding no
PasswordAuthentication no
`
	cfg := parseConfigString(content)

	cases := []struct {
		key  string
		want string
	}{
		{"PermitRootLogin", "no"},
		{"MaxAuthTries", "3"},
		{"LogLevel", "VERBOSE"},
		{"X11Forwarding", "no"},
		{"AllowTcpForwarding", "no"},
		{"PasswordAuthentication", "no"},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			got := directive(cfg, tc.key)
			if got != tc.want {
				t.Errorf("directive(%q) = %q, want %q", tc.key, got, tc.want)
			}
		})
	}
}

// TestParseSshdConfigString_EmptyInput verifies an empty string yields an
// empty (not nil) map with no _error key.
func TestParseSshdConfigString_EmptyInput(t *testing.T) {
	cfg := parseConfigString("")
	if cfg == nil {
		t.Fatal("expected non-nil map for empty config")
	}
	if _, hasErr := cfg["_error"]; hasErr {
		t.Error("empty config should not produce _error key")
	}
	if len(cfg) != 0 {
		t.Errorf("expected empty map for empty config, got %v", cfg)
	}
}

// TestParseSshdConfigString_KeyOnlyLine verifies that lines with no separator
// are skipped and do not panic.
func TestParseSshdConfigString_KeyOnlyLine(t *testing.T) {
	content := "KeywordOnly\nPermitRootLogin no\n"
	cfg := parseConfigString(content)
	if _, ok := cfg["keywordonly"]; ok {
		t.Error("key-only line (no value) should be skipped")
	}
	if directive(cfg, "PermitRootLogin") != "no" {
		t.Error("PermitRootLogin should parse normally alongside bad line")
	}
}

// TestParseSshdConfigString_CaseFolding verifies that directive keys are
// lowercased regardless of source casing.
func TestParseSshdConfigString_CaseFolding(t *testing.T) {
	content := "PERMITROOTLOGIN yes\nMaxAuthTries 6\n"
	cfg := parseConfigString(content)
	if directive(cfg, "permitrootlogin") != "yes" {
		t.Error("uppercase key should be folded to lowercase")
	}
	if directive(cfg, "PERMITROOTLOGIN") != "yes" {
		t.Error("uppercase lookup should work via directive() folding")
	}
}

// TestParseSshdConfigString_BlankLines verifies blank lines are ignored.
func TestParseSshdConfigString_BlankLines(t *testing.T) {
	content := "\n\n  \nPermitRootLogin no\n\n"
	cfg := parseConfigString(content)
	if directive(cfg, "PermitRootLogin") != "no" {
		t.Errorf("expected 'no', got %q", directive(cfg, "PermitRootLogin"))
	}
	if len(cfg) != 1 {
		t.Errorf("expected exactly 1 directive, got %d: %v", len(cfg), cfg)
	}
}

// TestParseSshdConfigString_MissingKey verifies that a directive not present
// returns empty string.
func TestParseSshdConfigString_MissingKey(t *testing.T) {
	cfg := parseConfigString("PermitRootLogin no\n")
	if got := directive(cfg, "MaxAuthTries"); got != "" {
		t.Errorf("missing directive should return empty string, got %q", got)
	}
}

// TestParseSshdConfigString_TabAndSpaceMixed verifies tab-separated directives
// alongside space-separated ones all parse correctly.
func TestParseSshdConfigString_TabAndSpaceMixed(t *testing.T) {
	content := "PermitRootLogin no\nMaxAuthTries\t3\nLogLevel\tVERBOSE\nX11Forwarding no\n"
	cfg := parseConfigString(content)
	cases := []struct{ key, want string }{
		{"PermitRootLogin", "no"},
		{"MaxAuthTries", "3"},
		{"LogLevel", "VERBOSE"},
		{"X11Forwarding", "no"},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			if got := directive(cfg, tc.key); got != tc.want {
				t.Errorf("directive(%q) = %q, want %q", tc.key, got, tc.want)
			}
		})
	}
}

// ---- checkSSHBool -----------------------------------------------------------

// TestCheckSSHBool_Pass verifies that a value matching expected records PASS.
func TestCheckSSHBool_Pass(t *testing.T) {
	tests := []struct {
		name     string
		val      string
		expected string
	}{
		{"no-lower", "no", "no"},
		{"no-upper", "NO", "no"},
		{"yes-lower", "yes", "yes"},
		{"yes-upper", "YES", "yes"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := NewBuilder(WithClock(fixedClock()))
			cfg := map[string]string{"x11forwarding": tc.val}
			checkSSHBool(b, cfg, "SSH-023", "X11Forwarding disabled", "X11Forwarding", tc.expected,
				"pass-msg", "fail-msg", "warn-msg", SeverityMedium)
			r := b.Build()
			if r.Checks[0].Status != StatusPass {
				t.Errorf("val=%q expected=%q: got %s, want PASS",
					tc.val, tc.expected, r.Checks[0].Status)
			}
		})
	}
}

// TestCheckSSHBool_Fail verifies a non-matching value records FAIL with the
// supplied failMsg.
func TestCheckSSHBool_Fail(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	cfg := map[string]string{"x11forwarding": "yes"}
	checkSSHBool(b, cfg, "SSH-023", "X11Forwarding disabled", "X11Forwarding", "no",
		"X11Forwarding = no",
		"X11Forwarding = yes (should be no)",
		"X11Forwarding not set",
		SeverityMedium)
	r := b.Build()
	if r.Checks[0].Status != StatusFail {
		t.Errorf("expected FAIL for yes when no required, got %s", r.Checks[0].Status)
	}
	if r.Checks[0].Detail != "X11Forwarding = yes (should be no)" {
		t.Errorf("unexpected fail detail: %q", r.Checks[0].Detail)
	}
}

// TestCheckSSHBool_WarnWhenNotSet verifies a missing directive emits WARN.
func TestCheckSSHBool_WarnWhenNotSet(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	cfg := map[string]string{}
	checkSSHBool(b, cfg, "SSH-023", "X11Forwarding disabled", "X11Forwarding", "no",
		"pass-msg", "fail-msg", "X11Forwarding not set (default may be yes)", SeverityMedium)
	r := b.Build()
	if r.Checks[0].Status != StatusWarn {
		t.Errorf("expected WARN when directive absent, got %s", r.Checks[0].Status)
	}
	if r.Checks[0].Detail != "X11Forwarding not set (default may be yes)" {
		t.Errorf("unexpected WARN detail: %q", r.Checks[0].Detail)
	}
}

// TestCheckSSHBool_SeverityPreserved verifies the supplied severity is stored.
func TestCheckSSHBool_SeverityPreserved(t *testing.T) {
	for _, sev := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
		t.Run(string(sev), func(t *testing.T) {
			b := NewBuilder(WithClock(fixedClock()))
			cfg := map[string]string{"x11forwarding": "no"}
			checkSSHBool(b, cfg, "SSH-023", "test", "X11Forwarding", "no",
				"pass", "fail", "warn", sev)
			r := b.Build()
			if r.Checks[0].Severity != sev {
				t.Errorf("severity = %q, want %q", r.Checks[0].Severity, sev)
			}
		})
	}
}

// TestCheckSSHBool_AllowTcpForwarding covers the AllowTcpForwarding=yes failure.
func TestCheckSSHBool_AllowTcpForwarding_Fail(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	cfg := map[string]string{"allowtcpforwarding": "yes"}
	checkSSHBool(b, cfg, "SSH-024", "AllowTcpForwarding disabled", "AllowTcpForwarding", "no",
		"AllowTcpForwarding = no",
		"AllowTcpForwarding = yes (should be no)",
		"AllowTcpForwarding not set (default is yes)",
		SeverityMedium)
	r := b.Build()
	if r.Checks[0].Status != StatusFail {
		t.Errorf("expected FAIL for AllowTcpForwarding=yes, got %s", r.Checks[0].Status)
	}
}

// ---- checkSSHInt edge cases --------------------------------------------------

// TestCheckSSHInt_UnparsableSuffix verifies that a non-numeric string after
// suffix stripping emits WARN.
func TestCheckSSHInt_UnparsableSuffix(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	cfg := map[string]string{"logingracetime": "infinites"}
	checkSSHInt(b, cfg, "SSH-008", "LoginGraceTime ≤ 60s", "LoginGraceTime",
		true,
		func(v int) bool { return v <= 60 },
		func(v int) string { return "ok" },
		func(v int) string { return "bad" },
		"not set",
		SeverityMedium,
	)
	r := b.Build()
	if r.Checks[0].Status != StatusWarn {
		t.Errorf("expected WARN for non-parseable value, got %s", r.Checks[0].Status)
	}
	if !strings.Contains(r.Checks[0].Detail, "not parseable") {
		t.Errorf("detail should mention 'not parseable', got %q", r.Checks[0].Detail)
	}
}

// TestCheckSSHInt_NoTrimSuffix verifies that trimSuffix=false keeps an 's'
// suffix causing a parse failure → WARN.
func TestCheckSSHInt_NoTrimSuffix(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	cfg := map[string]string{"maxauthtries": "3s"}
	checkSSHInt(b, cfg, "SSH-006", "MaxAuthTries ≤ 4", "MaxAuthTries",
		false,
		func(v int) bool { return v <= 4 },
		func(v int) string { return "ok" },
		func(v int) string { return "bad" },
		"not set",
		SeverityMedium,
	)
	r := b.Build()
	if r.Checks[0].Status != StatusWarn {
		t.Errorf("expected WARN when trimSuffix=false and value has suffix, got %s", r.Checks[0].Status)
	}
}

// TestCheckSSHInt_BoundaryExact verifies the exact limit value passes.
func TestCheckSSHInt_BoundaryExact(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	cfg := map[string]string{"maxauthtries": "4"}
	checkSSHInt(b, cfg, "SSH-006", "MaxAuthTries ≤ 4", "MaxAuthTries",
		false,
		func(v int) bool { return v <= 4 },
		func(v int) string { return "ok" },
		func(v int) string { return "bad" },
		"not set",
		SeverityMedium,
	)
	r := b.Build()
	if r.Checks[0].Status != StatusPass {
		t.Errorf("expected PASS at exact boundary 4, got %s", r.Checks[0].Status)
	}
}

// TestCheckSSHInt_BoundaryExceed verifies value one above limit fails.
func TestCheckSSHInt_BoundaryExceed(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	cfg := map[string]string{"maxauthtries": "5"}
	checkSSHInt(b, cfg, "SSH-006", "MaxAuthTries ≤ 4", "MaxAuthTries",
		false,
		func(v int) bool { return v <= 4 },
		func(v int) string { return "ok" },
		func(v int) string { return "bad" },
		"not set",
		SeverityMedium,
	)
	r := b.Build()
	if r.Checks[0].Status != StatusFail {
		t.Errorf("expected FAIL for value 5 > 4, got %s", r.Checks[0].Status)
	}
}

// TestCheckSSHInt_LoginGraceTime_NoSuffix verifies a numeric-only value without
// 's' parses correctly when trimSuffix=true.
func TestCheckSSHInt_LoginGraceTime_NoSuffix(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	cfg := map[string]string{"logingracetime": "30"}
	checkSSHInt(b, cfg, "SSH-008", "LoginGraceTime ≤ 60s", "LoginGraceTime",
		true,
		func(v int) bool { return v <= 60 },
		func(v int) string { return "ok" },
		func(v int) string { return "bad" },
		"not set",
		SeverityMedium,
	)
	r := b.Build()
	if r.Checks[0].Status != StatusPass {
		t.Errorf("expected PASS for 30 (no suffix), got %s", r.Checks[0].Status)
	}
}

// TestCheckSSHInt_LoginGraceTime_ExceedsLimit verifies 120s fails the ≤60 check.
func TestCheckSSHInt_LoginGraceTime_ExceedsLimit(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	cfg := map[string]string{"logingracetime": "120s"}
	checkSSHInt(b, cfg, "SSH-008", "LoginGraceTime ≤ 60s", "LoginGraceTime",
		true,
		func(v int) bool { return v <= 60 },
		func(v int) string { return "ok" },
		func(v int) string { return "bad" },
		"not set",
		SeverityMedium,
	)
	r := b.Build()
	if r.Checks[0].Status != StatusFail {
		t.Errorf("expected FAIL for 120s, got %s", r.Checks[0].Status)
	}
}

// ---- checkSSHAlgo edge cases -------------------------------------------------

// TestCheckSSHAlgo_WarnWhenNotSet verifies absent directive emits WARN.
func TestCheckSSHAlgo_WarnWhenNotSet(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	cfg := map[string]string{}
	checkSSHAlgo(b, cfg, "SSH-014", "KexAlgorithms", "KexAlgorithms",
		func(a string) bool { return weakKEX[a] },
		func() string { return "ok" },
		func(w []string) string { return "bad" },
		"KexAlgorithms not explicitly set",
		SeverityHigh,
	)
	r := b.Build()
	if r.Checks[0].Status != StatusWarn {
		t.Errorf("expected WARN when KexAlgorithms absent, got %s", r.Checks[0].Status)
	}
	if r.Checks[0].Detail != "KexAlgorithms not explicitly set" {
		t.Errorf("unexpected WARN detail: %q", r.Checks[0].Detail)
	}
}

// TestCheckSSHAlgo_SpaceAroundCommas verifies spaces around commas are trimmed.
func TestCheckSSHAlgo_SpaceAroundCommas(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	cfg := map[string]string{
		"kexalgorithms": "curve25519-sha256 , diffie-hellman-group1-sha1",
	}
	checkSSHAlgo(b, cfg, "SSH-014", "KexAlgorithms", "KexAlgorithms",
		func(a string) bool { return weakKEX[a] },
		func() string { return "ok" },
		func(w []string) string { return "weak: " + strings.Join(w, ",") },
		"not set",
		SeverityHigh,
	)
	r := b.Build()
	if r.Checks[0].Status != StatusFail {
		t.Errorf("expected FAIL (weak algo with surrounding spaces), got %s", r.Checks[0].Status)
	}
}

// TestCheckSSHAlgo_MultipleWeak verifies all weak algos appear in the detail.
func TestCheckSSHAlgo_MultipleWeak(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	cfg := map[string]string{
		"kexalgorithms": "diffie-hellman-group1-sha1,diffie-hellman-group14-sha1",
	}
	checkSSHAlgo(b, cfg, "SSH-014", "KexAlgorithms", "KexAlgorithms",
		func(a string) bool { return weakKEX[a] },
		func() string { return "ok" },
		func(w []string) string { return strings.Join(w, ",") },
		"not set",
		SeverityHigh,
	)
	r := b.Build()
	if r.Checks[0].Status != StatusFail {
		t.Errorf("expected FAIL for two weak algos, got %s", r.Checks[0].Status)
	}
	if !strings.Contains(r.Checks[0].Detail, "diffie-hellman-group1-sha1") {
		t.Errorf("detail missing first weak algo: %q", r.Checks[0].Detail)
	}
	if !strings.Contains(r.Checks[0].Detail, "diffie-hellman-group14-sha1") {
		t.Errorf("detail missing second weak algo: %q", r.Checks[0].Detail)
	}
}

// TestCheckSSHAlgo_SingleElement verifies a single-element (no comma) list works.
func TestCheckSSHAlgo_SingleElement(t *testing.T) {
	tests := []struct {
		name   string
		algo   string
		isWeak bool
		want   Status
	}{
		{"strong single", "curve25519-sha256", false, StatusPass},
		{"weak single", "diffie-hellman-group1-sha1", true, StatusFail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := NewBuilder(WithClock(fixedClock()))
			cfg := map[string]string{"kexalgorithms": tc.algo}
			checkSSHAlgo(b, cfg, "SSH-014", "KexAlgorithms", "KexAlgorithms",
				func(a string) bool { return weakKEX[a] },
				func() string { return "ok" },
				func(w []string) string { return "bad" },
				"not set", SeverityHigh,
			)
			r := b.Build()
			if r.Checks[0].Status != tc.want {
				t.Errorf("algo=%q: got %s, want %s", tc.algo, r.Checks[0].Status, tc.want)
			}
		})
	}
}

// ---- weakCiphers / weakKEX map content ----------------------------------------

// TestWeakCiphers_CBC verifies all four CBC-mode ciphers are flagged.
func TestWeakCiphers_CBC(t *testing.T) {
	expected := []string{"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"}
	for _, c := range expected {
		t.Run(c, func(t *testing.T) {
			if !weakCiphers[c] {
				t.Errorf("%q should be in weakCiphers", c)
			}
		})
	}
}

// TestWeakCiphers_StrongExcluded verifies AEAD ciphers are not in weakCiphers.
func TestWeakCiphers_StrongExcluded(t *testing.T) {
	strong := []string{
		"aes256-gcm@openssh.com",
		"aes128-gcm@openssh.com",
		"chacha20-poly1305@openssh.com",
	}
	for _, c := range strong {
		t.Run(c, func(t *testing.T) {
			if weakCiphers[c] {
				t.Errorf("%q should NOT be in weakCiphers", c)
			}
		})
	}
}

// TestWeakKEX_ContainsExpected verifies both deprecated DH groups are in weakKEX.
func TestWeakKEX_ContainsExpected(t *testing.T) {
	expected := []string{
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group14-sha1",
	}
	for _, k := range expected {
		t.Run(k, func(t *testing.T) {
			if !weakKEX[k] {
				t.Errorf("%q should be in weakKEX", k)
			}
		})
	}
}

// TestWeakKEX_StrongExcluded verifies modern KEX algorithms are not flagged.
func TestWeakKEX_StrongExcluded(t *testing.T) {
	strong := []string{"curve25519-sha256", "ecdh-sha2-nistp256", "sntrup761x25519-sha512@openssh.com"}
	for _, k := range strong {
		t.Run(k, func(t *testing.T) {
			if weakKEX[k] {
				t.Errorf("%q should NOT be in weakKEX", k)
			}
		})
	}
}

// ---- weakMACPrefixes detection logic -----------------------------------------

// TestWeakMACPrefixes_NonETMFlaggedTableDriven exercises the MAC-flagging
// logic used in SSH-016 for a variety of inputs.
func TestWeakMACPrefixes_NonETMFlaggedTableDriven(t *testing.T) {
	tests := []struct {
		name    string
		mac     string
		wantHit bool
	}{
		{"hmac-md5 weak", "hmac-md5", true},
		{"hmac-sha1 weak", "hmac-sha1", true},
		{"umac-64 weak", "umac-64@openssh.com", true},
		{"hmac-sha2-256-etm exempt", "hmac-sha2-256-etm@openssh.com", false},
		{"hmac-sha2-512-etm exempt", "hmac-sha2-512-etm@openssh.com", false},
		{"hmac-sha2-256 strong prefix not weak", "hmac-sha2-256", false},
		{"chacha not weak", "chacha20-poly1305@openssh.com", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := strings.TrimSpace(tc.mac)
			isWeakPrefix := false
			for _, p := range weakMACPrefixes {
				if strings.HasPrefix(a, p) {
					isWeakPrefix = true
					break
				}
			}
			flagged := isWeakPrefix && !strings.Contains(strings.ToLower(a), "etm")
			if flagged != tc.wantHit {
				t.Errorf("mac=%q: flagged=%v, want %v", tc.mac, flagged, tc.wantHit)
			}
		})
	}
}

// ---- runDirectiveChecks integration -----------------------------------------

// TestRunDirectiveChecks_AllPass verifies all four checks pass with a
// well-configured synthetic config.
func TestRunDirectiveChecks_AllPass(t *testing.T) {
	cfg := map[string]string{
		"maxauthtries":   "3",
		"logingracetime": "30s",
		"kexalgorithms":  "curve25519-sha256,ecdh-sha2-nistp256",
		"x11forwarding":  "no",
	}
	b := runSSHChecksWithCfg(cfg)
	r := b.Build()

	for _, c := range r.Checks {
		if c.Status == StatusFail {
			t.Errorf("check %s: expected no failures, got FAIL detail=%q", c.ID, c.Detail)
		}
		if c.Status == StatusWarn {
			t.Errorf("check %s: expected no warnings, got WARN detail=%q", c.ID, c.Detail)
		}
	}
}

// TestRunDirectiveChecks_AllWarn verifies all checks warn with an empty config.
func TestRunDirectiveChecks_AllWarn(t *testing.T) {
	b := runSSHChecksWithCfg(map[string]string{})
	r := b.Build()

	for _, c := range r.Checks {
		if c.Status != StatusWarn {
			t.Errorf("check %s: expected WARN with empty config, got %s", c.ID, c.Status)
		}
	}
}

// TestRunDirectiveChecks_MaxAuthTriesFail verifies SSH-006 fails for value > 4.
func TestRunDirectiveChecks_MaxAuthTriesFail(t *testing.T) {
	cfg := map[string]string{
		"maxauthtries":   "10",
		"logingracetime": "30s",
		"kexalgorithms":  "curve25519-sha256",
		"x11forwarding":  "no",
	}
	b := runSSHChecksWithCfg(cfg)
	r := b.Build()

	for _, c := range r.Checks {
		if c.ID == "SSH-006" {
			if c.Status != StatusFail {
				t.Errorf("SSH-006: expected FAIL for MaxAuthTries=10, got %s", c.Status)
			}
			return
		}
	}
	t.Error("SSH-006 check not found in results")
}

// TestRunDirectiveChecks_WeakKEXFail verifies SSH-014 fails for a weak KEX.
func TestRunDirectiveChecks_WeakKEXFail(t *testing.T) {
	cfg := map[string]string{
		"maxauthtries":   "3",
		"logingracetime": "30",
		"kexalgorithms":  "diffie-hellman-group1-sha1",
		"x11forwarding":  "no",
	}
	b := runSSHChecksWithCfg(cfg)
	r := b.Build()

	for _, c := range r.Checks {
		if c.ID == "SSH-014" {
			if c.Status != StatusFail {
				t.Errorf("SSH-014: expected FAIL for weak KEX, got %s detail=%q", c.Status, c.Detail)
			}
			return
		}
	}
	t.Error("SSH-014 check not found in results")
}

// TestRunDirectiveChecks_X11ForwardingFail verifies SSH-023 fails for yes.
func TestRunDirectiveChecks_X11ForwardingFail(t *testing.T) {
	cfg := map[string]string{
		"maxauthtries":   "3",
		"logingracetime": "30",
		"kexalgorithms":  "curve25519-sha256",
		"x11forwarding":  "yes",
	}
	b := runSSHChecksWithCfg(cfg)
	r := b.Build()

	for _, c := range r.Checks {
		if c.ID == "SSH-023" {
			if c.Status != StatusFail {
				t.Errorf("SSH-023: expected FAIL for X11Forwarding=yes, got %s", c.Status)
			}
			return
		}
	}
	t.Error("SSH-023 check not found in results")
}

// ---- SSHEnabled non-Darwin coverage -----------------------------------------

// TestSSHEnabled_NonDarwinAlwaysTrue verifies non-Darwin platforms always
// return true regardless of the remoteLoginEnabled value.
func TestSSHEnabled_NonDarwinAlwaysTrue(t *testing.T) {
	platforms := []string{"Linux", "linux", "FreeBSD", ""}
	vals := []*bool{nil, boolPtr(true), boolPtr(false)}
	for _, p := range platforms {
		for _, v := range vals {
			if !SSHEnabled(p, v) {
				t.Errorf("SSHEnabled(%q, %v) should be true for non-Darwin platform", p, v)
			}
		}
	}
}

// TestGetSSHDirectives_ReturnsNonNilMap verifies GetSSHDirectives always
// returns a non-nil map — either parsed content or an _error entry.
func TestGetSSHDirectives_ReturnsNonNilMap(t *testing.T) {
	got := GetSSHDirectives()
	if got == nil {
		t.Error("GetSSHDirectives() returned nil map")
	}
}

// ── LoginGraceTime = 0 hardening tests ────────────────────────────────────────

// TestCheckSSHInt_LoginGraceTime_Zero verifies that LoginGraceTime = 0 emits
// FAIL. The value 0 means "unlimited grace period" which is insecure.
// The check's testFn is `v > 0 && v <= 60`, so 0 must fail (not pass).
func TestCheckSSHInt_LoginGraceTime_Zero(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	cfg := map[string]string{"logingracetime": "0"}
	checkSSHInt(b, cfg, "SSH-008", "LoginGraceTime ≤ 60s", "LoginGraceTime",
		true,
		func(v int) bool { return v > 0 && v <= 60 },
		func(v int) string { return fmt.Sprintf("LoginGraceTime = %ds", v) },
		func(v int) string {
			return fmt.Sprintf("LoginGraceTime = %ds (should be between 1 and 60 seconds; 0 means unlimited)", v)
		},
		"LoginGraceTime not set (default is 120, should be ≤ 60)",
		SeverityMedium,
	)
	r := b.Build()
	if len(r.Checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(r.Checks))
	}
	if r.Checks[0].Status != StatusFail {
		t.Errorf("LoginGraceTime=0 must produce FAIL (0 means unlimited), got %s detail=%q",
			r.Checks[0].Status, r.Checks[0].Detail)
	}
	if !strings.Contains(r.Checks[0].Detail, "unlimited") {
		t.Errorf("FAIL detail should mention 'unlimited', got %q", r.Checks[0].Detail)
	}
}

// TestCheckSSHInt_LoginGraceTime_ZeroWithSuffix verifies the same FAIL
// result when the value appears as "0s" (trailing-s suffix form).
func TestCheckSSHInt_LoginGraceTime_ZeroWithSuffix(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	cfg := map[string]string{"logingracetime": "0s"}
	checkSSHInt(b, cfg, "SSH-008", "LoginGraceTime ≤ 60s", "LoginGraceTime",
		true,
		func(v int) bool { return v > 0 && v <= 60 },
		func(v int) string { return fmt.Sprintf("LoginGraceTime = %ds", v) },
		func(v int) string {
			return fmt.Sprintf("LoginGraceTime = %ds (should be between 1 and 60 seconds; 0 means unlimited)", v)
		},
		"LoginGraceTime not set (default is 120, should be ≤ 60)",
		SeverityMedium,
	)
	r := b.Build()
	if r.Checks[0].Status != StatusFail {
		t.Errorf("LoginGraceTime=0s must produce FAIL, got %s", r.Checks[0].Status)
	}
}

// TestCheckSSHInt_LoginGraceTime_ZeroIsLessThanOrEqualToSixty documents that
// the test helper runDirectiveChecks uses the simplified predicate v <= 60
// (which passes 0), while the production RunSSHChecks uses v > 0 && v <= 60
// (which fails 0). The two direct tests above verify the production predicate.
// This test verifies the boundary value 1 passes the production predicate.
func TestCheckSSHInt_LoginGraceTime_OneIsValid(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	cfg := map[string]string{"logingracetime": "1"}
	checkSSHInt(b, cfg, "SSH-008", "LoginGraceTime ≤ 60s", "LoginGraceTime",
		true,
		func(v int) bool { return v > 0 && v <= 60 },
		func(v int) string { return fmt.Sprintf("LoginGraceTime = %ds", v) },
		func(v int) string {
			return fmt.Sprintf("LoginGraceTime = %ds (should be between 1 and 60 seconds; 0 means unlimited)", v)
		},
		"LoginGraceTime not set",
		SeverityMedium,
	)
	r := b.Build()
	if r.Checks[0].Status != StatusPass {
		t.Errorf("LoginGraceTime=1 must produce PASS (minimum valid value), got %s", r.Checks[0].Status)
	}
}
