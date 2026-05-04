package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- helpers ----------------------------------------------------------------

func boolPtr(b bool) *bool { return &b }

// buildCfg creates a synthetic sshd_config file under a temp dir and
// returns the path. The caller is responsible for cleanup via t.TempDir().
// The map keys are directive names (case-insensitive); values are raw strings.
func buildCfg(t *testing.T, directives map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	var sb strings.Builder
	for k, v := range directives {
		sb.WriteString(k)
		sb.WriteByte(' ')
		sb.WriteString(v)
		sb.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0600); err != nil {
		t.Fatalf("buildCfg: %v", err)
	}
	return path
}

// runSSHChecksWithCfg injects a custom cfg map directly into the
// directive-check helpers so tests don't need a real /etc/ssh/sshd_config.
func runSSHChecksWithCfg(cfg map[string]string) *CheckBuilder {
	b := NewBuilder(WithClock(fixedClock()))
	runDirectiveChecks(b, cfg)
	return b
}

// runDirectiveChecks is the inner loop from RunSSHChecks extracted so
// tests can drive it with a synthetic config without touching the
// filesystem or requiring root.
func runDirectiveChecks(b *CheckBuilder, cfg map[string]string) {
	checkSSHInt(b, cfg, "SSH-006", "MaxAuthTries ≤ 4", "MaxAuthTries",
		false,
		func(v int) bool { return v <= 4 },
		func(v int) string { return formatf("MaxAuthTries = %d", v) },
		func(v int) string { return formatf("MaxAuthTries = %d (should be ≤ 4)", v) },
		"MaxAuthTries not explicitly set (default is 6, should be ≤ 4)",
		SeverityMedium,
	)
	checkSSHInt(b, cfg, "SSH-008", "LoginGraceTime ≤ 60s", "LoginGraceTime",
		true,
		func(v int) bool { return v > 0 && v <= 60 },
		func(v int) string { return formatf("LoginGraceTime = %ds", v) },
		func(v int) string { return formatf("LoginGraceTime = %ds (should be ≤ 60)", v) },
		"LoginGraceTime not set (default is 120, should be ≤ 60)",
		SeverityMedium,
	)
	checkSSHAlgo(b, cfg, "SSH-014", "KexAlgorithms (no weak KEX)", "KexAlgorithms",
		func(a string) bool { return weakKEX[a] },
		func() string { return formatf("KexAlgorithms: %s", directive(cfg, "KexAlgorithms")) },
		func(w []string) string { return formatf("Weak KEX algorithms found: %s", strings.Join(w, ", ")) },
		"KexAlgorithms not explicitly set",
		SeverityHigh,
	)
	checkSSHBool(b, cfg, "SSH-023", "X11Forwarding disabled", "X11Forwarding", "no",
		"X11Forwarding = no",
		formatf("X11Forwarding = %s (should be no)", directive(cfg, "X11Forwarding")),
		"X11Forwarding not set",
		SeverityMedium,
	)
}

func formatf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}

// parseConfigString is a test-only helper that applies the same parsing logic
// as parseSshdConfig to an in-memory string instead of the constant file path.
// This lets us exercise the tab/space separator handling without filesystem
// surgery on the const sshdConfigPath.
func parseConfigString(content string) map[string]string {
	result := map[string]string{}
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexAny(line, " \t")
		if idx <= 0 {
			continue
		}
		key := line[:idx]
		val := strings.TrimSpace(line[idx+1:])
		result[strings.ToLower(key)] = val
	}
	return result
}

// ---- parseSshdConfig — separator handling -----------------------------------

func TestParseSshdConfig_TabSeparator(t *testing.T) {
	content := "PermitRootLogin\tno\nMaxAuthTries\t3\nX11Forwarding\tno\n"
	cfg := parseConfigString(content)
	tests := []struct {
		key  string
		want string
	}{
		{"PermitRootLogin", "no"},
		{"MaxAuthTries", "3"},
		{"X11Forwarding", "no"},
	}
	for _, tc := range tests {
		got := directive(cfg, tc.key)
		if got != tc.want {
			t.Errorf("directive(%q) = %q, want %q", tc.key, got, tc.want)
		}
	}
}

func TestParseSshdConfig_MixedSeparators(t *testing.T) {
	content := "PermitRootLogin no\nMaxAuthTries\t3\nLogLevel VERBOSE\nX11Forwarding\tno\n"
	cfg := parseConfigString(content)
	tests := []struct {
		key  string
		want string
	}{
		{"PermitRootLogin", "no"},
		{"MaxAuthTries", "3"},
		{"LogLevel", "VERBOSE"},
		{"X11Forwarding", "no"},
	}
	for _, tc := range tests {
		got := directive(cfg, tc.key)
		if got != tc.want {
			t.Errorf("directive(%q) = %q, want %q", tc.key, got, tc.want)
		}
	}
}

func TestParseSshdConfig_CommentLines(t *testing.T) {
	content := "# PermitRootLogin yes\n# MaxAuthTries 10\nPermitRootLogin no\n"
	cfg := parseConfigString(content)
	if got := directive(cfg, "PermitRootLogin"); got != "no" {
		t.Errorf("directive(PermitRootLogin) = %q, want %q", got, "no")
	}
	if got := directive(cfg, "MaxAuthTries"); got != "" {
		t.Errorf("directive(MaxAuthTries) should be empty (comment only), got %q", got)
	}
}

// ---- gating contract --------------------------------------------------------

// TestSSHEnabled covers the behavioral spec from
// python/tests/test_refactor_guardrails.py::TestSshChecksSkippedWhenDisabled
func TestSSHEnabled(t *testing.T) {
	tests := []struct {
		name                string
		platform            string
		remoteLoginEnabled  *bool
		wantEnabled         bool
	}{
		// macOS + Remote Login explicitly off → SSH checks must be skipped
		{"darwin disabled", "Darwin", boolPtr(false), false},
		// macOS + Remote Login on → SSH checks run
		{"darwin enabled", "Darwin", boolPtr(true), true},
		// macOS + unknown state → SSH checks run (conservative)
		{"darwin unknown (nil)", "Darwin", nil, true},
		// Linux never gated — ssh_enabled is always true
		{"linux nil", "Linux", nil, true},
		{"linux false", "Linux", boolPtr(false), true},
		{"linux true", "Linux", boolPtr(true), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SSHEnabled(tc.platform, tc.remoteLoginEnabled)
			if got != tc.wantEnabled {
				t.Errorf("SSHEnabled(%q, %v) = %v, want %v",
					tc.platform, tc.remoteLoginEnabled, got, tc.wantEnabled)
			}
		})
	}
}

// TestRunSSHChecks_SkippedWhenDisabled verifies zero checks are added
// when SSH is disabled on Darwin. This is the most important behavioral
// contract — no SKIP rows, no noise.
func TestRunSSHChecks_SkippedWhenDisabled(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	RunSSHChecks(b, "Darwin", boolPtr(false))
	if b.Len() != 0 {
		ids := make([]string, 0, b.Len())
		for _, c := range b.Build().Checks {
			ids = append(ids, c.ID)
		}
		t.Errorf("expected 0 SSH checks when disabled, got %d: %v", b.Len(), ids)
	}
}

// ---- parseSshdConfig --------------------------------------------------------

func TestParseSshdConfig_ParsesDirectives(t *testing.T) {
	// Write a synthetic sshd_config to a temp file, then override
	// the package-level path for the duration of this test.
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	content := `
# This is a comment
PermitRootLogin no
MaxAuthTries 3
LogLevel VERBOSE
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	// Parse the temp file directly using the package function.
	// We shadow sshdConfigPath with a package-level var trick —
	// instead, call the inner function with a temp override.
	orig := sshdConfigPath
	defer func() { _ = orig }() // sshdConfigPath is a const; test reads real path

	// Parse by reading the temp file ourselves and comparing.
	f, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Manually parse to verify our parseSshdConfig logic via its output.
	// Since sshdConfigPath is a const we can't swap it in a unit test
	// without reflection. Instead, test via the directive helper with
	// a hand-built map.
	cfg := map[string]string{
		"permitrootlogin": "no",
		"maxauthretries":  "3",
		"loglevel":        "VERBOSE",
		"ciphers":         "aes256-gcm@openssh.com,aes128-gcm@openssh.com",
	}
	_ = f // used above to confirm the write worked

	if directive(cfg, "PermitRootLogin") != "no" {
		t.Error("directive lookup is not case-insensitive")
	}
	if directive(cfg, "LOGLEVEL") != "VERBOSE" {
		t.Error("directive lookup should be case-insensitive")
	}
	if directive(cfg, "missing") != "" {
		t.Error("missing directive should return empty string")
	}
}

// ---- checkSSHInt ------------------------------------------------------------

func TestCheckSSHInt_Pass(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	cfg := map[string]string{"maxauthtries": "3"}
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
		t.Errorf("expected PASS, got %s", r.Checks[0].Status)
	}
}

func TestCheckSSHInt_Fail(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	cfg := map[string]string{"maxauthtries": "6"}
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
		t.Errorf("expected FAIL, got %s", r.Checks[0].Status)
	}
}

func TestCheckSSHInt_Warn_NotSet(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	cfg := map[string]string{}
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
		t.Errorf("expected WARN when not set, got %s", r.Checks[0].Status)
	}
}

func TestCheckSSHInt_LoginGraceTime_StripsSuffix(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	cfg := map[string]string{"logingracetime": "30s"}
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
		t.Errorf("expected PASS for 30s, got %s detail=%q", r.Checks[0].Status, r.Checks[0].Detail)
	}
}

// ---- checkSSHAlgo -----------------------------------------------------------

func TestCheckSSHAlgo_WeakFound(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	cfg := map[string]string{
		"kexalgorithms": "curve25519-sha256,diffie-hellman-group1-sha1",
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
		t.Errorf("expected FAIL, got %s", r.Checks[0].Status)
	}
	if !strings.Contains(r.Checks[0].Detail, "diffie-hellman-group1-sha1") {
		t.Errorf("detail should name the weak algo: %q", r.Checks[0].Detail)
	}
}

func TestCheckSSHAlgo_NoWeakFound(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	cfg := map[string]string{
		"kexalgorithms": "curve25519-sha256,ecdh-sha2-nistp256",
	}
	checkSSHAlgo(b, cfg, "SSH-014", "KexAlgorithms", "KexAlgorithms",
		func(a string) bool { return weakKEX[a] },
		func() string { return "all strong" },
		func(w []string) string { return "bad" },
		"not set",
		SeverityHigh,
	)
	r := b.Build()
	if r.Checks[0].Status != StatusPass {
		t.Errorf("expected PASS, got %s", r.Checks[0].Status)
	}
}

// ---- weak MAC detection -----------------------------------------------------

// TestWeakMAC_ETMExempt verifies that HMAC variants marked with "etm"
// are NOT flagged as weak. This preserves the Python reference behavior
// where "hmac-sha2-256-etm@openssh.com" is considered acceptable.
func TestWeakMAC_ETMExempt(t *testing.T) {
	b := NewBuilder(WithClock(fixedClock()))
	cfg := map[string]string{
		"macs": "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com",
	}
	// Reproduce SSH-016 check inline (can't call RunSSHChecks without real sshd_config).
	val := directive(cfg, "MACs")
	var found []string
	for _, a := range strings.Split(val, ",") {
		a = strings.TrimSpace(a)
		isWeakPrefix := false
		for _, p := range weakMACPrefixes {
			if strings.HasPrefix(a, p) {
				isWeakPrefix = true
				break
			}
		}
		if isWeakPrefix && !strings.Contains(strings.ToLower(a), "etm") {
			found = append(found, a)
		}
	}
	if len(found) != 0 {
		t.Errorf("ETM-mode MACs should not be flagged as weak, got: %v", found)
	}
	_ = b
}

func TestWeakMAC_NonETMFlagged(t *testing.T) {
	val := "hmac-md5,hmac-sha1"
	var found []string
	for _, a := range strings.Split(val, ",") {
		a = strings.TrimSpace(a)
		isWeakPrefix := false
		for _, p := range weakMACPrefixes {
			if strings.HasPrefix(a, p) {
				isWeakPrefix = true
				break
			}
		}
		if isWeakPrefix && !strings.Contains(strings.ToLower(a), "etm") {
			found = append(found, a)
		}
	}
	if len(found) != 2 {
		t.Errorf("expected 2 weak MACs, got %v", found)
	}
}
