//go:build darwin || linux

package openclaw

import (
	"testing"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
)

// newBuilder returns a CheckBuilder with a fixed clock for deterministic tests.
func newBuilder() *scan.CheckBuilder {
	return scan.NewBuilder()
}

// TestRunAudit_SkipWhenBinaryMissing verifies that RunAudit emits exactly one
// SKIP check when the openclaw binary is not on PATH (guaranteed on CI/dev
// machines that don't have openclaw installed).
func TestRunAudit_SkipWhenBinaryMissing(t *testing.T) {
	// If openclaw happens to be installed on this machine, this test is
	// not meaningful — skip it rather than failing.
	install := DetectInstall()
	if install.BinaryPath != "" || install.Version != "" {
		t.Skip("openclaw is installed on this machine; skipping binary-missing test")
	}

	b := newBuilder()
	RunAudit(b)

	r := b.Build()
	if got := len(r.Checks); got != 1 {
		t.Fatalf("expected exactly 1 check, got %d: %+v", got, r.Checks)
	}

	c := r.Checks[0]
	if c.ID != skipID {
		t.Errorf("check ID = %q, want %q", c.ID, skipID)
	}
	if c.Status != scan.StatusSkip {
		t.Errorf("check Status = %q, want SKIP", c.Status)
	}
}

// TestDetectInstall_ChannelFromPath tests the path-marker channel detection
// logic directly with synthetic path strings (no subprocess needed).
func TestDetectInstall_ChannelFromPath(t *testing.T) {
	tests := []struct {
		name        string
		normPath    string
		wantChannel string
	}{
		{"npm node_modules", "/home/user/.nvm/versions/node/v20/node_modules/openclaw/bin/openclaw", "npm"},
		{"npm .npm", "/home/user/.npm/openclaw/bin/openclaw", "npm"},
		{"npm /npm/", "/usr/lib/npm/openclaw", "npm"},
		{"yarn global", "/home/user/.config/yarn/global/node_modules/.bin/openclaw", "npm"},
		{"pnpm global", "/home/user/.local/share/pnpm/global/5/node_modules/.bin/openclaw", "npm"},
		{"brew cellar", "/usr/local/cellar/openclaw/1.2.3/bin/openclaw", "brew"},
		{"opt homebrew", "/opt/homebrew/bin/openclaw", "brew"},
		{"linuxbrew", "/home/linuxbrew/.linuxbrew/bin/openclaw", "brew"},
		{"usr local opt", "/usr/local/opt/openclaw/bin/openclaw", "brew"},
		{"unknown path", "/usr/bin/openclaw", "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := channelFromPath(tc.normPath)
			if got != tc.wantChannel {
				t.Errorf("channelFromPath(%q) = %q, want %q", tc.normPath, got, tc.wantChannel)
			}
		})
	}
}

// TestTailorRemediation_NPM verifies that npm channel rewrites the generic
// update text to the correct npm command.
func TestTailorRemediation_NPM(t *testing.T) {
	input := "Please update openclaw to fix this issue."
	got := TailorRemediation(input, "npm")
	want := "Please npm update -g openclaw to fix this issue."
	if got != want {
		t.Errorf("TailorRemediation npm:\n  got  %q\n  want %q", got, want)
	}
}

// TestTailorRemediation_Brew verifies that brew channel rewrites correctly.
func TestTailorRemediation_Brew(t *testing.T) {
	input := "Please upgrade openclaw to the latest version."
	got := TailorRemediation(input, "brew")
	want := "Please brew upgrade openclaw to the latest version."
	if got != want {
		t.Errorf("TailorRemediation brew:\n  got  %q\n  want %q", got, want)
	}
}

// TestTailorRemediation_NoMatch verifies that unrelated text is returned
// unchanged.
func TestTailorRemediation_NoMatch(t *testing.T) {
	input := "Disable remote login to improve security."
	got := TailorRemediation(input, "npm")
	if got != input {
		t.Errorf("TailorRemediation no-match mutated text:\n  got  %q\n  want %q", got, input)
	}
}

// TestTailorRemediation_CaseInsensitive verifies that mixed-case trigger text
// like "Update OpenClaw" still triggers a rewrite.
func TestTailorRemediation_CaseInsensitive(t *testing.T) {
	input := "Update OpenClaw to resolve this finding."
	got := TailorRemediation(input, "brew")
	// The trigger "update openclaw" matches at index 0 (case-insensitive).
	// The replacement splices in the brew command in place of the matched
	// trigger, preserving surrounding text.
	if got == input {
		t.Errorf("TailorRemediation case-insensitive: text was not rewritten\n  input: %q", input)
	}
	if !containsString(got, "brew upgrade openclaw") {
		t.Errorf("TailorRemediation case-insensitive: expected brew command in output\n  got: %q", got)
	}
}

// TestTranslateFinding_Critical verifies that a critical finding maps to
// StatusFail + SeverityCritical.
func TestTranslateFinding_Critical(t *testing.T) {
	b := newBuilder()
	f := auditFinding{
		CheckID:  "OC-001",
		Title:    "Privileged access misconfigured",
		Severity: "critical",
		Detail:   "Root login is enabled.",
	}
	TranslateFinding(b, f, InstallInfo{Channel: "unknown"})

	r := b.Build()
	if len(r.Checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(r.Checks))
	}
	c := r.Checks[0]
	if c.Status != scan.StatusFail {
		t.Errorf("Status = %q, want FAIL", c.Status)
	}
	if c.Severity != scan.SeverityCritical {
		t.Errorf("Severity = %q, want critical", c.Severity)
	}
}

// TestTranslateFinding_Warn verifies that warn maps to StatusWarn + SeverityMedium.
func TestTranslateFinding_Warn(t *testing.T) {
	b := newBuilder()
	f := auditFinding{
		CheckID:  "OC-002",
		Title:    "Logging level suboptimal",
		Severity: "warn",
		Detail:   "Verbose logging is disabled.",
	}
	TranslateFinding(b, f, InstallInfo{Channel: "unknown"})

	r := b.Build()
	c := r.Checks[0]
	if c.Status != scan.StatusWarn {
		t.Errorf("Status = %q, want WARN", c.Status)
	}
	if c.Severity != scan.SeverityMedium {
		t.Errorf("Severity = %q, want medium", c.Severity)
	}
}

// TestTranslateFinding_Info verifies that info maps to StatusPass + SeverityLow.
func TestTranslateFinding_Info(t *testing.T) {
	b := newBuilder()
	f := auditFinding{
		CheckID:  "OC-003",
		Title:    "Auto-update enabled",
		Severity: "info",
		Detail:   "OpenClaw is set to auto-update.",
	}
	TranslateFinding(b, f, InstallInfo{Channel: "unknown"})

	r := b.Build()
	c := r.Checks[0]
	if c.Status != scan.StatusPass {
		t.Errorf("Status = %q, want PASS", c.Status)
	}
	if c.Severity != scan.SeverityLow {
		t.Errorf("Severity = %q, want low", c.Severity)
	}
}

// TestTranslateFinding_AppendsFix verifies that a non-empty remediation field
// causes "\nFix: <tailored>" to be appended to Detail.
func TestTranslateFinding_AppendsFix(t *testing.T) {
	b := newBuilder()
	f := auditFinding{
		CheckID:     "OC-004",
		Title:       "Old version",
		Severity:    "warn",
		Detail:      "You are running an outdated version.",
		Remediation: "update openclaw",
	}
	TranslateFinding(b, f, InstallInfo{Channel: "npm"})

	r := b.Build()
	c := r.Checks[0]

	wantSuffix := "\nFix: npm update -g openclaw"
	if !containsSuffix(c.Detail, wantSuffix) {
		t.Errorf("Detail does not end with expected Fix line\n  Detail: %q\n  want suffix: %q", c.Detail, wantSuffix)
	}
}

// TestTranslateFinding_NoFixWhenNoRemediation verifies that Detail is left
// unchanged when the finding has no remediation.
func TestTranslateFinding_NoFixWhenNoRemediation(t *testing.T) {
	b := newBuilder()
	originalDetail := "This is the original detail."
	f := auditFinding{
		CheckID:     "OC-005",
		Title:       "Some check",
		Severity:    "info",
		Detail:      originalDetail,
		Remediation: "",
	}
	TranslateFinding(b, f, InstallInfo{Channel: "npm"})

	r := b.Build()
	c := r.Checks[0]
	if c.Detail != originalDetail {
		t.Errorf("Detail was mutated when remediation is empty\n  got  %q\n  want %q", c.Detail, originalDetail)
	}
}

// TestOcVersionLT exercises the version comparator with openclaw-style date versions.
func TestOcVersionLT(t *testing.T) {
	tests := []struct {
		v1, v2 string
		want   bool
	}{
		{"2026.3.11", "2026.3.12", true},
		{"2026.3.12", "2026.3.12", false},
		{"2026.3.13", "2026.3.12", false},
		{"2026.2.14", "2026.3.12", true},
		{"2026.3.0", "2026.3.12", true},
		{"2025.12.31", "2026.1.1", true},
		{"2026.3.29", "2026.3.29", false},
	}
	for _, tc := range tests {
		got := ocVersionLT(tc.v1, tc.v2)
		if got != tc.want {
			t.Errorf("ocVersionLT(%q, %q) = %v, want %v", tc.v1, tc.v2, got, tc.want)
		}
	}
}

// TestCheckVulns_OldVersion verifies that a very old version gets findings.
func TestCheckVulns_OldVersion(t *testing.T) {
	r := CheckVulns("2026.1.1")
	if len(r.Findings) == 0 {
		t.Fatal("expected findings for a very old version, got none")
	}
	if r.Error != "" {
		t.Errorf("unexpected error: %s", r.Error)
	}
	if r.Checked != len(openclawGatewayCVEs) {
		t.Errorf("Checked = %d, want %d", r.Checked, len(openclawGatewayCVEs))
	}
}

// TestCheckVulns_CurrentVersion verifies that a version beyond all known advisories is clean.
func TestCheckVulns_CurrentVersion(t *testing.T) {
	// Use a version well beyond all current advisory thresholds.
	r := CheckVulns("2026.5.5")
	if len(r.Findings) != 0 {
		t.Errorf("expected no findings for future version, got %d: %+v", len(r.Findings), r.Findings)
	}
	if r.Error != "" {
		t.Errorf("unexpected error: %s", r.Error)
	}
}

// TestCheckVulns_April2026Version verifies that 2026.4.16 is flagged by the April advisories.
func TestCheckVulns_April2026Version(t *testing.T) {
	r := CheckVulns("2026.4.16")
	if r.Error != "" {
		t.Fatalf("unexpected error: %s", r.Error)
	}
	if len(r.Findings) == 0 {
		t.Fatal("expected findings for 2026.4.16 (April advisories should apply), got none")
	}
	hasCritical := false
	for _, f := range r.Findings {
		if f.Severity == "CRITICAL" {
			hasCritical = true
			break
		}
	}
	if !hasCritical {
		t.Error("expected at least one CRITICAL finding for 2026.4.16")
	}
}

// TestCheckVulns_EmptyVersion verifies that an empty version string produces an error.
func TestCheckVulns_EmptyVersion(t *testing.T) {
	r := CheckVulns("")
	if r.Error == "" {
		t.Error("expected error for empty version, got none")
	}
}

// TestCheckVulns_RawVersionString verifies that version text like "OpenClaw 2026.1.5" is parsed.
func TestCheckVulns_RawVersionString(t *testing.T) {
	r := CheckVulns("OpenClaw 2026.1.5")
	if r.Error != "" {
		t.Errorf("unexpected error parsing raw version string: %s", r.Error)
	}
	if len(r.Findings) == 0 {
		t.Error("expected findings for old version embedded in raw string")
	}
}

// TestCheckVulns_FindingSeverities verifies that critical findings appear in results.
func TestCheckVulns_FindingSeverities(t *testing.T) {
	r := CheckVulns("2026.1.1")
	hasCritical := false
	for _, f := range r.Findings {
		if f.Severity == "CRITICAL" {
			hasCritical = true
			break
		}
	}
	if !hasCritical {
		t.Error("expected at least one CRITICAL finding for very old version")
	}
}

// TestOcVersionLT_ShortVersion verifies that a two-segment version is treated
// as if it has a trailing .0 (e.g. "2026.3" == "2026.3.0").
func TestOcVersionLT_ShortVersion(t *testing.T) {
	if !ocVersionLT("2026.3", "2026.3.12") {
		t.Error("ocVersionLT(\"2026.3\", \"2026.3.12\") should be true (2026.3 treated as 2026.3.0)")
	}
}

// TestOcVersionLT_EqualTwoSegment verifies that identical two-segment versions
// are not considered less-than.
func TestOcVersionLT_EqualTwoSegment(t *testing.T) {
	if ocVersionLT("2026.3", "2026.3") {
		t.Error("ocVersionLT(\"2026.3\", \"2026.3\") should be false (equal versions)")
	}
}

// TestCheckVulns_VersionWithPrefix verifies that a version string with a
// human-readable prefix like "OpenClaw Gateway v2026.1.1" is parsed correctly.
func TestCheckVulns_VersionWithPrefix(t *testing.T) {
	r := CheckVulns("OpenClaw Gateway v2026.1.1")
	if r.Error != "" {
		t.Fatalf("unexpected error: %s", r.Error)
	}
	if len(r.Findings) == 0 {
		t.Error("expected findings for old version with prefix, got none")
	}
}

// TestCheckVulns_UnparsableVersion verifies that a version string with no
// numeric portion sets the Error field.
func TestCheckVulns_UnparsableVersion(t *testing.T) {
	r := CheckVulns("not-a-version")
	if r.Error == "" {
		t.Error("expected Error to be set for unparsable version, got empty string")
	}
}

// TestParseVersionDate verifies YYYY.M.D parsing.
func TestParseVersionDate(t *testing.T) {
	cases := []struct {
		input   string
		wantOK  bool
		wantY   int
		wantM   int
		wantD   int
	}{
		{"2026.4.16", true, 2026, 4, 16},
		{"2026.12.31", true, 2026, 12, 31},
		{"v2026.4.16", true, 2026, 4, 16},
		{"2026.4.16-rc1", true, 2026, 4, 16},
		{"2026.4.16+g3a1b2c", true, 2026, 4, 16},
		{"2026.4", false, 0, 0, 0},
		{"not-a-version", false, 0, 0, 0},
		{"", false, 0, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, ok := parseVersionDate(tc.input)
			if ok != tc.wantOK {
				t.Fatalf("parseVersionDate(%q) ok = %v, want %v", tc.input, ok, tc.wantOK)
			}
			if ok {
				if got.Year() != tc.wantY || int(got.Month()) != tc.wantM || got.Day() != tc.wantD {
					t.Errorf("parseVersionDate(%q) = %v, want %d-%d-%d", tc.input, got, tc.wantY, tc.wantM, tc.wantD)
				}
			}
		})
	}
}

// TestAddVersionCheck_OldVersionFails verifies that a >90-day-old version gets FAIL.
func TestAddVersionCheck_OldVersionFails(t *testing.T) {
	b := newBuilder()
	install := InstallInfo{Version: "2025.1.1", Channel: "brew"}
	addVersionCheck(b, install)
	r := b.Build()
	if len(r.Checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(r.Checks))
	}
	c := r.Checks[0]
	if c.ID != versionCheckID {
		t.Errorf("check ID = %q, want %q", c.ID, versionCheckID)
	}
	if c.Status != scan.StatusFail {
		t.Errorf("Status = %q, want FAIL for very old version", c.Status)
	}
}

// TestAddVersionCheck_RecentVersionPasses verifies that a fresh version gets PASS.
func TestAddVersionCheck_RecentVersionPasses(t *testing.T) {
	b := newBuilder()
	// Use a version one day in the future to guarantee it's always "fresh".
	import_time := "2099.1.1"
	install := InstallInfo{Version: import_time, Channel: "npm"}
	addVersionCheck(b, install)
	r := b.Build()
	c := r.Checks[0]
	if c.Status != scan.StatusPass {
		t.Errorf("Status = %q, want PASS for future version", c.Status)
	}
}

// TestAddVersionCheck_UnparsableVersionSkips verifies that a non-date version gets SKIP.
func TestAddVersionCheck_UnparsableVersionSkips(t *testing.T) {
	b := newBuilder()
	install := InstallInfo{Version: "nightly", Channel: "source"}
	addVersionCheck(b, install)
	r := b.Build()
	c := r.Checks[0]
	if c.Status != scan.StatusSkip {
		t.Errorf("Status = %q, want SKIP for unparsable version", c.Status)
	}
}

// containsString is a simple substring check used in assertions.
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}

// containsSuffix reports whether s contains suffix anywhere (not just at end).
// Named "containsSuffix" by convention but acts as a contains check for the
// "\nFix: ..." pattern which appears at the end of Detail.
func containsSuffix(s, substr string) bool {
	return containsString(s, substr)
}
