//go:build darwin || linux

package threat

import (
	"os"
	"testing"
)

// ---- isBinaryFile -----------------------------------------------------------

func TestIsBinaryFile_ELF(t *testing.T) {
	if !isBinaryFile([]byte("\x7fELF\x00\x00")) {
		t.Error("ELF magic prefix should be detected as binary")
	}
}

func TestIsBinaryFile_MachO(t *testing.T) {
	cases := []struct {
		name  string
		magic []byte
	}{
		{"mach-o LE 32", []byte("\xce\xfa\xed\xfe")},
		{"mach-o LE 64", []byte("\xcf\xfa\xed\xfe")},
		{"mach-o BE 32", []byte("\xfe\xed\xfa\xce")},
		{"mach-o BE 64", []byte("\xfe\xed\xfa\xcf")},
		{"fat binary",   []byte("\xca\xfe\xba\xbe")},
	}
	for _, tc := range cases {
		if !isBinaryFile(tc.magic) {
			t.Errorf("%s: expected true, got false", tc.name)
		}
	}
}

func TestIsBinaryFile_Text(t *testing.T) {
	if isBinaryFile([]byte("#!/bin/sh\necho hello\n")) {
		t.Error("plain text content should not be detected as binary")
	}
}

func TestIsBinaryFile_EmptySlice(t *testing.T) {
	if isBinaryFile([]byte{}) {
		t.Error("empty slice should return false")
	}
}

func TestIsBinaryFile_ShortSlice(t *testing.T) {
	if isBinaryFile([]byte{0x7f, 0x45}) {
		t.Error("2-byte slice should return false without panicking")
	}
}

// TestCheckLocalIOC_ReturnsResult verifies that CheckLocalIOC runs without
// panicking and returns a result with the expected struct shape. Content is
// system-dependent and not asserted.
func TestCheckLocalIOC_ReturnsResult(t *testing.T) {
	result := CheckLocalIOC()

	// All slice fields must be non-nil (initialised to empty slices, not nil).
	if result.SuspiciousCron == nil {
		t.Error("SuspiciousCron is nil")
	}
	if result.SuspiciousProcesses == nil {
		t.Error("SuspiciousProcesses is nil")
	}
	if result.SuspiciousTempFiles == nil {
		t.Error("SuspiciousTempFiles is nil")
	}
	if result.SSHPersistence == nil {
		t.Error("SSHPersistence is nil")
	}
	if result.ListeningBackdoors == nil {
		t.Error("ListeningBackdoors is nil")
	}
	if result.AuthAnomalies == nil {
		t.Error("AuthAnomalies is nil")
	}
}

// TestCheckCVEExposure_ReturnsResult verifies that CheckCVEExposure runs
// without panicking and returns a result with the expected struct shape.
func TestCheckCVEExposure_ReturnsResult(t *testing.T) {
	result := CheckCVEExposure()

	// Findings may be empty but must not be nil.
	if result.Findings == nil {
		t.Error("Findings is nil")
	}
	if result.PackagesChecked == nil {
		t.Error("PackagesChecked is nil")
	}
}

// TestVersionLT is a table-driven test for the versionLT helper.
func TestVersionLT(t *testing.T) {
	cases := []struct {
		installed string
		threshold string
		want      bool
		desc      string
	}{
		{"1.0.0", "2.0.0", true, "major version bump"},
		{"2.0.0", "1.0.0", false, "installed newer than threshold"},
		{"1.0.0", "1.0.0", false, "equal versions are not less-than"},
		{"1.0.9", "1.0.10", true, "numeric comparison (not lexicographic)"},
		{"9.7p1", "9.8", true, "pre-release/p suffix stripped"},
		{"1:9.7p1", "9.8", true, "epoch prefix stripped"},
		{"3.0.14", "3.0.14", false, "equal semver not less-than"},
		{"3.0.13", "3.0.14", true, "patch version less-than"},
		{"8.4.0", "8.6.0", true, "curl SOCKS5 case"},
		{"2.45.1", "2.45.1", false, "git equal not vulnerable"},
		{"2.44.0", "2.45.1", true, "git vulnerable version"},
		{"0.119", "0.120", true, "polkit PwnKit"},
		{"247.2", "247.3", true, "systemd minor patch"},
		{"5.6.1", "5.6.2", true, "three-part patch"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := versionLT(tc.installed, tc.threshold)
			if got != tc.want {
				t.Errorf("versionLT(%q, %q) = %v, want %v", tc.installed, tc.threshold, got, tc.want)
			}
		})
	}
}

// TestShodanSkipsPrivateIP verifies that private IPs are skipped gracefully.
func TestShodanSkipsPrivateIP(t *testing.T) {
	result := CheckShodan("192.168.1.1")
	if !result.Skipped {
		t.Errorf("expected Skipped=true for private IP, got Skipped=%v (SkipReason=%q)", result.Skipped, result.SkipReason)
	}
}

// TestShodanSkipsEmptyIP verifies that an empty IP string is skipped gracefully.
func TestShodanSkipsEmptyIP(t *testing.T) {
	result := CheckShodan("")
	if !result.Skipped {
		t.Errorf("expected Skipped=true for empty IP, got Skipped=%v (SkipReason=%q)", result.Skipped, result.SkipReason)
	}
}

// TestAbuseIPDB_SkipsWhenNoKey verifies that CheckAbuseIPDB returns a skip
// result when ABUSEIPDB_KEY is not set.
func TestAbuseIPDB_SkipsWhenNoKey(t *testing.T) {
	prev := os.Getenv("ABUSEIPDB_KEY")
	os.Unsetenv("ABUSEIPDB_KEY")
	defer func() {
		if prev != "" {
			os.Setenv("ABUSEIPDB_KEY", prev)
		}
	}()

	result := CheckAbuseIPDB("8.8.8.8")
	if !result.Skipped {
		t.Errorf("expected Skipped=true when ABUSEIPDB_KEY unset, got Skipped=%v", result.Skipped)
	}
}

// TestScan_StructureIsValid calls Scan() without a real public IP or API key
// and verifies the returned Result has the expected struct shape.
func TestScan_StructureIsValid(t *testing.T) {
	// Ensure no API key is set so AbuseIPDB is always skipped.
	prev := os.Getenv("ABUSEIPDB_KEY")
	os.Unsetenv("ABUSEIPDB_KEY")
	defer func() {
		if prev != "" {
			os.Setenv("ABUSEIPDB_KEY", prev)
		}
	}()

	result := Scan()

	// AbuseIPDB must be skipped (no key).
	if !result.AbuseIPDB.Skipped {
		t.Error("expected AbuseIPDB.Skipped=true when key is absent")
	}

	// LocalIOC slices must be initialised.
	if result.LocalIOC.SuspiciousCron == nil {
		t.Error("LocalIOC.SuspiciousCron is nil")
	}
	if result.LocalIOC.SuspiciousProcesses == nil {
		t.Error("LocalIOC.SuspiciousProcesses is nil")
	}
	if result.LocalIOC.SuspiciousTempFiles == nil {
		t.Error("LocalIOC.SuspiciousTempFiles is nil")
	}
	if result.LocalIOC.SSHPersistence == nil {
		t.Error("LocalIOC.SSHPersistence is nil")
	}
	if result.LocalIOC.ListeningBackdoors == nil {
		t.Error("LocalIOC.ListeningBackdoors is nil")
	}
	if result.LocalIOC.AuthAnomalies == nil {
		t.Error("LocalIOC.AuthAnomalies is nil")
	}

	// CVE slices must be initialised.
	if result.CVE.Findings == nil {
		t.Error("CVE.Findings is nil")
	}
	if result.CVE.PackagesChecked == nil {
		t.Error("CVE.PackagesChecked is nil")
	}

	// CISAKEV slice must be initialised.
	if result.CISAKEV.Matched == nil {
		t.Error("CISAKEV.Matched is nil")
	}

	// Scan must not report itself as skipped.
	if result.Skipped {
		t.Error("Scan().Skipped should be false")
	}
}
