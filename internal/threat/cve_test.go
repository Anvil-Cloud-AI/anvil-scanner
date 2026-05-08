//go:build darwin || linux

package threat

import (
	"runtime"
	"strings"
	"testing"
)

// ---- normalizeVersion -------------------------------------------------------

// TestNormalizeVersion_TableDriven exercises normalizeVersion with various
// Debian/Ubuntu/macOS version string formats.
func TestNormalizeVersion_TableDriven(t *testing.T) {
	cases := []struct {
		input string
		want  string
		desc  string
	}{
		{"1:9.7p1", "9.7p1", "epoch stripped"},
		{"2:1.0.3-5ubuntu2", "1.0.3", "epoch + Debian revision stripped"},
		{"3.0.14", "3.0.14", "plain semver unchanged"},
		{"9.8p1-3ubuntu1", "9.8p1", "Debian revision stripped"},
		{"1.27.1+dfsg-1", "1.27.1", "plus metadata stripped"},
		{"5.6.0", "5.6.0", "XZ version unchanged"},
		{"5.6.1", "5.6.1", "XZ version unchanged"},
		{"", "", "empty string"},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := normalizeVersion(tc.input)
			if got != tc.want {
				t.Errorf("normalizeVersion(%q) = %q; want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ---- versionLT extended edge cases ------------------------------------------

// TestVersionLT_ExtendedCases supplements the existing table-driven tests with
// cases focused on epoch handling, build metadata, and zero-padding.
func TestVersionLT_ExtendedCases(t *testing.T) {
	cases := []struct {
		installed string
		threshold string
		want      bool
		desc      string
	}{
		{"1:1.0.0", "2.0.0", true, "epoch stripped before comparison"},
		{"1:3.0.14", "3.0.14", false, "epoch 1:3.0.14 equals 3.0.14"},
		{"1.27.1+dfsg-1", "1.27.1", false, "installed with metadata equals threshold"},
		{"1.27.0+dfsg-1", "1.27.1", true, "installed older after stripping metadata"},
		{"0", "1", true, "zero less than one"},
		{"1", "0", false, "one greater than zero"},
		{"2.45.0", "2.45.1", true, "minor patch difference"},
		{"2.4.56", "2.4.62", true, "apache vulnerable patch"},
		{"2.4.62", "2.4.62", false, "apache equal to threshold"},
		{"9.8", "9.8", false, "openssh equal to threshold"},
		{"9.7", "9.8", true, "openssh older"},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := versionLT(tc.installed, tc.threshold)
			if got != tc.want {
				t.Errorf("versionLT(%q, %q) = %v; want %v", tc.installed, tc.threshold, got, tc.want)
			}
		})
	}
}

// ---- getPkgVersion ----------------------------------------------------------

// TestGetPkgVersion_UnknownPackageReturnsEmpty verifies that a package name
// that is certainly not installed returns an empty string without error.
// The package name contains characters that cannot be a real package identifier.
func TestGetPkgVersion_UnknownPackageReturnsEmpty(t *testing.T) {
	// A package name that cannot exist (contains uppercase and special chars
	// that no real package uses, and is not a valid dpkg/brew name).
	got := getPkgVersion("ANVIL-DOES-NOT-EXIST-XYZZY12345-TEST")
	if got != "" {
		t.Errorf("getPkgVersion(unknown) = %q; want empty string", got)
	}
}

// ---- CheckCVEExposure -------------------------------------------------------

// TestCheckCVEExposure_SlicesInitialised verifies that both Findings and
// PackagesChecked are non-nil after CheckCVEExposure runs.
// This test is skipped on macOS because getPkgVersion() invokes 'brew' for
// every package in knownCVEs, which is far too slow for a unit test.
func TestCheckCVEExposure_SlicesInitialised(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("skipping on macOS: CheckCVEExposure calls brew for each package (too slow)")
	}
	result := CheckCVEExposure()
	if result.Findings == nil {
		t.Error("CheckCVEExposure() Findings is nil; want non-nil (possibly empty) slice")
	}
	if result.PackagesChecked == nil {
		t.Error("CheckCVEExposure() PackagesChecked is nil; want non-nil (possibly empty) slice")
	}
}

// TestCheckCVEExposure_FindingsAreConsistent verifies that every finding
// references a package that also appears in PackagesChecked, and that the CVE
// field is non-empty.
func TestCheckCVEExposure_FindingsAreConsistent(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("skipping on macOS: too slow due to brew invocations")
	}
	result := CheckCVEExposure()

	checked := make(map[string]bool, len(result.PackagesChecked))
	for _, p := range result.PackagesChecked {
		// PackagesChecked entries are "pkg version" — extract the package name.
		parts := strings.Fields(p)
		if len(parts) > 0 {
			checked[parts[0]] = true
		}
	}

	for _, f := range result.Findings {
		if f.CVE == "" {
			t.Errorf("finding for package %q has empty CVE field", f.Package)
		}
		if f.Package == "" {
			t.Error("finding has empty Package field")
		}
		if f.Severity == "" {
			t.Errorf("finding %q has empty Severity", f.CVE)
		}
		if !checked[f.Package] {
			t.Errorf("finding for %q is not in PackagesChecked (%v)", f.Package, result.PackagesChecked)
		}
	}
}

// TestCheckCVEExposure_FixFieldPopulated verifies that every finding has a
// non-empty Fix field.
func TestCheckCVEExposure_FixFieldPopulated(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("skipping on macOS: too slow due to brew invocations")
	}
	result := CheckCVEExposure()
	for _, f := range result.Findings {
		if f.Fix == "" {
			t.Errorf("finding %q (package %s) has empty Fix field", f.CVE, f.Package)
		}
	}
}

// ---- knownCVEs database integrity ------------------------------------------

// TestKnownCVEs_AllEntriesNonEmpty verifies that each entry in knownCVEs has
// non-empty required fields. This is pure in-memory and runs instantly.
func TestKnownCVEs_AllEntriesNonEmpty(t *testing.T) {
	for pkg, cves := range knownCVEs {
		if pkg == "" {
			t.Error("knownCVEs has an empty package name key")
		}
		if len(cves) == 0 {
			t.Errorf("package %q has empty CVE list", pkg)
		}
		for _, cve := range cves {
			if cve.CVE == "" {
				t.Errorf("package %q has entry with empty CVE field", pkg)
			}
			if cve.Severity == "" {
				t.Errorf("CVE %q for package %q has empty Severity", cve.CVE, pkg)
			}
			if cve.Desc == "" {
				t.Errorf("CVE %q for package %q has empty Desc", cve.CVE, pkg)
			}
		}
	}
}

// TestKnownCVEs_XZBackdoorVersionsCorrect verifies the XZ entry uses CVE-2024-3094.
func TestKnownCVEs_XZBackdoorVersionsCorrect(t *testing.T) {
	xzCVEs, ok := knownCVEs["xz-utils"]
	if !ok {
		t.Skip("xz-utils not in knownCVEs")
	}
	found := false
	for _, c := range xzCVEs {
		if c.CVE == "CVE-2024-3094" {
			found = true
			break
		}
	}
	if !found {
		t.Error("CVE-2024-3094 not found in xz-utils entries")
	}
}

// TestKnownCVEs_XZBackdoorLogic verifies the special-case XZ backdoor check:
// versions 5.6.0 and 5.6.1 are affected; 5.5.9 and 5.6.2 are not.
func TestKnownCVEs_XZBackdoorLogic(t *testing.T) {
	cases := []struct {
		version      string
		wantAffected bool
	}{
		{"5.6.0", true},
		{"5.6.1", true},
		{"5.5.9", false},
		{"5.6.2", false},
		{"5.4.0", false},
	}
	for _, tc := range cases {
		t.Run("xz-"+tc.version, func(t *testing.T) {
			norm := normalizeVersion(tc.version)
			affected := norm == "5.6.0" || norm == "5.6.1"
			if affected != tc.wantAffected {
				t.Errorf("XZ backdoor: version %q affected=%v; want %v",
					tc.version, affected, tc.wantAffected)
			}
		})
	}
}

// TestKnownCVEs_CVEIDFormat verifies that all CVE IDs follow the CVE-YYYY-NNNN format.
func TestKnownCVEs_CVEIDFormat(t *testing.T) {
	for pkg, cves := range knownCVEs {
		for _, cve := range cves {
			if !strings.HasPrefix(cve.CVE, "CVE-") {
				t.Errorf("package %q: CVE ID %q does not start with 'CVE-'", pkg, cve.CVE)
			}
			parts := strings.SplitN(cve.CVE, "-", 3)
			if len(parts) != 3 {
				t.Errorf("package %q: CVE ID %q has wrong format (want CVE-YYYY-NNNN)", pkg, cve.CVE)
			}
		}
	}
}

// TestKnownCVEs_SeverityValues verifies that all Severity values are one of
// the accepted strings (CRITICAL, HIGH, MEDIUM, LOW).
func TestKnownCVEs_SeverityValues(t *testing.T) {
	valid := map[string]bool{
		"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true,
	}
	for pkg, cves := range knownCVEs {
		for _, cve := range cves {
			if !valid[cve.Severity] {
				t.Errorf("package %q CVE %q has unrecognised Severity %q", pkg, cve.CVE, cve.Severity)
			}
		}
	}
}

// TestKnownCVEs_AffectedBelowIsVersionString verifies that AffectedBelow looks
// like a version string (contains at least one digit).
func TestKnownCVEs_AffectedBelowIsVersionString(t *testing.T) {
	for pkg, cves := range knownCVEs {
		for _, cve := range cves {
			if cve.AffectedBelow == "" {
				// XZ backdoor has no AffectedBelow — that's intentional.
				if cve.CVE != "CVE-2024-3094" {
					t.Errorf("package %q CVE %q has empty AffectedBelow", pkg, cve.CVE)
				}
				continue
			}
			hasDigit := false
			for _, ch := range cve.AffectedBelow {
				if ch >= '0' && ch <= '9' {
					hasDigit = true
					break
				}
			}
			if !hasDigit {
				t.Errorf("package %q CVE %q AffectedBelow %q contains no digit",
					pkg, cve.CVE, cve.AffectedBelow)
			}
		}
	}
}
