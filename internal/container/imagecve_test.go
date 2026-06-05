//go:build darwin || linux

package container

import (
	"testing"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
)

const grypeJSON = `{
  "matches": [
    {
      "vulnerability": {
        "id": "CVE-2023-0001",
        "severity": "Critical",
        "risk": 8.7,
        "fix": {"versions": ["1.2.4", "1.3.0"], "state": "fixed"}
      },
      "artifact": {"name": "openssl", "version": "1.2.3"}
    },
    {
      "vulnerability": {
        "id": "GHSA-xxxx",
        "severity": "Medium",
        "fix": {"versions": [], "state": "not-fixed"}
      },
      "artifact": {"name": "zlib", "version": "1.0"}
    }
  ]
}`

const trivyJSON = `{
  "Results": [
    {
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-0001",
          "Severity": "CRITICAL",
          "PkgName": "openssl",
          "InstalledVersion": "1.2.3",
          "FixedVersion": "1.2.4"
        },
        {
          "VulnerabilityID": "CVE-2023-0002",
          "Severity": "HIGH",
          "PkgName": "curl",
          "InstalledVersion": "8.0",
          "FixedVersion": ""
        }
      ]
    }
  ]
}`

func TestParseGrype(t *testing.T) {
	got, err := parseGrype(grypeJSON)
	if err != nil {
		t.Fatalf("parseGrype: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}
	first := got[0]
	if first.ID != "CVE-2023-0001" || first.Severity != "CRITICAL" {
		t.Errorf("first = %+v", first)
	}
	if first.Package != "openssl" || first.Version != "1.2.3" {
		t.Errorf("artifact fields = %+v", first)
	}
	if first.FixedIn != "1.2.4, 1.3.0" {
		t.Errorf("FixedIn = %q, want \"1.2.4, 1.3.0\"", first.FixedIn)
	}
	if first.Risk != 8.7 {
		t.Errorf("Risk = %v, want 8.7", first.Risk)
	}
	if got[1].Severity != "MEDIUM" || got[1].FixedIn != "" {
		t.Errorf("second = %+v", got[1])
	}
}

func TestParseTrivy(t *testing.T) {
	got, err := parseTrivy(trivyJSON)
	if err != nil {
		t.Fatalf("parseTrivy: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}
	if got[0].ID != "CVE-2023-0001" || got[0].Severity != "CRITICAL" || got[0].FixedIn != "1.2.4" {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].Severity != "HIGH" || got[1].Package != "curl" {
		t.Errorf("second = %+v", got[1])
	}
}

func TestParseInvalidJSON(t *testing.T) {
	if _, err := parseGrype("not json"); err == nil {
		t.Error("parseGrype: expected error on invalid JSON")
	}
	if _, err := parseTrivy("not json"); err == nil {
		t.Error("parseTrivy: expected error on invalid JSON")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]string{
		"Critical":   "CRITICAL",
		"high":       "HIGH",
		" Medium ":   "MEDIUM",
		"low":        "LOW",
		"negligible": "UNKNOWN",
		"":           "UNKNOWN",
	}
	for in, want := range cases {
		if got := normalizeSeverity(in); got != want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateImageRef(t *testing.T) {
	valid := []string{
		"alpine:3.19",
		"nginx",
		"ghcr.io/openclaw/openclaw:v1.2.3",
		"registry.example.com:5000/team/app:tag",
		"alpine@sha256:abcdef0123456789",
	}
	for _, ref := range valid {
		if err := ValidateImageRef(ref); err != nil {
			t.Errorf("ValidateImageRef(%q) = %v, want nil", ref, err)
		}
	}

	invalid := []string{
		"",                       // empty
		"--output=/etc/cron.d/x", // flag injection
		"-o",                     // leading dash
		"alpine; rm -rf /",       // shell metachars + space
		"alpine`whoami`",         // backtick
		"alpine$(id)",            // command substitution
		"image|tee",              // pipe
	}
	for _, ref := range invalid {
		if err := ValidateImageRef(ref); err == nil {
			t.Errorf("ValidateImageRef(%q) = nil, want error", ref)
		}
	}

	// Over-length ref is rejected.
	long := make([]byte, maxImageRefLen+1)
	for i := range long {
		long[i] = 'a'
	}
	if err := ValidateImageRef(string(long)); err == nil {
		t.Error("ValidateImageRef(over-length) = nil, want error")
	}
}

func TestDedupe(t *testing.T) {
	got := dedupe([]string{"a", "b", "a", "", "  ", "c", "b"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dedupe[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSeverityCounts(t *testing.T) {
	r := &ImageCVEResult{Scans: []ImageScan{
		{Findings: []ImageCVE{
			{Severity: "CRITICAL"}, {Severity: "HIGH"}, {Severity: "HIGH"}, {Severity: "LOW"},
		}},
		{Findings: []ImageCVE{{Severity: "CRITICAL"}, {Severity: "MEDIUM"}}},
	}}
	crit, high, total := r.SeverityCounts()
	if crit != 2 || high != 2 || total != 6 {
		t.Errorf("counts = (%d crit, %d high, %d total), want (2, 2, 6)", crit, high, total)
	}
}

func TestRunImageCVECheck(t *testing.T) {
	tests := []struct {
		name   string
		result *ImageCVEResult
		want   scan.Status
	}{
		{"nil result skips", nil, scan.StatusSkip},
		{"explicitly skipped", &ImageCVEResult{Skipped: true, SkipReason: "no scanner"}, scan.StatusSkip},
		{"scanner but no images skips", &ImageCVEResult{Scanner: "grype"}, scan.StatusSkip},
		{
			name: "critical fails",
			result: &ImageCVEResult{Scanner: "grype", Scans: []ImageScan{
				{Ref: "img", Findings: []ImageCVE{{Severity: "CRITICAL"}}},
			}},
			want: scan.StatusFail,
		},
		{
			name: "high warns",
			result: &ImageCVEResult{Scanner: "grype", Scans: []ImageScan{
				{Ref: "img", Findings: []ImageCVE{{Severity: "HIGH"}}},
			}},
			want: scan.StatusWarn,
		},
		{
			name: "only low passes",
			result: &ImageCVEResult{Scanner: "grype", Scans: []ImageScan{
				{Ref: "img", Findings: []ImageCVE{{Severity: "LOW"}}},
			}},
			want: scan.StatusPass,
		},
		{
			name: "clean image passes",
			result: &ImageCVEResult{Scanner: "grype", Scans: []ImageScan{
				{Ref: "img", Findings: nil},
			}},
			want: scan.StatusPass,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := scan.NewBuilder()
			RunImageCVECheck(b, tc.result)
			out := b.Build()
			if len(out.Checks) != 1 {
				t.Fatalf("expected 1 check, got %d", len(out.Checks))
			}
			if out.Checks[0].ID != "CONTAINER-CVE" {
				t.Errorf("id = %q, want CONTAINER-CVE", out.Checks[0].ID)
			}
			if out.Checks[0].Status != tc.want {
				t.Errorf("status = %q, want %q", out.Checks[0].Status, tc.want)
			}
		})
	}
}
