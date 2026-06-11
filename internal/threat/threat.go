//go:build darwin || linux || windows

// Package threat is handled by doc.go.
package threat

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/safehttp"
)

// ShodanResult holds the Shodan InternetDB response for a public IP.
type ShodanResult struct {
	IP         string
	Ports      []int
	Vulns      []string
	Tags       []string
	Hostnames  []string
	Skipped    bool
	SkipReason string
	Error      string
}

// AbuseIPDBResult holds the AbuseIPDB check for a public IP.
type AbuseIPDBResult struct {
	AbuseScore   int
	TotalReports int
	LastReported string
	ISP          string
	Skipped      bool
	SkipReason   string
	Error        string
}

// LocalIOCResult contains findings from local indicator-of-compromise scanning.
type LocalIOCResult struct {
	SuspiciousCron      []string
	SuspiciousProcesses []string
	SuspiciousTempFiles []string
	SSHPersistence      []string
	ListeningBackdoors  []string
	AuthAnomalies       []string
}

// CVEFinding describes a single CVE match against an installed package.
type CVEFinding struct {
	Package  string
	Version  string
	CVE      string
	Severity string
	Desc     string
	Fix      string
}

// CVEResult holds the CVE exposure check output.
type CVEResult struct {
	Findings        []CVEFinding
	PackagesChecked []string
}

// KEVMatch is a single CISA KEV entry that matched an installed package.
type KEVMatch struct {
	CVE              string
	Vendor           string
	Product          string
	Name             string
	DateAdded        string
	DueDate          string
	InstalledPackage string
	InstalledVersion string
}

// CISAKEVResult holds the CISA KEV cross-reference output.
type CISAKEVResult struct {
	Matched       []KEVMatch
	KEVTotal      int
	CacheAgeHours float64
	Error         string
}

// Result is the top-level output of a full threat intelligence scan.
type Result struct {
	Shodan    ShodanResult
	AbuseIPDB AbuseIPDBResult
	LocalIOC  LocalIOCResult
	CVE       CVEResult
	CISAKEV   CISAKEVResult
	Skipped   bool
}

// getPublicIP fetches the machine's public IP via ipify.
func getPublicIP(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "anvil-scanner/1.0")

	// Use the centralized SSRF-safe client (upgrades previous unguarded transport).
	client := safehttp.SafeClient(10 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

// Scan runs all threat intelligence checks and returns a consolidated Result.
func Scan(ctx context.Context) Result {
	publicIP := getPublicIP(ctx)

	return Result{
		Shodan:    CheckShodan(ctx, publicIP),
		AbuseIPDB: CheckAbuseIPDB(ctx, publicIP),
		LocalIOC:  CheckLocalIOC(),
		CVE:       CheckCVEExposure(),
		CISAKEV:   CheckCISAKEV(ctx),
	}
}
