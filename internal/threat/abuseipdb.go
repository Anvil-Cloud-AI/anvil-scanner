//go:build darwin || linux

package threat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// abuseIPDBResponse is the outer JSON envelope from AbuseIPDB v2.
type abuseIPDBResponse struct {
	Data struct {
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		TotalReports         int    `json:"totalReports"`
		LastReportedAt       string `json:"lastReportedAt"`
		ISP                  string `json:"isp"`
	} `json:"data"`
}

// CheckAbuseIPDB queries the AbuseIPDB v2 API for the given public IP.
// It requires the ABUSEIPDB_KEY environment variable; if absent it returns
// a skip result. All HTTP errors are captured in the Error field.
func CheckAbuseIPDB(publicIP string) AbuseIPDBResult {
	if publicIP == "" || publicIP == "unavailable" {
		return AbuseIPDBResult{Skipped: true, SkipReason: "Public IP unavailable"}
	}

	// Validate that publicIP is a well-formed IP address.
	if net.ParseIP(publicIP) == nil {
		return AbuseIPDBResult{
			Skipped:    true,
			SkipReason: fmt.Sprintf("Invalid IP address: %q", publicIP),
		}
	}

	if isPrivateIP(publicIP) {
		return AbuseIPDBResult{
			Skipped:    true,
			SkipReason: fmt.Sprintf("IP %s is private/local", publicIP),
		}
	}

	apiKey := os.Getenv("ABUSEIPDB_KEY")
	if apiKey == "" {
		return AbuseIPDBResult{
			Skipped:    true,
			SkipReason: "Set ABUSEIPDB_KEY env var for abuse IP check (free at abuseipdb.com)",
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", publicIP)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return AbuseIPDBResult{Error: fmt.Sprintf("AbuseIPDB request build failed: %v", err)}
	}
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "anvil-scanner/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return AbuseIPDBResult{Error: fmt.Sprintf("AbuseIPDB query failed: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return AbuseIPDBResult{Error: fmt.Sprintf("AbuseIPDB HTTP %d: %s", resp.StatusCode, resp.Status)}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return AbuseIPDBResult{Error: fmt.Sprintf("AbuseIPDB read failed: %v", err)}
	}

	var data abuseIPDBResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return AbuseIPDBResult{Error: fmt.Sprintf("AbuseIPDB JSON parse failed: %v", err)}
	}

	return AbuseIPDBResult{
		AbuseScore:   data.Data.AbuseConfidenceScore,
		TotalReports: data.Data.TotalReports,
		LastReported: data.Data.LastReportedAt,
		ISP:          data.Data.ISP,
	}
}
