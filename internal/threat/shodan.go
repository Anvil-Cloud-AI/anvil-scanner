//go:build darwin || linux

package threat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/safehttp"
)

// shodanResponse is the JSON shape returned by internetdb.shodan.io.
type shodanResponse struct {
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	Vulns     []string `json:"vulns"`
	Tags      []string `json:"tags"`
	Hostnames []string `json:"hostnames"`
	CPEs      []string `json:"cpes"`
}

// CheckShodan queries Shodan's free InternetDB endpoint for the given public IP.
// It returns a skip result for private, loopback, link-local, or empty IPs.
// All HTTP errors are captured in the Error field; the function never panics.
func CheckShodan(ctx context.Context, publicIP string) ShodanResult {
	if publicIP == "" || publicIP == "unavailable" {
		return ShodanResult{Skipped: true, SkipReason: "Public IP unavailable"}
	}

	if isPrivateIP(publicIP) {
		return ShodanResult{
			Skipped:    true,
			SkipReason: fmt.Sprintf("IP %s is private/local — Shodan only indexes public IPs", publicIP),
		}
	}

	if net.ParseIP(publicIP) == nil {
		return ShodanResult{Error: fmt.Sprintf("invalid public IP from ipify: %q", publicIP)}
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://internetdb.shodan.io/%s", publicIP)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ShodanResult{Error: fmt.Sprintf("Shodan request build failed: %v", err)}
	}
	req.Header.Set("User-Agent", "anvil-scanner/1.0")

	// SSRF-safe client (was previously unguarded).
	client := safehttp.SafeClient(10 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return ShodanResult{Error: fmt.Sprintf("Shodan query failed: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return ShodanResult{
			IP:        publicIP,
			Ports:     []int{},
			Vulns:     []string{},
			Tags:      []string{},
			Hostnames: []string{},
		}
	}
	if resp.StatusCode != http.StatusOK {
		return ShodanResult{Error: fmt.Sprintf("Shodan HTTP %d: %s", resp.StatusCode, resp.Status)}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return ShodanResult{Error: fmt.Sprintf("Shodan read failed: %v", err)}
	}

	var data shodanResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return ShodanResult{Error: fmt.Sprintf("Shodan JSON parse failed: %v", err)}
	}

	// Normalise nil slices to empty slices.
	if data.Ports == nil {
		data.Ports = []int{}
	}
	if data.Vulns == nil {
		data.Vulns = []string{}
	}
	if data.Tags == nil {
		data.Tags = []string{}
	}
	if data.Hostnames == nil {
		data.Hostnames = []string{}
	}

	return ShodanResult{
		IP:        publicIP,
		Ports:     data.Ports,
		Vulns:     data.Vulns,
		Tags:      data.Tags,
		Hostnames: data.Hostnames,
	}
}
