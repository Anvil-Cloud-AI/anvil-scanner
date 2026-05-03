//go:build darwin || linux

package threat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	kevFeedURL      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	kevMaxAgeHours  = 24
	kevMaxSizeBytes = 10 * 1024 * 1024 // 10 MB
)

// kevFeedEntry is a single vulnerability entry in the CISA KEV JSON feed.
type kevFeedEntry struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	DueDate           string `json:"dueDate"`
}

// kevFeed is the top-level CISA KEV JSON structure.
type kevFeed struct {
	Vulnerabilities []kevFeedEntry `json:"vulnerabilities"`
}

// kevCacheDir returns the path to ~/.anvil-scanner/cache/ and ensures it exists.
func kevCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	dir := filepath.Join(home, ".anvil-scanner", "cache")
	_ = os.MkdirAll(dir, 0o700)
	return dir
}

// kevCacheFile returns the full path to the KEV cache file.
func kevCacheFile() string {
	return filepath.Join(kevCacheDir(), "kev.json")
}

// fetchKEVFeed retrieves the CISA KEV JSON feed, using a 24-hour file cache.
// Returns the parsed feed or nil with an error string on failure.
func fetchKEVFeed() (*kevFeed, float64, string) {
	cacheFile := kevCacheFile()

	// Check cache freshness.
	var cacheAgeHours float64
	if fi, err := os.Stat(cacheFile); err == nil {
		cacheAgeHours = time.Since(fi.ModTime()).Hours()
		if cacheAgeHours < kevMaxAgeHours {
			data, err := os.ReadFile(cacheFile)
			if err == nil {
				var feed kevFeed
				if json.Unmarshal(data, &feed) == nil {
					return &feed, cacheAgeHours, ""
				}
				// Cache is corrupt — delete and re-fetch.
				_ = os.Remove(cacheFile)
			}
		}
	}

	// Fetch from network.
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, kevFeedURL, nil)
	if err != nil {
		return nil, 0, fmt.Sprintf("KEV request build failed: %v", err)
	}
	req.Header.Set("User-Agent", "anvil-scanner/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Sprintf("KEV fetch failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Sprintf("KEV HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Read up to the size limit.
	lr := io.LimitReader(resp.Body, int64(kevMaxSizeBytes)+1)
	raw, err := io.ReadAll(lr)
	if err != nil {
		return nil, 0, fmt.Sprintf("KEV read failed: %v", err)
	}
	if len(raw) > kevMaxSizeBytes {
		return nil, 0, "KEV feed too large (>10 MB) — skipping"
	}

	var feed kevFeed
	if err := json.Unmarshal(raw, &feed); err != nil {
		return nil, 0, fmt.Sprintf("KEV JSON parse failed: %v", err)
	}

	// Atomic write to cache.
	tmpFile := cacheFile + ".tmp"
	if err := os.WriteFile(tmpFile, raw, 0o600); err == nil {
		if err := os.Rename(tmpFile, cacheFile); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: anvil-scanner: KEV cache write failed: %v\n", err)
			_ = os.Remove(tmpFile)
		}
	} else {
		fmt.Fprintf(os.Stderr, "WARNING: anvil-scanner: KEV cache tmp write failed: %v\n", err)
	}

	return &feed, 0, ""
}

// CheckCISAKEV fetches the CISA Known Exploited Vulnerabilities feed and
// cross-references it against installed packages from the bundled CVE database.
func CheckCISAKEV() CISAKEVResult {
	feed, cacheAgeHours, fetchErr := fetchKEVFeed()
	if feed == nil {
		return CISAKEVResult{
			Matched: []KEVMatch{},
			Error:   fetchErr,
		}
	}

	// Build a fast lookup map: cveID -> entry.
	kevByCVE := make(map[string]kevFeedEntry, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		if v.CVEID != "" {
			kevByCVE[v.CVEID] = v
		}
	}

	var matched []KEVMatch

	for pkg, cves := range knownCVEs {
		version := getPkgVersion(pkg)
		if version == "" {
			continue
		}
		for _, cve := range cves {
			kevEntry, inKEV := kevByCVE[cve.CVE]
			if !inKEV {
				continue
			}
			// For the XZ backdoor, check for the specific affected versions.
			if cve.CVE == "CVE-2024-3094" {
				norm2 := normalizeVersion(version)
				if norm2 != "5.6.0" && norm2 != "5.6.1" {
					continue
				}
			} else if !versionLT(version, cve.AffectedBelow) {
				continue
			}
			matched = append(matched, KEVMatch{
				CVE:              cve.CVE,
				Vendor:           kevEntry.VendorProject,
				Product:          kevEntry.Product,
				Name:             kevEntry.VulnerabilityName,
				DateAdded:        kevEntry.DateAdded,
				DueDate:          kevEntry.DueDate,
				InstalledPackage: pkg,
				InstalledVersion: version,
			})
		}
	}

	if matched == nil {
		matched = []KEVMatch{}
	}

	return CISAKEVResult{
		Matched:       matched,
		KEVTotal:      len(feed.Vulnerabilities),
		CacheAgeHours: cacheAgeHours,
	}
}
