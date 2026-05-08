//go:build darwin || linux

package threat

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestCheckAbuseIPDB_SkipsEmptyIP verifies the empty-IP early return.
func TestCheckAbuseIPDB_SkipsEmptyIP(t *testing.T) {
	result := CheckAbuseIPDB(context.Background(), "")
	if !result.Skipped {
		t.Errorf("Skipped = false for empty IP; want true")
	}
	if result.SkipReason == "" {
		t.Error("SkipReason is empty for empty IP; want non-empty")
	}
}

// TestCheckAbuseIPDB_SkipsUnavailableIP verifies the "unavailable" sentinel value.
func TestCheckAbuseIPDB_SkipsUnavailableIP(t *testing.T) {
	result := CheckAbuseIPDB(context.Background(), "unavailable")
	if !result.Skipped {
		t.Errorf("Skipped = false for 'unavailable' IP; want true")
	}
}

// TestCheckAbuseIPDB_SkipsInvalidIP verifies that a non-IP string is rejected.
func TestCheckAbuseIPDB_SkipsInvalidIP(t *testing.T) {
	cases := []struct {
		name string
		ip   string
	}{
		{"hostname", "example.com"},
		{"garbage", "not-an-ip"},
		{"partial", "192.168"},
		{"with port", "8.8.8.8:53"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := CheckAbuseIPDB(context.Background(), tc.ip)
			if !result.Skipped {
				t.Errorf("Skipped = false for invalid IP %q; want true", tc.ip)
			}
			if !strings.Contains(result.SkipReason, "Invalid") {
				t.Errorf("SkipReason = %q; want to contain 'Invalid'", result.SkipReason)
			}
		})
	}
}

// TestCheckAbuseIPDB_SkipsPrivateIPs verifies RFC-1918 and loopback addresses
// are skipped without an API call.
func TestCheckAbuseIPDB_SkipsPrivateIPs(t *testing.T) {
	cases := []struct {
		name string
		ip   string
	}{
		{"RFC-1918 10.x", "10.0.0.1"},
		{"RFC-1918 172.16.x", "172.16.0.1"},
		{"RFC-1918 192.168.x", "192.168.1.100"},
		{"loopback", "127.0.0.1"},
		{"link-local", "169.254.0.1"},
		{"IPv6 loopback", "::1"},
		{"IPv6 ULA", "fd00::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := CheckAbuseIPDB(context.Background(), tc.ip)
			if !result.Skipped {
				t.Errorf("Skipped = false for private IP %q; want true", tc.ip)
			}
			if !strings.Contains(result.SkipReason, "private") {
				t.Errorf("SkipReason = %q; want to contain 'private'", result.SkipReason)
			}
		})
	}
}

// TestCheckAbuseIPDB_SkipsWhenNoAPIKey verifies the missing-key early return.
func TestCheckAbuseIPDB_SkipsWhenNoAPIKey(t *testing.T) {
	prev, had := os.LookupEnv("ABUSEIPDB_KEY")
	os.Unsetenv("ABUSEIPDB_KEY")
	defer func() {
		if had {
			os.Setenv("ABUSEIPDB_KEY", prev)
		}
	}()

	result := CheckAbuseIPDB(context.Background(), "8.8.8.8")
	if !result.Skipped {
		t.Errorf("Skipped = false when ABUSEIPDB_KEY is unset; want true")
	}
	if result.SkipReason == "" {
		t.Error("SkipReason is empty when key is absent; want non-empty hint")
	}
	if !strings.Contains(result.SkipReason, "ABUSEIPDB_KEY") {
		t.Errorf("SkipReason = %q; want to mention ABUSEIPDB_KEY", result.SkipReason)
	}
}

// TestCheckAbuseIPDB_ErrorOnNetworkFailure verifies that when a key is set but
// the context is cancelled, the Error field is set and Skipped is false.
func TestCheckAbuseIPDB_ErrorOnNetworkFailure(t *testing.T) {
	prev, had := os.LookupEnv("ABUSEIPDB_KEY")
	os.Setenv("ABUSEIPDB_KEY", "test-key-for-network-test")
	defer func() {
		if had {
			os.Setenv("ABUSEIPDB_KEY", prev)
		} else {
			os.Unsetenv("ABUSEIPDB_KEY")
		}
	}()

	// Cancel the context immediately so the HTTP call fails.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := CheckAbuseIPDB(ctx, "8.8.8.8")
	// Should not be skipped — it should fail with a network error.
	if result.Skipped {
		t.Error("Skipped = true on cancelled context; want false (should produce Error)")
	}
	if result.Error == "" {
		t.Error("Error is empty on cancelled context; want non-empty error string")
	}
}

// TestCheckAbuseIPDB_PublicIPNoKey checks that a public IP with no key is skipped
// with an informative reason.
func TestCheckAbuseIPDB_PublicIPNoKey(t *testing.T) {
	prev, had := os.LookupEnv("ABUSEIPDB_KEY")
	os.Unsetenv("ABUSEIPDB_KEY")
	defer func() {
		if had {
			os.Setenv("ABUSEIPDB_KEY", prev)
		}
	}()

	publicIPs := []string{"1.1.1.1", "8.8.8.8", "203.0.113.1"}
	for _, ip := range publicIPs {
		t.Run(ip, func(t *testing.T) {
			result := CheckAbuseIPDB(context.Background(), ip)
			if !result.Skipped {
				t.Errorf("expected Skipped=true for public IP %q with no key", ip)
			}
		})
	}
}
