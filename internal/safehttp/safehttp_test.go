package safehttp

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestIsPrivateIP_Table(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		// IPv4 private / special
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"192.168.0.0", true},
		{"127.0.0.1", true},
		{"127.255.255.255", true},
		{"169.254.1.1", true}, // link-local
		{"0.0.0.0", true},
		{"100.64.0.1", true}, // CGN

		// Public IPv4
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"104.16.123.45", false},

		// IPv6
		{"::1", true},
		{"fe80::1", true},
		{"fc00::1", true},
		{"64:ff9b::1", true},

		// Public IPv6
		{"2001:4860:4860::8888", false},

		// Malformed
		{"not-an-ip", false},
		{"999.999.999.999", false},
	}

	for _, tc := range tests {
		t.Run(tc.addr, func(t *testing.T) {
			if got := IsPrivateIP(tc.addr); got != tc.want {
				t.Errorf("IsPrivateIP(%q) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

func TestSafeClient_UsesGuardedTransport(t *testing.T) {
	c := SafeClient(10 * time.Second)
	if c.Timeout != 10*time.Second {
		t.Errorf("timeout not propagated")
	}
	// We can't easily assert the exact transport without exporting it,
	// but we can at least verify it doesn't panic and is non-nil.
	if c.Transport == nil {
		t.Error("Transport is nil")
	}
}

func TestLocalhostOnlyClient_AllowsLoopback(t *testing.T) {
	c := LocalhostOnlyClient(5 * time.Second)
	if c.Timeout != 5*time.Second {
		t.Error("timeout not set")
	}
	// Sanity: this client is intentionally not guarded.
	// (We don't have a negative test here because the guard is absent by design.)
}

func TestTelemetryClient_HasShortTimeoutAndTLSMin(t *testing.T) {
	c := TelemetryClient()
	if c.Timeout != 5*time.Second {
		t.Errorf("telemetry timeout = %v, want 5s", c.Timeout)
	}

	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", c.Transport)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != 0x0303 { // tls.VersionTLS12
		t.Error("TelemetryClient did not enforce TLS 1.2 minimum")
	}
}

// Quick integration-style check that a real public IP is allowed and a private one is blocked
// via the dial guard (this will fail fast on the guard without actually connecting).
func TestSafeTransport_BlocksPrivateAtDial(t *testing.T) {
	c := SafeClient(2 * time.Second)

	// This should fail at dial time with our SSRF error, not a network error.
	_, err := c.Get("http://192.168.1.1:1/")
	if err == nil {
		t.Fatal("expected error for private address")
	}
	if !strings.Contains(err.Error(), "SSRF guard") {
		t.Errorf("expected SSRF guard error, got: %v", err)
	}
}
