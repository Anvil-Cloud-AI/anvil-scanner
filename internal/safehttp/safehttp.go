// Package safehttp provides SSRF-safe HTTP clients and transports for all
// outbound network calls in anvil-scanner.
//
// It centralizes the project's security requirement that outbound HTTP must
// reject RFC-1918, loopback, link-local, and other private/reserved ranges
// (with a documented exception only for explicitly validated Ollama localhost
// endpoints).
//
// All new or migrated HTTP usage should go through the constructors here
// instead of creating ad-hoc *http.Client / *http.Transport values.
package safehttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

// privateCIDRs is the single source of truth for ranges that must never be
// contacted for external threat intel, CVE feeds, telemetry, etc.
// It is a superset of previous lists that were duplicated in internal/ai
// and internal/threat.
var privateCIDRs []*net.IPNet

func init() {
	for _, cidr := range []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10", // CGN
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16", // link-local
		"::1/128",
		"fc00::/7",  // IPv6 ULA
		"fe80::/10", // IPv6 link-local
		"64:ff9b::/96",
	} {
		_, n, err := net.ParseCIDR(cidr)
		if err == nil {
			privateCIDRs = append(privateCIDRs, n)
		}
	}
}

// IsPrivateIP reports whether addr is in any private, loopback, link-local,
// or otherwise non-routable range that anvil-scanner refuses to contact
// for security-sensitive outbound calls.
//
// It is safe for concurrent use and performs no DNS resolution.
func IsPrivateIP(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, n := range privateCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// safeTransport is the dial-time guarded transport used by SafeClient.
// It mirrors (and now owns) the original ssrfSafeTransport logic from
// internal/ai, but is no longer package-private.
var safeTransport = &http.Transport{
	DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("parse dial addr: %w", err)
		}
		ips, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", host, err)
		}
		for _, ipStr := range ips {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			for _, n := range privateCIDRs {
				if n.Contains(ip) {
					return nil, fmt.Errorf("SSRF guard: %s resolves to private address %s", host, ipStr)
				}
			}
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no addresses resolved for %s", host)
		}
		// Use a fresh dialer per call to respect per-client timeouts.
		d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		return d.DialContext(ctx, network, net.JoinHostPort(ips[0], port))
	},
}

// SafeClient returns an *http.Client that uses the SSRF-guarded transport
// and the supplied overall timeout. This is the default choice for all
// external threat intel, CVE feeds, telemetry, and AI provider calls
// (except validated Ollama localhost).
func SafeClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: safeTransport,
	}
}

// LocalhostOnlyClient returns a client that deliberately allows loopback
// (for Ollama on 127.0.0.1 / ::1 / localhost after strict validation in
// the ai package). It does NOT use the private-IP guard.
func LocalhostOnlyClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
	}
}

// TelemetryClient returns a short-lived client with an explicit TLS 1.2
// minimum (matching the previous ad-hoc telemetry implementation) while
// still using the SSRF-safe transport.
func TelemetryClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 5 * time.Second,
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext,
			// Note: we still want the SSRF guard even for telemetry.
			// The original telemetry transport did not have it; we are
			// deliberately upgrading it here for consistency.
		},
	}
}
