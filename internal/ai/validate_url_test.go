package ai

import (
	"strings"
	"testing"
)

// TestValidateExternalAPIURL covers all branches of validateExternalAPIURL.
//
// The function requires HTTPS, a non-empty host, and that the host does not
// resolve to a private/loopback address.
func TestValidateExternalAPIURL(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		wantErr bool
		errFrag string // substring expected in the error message when wantErr=true
	}{
		{
			name:    "non-HTTPS http URL is rejected",
			rawURL:  "http://api.example.com/v1",
			wantErr: true,
			errFrag: "HTTPS",
		},
		{
			name:    "ftp scheme is rejected",
			rawURL:  "ftp://api.example.com/v1",
			wantErr: true,
			errFrag: "HTTPS",
		},
		{
			// "https:///v1" parses fine but Hostname() returns "".
			name:    "https with no host is rejected",
			rawURL:  "https:///v1/path",
			wantErr: true,
			errFrag: "no host",
		},
		{
			// 127.0.0.1 is loopback — SSRF guard must reject it.
			name:    "URL with loopback 127.0.0.1 is rejected",
			rawURL:  "https://127.0.0.1/v1",
			wantErr: true,
			errFrag: "private",
		},
		{
			// 192.168.x.x is RFC-1918 — always rejected.
			name:    "URL with RFC-1918 192.168 IP is rejected",
			rawURL:  "https://192.168.1.1/v1",
			wantErr: true,
			errFrag: "private",
		},
		{
			// 10.x.x.x is RFC-1918 — always rejected.
			name:    "URL with RFC-1918 10.x IP is rejected",
			rawURL:  "https://10.0.0.1/api",
			wantErr: true,
			errFrag: "private",
		},
		{
			// A real public hostname. If DNS fails the function returns nil
			// (treat DNS failure as safe at config time), so this test passes in
			// both network-available and air-gapped environments.
			name:    "valid HTTPS URL with public hostname returns nil",
			rawURL:  "https://api.openai.com/v1",
			wantErr: false,
		},
		{
			// Same rationale — DNS failure → nil.
			name:    "valid HTTPS URL for anthropic returns nil",
			rawURL:  "https://api.anthropic.com/v1/messages",
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateExternalAPIURL(tc.rawURL)
			if tc.wantErr && err == nil {
				t.Fatalf("validateExternalAPIURL(%q) = nil; want error containing %q",
					tc.rawURL, tc.errFrag)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateExternalAPIURL(%q) = %v; want nil", tc.rawURL, err)
			}
			if tc.wantErr && tc.errFrag != "" && !strings.Contains(err.Error(), tc.errFrag) {
				t.Errorf("validateExternalAPIURL(%q) error = %q; want it to contain %q",
					tc.rawURL, err.Error(), tc.errFrag)
			}
		})
	}
}

// TestValidateExternalAPIURL_UnresolvableHost verifies that a hostname that
// cannot be resolved is treated as safe (nil is returned).
// The implementation comment: "DNS failure at config time should not block startup."
func TestValidateExternalAPIURL_UnresolvableHost(t *testing.T) {
	// .invalid is an IANA-reserved TLD guaranteed never to resolve.
	err := validateExternalAPIURL("https://this.host.does.not.exist.invalid/v1")
	if err != nil {
		t.Errorf("validateExternalAPIURL with unresolvable host = %v; want nil (DNS failure is safe)", err)
	}
}
