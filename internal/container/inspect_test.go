//go:build darwin || linux

package container

import (
	"testing"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
)

func TestPortBindingFinding(t *testing.T) {
	tests := []struct {
		name     string
		bindings map[string][]portBinding
		want     scan.Status
	}{
		{
			name:     "no bindings passes",
			bindings: nil,
			want:     scan.StatusPass,
		},
		{
			name:     "loopback bind passes",
			bindings: map[string][]portBinding{"8080/tcp": {{HostIP: "127.0.0.1", HostPort: "8080"}}},
			want:     scan.StatusPass,
		},
		{
			name:     "specific IP passes",
			bindings: map[string][]portBinding{"8080/tcp": {{HostIP: "10.0.0.5", HostPort: "8080"}}},
			want:     scan.StatusPass,
		},
		{
			name:     "0.0.0.0 fails",
			bindings: map[string][]portBinding{"8080/tcp": {{HostIP: "0.0.0.0", HostPort: "8080"}}},
			want:     scan.StatusFail,
		},
		{
			name:     "empty host IP fails",
			bindings: map[string][]portBinding{"443/tcp": {{HostIP: "", HostPort: "443"}}},
			want:     scan.StatusFail,
		},
		{
			name:     "IPv6 wildcard fails",
			bindings: map[string][]portBinding{"443/tcp": {{HostIP: "::", HostPort: "443"}}},
			want:     scan.StatusFail,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var ci containerInspect
			ci.HostConfig.PortBindings = tc.bindings
			got := portBindingFinding(ci, "abc123")
			if got.Status != tc.want {
				t.Errorf("status = %q, want %q", got.Status, tc.want)
			}
			if got.ID != "CONTAINER-001" {
				t.Errorf("id = %q, want CONTAINER-001", got.ID)
			}
			if got.Severity != scan.SeverityCritical {
				t.Errorf("severity = %q, want critical", got.Severity)
			}
		})
	}
}

func TestPrivilegedFinding(t *testing.T) {
	var priv containerInspect
	priv.HostConfig.Privileged = true
	if got := privilegedFinding(priv, "x"); got.Status != scan.StatusFail {
		t.Errorf("privileged container: status = %q, want FAIL", got.Status)
	}

	var unpriv containerInspect
	if got := privilegedFinding(unpriv, "x"); got.Status != scan.StatusPass {
		t.Errorf("unprivileged container: status = %q, want PASS", got.Status)
	}
}

func TestUserFinding(t *testing.T) {
	tests := []struct {
		user string
		want scan.Status
	}{
		{"", scan.StatusWarn},
		{"0", scan.StatusWarn},
		{"root", scan.StatusWarn},
		{"0:0", scan.StatusWarn},
		{"root:root", scan.StatusWarn},
		{"root:0", scan.StatusWarn},
		{"root:appgroup", scan.StatusWarn},
		{"1000", scan.StatusPass},
		{"1000:1000", scan.StatusPass},
		{"appuser", scan.StatusPass},
		{"appuser:root", scan.StatusPass},
	}
	for _, tc := range tests {
		t.Run(tc.user, func(t *testing.T) {
			var ci containerInspect
			ci.Config.User = tc.user
			got := userFinding(ci, "x")
			if got.Status != tc.want {
				t.Errorf("user %q: status = %q, want %q", tc.user, got.Status, tc.want)
			}
			if got.Severity != scan.SeverityHigh {
				t.Errorf("user %q: severity = %q, want high", tc.user, got.Severity)
			}
		})
	}
}

func TestSocketMountFinding(t *testing.T) {
	mount := func(src string) containerInspect {
		var ci containerInspect
		ci.Mounts = []struct {
			Type   string `json:"Type"`
			Source string `json:"Source"`
		}{{Type: "bind", Source: src}}
		return ci
	}

	tests := []struct {
		name string
		ci   containerInspect
		want scan.Status
	}{
		{"docker socket fails", mount("/var/run/docker.sock"), scan.StatusFail},
		{"run docker socket fails", mount("/run/docker.sock"), scan.StatusFail},
		{"podman socket fails", mount("/run/user/1000/podman/podman.sock"), scan.StatusFail},
		{"unrelated bind passes", mount("/etc/config"), scan.StatusPass},
		{"no mounts passes", containerInspect{}, scan.StatusPass},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := socketMountFinding(tc.ci, "x")
			if got.Status != tc.want {
				t.Errorf("status = %q, want %q", got.Status, tc.want)
			}
		})
	}
}

func TestRuntimeFindingsEmitsAll(t *testing.T) {
	got := runtimeFindings(containerInspect{}, "x")
	if len(got) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(got))
	}
	wantIDs := map[string]bool{
		"CONTAINER-001": false, "CONTAINER-002": false,
		"CONTAINER-003": false, "CONTAINER-004": false,
	}
	for _, f := range got {
		if _, ok := wantIDs[f.ID]; !ok {
			t.Errorf("unexpected finding ID %q", f.ID)
		}
		wantIDs[f.ID] = true
	}
	for id, seen := range wantIDs {
		if !seen {
			t.Errorf("missing finding %q", id)
		}
	}
}

func TestShortID(t *testing.T) {
	if got := shortID("abcdef0123456789"); got != "abcdef012345" {
		t.Errorf("shortID truncation = %q, want abcdef012345", got)
	}
	if got := shortID("abc"); got != "abc" {
		t.Errorf("shortID short = %q, want abc", got)
	}
}
