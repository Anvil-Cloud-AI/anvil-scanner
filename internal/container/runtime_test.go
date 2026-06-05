//go:build darwin || linux

package container

import (
	"testing"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
)

func TestEmit(t *testing.T) {
	tests := []struct {
		status scan.Status
	}{
		{scan.StatusPass},
		{scan.StatusFail},
		{scan.StatusWarn},
		{scan.StatusSkip},
	}
	for _, tc := range tests {
		t.Run(string(tc.status), func(t *testing.T) {
			b := scan.NewBuilder()
			emit(b, finding{
				ID:       "CONTAINER-999",
				Name:     "test",
				Status:   tc.status,
				Detail:   "detail",
				Severity: scan.SeverityHigh,
			})
			out := b.Build()
			if len(out.Checks) != 1 {
				t.Fatalf("expected 1 check, got %d", len(out.Checks))
			}
			c := out.Checks[0]
			if c.Status != tc.status {
				t.Errorf("status = %q, want %q", c.Status, tc.status)
			}
			if c.ID != "CONTAINER-999" || c.Severity != scan.SeverityHigh {
				t.Errorf("unexpected check %+v", c)
			}
		})
	}
}
