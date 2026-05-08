//go:build darwin || linux

package scan

import (
	"runtime"
	"sort"
	"strconv"
	"testing"
)

// ---- sortedPorts -------------------------------------------------------------

// TestSortedPorts_Empty verifies nil input returns nil (no panic).
func TestSortedPorts_Empty(t *testing.T) {
	got := sortedPorts(map[string]bool{})
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %v", got)
	}
}

// TestSortedPorts_SingleEntry verifies a single port is returned correctly.
func TestSortedPorts_SingleEntry(t *testing.T) {
	got := sortedPorts(map[string]bool{"22": true})
	if len(got) != 1 || got[0] != "22" {
		t.Errorf("expected [22], got %v", got)
	}
}

// TestSortedPorts_NumericalOrder verifies ports are sorted numerically not
// lexicographically (22 < 80 < 443 < 8080 — in lexical order 22 < 443 < 80).
func TestSortedPorts_NumericalOrder(t *testing.T) {
	seen := map[string]bool{
		"8080": true,
		"443":  true,
		"22":   true,
		"80":   true,
	}
	got := sortedPorts(seen)
	want := []string{"22", "80", "443", "8080"}
	if len(got) != len(want) {
		t.Fatalf("len=%d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("position %d: got %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

// TestSortedPorts_IsMonotonicallyIncreasing verifies numerical monotonicity on
// a larger randomly-ordered input.
func TestSortedPorts_IsMonotonicallyIncreasing(t *testing.T) {
	seen := map[string]bool{
		"65535": true,
		"1024":  true,
		"3306":  true,
		"22":    true,
		"5432":  true,
		"80":    true,
	}
	got := sortedPorts(seen)
	if !sort.SliceIsSorted(got, func(i, j int) bool {
		a, _ := strconv.Atoi(got[i])
		b, _ := strconv.Atoi(got[j])
		return a < b
	}) {
		t.Errorf("sortedPorts is not numerically sorted: %v", got)
	}
}

// TestSortedPorts_DuplicateKeysHandled verifies map semantics deduplicate ports.
func TestSortedPorts_DuplicateKeysHandled(t *testing.T) {
	// Maps cannot have duplicate keys — this confirms sortedPorts doesn't
	// introduce duplicates via its own logic.
	seen := map[string]bool{"22": true, "80": true, "443": true}
	got := sortedPorts(seen)
	if len(got) != 3 {
		t.Errorf("expected 3 unique ports, got %d: %v", len(got), got)
	}
}

// ---- GetOpenPorts ------------------------------------------------------------

// TestGetOpenPorts_DoesNotPanic verifies GetOpenPorts runs on the current OS
// without panicking (even if no tool is available it should return nil/empty).
func TestGetOpenPorts_DoesNotPanic(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("GetOpenPorts only runs on darwin/linux")
	}
	got := GetOpenPorts()
	// Result may be nil (no lsof/ss/netstat) or a list — both are fine.
	// Verify that every element is a valid port number string.
	for _, p := range got {
		n, err := strconv.Atoi(p)
		if err != nil {
			t.Errorf("GetOpenPorts returned non-integer port %q", p)
		}
		if n < 1 || n > 65535 {
			t.Errorf("GetOpenPorts returned out-of-range port %d", n)
		}
	}
}

// TestGetOpenPorts_IsSorted verifies the returned slice is numerically sorted.
func TestGetOpenPorts_IsSorted(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("GetOpenPorts only runs on darwin/linux")
	}
	got := GetOpenPorts()
	if !sort.SliceIsSorted(got, func(i, j int) bool {
		a, _ := strconv.Atoi(got[i])
		b, _ := strconv.Atoi(got[j])
		return a < b
	}) {
		t.Errorf("GetOpenPorts result is not numerically sorted: %v", got)
	}
}

// ---- GetPendingUpdates -------------------------------------------------------

// TestGetPendingUpdates_NonNegative verifies the function returns a non-negative
// count. It may be 0 when the system has no pending updates or the tool is absent.
func TestGetPendingUpdates_NonNegative(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("GetPendingUpdates only runs on darwin/linux")
	}
	got := GetPendingUpdates()
	if got < 0 {
		t.Errorf("GetPendingUpdates() = %d, want >= 0", got)
	}
}
