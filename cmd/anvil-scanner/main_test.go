//go:build darwin || linux

package main

import (
	"testing"
)

func TestFilterExposedOCPorts_NoneExposed(t *testing.T) {
	input := []string{"22", "80", "443", "8080"}
	got := filterExposedOCPorts(input)
	if len(got) != 0 {
		t.Errorf("expected 0 exposed OC ports, got %d: %v", len(got), got)
	}
}

func TestFilterExposedOCPorts_SomeExposed(t *testing.T) {
	input := []string{"22", "18789", "443", "9090", "8080", "19001"}
	got := filterExposedOCPorts(input)
	want := map[string]bool{"18789": true, "9090": true, "19001": true}
	if len(got) != len(want) {
		t.Fatalf("expected %d exposed OC ports, got %d: %v", len(want), len(got), got)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected port in result: %q", p)
		}
	}
}

func TestFilterExposedOCPorts_NilInput(t *testing.T) {
	got := filterExposedOCPorts(nil)
	if len(got) != 0 {
		t.Errorf("expected empty result for nil input, got %d: %v", len(got), got)
	}
}
