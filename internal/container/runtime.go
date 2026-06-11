//go:build darwin || linux || windows

package container

import (
	"fmt"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
)

// RunRuntimeChecks discovers every running container across the available
// runtime (docker, then podman) and emits CONTAINER-001..004 hardening checks
// for each. It is a clean no-op — no checks added — when no runtime is
// installed, the daemon is unreachable, or nothing is running, so it is safe
// to call unconditionally on any host.
func RunRuntimeChecks(b *scan.CheckBuilder) {
	bin := detectRuntime()
	if bin == "" {
		return
	}
	for _, ref := range listContainers(bin) {
		auditContainer(b, bin, ref)
	}
}

// auditContainer inspects one container and emits its hardening findings.
func auditContainer(b *scan.CheckBuilder, bin string, ref containerRef) {
	short := shortID(ref.ID)
	ci, err := inspectContainer(bin, ref.ID)
	if err != nil {
		b.Skip("CONTAINER-000", fmt.Sprintf("Container audit [%s]", short),
			err.Error(), scan.SeverityHigh)
		return
	}
	for _, f := range runtimeFindings(ci, short) {
		emit(b, f)
	}
}

// emit writes a finding to the builder using the status-appropriate method.
func emit(b *scan.CheckBuilder, f finding) {
	switch f.Status {
	case scan.StatusFail:
		b.Fail(f.ID, f.Name, f.Detail, f.Severity)
	case scan.StatusWarn:
		b.Warn(f.ID, f.Name, f.Detail, f.Severity)
	case scan.StatusSkip:
		b.Skip(f.ID, f.Name, f.Detail, f.Severity)
	default:
		b.Pass(f.ID, f.Name, f.Detail, f.Severity)
	}
}
