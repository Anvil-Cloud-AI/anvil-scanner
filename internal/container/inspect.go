//go:build darwin || linux

// Package container scans local container runtimes (docker, podman) for
// runtime-hardening issues and known image vulnerabilities.
//
// It has two halves:
//
//   - Runtime hardening: structural checks (CONTAINER-001..004) run against
//     every running container, regardless of image. These mirror the
//     "OpenClaw container audit" checks that previously lived in
//     internal/openclaw but apply to all containers.
//   - Image CVE scanning: shells out to grype (preferred) or trivy (fallback)
//     to enumerate known vulnerabilities in the images backing those
//     containers, plus any explicit registry references the user passes.
//
// The OpenClaw-specific deep audit (running `openclaw security audit` inside
// the container) deliberately stays in internal/openclaw.
package container

import (
	"fmt"
	"strings"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
)

// containerInspect holds the fields we extract from `docker inspect` /
// `podman inspect` output. Both runtimes emit a docker-compatible shape.
type containerInspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Image string `json:"Image"`
		User  string `json:"User"`
	} `json:"Config"`
	HostConfig struct {
		Privileged   bool                     `json:"Privileged"`
		PortBindings map[string][]portBinding `json:"PortBindings"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type   string `json:"Type"`
		Source string `json:"Source"`
	} `json:"Mounts"`
}

type portBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

// finding is the fully-resolved result of one runtime-hardening predicate.
// Predicates are pure functions of a containerInspect so they can be unit
// tested without a live container runtime; runtime.go emits them via the
// CheckBuilder.
type finding struct {
	ID       string
	Name     string
	Status   scan.Status
	Detail   string
	Severity scan.Severity
}

// shortID truncates a container ID to the conventional 12-char display form.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// portBindingFinding (CONTAINER-001) flags ports published to all interfaces
// (0.0.0.0, ::, or an empty host IP).
func portBindingFinding(ci containerInspect, short string) finding {
	const sev = scan.SeverityCritical
	name := fmt.Sprintf("Ports not published to all interfaces [%s]", short)

	var exposed []string
	for port, bindings := range ci.HostConfig.PortBindings {
		for _, pb := range bindings {
			if ip := pb.HostIP; ip == "" || ip == "0.0.0.0" || ip == "::" {
				exposed = append(exposed, fmt.Sprintf("%s→%s:%s", port, ip, pb.HostPort))
			}
		}
	}
	if len(exposed) > 0 {
		return finding{"CONTAINER-001", name, scan.StatusFail,
			fmt.Sprintf("Container publishes ports on all interfaces: %s — bind to 127.0.0.1 "+
				"or put a reverse proxy in front.", strings.Join(exposed, ", ")), sev}
	}
	return finding{"CONTAINER-001", name, scan.StatusPass,
		"All published ports are bound to loopback or a specific IP.", sev}
}

// privilegedFinding (CONTAINER-002) flags containers running with --privileged.
func privilegedFinding(ci containerInspect, short string) finding {
	const sev = scan.SeverityCritical
	name := fmt.Sprintf("Container not running privileged [%s]", short)
	if ci.HostConfig.Privileged {
		return finding{"CONTAINER-002", name, scan.StatusFail,
			"Container is running with --privileged. This grants full host capabilities " +
				"and breaks container isolation.", sev}
	}
	return finding{"CONTAINER-002", name, scan.StatusPass,
		"Container is not running in privileged mode.", sev}
}

// userFinding (CONTAINER-003) flags containers running as root.
func userFinding(ci containerInspect, short string) finding {
	const sev = scan.SeverityHigh
	name := fmt.Sprintf("Container not running as root [%s]", short)
	user := strings.TrimSpace(ci.Config.User)
	// User may be "uid", "uid:gid", "name", or "name:group". Inspect only the
	// user half so root expressed as "root:appgroup" or "0:0" is still caught.
	userPart := strings.SplitN(user, ":", 2)[0]
	isRoot := userPart == "" || userPart == "0" || userPart == "root"
	if isRoot {
		return finding{"CONTAINER-003", name, scan.StatusWarn,
			"Container process runs as root (no USER directive or USER 0). " +
				"Add a non-root USER to the image to limit blast radius.", sev}
	}
	return finding{"CONTAINER-003", name, scan.StatusPass,
		fmt.Sprintf("Container runs as user %q.", user), sev}
}

// socketMountFinding (CONTAINER-004) flags a bind-mounted docker socket.
func socketMountFinding(ci containerInspect, short string) finding {
	const sev = scan.SeverityCritical
	name := fmt.Sprintf("Container runtime socket not mounted [%s]", short)
	for _, m := range ci.Mounts {
		if m.Source == "/var/run/docker.sock" || m.Source == "/run/docker.sock" ||
			strings.HasSuffix(m.Source, "/podman.sock") {
			return finding{"CONTAINER-004", name, scan.StatusFail,
				fmt.Sprintf("%s is mounted into the container — this grants full daemon "+
					"control, equivalent to root on the host.", m.Source), sev}
		}
	}
	return finding{"CONTAINER-004", name, scan.StatusPass,
		"Container runtime socket is not mounted into the container.", sev}
}

// runtimeFindings runs every structural predicate against one container.
func runtimeFindings(ci containerInspect, short string) []finding {
	return []finding{
		portBindingFinding(ci, short),
		privilegedFinding(ci, short),
		userFinding(ci, short),
		socketMountFinding(ci, short),
	}
}
