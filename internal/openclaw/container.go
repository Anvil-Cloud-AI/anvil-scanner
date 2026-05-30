//go:build darwin || linux

package openclaw

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	iexec "github.com/Anvil-Cloud-AI/anvil-scanner/internal/exec"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
)

const (
	// ocImagePrefix is the GHCR image path for OpenClaw containers.
	ocImagePrefix = "ghcr.io/openclaw/openclaw"

	containerAuditTimeout = 30 * time.Second
)

// containerInspect holds the fields we extract from docker inspect output.
type containerInspect struct {
	ID   string `json:"Id"`
	Name string `json:"Name"`
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

// RunContainerAudits finds all running OpenClaw containers and runs
// security checks on each one. It is a no-op when Docker is unavailable
// or no matching containers are running — no SKIP check is added.
func RunContainerAudits(b *scan.CheckBuilder) {
	for _, id := range findOpenClawContainers() {
		auditContainer(b, id)
	}
}

// findOpenClawContainers returns the IDs of running containers whose image
// matches the OpenClaw image prefix.
func findOpenClawContainers() []string {
	r := iexec.Run("docker", "ps", "--format", "{{.ID}}\t{{.Image}}")
	if !r.Success() {
		return nil
	}
	var ids []string
	for _, line := range strings.Split(strings.TrimSpace(r.Stdout), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "\t", 2)
		if len(parts) != 2 {
			continue
		}
		img := parts[1]
		if strings.HasPrefix(img, ocImagePrefix) || strings.HasPrefix(img, "openclaw/openclaw") {
			ids = append(ids, parts[0])
		}
	}
	return ids
}

func auditContainer(b *scan.CheckBuilder, containerID string) {
	short := containerID
	if len(short) > 12 {
		short = short[:12]
	}

	r := iexec.Run("docker", "inspect", containerID)
	if !r.Success() {
		b.Skip("OCC-000", fmt.Sprintf("OpenClaw container audit [%s]", short),
			fmt.Sprintf("docker inspect failed (exit %d): %s", r.ExitCode, strings.TrimSpace(r.Stderr)),
			scan.SeverityHigh)
		return
	}

	var inspects []containerInspect
	if err := json.Unmarshal([]byte(r.Stdout), &inspects); err != nil || len(inspects) == 0 {
		b.Skip("OCC-000", fmt.Sprintf("OpenClaw container audit [%s]", short),
			"could not parse docker inspect output", scan.SeverityHigh)
		return
	}

	ci := inspects[0]
	checkPortBinding(b, ci, short)
	checkPrivileged(b, ci, short)
	checkContainerUser(b, ci, short)
	checkSocketMount(b, ci, short)
	execContainerAudit(b, containerID, short, ci)
}

// checkPortBinding flags ports published to all interfaces (0.0.0.0 or ::).
func checkPortBinding(b *scan.CheckBuilder, ci containerInspect, short string) {
	var exposed []string
	for port, bindings := range ci.HostConfig.PortBindings {
		for _, pb := range bindings {
			ip := pb.HostIP
			if ip == "" || ip == "0.0.0.0" || ip == "::" {
				exposed = append(exposed, fmt.Sprintf("%s→%s:%s", port, ip, pb.HostPort))
			}
		}
	}
	name := fmt.Sprintf("Port not exposed to all interfaces [%s]", short)
	if len(exposed) > 0 {
		b.Fail("OCC-001", name,
			fmt.Sprintf("Container is publishing ports on all interfaces: %s — "+
				"bind to 127.0.0.1 or put a reverse proxy in front",
				strings.Join(exposed, ", ")),
			scan.SeverityCritical)
	} else {
		b.Pass("OCC-001", name,
			"All published ports are bound to loopback or a specific IP", scan.SeverityCritical)
	}
}

// checkPrivileged flags containers running with --privileged.
func checkPrivileged(b *scan.CheckBuilder, ci containerInspect, short string) {
	name := fmt.Sprintf("Container not running privileged [%s]", short)
	if ci.HostConfig.Privileged {
		b.Fail("OCC-002", name,
			"Container is running with --privileged. This grants full host capabilities and breaks container isolation.",
			scan.SeverityCritical)
	} else {
		b.Pass("OCC-002", name, "Container is not running in privileged mode", scan.SeverityMedium)
	}
}

// checkContainerUser flags containers running as root (no USER directive or USER 0).
func checkContainerUser(b *scan.CheckBuilder, ci containerInspect, short string) {
	user := strings.TrimSpace(ci.Config.User)
	isRoot := user == "" || user == "0" || user == "root" || strings.HasPrefix(user, "0:")
	name := fmt.Sprintf("Container not running as root [%s]", short)
	if isRoot {
		b.Warn("OCC-003", name,
			"Container process runs as root (no USER directive or USER 0). "+
				"Add a non-root USER to the Dockerfile to limit blast radius.",
			scan.SeverityHigh)
	} else {
		b.Pass("OCC-003", name, fmt.Sprintf("Container runs as user %q", user), scan.SeverityHigh)
	}
}

// checkSocketMount flags containers with /var/run/docker.sock bind-mounted.
func checkSocketMount(b *scan.CheckBuilder, ci containerInspect, short string) {
	name := fmt.Sprintf("Docker socket not mounted [%s]", short)
	for _, m := range ci.Mounts {
		if m.Source == "/var/run/docker.sock" {
			b.Fail("OCC-004", name,
				"/var/run/docker.sock is mounted into the container — "+
					"this grants full Docker daemon control, equivalent to root on the host.",
				scan.SeverityCritical)
			return
		}
	}
	b.Pass("OCC-004", name, "Docker socket is not mounted into the container", scan.SeverityCritical)
}

// execContainerAudit runs `openclaw security audit --json` inside the container
// and translates the findings through the standard path.
func execContainerAudit(b *scan.CheckBuilder, containerID, short string, ci containerInspect) {
	install := InstallInfo{
		Channel:    "docker",
		Version:    imageTag(ci.Config.Image),
		BinaryPath: containerID,
	}
	skipName := fmt.Sprintf("OpenClaw container audit [%s]", short)

	ctx, cancel := context.WithTimeout(context.Background(), containerAuditTimeout)
	defer cancel()
	r := iexec.RunCtx(ctx, nil, "docker", "exec", containerID,
		"openclaw", "security", "audit", "--json")

	if r.TimedOut {
		b.Skip("OCC-AUDIT-000", skipName,
			fmt.Sprintf("openclaw security audit timed out after %ds", int(containerAuditTimeout.Seconds())),
			scan.SeverityLow)
		b.WithRemediation("Source: " + install.sourceTag())
		return
	}
	if r.ExitCode != 0 {
		stderr := strings.TrimSpace(r.Stderr)
		if len(stderr) > 200 {
			stderr = stderr[:200]
		}
		b.Skip("OCC-AUDIT-000", skipName,
			fmt.Sprintf("openclaw security audit exited %d: %s", r.ExitCode, stderr),
			scan.SeverityLow)
		b.WithRemediation("Source: " + install.sourceTag())
		return
	}

	var payload struct {
		Findings json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal([]byte(r.Stdout), &payload); err != nil || payload.Findings == nil {
		b.Skip("OCC-AUDIT-000", skipName, "could not parse openclaw audit output as JSON", scan.SeverityLow)
		b.WithRemediation("Source: " + install.sourceTag())
		return
	}

	var findings []auditFinding
	if err := json.Unmarshal(payload.Findings, &findings); err != nil {
		b.Skip("OCC-AUDIT-000", skipName, "could not parse openclaw findings as JSON", scan.SeverityLow)
		b.WithRemediation("Source: " + install.sourceTag())
		return
	}

	for _, f := range findings {
		TranslateFinding(b, f, install)
	}
}

// imageTag extracts the tag portion from a full image reference.
// "ghcr.io/openclaw/openclaw:v1.2.3" → "v1.2.3"
func imageTag(image string) string {
	if idx := strings.LastIndex(image, ":"); idx != -1 {
		return image[idx+1:]
	}
	return "unknown"
}
