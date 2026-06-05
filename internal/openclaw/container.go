//go:build darwin || linux || windows

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
// Structural runtime-hardening checks (ports, privileged, user, socket) now
// live in internal/container and cover every container; this package only
// needs the image reference to derive the OpenClaw version for the in-container
// security audit.
type containerInspect struct {
	Config struct {
		Image string `json:"Image"`
	} `json:"Config"`
}

// RunContainerAudits finds all running OpenClaw containers and runs the
// OpenClaw-specific in-container security audit on each. General container
// runtime hardening (CONTAINER-*) is handled separately by
// internal/container.RunRuntimeChecks. It is a no-op when Docker is
// unavailable or no matching containers are running — no SKIP check is added.
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
	execContainerAudit(b, containerID, short, ci)
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
