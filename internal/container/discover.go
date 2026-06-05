//go:build darwin || linux

package container

import (
	"encoding/json"
	"fmt"
	osexec "os/exec"
	"strings"

	iexec "github.com/Anvil-Cloud-AI/anvil-scanner/internal/exec"
)

// containerRef is a running container's ID and the image backing it.
type containerRef struct {
	ID    string
	Image string
}

// detectRuntime returns the first available container runtime binary on PATH
// ("docker", then "podman"), or "" when neither is installed. Docker is
// preferred because podman ships a docker-compatible CLI, so a host with both
// behaves identically either way.
func detectRuntime() string {
	for _, bin := range []string{"docker", "podman"} {
		if _, err := osexec.LookPath(bin); err == nil {
			return bin
		}
	}
	return ""
}

// listContainers returns the running containers reported by `<bin> ps`.
// Malformed lines are skipped. A failed invocation (daemon down, no
// permission) yields an empty slice rather than an error — the caller treats
// "no containers" and "could not list" identically: no checks are emitted.
func listContainers(bin string) []containerRef {
	r := iexec.Run(bin, "ps", "--format", "{{.ID}}\t{{.Image}}")
	if !r.Success() {
		return nil
	}
	return parsePS(r.Stdout)
}

// parsePS parses tab-separated `<id>\t<image>` lines from `<runtime> ps`
// output. Malformed or empty lines are skipped.
func parsePS(stdout string) []containerRef {
	var refs []containerRef
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "\t", 2)
		if len(parts) != 2 || parts[0] == "" {
			continue
		}
		refs = append(refs, containerRef{ID: parts[0], Image: parts[1]})
	}
	return refs
}

// inspectContainer runs `<bin> inspect <id>` and decodes the first element of
// the returned JSON array.
func inspectContainer(bin, id string) (containerInspect, error) {
	// "--" guards against a container ID (external data from `ps`) that begins
	// with a dash being reinterpreted as an inspect flag.
	r := iexec.Run(bin, "inspect", "--", id)
	if !r.Success() {
		return containerInspect{}, fmt.Errorf("%s inspect %s (exit %d): %s",
			bin, shortID(id), r.ExitCode, strings.TrimSpace(r.Stderr))
	}
	var inspects []containerInspect
	if err := json.Unmarshal([]byte(r.Stdout), &inspects); err != nil {
		return containerInspect{}, fmt.Errorf("%s inspect %s: parse output: %w", bin, shortID(id), err)
	}
	if len(inspects) == 0 {
		return containerInspect{}, fmt.Errorf("%s inspect %s: empty result", bin, shortID(id))
	}
	return inspects[0], nil
}

// runningImages returns the deduplicated set of image references backing the
// currently running containers. Order is deterministic (first-seen).
func runningImages(bin string) []string {
	seen := map[string]bool{}
	var images []string
	for _, ref := range listContainers(bin) {
		img := strings.TrimSpace(ref.Image)
		if img == "" || seen[img] {
			continue
		}
		seen[img] = true
		images = append(images, img)
	}
	return images
}
