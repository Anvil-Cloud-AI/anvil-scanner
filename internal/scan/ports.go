//go:build darwin || linux

package scan

import (
	"context"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	iexec "github.com/Anvil-Cloud-AI/anvil-scanner/internal/exec"
)

var (
	portRegexLinux = regexp.MustCompile(`[:[](\d+)\s`)
	portRegexMacOS = regexp.MustCompile(`:(\d+)\s*\(LISTEN\)`)
)

// GetOpenPorts returns sorted listening TCP/UDP port numbers as strings.
// On macOS it uses lsof; on Linux it tries ss then netstat.
func GetOpenPorts() []string {
	if runtime.GOOS == "darwin" {
		return getOpenPortsMacOS()
	}
	return getOpenPortsLinux()
}

func getOpenPortsMacOS() []string {
	res := iexec.Run("lsof", "-iTCP", "-iUDP", "-sTCP:LISTEN", "-n", "-P")
	if res.ExitCode != 0 {
		return nil
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(res.Stdout, "\n") {
		m := portRegexMacOS.FindStringSubmatch(line)
		if m != nil {
			seen[m[1]] = true
		}
	}
	return sortedPorts(seen)
}

func getOpenPortsLinux() []string {
	res := iexec.Run("ss", "-tuln")
	if res.ExitCode != 0 {
		res = iexec.Run("netstat", "-tuln")
	}
	if res.ExitCode != 0 {
		return nil
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(res.Stdout, "\n") {
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "listen") && !strings.Contains(lower, "0.0.0.0") && !strings.Contains(lower, "::") {
			continue
		}
		m := portRegexLinux.FindStringSubmatch(line)
		if m != nil {
			seen[m[1]] = true
		}
	}
	return sortedPorts(seen)
}

func sortedPorts(seen map[string]bool) []string {
	ports := make([]string, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Slice(ports, func(i, j int) bool {
		a, _ := strconv.Atoi(ports[i])
		b, _ := strconv.Atoi(ports[j])
		return a < b
	})
	return ports
}

// GetPendingUpdates returns the count of packages with available updates.
// On macOS it uses brew; on Linux it uses apt.
func GetPendingUpdates() int {
	if runtime.GOOS == "darwin" {
		return getPendingUpdatesMacOS()
	}
	return getPendingUpdatesLinux()
}

func getPendingUpdatesMacOS() int {
	res := iexec.Run("brew", "outdated")
	if res.ExitCode != 0 {
		return 0
	}
	count := 0
	for _, line := range strings.Split(res.Stdout, "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

func getPendingUpdatesLinux() int {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res := iexec.RunCtx(ctx, nil, "apt", "list", "--upgradable")
	if res.ExitCode != 0 {
		return 0
	}
	count := 0
	for _, line := range strings.Split(res.Stdout, "\n") {
		if strings.Contains(line, "/") {
			count++
		}
	}
	return count
}
