//go:build darwin || linux

package hardening

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/backup"
	iexec "github.com/Anvil-Cloud-AI/anvil-scanner/internal/exec"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
)

// applyRPi applies Raspberry Pi-specific hardening fixes.
func applyRPi(idx map[string]scan.Status, bkup *backup.Manager, r *Result) {
	applyRPI006(idx, bkup, r)
	applyRPI007(idx, r)
	applyRPI009(idx, bkup, r)
}

// applyRPI006 fixes world-writable boot partition files (RPI-006).
func applyRPI006(idx map[string]scan.Status, bkup *backup.Manager, r *Result) {
	if !needsFix(idx, "RPI-006") {
		return
	}

	bootPath := findBootPath()
	if bootPath == "" {
		r.skipped("RPI-006", "Boot partition file permissions", "boot partition not found")
		return
	}

	var fixed, errs []string
	for _, name := range []string{"config.txt", "cmdline.txt"} {
		p := filepath.Join(bootPath, name)
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if info.Mode().Perm()&0o002 == 0 {
			continue
		}
		bkup.Backup(p, "RPi boot file before hardening")
		if err := os.Chmod(p, 0o644); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
		} else {
			fixed = append(fixed, name)
		}
	}

	if len(errs) > 0 {
		r.failed("RPI-006", "Boot partition file permissions", strings.Join(errs, "; "))
		return
	}
	if len(fixed) == 0 {
		r.skipped("RPI-006", "Boot partition file permissions", "no world-writable boot files found")
		return
	}
	r.applied("RPI-006", "Boot partition file permissions",
		fmt.Sprintf("chmod 644 %s", strings.Join(fixed, ", ")))
}

// applyRPI007 disables automatic console login (RPI-007).
func applyRPI007(idx map[string]scan.Status, r *Result) {
	if !needsFix(idx, "RPI-007") {
		return
	}

	res := iexec.Run("raspi-config", "nonint", "do_boot_behaviour", "B1")
	if res.Success() {
		r.applied("RPI-007", "Automatic console login disabled",
			"raspi-config nonint do_boot_behaviour B1")
	} else {
		r.failed("RPI-007", "Automatic console login disabled",
			fmt.Sprintf("raspi-config failed: %s", strings.TrimSpace(res.Stderr+res.Stdout)))
	}
}

// applyRPI009 sets GPU memory split to 16 MB (server-optimised) (RPI-009).
func applyRPI009(idx map[string]scan.Status, bkup *backup.Manager, r *Result) {
	if !needsFix(idx, "RPI-009") {
		return
	}

	configPath := findBootConfigPath()
	if configPath == "" {
		r.skipped("RPI-009", "GPU memory optimized for server", "boot config not found")
		return
	}

	bkup.Backup(configPath, "RPi config.txt before GPU memory hardening")

	res := iexec.Run("raspi-config", "nonint", "do_memory_split", "16")
	if res.Success() {
		r.applied("RPI-009", "GPU memory optimized for server",
			"raspi-config nonint do_memory_split 16")
		return
	}

	// Fallback: edit config.txt directly.
	raw, err := os.ReadFile(configPath)
	if err != nil {
		r.failed("RPI-009", "GPU memory optimized for server", "read config.txt: "+err.Error())
		return
	}

	lines := strings.Split(string(raw), "\n")
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "gpu_mem=") || strings.HasPrefix(trimmed, "#gpu_mem=") {
			lines[i] = "gpu_mem=16"
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, "gpu_mem=16")
	}

	if err := os.WriteFile(configPath, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		r.failed("RPI-009", "GPU memory optimized for server", "write config.txt: "+err.Error())
		return
	}
	r.applied("RPI-009", "GPU memory optimized for server", "set gpu_mem=16 in "+configPath)
}

func findBootPath() string {
	for _, d := range []string{"/boot/firmware", "/boot"} {
		if _, err := os.Stat(d); err == nil {
			return d
		}
	}
	return ""
}

func findBootConfigPath() string {
	for _, d := range []string{"/boot/firmware", "/boot"} {
		p := filepath.Join(d, "config.txt")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
