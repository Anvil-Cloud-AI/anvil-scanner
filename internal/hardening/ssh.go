//go:build darwin || linux

package hardening

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/backup"
	iexec "github.com/Anvil-Cloud-AI/anvil-scanner/internal/exec"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
)

const sshdConfigPath = "/etc/ssh/sshd_config"

// hardenedValues maps lowercase directive name → recommended value.
// Applied when the corresponding SSH-* check is FAIL or WARN.
var hardenedValues = map[string]struct {
	checkID   string
	canonical string // proper capitalisation for the config file
	value     string
}{
	"maxauthtries":         {"SSH-006", "MaxAuthTries", "4"},
	"logingracetime":       {"SSH-008", "LoginGraceTime", "60"},
	"kexalgorithms":        {"SSH-014", "KexAlgorithms", "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256"},
	"ciphers":              {"SSH-015", "Ciphers", "aes256-gcm@openssh.com,aes128-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"},
	"macs":                 {"SSH-016", "MACs", "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"},
	"clientaliveinterval":  {"SSH-021", "ClientAliveInterval", "300"},
	"x11forwarding":        {"SSH-023", "X11Forwarding", "no"},
	"allowtcpforwarding":   {"SSH-024", "AllowTcpForwarding", "no"},
	"permituserenvironment":{"SSH-029", "PermitUserEnvironment", "no"},
	"loglevel":             {"SSH-030", "LogLevel", "VERBOSE"},
}

// matchBlockRE matches a line that starts a Match block in sshd_config.
var matchBlockRE = regexp.MustCompile(`(?i)^\s*Match\s+`)

// applySSH patches sshd_config for all failing SSH directive checks,
// then fixes file permissions (SSH-042, SSH-043).
func applySSH(idx map[string]scan.Status, bkup *backup.Manager, platform string, r *Result) {
	// Determine which directives actually need patching.
	patches := map[string]struct{ canonical, value string }{}
	for lower, hv := range hardenedValues {
		if needsFix(idx, hv.checkID) {
			patches[lower] = struct{ canonical, value string }{hv.canonical, hv.value}
		}
	}

	if len(patches) > 0 {
		raw, readErr := iexec.ReadFileElevated(sshdConfigPath)
		if readErr != nil {
			r.failed("SSH-config", "sshd_config read", readErr.Error())
			return
		}
		bkup.BackupContent(sshdConfigPath, raw, "sshd_config before hardening")
		changed, applied, err := patchSSHConfig(sshdConfigPath, raw, patches)
		if err != nil {
			r.failed("SSH-config", "sshd_config patch", err.Error())
		} else if changed {
			if restartErr := restartSSHD(platform); restartErr != nil {
				r.applied("SSH-config", "sshd_config patch",
					fmt.Sprintf("patched %s directive(s) — WARNING: sshd restart failed: %v (config is valid; restart manually)",
						strings.Join(applied, ", "), restartErr))
			} else {
				r.applied("SSH-config", "sshd_config patch",
					fmt.Sprintf("set %s; sshd restarted", strings.Join(applied, ", ")))
			}
		}
	}

	// SSH-042 — sshd_config permissions (root:root 600)
	applySSH042(idx, bkup, r)

	// SSH-043 — host private key permissions (600)
	applySSH043(idx, r)
}

// patchSSHConfig rewrites path applying each directive in patches.
// It returns (changed, appliedDirectives, error).
// If nothing needed changing, changed=false is returned without touching the file.
// The temp file is removed on any validation error.
// rewriteSSHLines applies patches to lines from an sshd_config, returning
// (newContent, replaced map, toAppend slice).  Pure function — no I/O.
func rewriteSSHLines(lines []string, patches map[string]struct{ canonical, value string }) (string, map[string]bool, []string) {
	replaced := make(map[string]bool, len(patches))
	inMatchBlock := false
	newLines := make([]string, 0, len(lines)+len(patches)+2)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Track Match blocks — they run until the next Match keyword or EOF.
		if matchBlockRE.MatchString(line) {
			inMatchBlock = true
			newLines = append(newLines, line)
			continue
		}

		if inMatchBlock || strings.HasPrefix(trimmed, "#") || trimmed == "" {
			newLines = append(newLines, line)
			continue
		}

		fields := strings.Fields(trimmed)
		if len(fields) < 1 {
			newLines = append(newLines, line)
			continue
		}
		lower := strings.ToLower(fields[0])

		if p, ok := patches[lower]; ok && !replaced[lower] {
			newLines = append(newLines, p.canonical+" "+p.value)
			replaced[lower] = true
			continue
		}
		newLines = append(newLines, line)
	}

	var toAppend []string
	for lower, p := range patches {
		if !replaced[lower] {
			toAppend = append(toAppend, p.canonical+" "+p.value)
		}
	}
	if len(toAppend) > 0 {
		sort.Strings(toAppend)
		newLines = append(newLines, "")
		newLines = append(newLines, "# Added by anvil-scanner hardening")
		newLines = append(newLines, toAppend...)
	}

	return strings.Join(newLines, "\n"), replaced, toAppend
}

func patchSSHConfig(path string, raw []byte, patches map[string]struct{ canonical, value string }) (bool, []string, error) {
	newContent, replaced, toAppend := rewriteSSHLines(strings.Split(string(raw), "\n"), patches)

	if len(replaced) == 0 && len(toAppend) == 0 {
		return false, nil, nil
	}

	// Stage to a temp file we own for sshd -t validation (avoids writing to
	// the root-owned /etc/ssh/ dir before we know the config is valid).
	tmp, err := os.CreateTemp("", "anvil-sshd-validate-*")
	if err != nil {
		return false, nil, fmt.Errorf("create validation temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.WriteString(newContent); err != nil {
		tmp.Close()
		return false, nil, fmt.Errorf("write validation temp: %w", err)
	}
	tmp.Close()

	// Validate before committing.
	res := iexec.Run("sshd", "-t", "-f", tmpPath)
	if !res.Success() {
		return false, nil, fmt.Errorf("sshd -t validation failed: %s", strings.TrimSpace(res.Stderr+res.Stdout))
	}

	// Write to the real destination via sudo (stages through /tmp internally).
	if err := iexec.WriteFileElevated(path, []byte(newContent), "0600"); err != nil {
		return false, nil, fmt.Errorf("write %s: %w", path, err)
	}

	var applied []string
	for lower, p := range patches {
		if replaced[lower] || func() bool {
			for _, s := range toAppend {
				if strings.HasPrefix(s, p.canonical) {
					return true
				}
			}
			return false
		}() {
			applied = append(applied, p.canonical)
		}
	}
	sort.Strings(applied)
	return true, applied, nil
}

// restartSSHD restarts the SSH daemon on the current platform.
func restartSSHD(platform string) error {
	if runtime.GOOS == "darwin" {
		res := iexec.RunElevated("launchctl", "kickstart", "-k", "system/com.openssh.sshd")
		if res.Success() {
			return nil
		}
		// Fallback for older macOS.
		iexec.RunElevated("launchctl", "stop", "com.openssh.sshd")
		res2 := iexec.RunElevated("launchctl", "start", "com.openssh.sshd")
		if !res2.Success() {
			return fmt.Errorf("launchctl restart: %s", strings.TrimSpace(res2.Stderr))
		}
		return nil
	}
	// Linux: try systemctl sshd then ssh (Ubuntu naming).
	res := iexec.RunElevated("systemctl", "restart", "sshd")
	if res.Success() {
		return nil
	}
	res2 := iexec.RunElevated("systemctl", "restart", "ssh")
	if res2.Success() {
		return nil
	}
	return fmt.Errorf("systemctl restart sshd/ssh: %s", strings.TrimSpace(res2.Stderr))
}

// applySSH042 fixes sshd_config ownership and permissions (SSH-042).
func applySSH042(idx map[string]scan.Status, bkup *backup.Manager, r *Result) {
	if !needsFix(idx, "SSH-042") {
		return
	}
	info, err := os.Stat(sshdConfigPath)
	if err != nil {
		r.failed("SSH-042", "sshd_config permissions", err.Error())
		return
	}
	mode := info.Mode().Perm()
	if mode != 0o600 {
		if err := iexec.ChmodElevated(sshdConfigPath, "0600"); err != nil {
			r.failed("SSH-042", "sshd_config permissions", "chmod 600: "+err.Error())
			return
		}
		r.applied("SSH-042", "sshd_config permissions", "chmod 600 /etc/ssh/sshd_config")
		return
	}
	r.skipped("SSH-042", "sshd_config permissions", "already 600")
}

// applySSH043 fixes host private key permissions (SSH-043).
func applySSH043(idx map[string]scan.Status, r *Result) {
	if !needsFix(idx, "SSH-043") {
		return
	}
	keys, err := filepath.Glob("/etc/ssh/ssh_host_*_key")
	if err != nil || len(keys) == 0 {
		r.skipped("SSH-043", "host private key permissions", "no host keys found at /etc/ssh/ssh_host_*_key")
		return
	}
	var fixed []string
	var errs []string
	for _, k := range keys {
		if err := iexec.ChmodElevated(k, "0600"); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", filepath.Base(k), err))
		} else {
			fixed = append(fixed, filepath.Base(k))
		}
	}
	if len(errs) > 0 {
		r.failed("SSH-043", "host private key permissions", strings.Join(errs, "; "))
		return
	}
	r.applied("SSH-043", "host private key permissions",
		fmt.Sprintf("chmod 600 %s", strings.Join(fixed, ", ")))
}
