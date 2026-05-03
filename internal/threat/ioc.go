//go:build darwin || linux

package threat

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	iexec "github.com/Anvil-Cloud-AI/anvil-scanner/internal/exec"
)

// currentUsername returns the OS login name for the current UID, equivalent
// to getpwuid(os.getuid()).pw_name in Python.
func currentUsername() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

// knownSafePorts matches the Python reference KNOWN_SAFE_PORTS set exactly.
var knownSafePorts = map[int]bool{
	22: true, 80: true, 443: true,
	8000: true, 3000: true,
	5432: true, 3306: true, 6379: true,
	18789: true, 18791: true,
	9090: true, 19001: true,
}

// cryptoMiners is a set of known crypto miner process names.
var cryptoMiners = map[string]bool{
	"xmrig": true, "minerd": true, "cryptonight": true,
	"cgminer": true, "ethminer": true, "cpuminer": true,
	"bfgminer": true, "nbminer": true, "t-rex": true, "lolminer": true,
}

// reverseShellRE matches common reverse shell patterns in process cmdlines.
var reverseShellRE = regexp.MustCompile(
	`(?i)(bash\s+-i.*>/dev/tcp/|base64\s+-[dD].*\|\s*(bash|sh)|nohup.*bash\s+-[ic])`,
)

// cronSuspiciousPatterns are (regex, description) pairs for cron file scanning.
var cronSuspiciousPatterns = []struct {
	re   *regexp.Regexp
	desc string
}{
	{regexp.MustCompile(`(?i)https?://`), "URL in cron command"},
	{regexp.MustCompile(`(?i)base64`), "Base64 encoding in cron"},
	{regexp.MustCompile(`(?i)(curl|wget)\s.*\|\s*(bash|sh|python|perl)`), "curl/wget piped to shell"},
	{regexp.MustCompile(`/tmp/`), "References /tmp"},
	{regexp.MustCompile(`/dev/shm/`), "References /dev/shm"},
	{regexp.MustCompile(`/var/tmp/`), "References /var/tmp"},
}

// normalCommentRE matches a typical SSH key comment (user@host).
var normalCommentRE = regexp.MustCompile(`^[\w.+-]+@[\w.-]+$`)

// keyIPRE matches an IP-address-like key comment.
var keyIPRE = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)

// keyCommentRE matches a valid (non-suspicious) key comment character set.
var keyCommentRE = regexp.MustCompile(`^[\w.@+-]+$`)

// portLineRE matches a listening IPv4-wildcard socket line from ss output.
var portLineRE = regexp.MustCompile(`(?:0\.0\.0\.0|\*):(\d+)\s`)

// authFromIPRE extracts the remote IP from an auth log "Accepted" line.
var authFromIPRE = regexp.MustCompile(`from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)

// authSudoRE extracts the sudo invoking user from a sudo log line.
var authSudoRE = regexp.MustCompile(`sudo:\s+(\w+)\s+:`)

// CheckLocalIOC scans the local system for common post-exploit indicators of
// compromise. All filesystem operations are read-only.
func CheckLocalIOC() LocalIOCResult {
	result := LocalIOCResult{
		SuspiciousCron:      []string{},
		SuspiciousProcesses: []string{},
		SuspiciousTempFiles: []string{},
		SSHPersistence:      []string{},
		ListeningBackdoors:  []string{},
		AuthAnomalies:       []string{},
	}

	isLinux := runtime.GOOS == "linux"
	isMacOS := runtime.GOOS == "darwin"

	// ── a) Suspicious cron jobs (Linux only) ─────────────────────────────
	if isLinux {
		checkCronFiles(&result)
	}

	// ── b) Suspicious processes ───────────────────────────────────────────
	if isLinux {
		checkLinuxProcesses(&result)
	}

	// ── c) Suspicious files in temp dirs ─────────────────────────────────
	checkTempDirs(&result)

	// ── d) SSH persistence check ──────────────────────────────────────────
	checkSSHKeys(&result)

	// ── e) Listening backdoors (Linux via /proc/net/tcp) ─────────────────
	if isLinux {
		checkListeningPorts(&result)
	}

	// ── f) Auth log anomaly check (Linux only) ────────────────────────────
	if isLinux {
		checkAuthLog(&result)
	}

	// ── i) macOS $TMPDIR executable scan ──────────────────────────────────
	if isMacOS {
		checkMacOSTmpdir(&result)
	}

	// ── j) macOS xattr quarantine bypass detection ────────────────────────
	if isMacOS {
		checkMacOSXattr(&result)
	}

	return result
}

func checkCronFiles(result *LocalIOCResult) {
	var cronFiles []string

	patterns := []string{
		"/etc/cron.d/*", "/etc/cron.daily/*", "/etc/cron.hourly/*",
		"/etc/cron.weekly/*", "/etc/cron.monthly/*",
	}
	for _, pat := range patterns {
		matches, _ := filepath.Glob(pat)
		cronFiles = append(cronFiles, matches...)
	}
	if _, err := os.Stat("/etc/crontab"); err == nil {
		cronFiles = append(cronFiles, "/etc/crontab")
	}

	spoolDir := "/var/spool/cron/crontabs"
	if entries, err := os.ReadDir(spoolDir); err == nil {
		for _, e := range entries {
			cronFiles = append(cronFiles, filepath.Join(spoolDir, e.Name()))
		}
	}

	for _, cf := range cronFiles {
		data, err := readFileCapped(cf, 64*1024)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(data), "\n") {
			stripped := strings.TrimSpace(line)
			if stripped == "" || strings.HasPrefix(stripped, "#") {
				continue
			}
			for _, pat := range cronSuspiciousPatterns {
				if pat.re.MatchString(stripped) {
					content := stripped
					if len(content) > 200 {
						content = content[:200]
					}
					result.SuspiciousCron = append(result.SuspiciousCron,
						fmt.Sprintf("%s (line %d): %s — %s", cf, i+1, content, pat.desc))
					break
				}
			}
		}
	}
}

func checkLinuxProcesses(result *LocalIOCResult) {
	procDir, err := os.Open("/proc")
	if err != nil {
		return
	}
	defer procDir.Close()
	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return
	}

	for _, name := range entries {
		// Only numeric directories are PIDs.
		if _, err := strconv.Atoi(name); err != nil {
			continue
		}
		cmdlineBytes, err := readFileCapped(fmt.Sprintf("/proc/%s/cmdline", name), 8*1024)
		if err != nil {
			continue
		}
		// cmdline uses NUL separators.
		cmdline := strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")
		cmdline = strings.TrimSpace(cmdline)
		if cmdline == "" {
			continue
		}
		cmdlineLow := strings.ToLower(cmdline)

		// Check for temp-dir execution.
		flagged := false
		for _, tmpDir := range []string{"/tmp/", "/dev/shm/", "/var/tmp/"} {
			if strings.Contains(cmdline, tmpDir) {
				short := cmdline
				if len(short) > 200 {
					short = short[:200]
				}
				result.SuspiciousProcesses = append(result.SuspiciousProcesses,
					fmt.Sprintf("PID %s running from %s: %s", name, tmpDir, short))
				flagged = true
				break
			}
		}
		if flagged {
			continue
		}

		// Check for crypto miners.
		for miner := range cryptoMiners {
			if strings.Contains(cmdlineLow, miner) {
				short := cmdline
				if len(short) > 200 {
					short = short[:200]
				}
				result.SuspiciousProcesses = append(result.SuspiciousProcesses,
					fmt.Sprintf("PID %s possible crypto miner (%s): %s", name, miner, short))
				flagged = true
				break
			}
		}
		if flagged {
			continue
		}

		// Check for ngrok / C2 tunneling.
		if strings.Contains(cmdlineLow, "ngrok") {
			short := cmdline
			if len(short) > 200 {
				short = short[:200]
			}
			result.SuspiciousProcesses = append(result.SuspiciousProcesses,
				fmt.Sprintf("PID %s known C2/tunneling tool (ngrok): %s", name, short))
			flagged = true
		}
		if flagged {
			continue
		}

		// ncat/socat in listener mode.
		if (strings.Contains(cmdlineLow, "ncat") || strings.Contains(cmdlineLow, "socat")) &&
			(strings.Contains(cmdlineLow, "-l") || strings.Contains(cmdlineLow, "listen")) {
			short := cmdline
			if len(short) > 200 {
				short = short[:200]
			}
			result.SuspiciousProcesses = append(result.SuspiciousProcesses,
				fmt.Sprintf("PID %s ncat/socat in listener mode: %s", name, short))
			flagged = true
		}
		if flagged {
			continue
		}

		// Reverse shell pattern.
		if reverseShellRE.MatchString(cmdline) {
			short := cmdline
			if len(short) > 200 {
				short = short[:200]
			}
			result.SuspiciousProcesses = append(result.SuspiciousProcesses,
				fmt.Sprintf("PID %s reverse shell pattern: %s", name, short))
		}
	}

	// Check /proc/net/tcp for known C2 IPs.
	checkC2Connections(result)
}

// checkC2Connections looks for active TCP connections to known C2 IPs.
func checkC2Connections(result *LocalIOCResult) {
	c2IPs := map[string]string{
		"91.92.242.30":  "ClawHavoc/AMOS dropper C2",
		"54.91.154.110": "AuthTool reverse shell endpoint",
	}

	ipToHex := func(ip string) string {
		parts := strings.Split(ip, ".")
		if len(parts) != 4 {
			return ""
		}
		var h string
		for i := 3; i >= 0; i-- {
			n, err := strconv.Atoi(parts[i])
			if err != nil {
				return ""
			}
			h += fmt.Sprintf("%02X", n)
		}
		return h
	}

	c2Hex := make(map[string]struct{ ip, label string })
	for ip, label := range c2IPs {
		h := ipToHex(ip)
		if h != "" {
			c2Hex[h] = struct{ ip, label string }{ip, label}
		}
	}

	for _, tcpFile := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := readFileCapped(tcpFile, 1<<20)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			remote := fields[2]
			colonIdx := strings.LastIndex(remote, ":")
			if colonIdx < 0 {
				continue
			}
			remoteHex := strings.ToUpper(remote[:colonIdx])
			if entry, ok := c2Hex[remoteHex]; ok {
				portHex := remote[colonIdx+1:]
				port, _ := strconv.ParseInt(portHex, 16, 32)
				result.SuspiciousProcesses = append(result.SuspiciousProcesses,
					fmt.Sprintf("Active TCP connection to known C2 %s:%d — %s", entry.ip, port, entry.label))
			}
		}
	}
}

func checkTempDirs(result *LocalIOCResult) {
	now := time.Now()
	dayAgo := now.Add(-24 * time.Hour)

	tmpDirs := []string{"/tmp", "/dev/shm", "/var/tmp"}

	for _, dir := range tmpDirs {
		fi, err := os.Stat(dir)
		if err != nil || !fi.IsDir() {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			isExec := info.Mode()&0111 != 0
			isRecent := info.ModTime().After(dayAgo)
			ext := filepath.Ext(entry.Name())

			// Check for ELF or Mach-O magic bytes on files without extensions.
			isBin := false
			var binaryKind string
			if ext == "" {
				if magic, err := readMagicBytes(path, 4); err == nil && isBinaryFile(magic) {
					isBin = true
					if len(magic) >= 4 && string(magic[:4]) == "\x7fELF" {
						binaryKind = "ELF binary"
					} else {
						binaryKind = "Mach-O binary"
					}
				}
			}

			var reason string
			switch {
			case isBin:
				reason = fmt.Sprintf("%s with no extension in temp dir", binaryKind)
			case isExec && isRecent:
				reason = "Executable file modified in last 24h"
			case isExec:
				reason = "Executable file in temp dir"
			}
			if reason != "" {
				result.SuspiciousTempFiles = append(result.SuspiciousTempFiles,
					fmt.Sprintf("%s (%d bytes): %s", path, info.Size(), reason))
			}
		}
	}
}

// isBinaryFile reports whether data starts with an ELF or Mach-O magic
// sequence. Callers pass the first 4 bytes of the file.
func isBinaryFile(data []byte) bool {
	if len(data) >= 4 && string(data[:4]) == "\x7fELF" {
		return true
	}
	// Mach-O little-endian (most common on x86-64 and ARM64).
	if len(data) >= 4 &&
		(string(data[:4]) == "\xce\xfa\xed\xfe" || string(data[:4]) == "\xcf\xfa\xed\xfe") {
		return true
	}
	// Mach-O big-endian and fat binaries.
	if len(data) >= 4 &&
		(string(data[:4]) == "\xfe\xed\xfa\xce" || string(data[:4]) == "\xfe\xed\xfa\xcf" ||
			string(data[:4]) == "\xca\xfe\xba\xbe") {
		return true
	}
	return false
}

// readMagicBytes reads the first n bytes of a file without opening it fully.
func readMagicBytes(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	nr, err := io.ReadFull(f, buf)
	if err != nil && nr == 0 {
		return nil, err
	}
	return buf[:nr], nil
}

// readFileCapped reads at most maxBytes from path. It is used instead of
// os.ReadFile on user-controlled or potentially large files to prevent
// excessive memory allocation from adversarially large file contents.
func readFileCapped(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxBytes))
}

func checkSSHKeys(result *LocalIOCResult) {
	sevenDaysAgo := time.Now().Add(-7 * 24 * time.Hour)

	var akPaths []string
	seen := make(map[string]bool)

	addPath := func(p string) {
		if !seen[p] {
			if _, err := os.Stat(p); err == nil {
				seen[p] = true
				akPaths = append(akPaths, p)
			}
		}
	}

	addPath("/root/.ssh/authorized_keys")

	// Parse /etc/passwd for home directories.
	passwdData, err := readFileCapped("/etc/passwd", 1*1024*1024)
	if err == nil {
		for _, line := range strings.Split(string(passwdData), "\n") {
			parts := strings.Split(line, ":")
			if len(parts) >= 6 {
				ak := filepath.Join(parts[5], ".ssh", "authorized_keys")
				addPath(ak)
			}
		}
	}

	// Also check /home/*/.ssh/authorized_keys.
	homeMatches, _ := filepath.Glob("/home/*/.ssh/authorized_keys")
	for _, p := range homeMatches {
		addPath(p)
	}

	for _, akPath := range akPaths {
		st, err := os.Stat(akPath)
		if err != nil {
			continue
		}
		akRecent := st.ModTime().After(sevenDaysAgo)

		data, err := readFileCapped(akPath, 512*1024)
		if err != nil {
			continue
		}

		var keys []string
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				keys = append(keys, trimmed)
			}
		}

		var flags []string
		if akRecent {
			flags = append(flags, "File modified within last 7 days — possible unauthorized key addition")
		}

		for _, keyLine := range keys {
			parts := strings.Fields(keyLine)
			if len(parts) >= 3 {
				comment := parts[len(parts)-1]
				if !normalCommentRE.MatchString(comment) {
					// Check if it looks like an IP address.
					if net.ParseIP(comment) != nil || keyIPRE.MatchString(comment) {
						flags = append(flags, fmt.Sprintf("Key with IP address comment: %s", comment))
					} else if len(comment) > 40 || !keyCommentRE.MatchString(comment) {
						if len(comment) > 60 {
							comment = comment[:60]
						}
						flags = append(flags, fmt.Sprintf("Key with unusual comment: %s", comment))
					}
				}
			}
		}

		if len(flags) > 0 || akRecent {
			for _, flag := range flags {
				result.SSHPersistence = append(result.SSHPersistence,
					fmt.Sprintf("%s (%d keys): %s", akPath, len(keys), flag))
			}
			if len(flags) == 0 && akRecent {
				result.SSHPersistence = append(result.SSHPersistence,
					fmt.Sprintf("%s (%d keys): recently modified", akPath, len(keys)))
			}
		}
	}
}

func checkListeningPorts(result *LocalIOCResult) {
	// Try ss first.
	res := iexec.Run("ss", "-tlnp")
	if res.Success() {
		lines := strings.Split(res.Stdout, "\n")
		for _, line := range lines[1:] { // skip header
			m := portLineRE.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			port, err := strconv.Atoi(m[1])
			if err != nil || knownSafePorts[port] {
				continue
			}
			var reason string
			if port > 32768 {
				reason = fmt.Sprintf("High port %d listening on 0.0.0.0 (ephemeral range)", port)
			} else {
				reason = fmt.Sprintf("Port %d listening on 0.0.0.0 — not in known-safe list", port)
			}
			result.ListeningBackdoors = append(result.ListeningBackdoors,
				fmt.Sprintf("%s — %s", strings.TrimSpace(line), reason))
		}
		return
	}

	// Fall back to /proc/net/tcp.
	data, err := readFileCapped("/proc/net/tcp", 1<<20)
	if err != nil {
		return
	}
	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 {
			continue // skip header
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// State 0A = listening.
		if fields[3] != "0A" {
			continue
		}
		local := fields[1]
		colonIdx := strings.LastIndex(local, ":")
		if colonIdx < 0 {
			continue
		}
		portHex := local[colonIdx+1:]
		port64, err := strconv.ParseInt(portHex, 16, 32)
		if err != nil {
			continue
		}
		port := int(port64)
		if knownSafePorts[port] {
			continue
		}
		var reason string
		if port > 32768 {
			reason = fmt.Sprintf("High port %d in /proc/net/tcp (ephemeral range)", port)
		} else {
			reason = fmt.Sprintf("Port %d in /proc/net/tcp — not in known-safe list", port)
		}
		result.ListeningBackdoors = append(result.ListeningBackdoors, reason)
	}
}

func checkAuthLog(result *LocalIOCResult) {
	authLog := "/var/log/auth.log"
	if _, err := os.Stat(authLog); err != nil {
		// Try /var/log/secure (RHEL/CentOS).
		authLog = "/var/log/secure"
	}

	// Read at most 2 MB from the end of the log to avoid loading gigabyte-sized files.
	const maxAuthLogBytes = 2 * 1024 * 1024
	f, err := os.Open(authLog)
	if err != nil {
		result.AuthAnomalies = append(result.AuthAnomalies,
			fmt.Sprintf("Could not read %s (permission denied or not found)", authLog))
		return
	}
	defer f.Close()

	if fi, statErr := f.Stat(); statErr == nil && fi.Size() > maxAuthLogBytes {
		_, _ = f.Seek(-maxAuthLogBytes, io.SeekEnd)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		result.AuthAnomalies = append(result.AuthAnomalies,
			fmt.Sprintf("Could not read %s (permission denied or not found)", authLog))
		return
	}

	// Take only the last 200 lines to avoid loading huge files.
	allLines := strings.Split(string(data), "\n")
	start := 0
	if len(allLines) > 200 {
		start = len(allLines) - 200
	}
	lines := allLines[start:]

	// Resolve the current login user once; used to whitelist sudo checks below.
	currentUser, _ := currentUsername()

	failedSSH := 0

	for _, line := range lines {
		if strings.Contains(line, "Failed password") ||
			strings.Contains(strings.ToLower(line), "authentication failure") {
			failedSSH++
		}

		if strings.Contains(line, "Accepted ") {
			if m := authFromIPRE.FindStringSubmatch(line); m != nil {
				loginIP := m[1]
				// Flag logins from public IPs (non-RFC-1918/loopback/link-local).
				if !isPrivateIP(loginIP) {
					result.AuthAnomalies = append(result.AuthAnomalies,
						fmt.Sprintf("Successful login from external IP %s", loginIP))
				}
			}
		}

		if m := authSudoRE.FindStringSubmatch(line); m != nil {
			usr := m[1]
			knownSafe := map[string]bool{
				"root": true, "admin": true, "ubuntu": true,
				"debian": true, "ec2-user": true,
			}
			// Only trust SUDO_USER when running as root (matches Python: os.geteuid()==0).
			if os.Getuid() == 0 {
				if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
					knownSafe[sudoUser] = true
				}
			}
			if currentUser != "" {
				knownSafe[currentUser] = true
			}
			if !knownSafe[usr] {
				result.AuthAnomalies = append(result.AuthAnomalies,
					fmt.Sprintf("sudo used by non-standard user: %s", usr))
			}
		}
	}

	if failedSSH > 10 {
		result.AuthAnomalies = append(result.AuthAnomalies,
			fmt.Sprintf("%d failed SSH attempts in recent auth.log entries", failedSSH))
	}
}

func checkMacOSTmpdir(result *LocalIOCResult) {
	macTmpDir := os.Getenv("TMPDIR")
	if macTmpDir == "" {
		return
	}
	fi, err := os.Stat(macTmpDir)
	if err != nil || !fi.IsDir() {
		return
	}

	entries, err := os.ReadDir(macTmpDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		path := filepath.Join(macTmpDir, entry.Name())
		isExec := info.Mode()&0111 != 0
		ext := filepath.Ext(entry.Name())

		isMachO := false
		if ext == "" {
			if magic, err := readMagicBytes(path, 4); err == nil {
				isMachO = isBinaryFile(magic)
			}
		}

		if isMachO || isExec {
			kind := "Executable"
			if isMachO {
				kind = "Mach-O binary"
			}
			result.SuspiciousTempFiles = append(result.SuspiciousTempFiles,
				fmt.Sprintf("%s (%s in macOS $TMPDIR %s, %d bytes)", path, kind, macTmpDir, info.Size()))
		}
	}
}

func checkMacOSXattr(result *LocalIOCResult) {
	res := iexec.Run("ps", "aux")
	if !res.Success() {
		return
	}
	for _, line := range strings.Split(res.Stdout, "\n") {
		if strings.Contains(line, "xattr") && strings.Contains(line, "-c") {
			fields := strings.Fields(line)
			pid := "?"
			if len(fields) > 1 {
				pid = fields[1]
			}
			short := strings.TrimSpace(line)
			if len(short) > 200 {
				short = short[:200]
			}
			result.SuspiciousProcesses = append(result.SuspiciousProcesses,
				fmt.Sprintf("PID %s xattr -c running — Gatekeeper quarantine bypass in progress (ClawHavoc indicator): %s", pid, short))
		}
	}
}
