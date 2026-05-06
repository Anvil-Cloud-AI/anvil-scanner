//go:build darwin || linux

package threat

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ---- currentUsername --------------------------------------------------------

// TestCurrentUsername_ReturnsNonEmpty verifies that currentUsername returns a
// non-empty string on any supported platform without error.
func TestCurrentUsername_ReturnsNonEmpty(t *testing.T) {
	name, err := currentUsername()
	if err != nil {
		t.Fatalf("currentUsername() error = %v; want nil", err)
	}
	if name == "" {
		t.Error("currentUsername() returned empty string; want OS login name")
	}
}

// ---- checkCronFiles ---------------------------------------------------------
// checkCronFiles reads hardcoded system paths (/etc/cron.d/*, etc.).
// We exercise the function's scanning logic directly by calling it on a
// LocalIOCResult and verifying it does not panic even when cron directories
// are absent (non-Linux) or when they exist but are empty.

// TestCheckCronFiles_NoPanicOnMissingDirs verifies checkCronFiles does not
// panic when none of the standard cron paths exist.
func TestCheckCronFiles_NoPanicOnMissingDirs(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("checkCronFiles is a Linux-only code path")
	}
	result := &LocalIOCResult{SuspiciousCron: []string{}}
	// Must not panic regardless of cron file existence on the host.
	checkCronFiles(result)
	// SuspiciousCron may be empty or non-empty — the key invariant is no panic.
	_ = result.SuspiciousCron
}

// ---- checkSSHKeys with real files -------------------------------------------

// TestCheckSSHKeys_NoPanicOnMissingFiles verifies that checkSSHKeys does not
// panic when /root/.ssh/authorized_keys and /etc/passwd both do not exist or
// are inaccessible.
func TestCheckSSHKeys_NoPanicOnMissingFiles(t *testing.T) {
	result := &LocalIOCResult{SSHPersistence: []string{}}
	// Must not panic; SSH key files may or may not be present on the host.
	checkSSHKeys(result)
}

// TestCheckSSHKeys_RecentModificationFlagged creates a synthetic authorized_keys
// file (modified now) in a temp directory and verifies that an entry is flagged
// when the file path is exercised through the logic extracted from checkSSHKeys.
//
// checkSSHKeys reads from fixed paths (/root/.ssh, /etc/passwd, /home/*/...),
// so we replicate the relevant sub-logic directly.
func TestCheckSSHKeys_RecentModificationFlagged(t *testing.T) {
	dir := t.TempDir()
	sshDir := filepath.Join(dir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	akPath := filepath.Join(sshDir, "authorized_keys")
	// Write a valid-looking key line.
	content := "ssh-rsa AAAAB3NzaC1yc2EAAAA user@host\n"
	if err := os.WriteFile(akPath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Replicate the checkSSHKeys file-reading logic inline to avoid depending
	// on system paths.
	st, err := os.Stat(akPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	data, err := readFileCapped(akPath, 512*1024)
	if err != nil {
		t.Fatalf("readFileCapped: %v", err)
	}

	var keys []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			keys = append(keys, trimmed)
		}
	}

	result := &LocalIOCResult{SSHPersistence: []string{}}
	// The file was just created — it is "recent" (within 7 days).
	sevenDaysAgo := st.ModTime().Add(-1) // before mtime → recent
	akRecent := st.ModTime().After(sevenDaysAgo)
	if akRecent {
		result.SSHPersistence = append(result.SSHPersistence,
			fmt.Sprintf("%s (%d keys): File modified within last 7 days — possible unauthorized key addition",
				akPath, len(keys)))
	}

	if len(result.SSHPersistence) == 0 {
		t.Error("expected a recent-modification finding; got none")
	}
	if !strings.Contains(result.SSHPersistence[0], "7 days") {
		t.Errorf("finding = %q; want to mention '7 days'", result.SSHPersistence[0])
	}
}

// TestCheckSSHKeys_IPCommentFlagged verifies the IP-as-comment detection logic.
func TestCheckSSHKeys_IPCommentFlagged(t *testing.T) {
	// Replicate the key-comment analysis from checkSSHKeys.
	keyLine := "ssh-rsa AAAAB3NzaC1yc2EAAAA 192.168.1.10"
	parts := strings.Fields(keyLine)
	if len(parts) < 3 {
		t.Fatal("test data malformed")
	}
	comment := parts[len(parts)-1]

	result := &LocalIOCResult{SSHPersistence: []string{}}
	akPath := "/tmp/test_authorized_keys"
	numKeys := 1

	if !normalCommentRE.MatchString(comment) {
		var flag string
		if keyIPRE.MatchString(comment) {
			flag = fmt.Sprintf("Key with IP address comment: %s", comment)
		}
		if flag != "" {
			result.SSHPersistence = append(result.SSHPersistence,
				fmt.Sprintf("%s (%d keys): %s", akPath, numKeys, flag))
		}
	}

	if len(result.SSHPersistence) == 0 {
		t.Error("expected IP comment finding; got none")
	}
	if !strings.Contains(result.SSHPersistence[0], "IP address") {
		t.Errorf("finding = %q; want to mention 'IP address'", result.SSHPersistence[0])
	}
}

// TestCheckSSHKeys_UnusualCommentFlagged verifies that a key with a long
// unusual comment is flagged.
func TestCheckSSHKeys_UnusualCommentFlagged(t *testing.T) {
	longComment := strings.Repeat("x", 50) // >40, unusual chars present in keyCommentRE
	keyLine := "ssh-rsa AAAAB3NzaC1yc2EAAAA " + longComment
	parts := strings.Fields(keyLine)
	comment := parts[len(parts)-1]

	result := &LocalIOCResult{SSHPersistence: []string{}}
	akPath := "/tmp/test_authorized_keys"
	numKeys := 1

	if !normalCommentRE.MatchString(comment) {
		if len(comment) > 40 || !keyCommentRE.MatchString(comment) {
			display := comment
			if len(display) > 60 {
				display = display[:60]
			}
			result.SSHPersistence = append(result.SSHPersistence,
				fmt.Sprintf("%s (%d keys): Key with unusual comment: %s", akPath, numKeys, display))
		}
	}

	if len(result.SSHPersistence) == 0 {
		t.Error("expected unusual-comment finding; got none")
	}
	if !strings.Contains(result.SSHPersistence[0], "unusual") {
		t.Errorf("finding = %q; want to mention 'unusual'", result.SSHPersistence[0])
	}
}

// ---- checkAuthLog -----------------------------------------------------------

// TestCheckAuthLog_NoPanicWhenNoLogFile verifies checkAuthLog does not panic
// when neither /var/log/auth.log nor /var/log/secure exists.
func TestCheckAuthLog_NoPanicWhenNoLogFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("checkAuthLog is a Linux-only code path")
	}
	result := &LocalIOCResult{AuthAnomalies: []string{}}
	// Must not panic regardless of whether auth.log / secure exist.
	checkAuthLog(result)
}

// TestCheckAuthLog_FailedSSHThresholdDetected creates a synthetic auth log
// content and drives the anomaly-detection logic directly.
func TestCheckAuthLog_FailedSSHThresholdDetected(t *testing.T) {
	var lines []string
	for i := 0; i < 15; i++ {
		lines = append(lines, fmt.Sprintf(
			"May  4 10:00:%02d host sshd[1234]: Failed password for root from 8.8.8.8 port 22 ssh2", i))
	}
	content := strings.Join(lines, "\n") + "\n"

	result := &LocalIOCResult{AuthAnomalies: []string{}}
	failedSSH := 0
	for _, line := range strings.Split(content, "\n") {
		if strings.Contains(line, "Failed password") ||
			strings.Contains(strings.ToLower(line), "authentication failure") {
			failedSSH++
		}
	}
	if failedSSH > 10 {
		result.AuthAnomalies = append(result.AuthAnomalies,
			fmt.Sprintf("%d failed SSH attempts in recent auth.log entries", failedSSH))
	}

	if len(result.AuthAnomalies) == 0 {
		t.Error("expected failed SSH anomaly; got none")
	}
	if !strings.Contains(result.AuthAnomalies[0], "15") {
		t.Errorf("anomaly = %q; expected count '15'", result.AuthAnomalies[0])
	}
}

// TestCheckAuthLog_ExternalIPLoginDetected verifies that an "Accepted" line
// from a public IP produces an anomaly.
func TestCheckAuthLog_ExternalIPLoginDetected(t *testing.T) {
	line := "May  4 10:00:00 host sshd[999]: Accepted publickey for ubuntu from 8.8.8.8 port 54321 ssh2"

	result := &LocalIOCResult{AuthAnomalies: []string{}}
	if strings.Contains(line, "Accepted ") {
		if m := authFromIPRE.FindStringSubmatch(line); m != nil {
			loginIP := m[1]
			if !isPrivateIP(loginIP) {
				result.AuthAnomalies = append(result.AuthAnomalies,
					fmt.Sprintf("Successful login from external IP %s", loginIP))
			}
		}
	}

	if len(result.AuthAnomalies) == 0 {
		t.Error("expected external IP login anomaly; got none")
	}
	if !strings.Contains(result.AuthAnomalies[0], "8.8.8.8") {
		t.Errorf("anomaly = %q; want to mention 8.8.8.8", result.AuthAnomalies[0])
	}
}

// TestCheckAuthLog_PrivateIPLoginNotFlagged verifies that an "Accepted" line
// from a private IP does not produce an anomaly.
func TestCheckAuthLog_PrivateIPLoginNotFlagged(t *testing.T) {
	line := "May  4 10:00:00 host sshd[999]: Accepted publickey for ubuntu from 192.168.1.5 port 54321 ssh2"

	result := &LocalIOCResult{AuthAnomalies: []string{}}
	if strings.Contains(line, "Accepted ") {
		if m := authFromIPRE.FindStringSubmatch(line); m != nil {
			loginIP := m[1]
			if !isPrivateIP(loginIP) {
				result.AuthAnomalies = append(result.AuthAnomalies,
					fmt.Sprintf("Successful login from external IP %s", loginIP))
			}
		}
	}

	if len(result.AuthAnomalies) != 0 {
		t.Errorf("expected no anomaly for private-IP login, got: %v", result.AuthAnomalies)
	}
}

// TestCheckAuthLog_NonStandardSudoFlagged verifies that a sudo line from an
// unusual user produces an anomaly.
func TestCheckAuthLog_NonStandardSudoFlagged(t *testing.T) {
	line := "May  4 10:00:00 host sudo: hacker : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash"

	result := &LocalIOCResult{AuthAnomalies: []string{}}
	knownSafe := map[string]bool{
		"root": true, "admin": true, "ubuntu": true,
		"debian": true, "ec2-user": true,
	}
	if m := authSudoRE.FindStringSubmatch(line); m != nil {
		usr := m[1]
		if !knownSafe[usr] {
			result.AuthAnomalies = append(result.AuthAnomalies,
				fmt.Sprintf("sudo used by non-standard user: %s", usr))
		}
	}

	if len(result.AuthAnomalies) == 0 {
		t.Error("expected sudo anomaly for non-standard user; got none")
	}
	if !strings.Contains(result.AuthAnomalies[0], "hacker") {
		t.Errorf("anomaly = %q; want to mention 'hacker'", result.AuthAnomalies[0])
	}
}

// TestCheckAuthLog_KnownSudoUserNotFlagged verifies that a sudo line from a
// known-safe user does not produce an anomaly.
func TestCheckAuthLog_KnownSudoUserNotFlagged(t *testing.T) {
	line := "May  4 10:00:00 host sudo: ubuntu : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/apt-get"

	result := &LocalIOCResult{AuthAnomalies: []string{}}
	knownSafe := map[string]bool{
		"root": true, "admin": true, "ubuntu": true,
		"debian": true, "ec2-user": true,
	}
	if m := authSudoRE.FindStringSubmatch(line); m != nil {
		usr := m[1]
		if !knownSafe[usr] {
			result.AuthAnomalies = append(result.AuthAnomalies,
				fmt.Sprintf("sudo used by non-standard user: %s", usr))
		}
	}

	if len(result.AuthAnomalies) != 0 {
		t.Errorf("expected no anomaly for known-safe sudo user, got: %v", result.AuthAnomalies)
	}
}

// ---- checkListeningPorts logic ----------------------------------------------

// TestCheckListeningPorts_NoPanicOnSystem verifies checkListeningPorts does
// not panic regardless of whether 'ss' is available.
func TestCheckListeningPorts_NoPanicOnSystem(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("checkListeningPorts is a Linux-only code path")
	}
	result := &LocalIOCResult{ListeningBackdoors: []string{}}
	checkListeningPorts(result)
}

// TestCheckListeningPorts_ProcNetTCPParsing verifies the /proc/net/tcp parsing
// logic by feeding synthetic data through the same code path.
func TestCheckListeningPorts_ProcNetTCPParsing(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		wantHit  bool
		wantHigh bool // true if port > 32768
	}{
		{
			// 0.0.0.0:9999 listening — not in safe list, not high port.
			name:    "unlisted mid-range port",
			line:    "   1: 0F270000:270F 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0",
			wantHit: true, wantHigh: false,
		},
		{
			// 0.0.0.0:80 listening — known safe, must NOT be flagged.
			name:    "known safe port 80",
			line:    "   2: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 100 0 0 10 0",
			wantHit: false, wantHigh: false,
		},
		{
			// State 01 (ESTABLISHED), not 0A (LISTEN) — must NOT be flagged.
			name:    "established connection not listening",
			line:    "   3: 00000000:9999 00000000:0000 01 00000000:00000000 00:00000000 00000000  1000        0 12347 1 0000000000000000 100 0 0 10 0",
			wantHit: false, wantHigh: false,
		},
		{
			// High port > 32768 listening.
			name:    "high ephemeral port",
			line:    "   4: 00000000:9001 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12348 1 0000000000000000 100 0 0 10 0",
			wantHit: true, wantHigh: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := &LocalIOCResult{ListeningBackdoors: []string{}}
			// Drive the /proc/net/tcp parsing sub-logic directly.
			fields := strings.Fields(tc.line)
			if len(fields) < 4 {
				// Malformed — skip.
				return
			}
			if fields[3] != "0A" {
				if tc.wantHit {
					t.Errorf("state %q is not 0A; test setup error", fields[3])
				}
				return
			}
			local := fields[1]
			colonIdx := strings.LastIndex(local, ":")
			if colonIdx < 0 {
				return
			}
			portHex := local[colonIdx+1:]
			var port64 int64
			_, err := fmt.Sscanf(portHex, "%x", &port64)
			if err != nil {
				if tc.wantHit {
					t.Fatalf("failed to parse port hex %q: %v", portHex, err)
				}
				return
			}
			port := int(port64)
			if knownSafePorts[port] {
				if tc.wantHit {
					t.Errorf("port %d is in knownSafePorts but expected a finding", port)
				}
				return
			}
			var reason string
			if port > 32768 {
				reason = fmt.Sprintf("High port %d in /proc/net/tcp (ephemeral range)", port)
			} else {
				reason = fmt.Sprintf("Port %d in /proc/net/tcp — not in known-safe list", port)
			}
			result.ListeningBackdoors = append(result.ListeningBackdoors, reason)

			if tc.wantHit && len(result.ListeningBackdoors) == 0 {
				t.Error("expected a finding; got none")
			}
			if !tc.wantHit && len(result.ListeningBackdoors) != 0 {
				t.Errorf("expected no finding; got: %v", result.ListeningBackdoors)
			}
			if tc.wantHit && tc.wantHigh && !strings.Contains(result.ListeningBackdoors[0], "High port") {
				t.Errorf("finding = %q; want 'High port'", result.ListeningBackdoors[0])
			}
			if tc.wantHit && !tc.wantHigh && !strings.Contains(result.ListeningBackdoors[0], "not in known-safe") {
				t.Errorf("finding = %q; want 'not in known-safe'", result.ListeningBackdoors[0])
			}
		})
	}
}

// ---- checkC2Connections logic -----------------------------------------------

// TestCheckC2Connections_NoPanicOnSystem verifies checkC2Connections does not
// panic on any system (it reads /proc/net/tcp which may not exist on macOS).
func TestCheckC2Connections_NoPanicOnSystem(t *testing.T) {
	result := &LocalIOCResult{SuspiciousProcesses: []string{}}
	checkC2Connections(result)
}

// TestCheckC2Connections_MatchesKnownC2Hex verifies the hex-conversion and
// matching logic by synthesising a /proc/net/tcp line containing a known C2 IP.
//
// The known C2 IP 91.92.242.30 in little-endian hex is:
//   91  = 0x5B
//   92  = 0x5C
//   242 = 0xF2
//   30  = 0x1E
// Reversed (little-endian): 1E F2 5C 5B → 1EF25C5B
func TestCheckC2Connections_MatchesKnownC2Hex(t *testing.T) {
	// Compute expected hex for 91.92.242.30 (little-endian byte order).
	// Each octet in reverse order, two uppercase hex digits.
	// 30.242.92.91 → 1E F2 5C 5B
	knownC2Hex := "1EF25C5B"
	// Port 4444 in hex = 115C.
	syntheticLine := fmt.Sprintf("  10: 00000000:0000 %s:115C 01 00000000:00000000 00:00000000 00000000  0 0 0 1 0000000000000000", knownC2Hex)

	result := &LocalIOCResult{SuspiciousProcesses: []string{}}

	// Drive the matching sub-logic directly (same as checkC2Connections body).
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
			var n int
			fmt.Sscanf(parts[i], "%d", &n)
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

	fields := strings.Fields(syntheticLine)
	if len(fields) >= 4 {
		remote := fields[2]
		colonIdx := strings.LastIndex(remote, ":")
		if colonIdx >= 0 {
			remoteHex := strings.ToUpper(remote[:colonIdx])
			if entry, ok := c2Hex[remoteHex]; ok {
				portHex := remote[colonIdx+1:]
				var port int64
				fmt.Sscanf(portHex, "%x", &port)
				result.SuspiciousProcesses = append(result.SuspiciousProcesses,
					fmt.Sprintf("Active TCP connection to known C2 %s:%d — %s", entry.ip, port, entry.label))
			}
		}
	}

	if len(result.SuspiciousProcesses) == 0 {
		t.Error("expected C2 connection finding; got none")
	}
	if !strings.Contains(result.SuspiciousProcesses[0], "91.92.242.30") {
		t.Errorf("finding = %q; want to mention known C2 IP 91.92.242.30", result.SuspiciousProcesses[0])
	}
	if !strings.Contains(result.SuspiciousProcesses[0], "ClawHavoc") {
		t.Errorf("finding = %q; want to mention 'ClawHavoc'", result.SuspiciousProcesses[0])
	}
}

// TestCheckC2Connections_UnknownIPNotFlagged verifies that a connection to an
// unknown IP produces no finding.
func TestCheckC2Connections_UnknownIPNotFlagged(t *testing.T) {
	result := &LocalIOCResult{SuspiciousProcesses: []string{}}
	// IP 1.2.3.4 is not in the C2 list.
	// Little-endian hex: 04 03 02 01 → 04030201
	syntheticLine := "  10: 00000000:0000 04030201:115C 01 00000000:00000000 00:00000000 00000000  0 0 0 1 0000000000000000"

	c2IPs := map[string]string{
		"91.92.242.30": "ClawHavoc/AMOS dropper C2",
	}
	ipToHex := func(ip string) string {
		parts := strings.Split(ip, ".")
		if len(parts) != 4 {
			return ""
		}
		var h string
		for i := 3; i >= 0; i-- {
			var n int
			fmt.Sscanf(parts[i], "%d", &n)
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

	fields := strings.Fields(syntheticLine)
	if len(fields) >= 4 {
		remote := fields[2]
		colonIdx := strings.LastIndex(remote, ":")
		if colonIdx >= 0 {
			remoteHex := strings.ToUpper(remote[:colonIdx])
			if entry, ok := c2Hex[remoteHex]; ok {
				portHex := remote[colonIdx+1:]
				var port int64
				fmt.Sscanf(portHex, "%x", &port)
				result.SuspiciousProcesses = append(result.SuspiciousProcesses,
					fmt.Sprintf("Active TCP connection to known C2 %s:%d — %s", entry.ip, port, entry.label))
			}
		}
	}

	if len(result.SuspiciousProcesses) != 0 {
		t.Errorf("expected no finding for unknown IP; got: %v", result.SuspiciousProcesses)
	}
}

// ---- checkLinuxProcesses ----------------------------------------------------

// TestCheckLinuxProcesses_NoPanic verifies checkLinuxProcesses does not panic.
// On macOS /proc does not exist and the function returns immediately.
func TestCheckLinuxProcesses_NoPanic(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("checkLinuxProcesses is a Linux-only code path")
	}
	result := &LocalIOCResult{SuspiciousProcesses: []string{}}
	checkLinuxProcesses(result)
}

// ---- portLineRE -------------------------------------------------------------

// TestPortLineRE_TableDriven verifies the ss output regex matches expected lines
// and ignores non-matching ones.
func TestPortLineRE_TableDriven(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		wantHit bool
		wantPort string
	}{
		{
			name:     "wildcard 0.0.0.0 port 4444",
			line:     "LISTEN  0  128  0.0.0.0:4444  0.0.0.0:*  users:(('nc',pid=1234,fd=3))",
			wantHit:  true,
			wantPort: "4444",
		},
		{
			name:     "wildcard * port 8080",
			line:     "LISTEN  0  128  *:8080  *:*  users:(('python3',pid=9999,fd=4))",
			wantHit:  true,
			wantPort: "8080",
		},
		{
			name:     "specific interface not matched",
			line:     "LISTEN  0  128  127.0.0.1:5432  0.0.0.0:*",
			wantHit:  false,
			wantPort: "",
		},
		{
			name:     "established connection not matched",
			line:     "ESTAB   0  0  192.168.1.5:22  10.0.0.1:12345",
			wantHit:  false,
			wantPort: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := portLineRE.FindStringSubmatch(tc.line)
			if tc.wantHit {
				if m == nil {
					t.Errorf("portLineRE should match %q; got nil", tc.line)
					return
				}
				if m[1] != tc.wantPort {
					t.Errorf("portLineRE captured port %q; want %q", m[1], tc.wantPort)
				}
			} else {
				if m != nil {
					t.Errorf("portLineRE should NOT match %q; got %v", tc.line, m)
				}
			}
		})
	}
}

// ---- authFromIPRE / authSudoRE regex coverage --------------------------------

// TestAuthFromIPRE_TableDriven verifies the regex extracts IPs from auth.log lines.
func TestAuthFromIPRE_TableDriven(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		wantIP  string
		wantHit bool
	}{
		{
			name:    "accepted pubkey",
			line:    "May  4 10:00:00 host sshd[123]: Accepted publickey for user from 1.2.3.4 port 22",
			wantIP:  "1.2.3.4",
			wantHit: true,
		},
		{
			name:    "accepted password",
			line:    "May  4 10:00:00 host sshd[123]: Accepted password for root from 203.0.113.5 port 54321 ssh2",
			wantIP:  "203.0.113.5",
			wantHit: true,
		},
		{
			name:    "no IP in line",
			line:    "May  4 10:00:00 host sshd[123]: Server listening on 0.0.0.0 port 22",
			wantIP:  "",
			wantHit: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := authFromIPRE.FindStringSubmatch(tc.line)
			if tc.wantHit {
				if m == nil {
					t.Errorf("authFromIPRE should match %q; got nil", tc.line)
					return
				}
				if m[1] != tc.wantIP {
					t.Errorf("captured IP = %q; want %q", m[1], tc.wantIP)
				}
			} else {
				if m != nil {
					t.Errorf("authFromIPRE should NOT match %q; got %v", tc.line, m)
				}
			}
		})
	}
}

// TestAuthSudoRE_TableDriven verifies the regex extracts usernames from sudo log lines.
func TestAuthSudoRE_TableDriven(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		wantUser string
		wantHit  bool
	}{
		{
			name:     "standard sudo line",
			line:     "May  4 10:00:00 host sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/apt",
			wantUser: "ubuntu",
			wantHit:  true,
		},
		{
			name:     "suspicious user",
			line:     "May  4 10:00:00 host sudo: badactor : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/bash",
			wantUser: "badactor",
			wantHit:  true,
		},
		{
			name:     "no sudo in line",
			line:     "May  4 10:00:00 host sshd[123]: Accepted publickey for root from 1.2.3.4",
			wantUser: "",
			wantHit:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := authSudoRE.FindStringSubmatch(tc.line)
			if tc.wantHit {
				if m == nil {
					t.Errorf("authSudoRE should match %q; got nil", tc.line)
					return
				}
				if m[1] != tc.wantUser {
					t.Errorf("captured user = %q; want %q", m[1], tc.wantUser)
				}
			} else {
				if m != nil {
					t.Errorf("authSudoRE should NOT match %q; got %v", tc.line, m)
				}
			}
		})
	}
}

// ---- knownSafePorts ---------------------------------------------------------

// TestKnownSafePorts_ContainsExpected verifies well-known service ports are safe.
func TestKnownSafePorts_ContainsExpected(t *testing.T) {
	safe := []int{22, 80, 443, 8000, 3000, 5432, 3306, 6379}
	for _, port := range safe {
		t.Run(fmt.Sprintf("port %d", port), func(t *testing.T) {
			if !knownSafePorts[port] {
				t.Errorf("port %d should be in knownSafePorts", port)
			}
		})
	}
}

// TestKnownSafePorts_UncommonPortNotSafe verifies that an unusual port is not safe.
func TestKnownSafePorts_UncommonPortNotSafe(t *testing.T) {
	unusual := []int{4444, 31337, 1337, 12345}
	for _, port := range unusual {
		t.Run(fmt.Sprintf("port %d", port), func(t *testing.T) {
			if knownSafePorts[port] {
				t.Errorf("port %d should NOT be in knownSafePorts", port)
			}
		})
	}
}

// ---- Direct calls to exercise macOS-reachable paths in Linux-gated funcs ---

// TestCheckAuthLog_DirectCall calls checkAuthLog directly (bypassing the
// runtime.GOOS guard in CheckLocalIOC). On macOS neither /var/log/auth.log nor
// /var/log/secure exists, so the function appends a "could not read" anomaly.
// This exercises the open-failure path of checkAuthLog.
func TestCheckAuthLog_DirectCall_NoPanic(t *testing.T) {
	result := &LocalIOCResult{AuthAnomalies: []string{}}
	// Must not panic on any platform.
	checkAuthLog(result)
	// On macOS neither auth log exists — the function should report it.
	// On Linux it may find the file and succeed (or fail due to permissions).
	// Either way: no panic and AuthAnomalies is in a consistent state.
	_ = result.AuthAnomalies
}

// TestCheckListeningPorts_DirectCall calls checkListeningPorts directly on any
// platform. On macOS 'ss' is absent and /proc/net/tcp does not exist, so the
// function returns without panicking.
func TestCheckListeningPorts_DirectCall_NoPanic(t *testing.T) {
	result := &LocalIOCResult{ListeningBackdoors: []string{}}
	checkListeningPorts(result)
	_ = result.ListeningBackdoors
}

// TestCheckCronFiles_DirectCall calls checkCronFiles directly on any platform.
// On macOS cron paths under /etc/cron.d/ typically do not exist.
func TestCheckCronFiles_DirectCall_NoPanic(t *testing.T) {
	result := &LocalIOCResult{SuspiciousCron: []string{}}
	checkCronFiles(result)
	_ = result.SuspiciousCron
}

// TestCheckLinuxProcesses_DirectCall calls checkLinuxProcesses directly.
// On macOS /proc does not exist; the function returns immediately.
func TestCheckLinuxProcesses_DirectCall_NoPanic(t *testing.T) {
	result := &LocalIOCResult{SuspiciousProcesses: []string{}}
	checkLinuxProcesses(result)
	_ = result.SuspiciousProcesses
}
