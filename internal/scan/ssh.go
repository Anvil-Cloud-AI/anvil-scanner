package scan

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/exec"
)

// sshdConfigPath is the canonical location on both macOS and Linux.
const sshdConfigPath = "/etc/ssh/sshd_config"

// weakKEX lists DH groups deprecated by NIST / RFC 8270.
var weakKEX = map[string]bool{
	"diffie-hellman-group1-sha1":  true,
	"diffie-hellman-group14-sha1": true,
}

// weakCiphers lists CBC-mode ciphers and legacy stream ciphers.
var weakCiphers = map[string]bool{
	"3des-cbc":    true,
	"aes128-cbc":  true,
	"aes192-cbc":  true,
	"aes256-cbc":  true,
}

// weakMACPrefixes lists HMAC prefixes that are not ETM-mode.
// An algorithm is weak when it starts with one of these prefixes
// AND does not contain "etm" in its name.
var weakMACPrefixes = []string{"hmac-md5", "hmac-sha1", "umac-64"}

// MacOSRemoteLoginEnabled probes the macOS Remote Login toggle via
// `systemsetup -getremotelogin`. Returns nil when the state cannot
// be determined (no systemsetup, permission denied, unexpected output,
// or non-macOS). Callers on Linux should not call this — it will
// always return nil.
func MacOSRemoteLoginEnabled() *bool {
	res := exec.Run("systemsetup", "-getremotelogin")
	if !res.Success() {
		return nil
	}
	lower := strings.ToLower(strings.TrimSpace(res.Stdout))
	t, f := true, false
	if strings.Contains(lower, " on") || strings.HasSuffix(lower, ": on") {
		return &t
	}
	if strings.Contains(lower, " off") || strings.HasSuffix(lower, ": off") {
		return &f
	}
	return nil
}

// SSHEnabled returns true when SSH checks should run. The only case
// where it returns false is macOS with Remote Login explicitly off —
// we skip the entire SSH section rather than emit a wall of WARN/SKIP
// rows from a sshd that isn't running.
//
// remoteLoginEnabled is the result of MacOSRemoteLoginEnabled(); pass
// nil on Linux (SSH is always enabled there) or when the probe failed.
//
// Behavioral contract: when Remote Login is explicitly disabled on macOS,
// all SSH checks are skipped rather than run against a non-running sshd.
func SSHEnabled(platform string, remoteLoginEnabled *bool) bool {
	if platform != "Darwin" {
		return true
	}
	// Only skip when we are *certain* SSH is off. Unknown ⇒ keep running
	// checks (conservative — better to produce noise than to silently miss
	// a mis-configured sshd).
	return remoteLoginEnabled == nil || *remoteLoginEnabled
}

// GetSSHDirectives returns a case-folded directive→value map for the
// SSH Configuration table in the report.
//
// It prefers `sshd -T` output (when available) because it reflects the
// *effective* configuration after processing all Include directives and
// drop-in files (the common situation on modern Ubuntu/Debian). This makes
// the report accurate even when settings live in /etc/ssh/sshd_config.d/.
//
// Falls back to parsing /etc/ssh/sshd_config directly if `sshd -T` cannot
// be run (older systems, macOS without sshd in PATH, permission issues, etc.).
func GetSSHDirectives() map[string]string {
	if cfg := getEffectiveSSHDirectivesViaSSHDMinusT(); cfg != nil {
		return cfg
	}
	return parseSshdConfig()
}

// getEffectiveSSHDirectivesViaSSHDMinusT attempts to run `sshd -T` (non-elevated,
// then elevated) to obtain the true runtime configuration. Returns nil if it
// cannot be obtained (caller should fall back).
//
// It tries common full paths because on many Linux distributions (especially
// Ubuntu/Debian) `sshd` lives in /usr/sbin which is often not in a normal
// user's PATH.
func getEffectiveSSHDirectivesViaSSHDMinusT() map[string]string {
	candidates := []string{"sshd", "/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"}

	for _, bin := range candidates {
		// Try non-elevated first.
		res := exec.Run(bin, "-T")
		if res.Success() && strings.TrimSpace(res.Stdout) != "" {
			return parseSSHDMinusTOutput(res.Stdout)
		}

		// Then try with sudo.
		res = exec.RunElevated(bin, "-T")
		if res.Success() && strings.TrimSpace(res.Stdout) != "" {
			return parseSSHDMinusTOutput(res.Stdout)
		}
	}

	return nil
}

// parseSSHDMinusTOutput turns the stdout of `sshd -T` into a directive map.
func parseSSHDMinusTOutput(output string) map[string]string {
	result := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexAny(line, " \t")
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		val := strings.TrimSpace(line[idx+1:])
		if key != "" {
			result[key] = val
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// parseSshdConfig is the fallback parser that reads only /etc/ssh/sshd_config
// directly. It is used when `sshd -T` cannot be executed.
//
// It detects Include directives and Match blocks and records warnings in
// "_include" and "_match" keys (used by the report renderer).
func parseSshdConfig() map[string]string {
	result := map[string]string{}

	data, err := os.ReadFile(sshdConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			result["_error"] = "sshd_config not found"
			return result
		}
		if os.IsPermission(err) {
			// Retry with sudo so non-root runs can still inspect the config.
			elevated, elevErr := exec.ReadFileElevated(sshdConfigPath)
			if elevErr != nil {
				result["_error"] = "Permission denied reading sshd_config — re-run with sudo"
				return result
			}
			data = elevated
		} else {
			result["_error"] = fmt.Sprintf("read error: %v", err)
			return result
		}
	}

	hasIncludes := false
	inMatchBlock := false
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// sshd_config allows space or tab as the separator between keyword and value.
		// SplitN on a single space would miss tab-separated directives.
		idx := strings.IndexAny(line, " \t")
		if idx <= 0 {
			// Single-token line (e.g. bare "Match") — treat as a Match keyword.
			if strings.EqualFold(line, "match") {
				result["_match"] = "sshd_config contains Match blocks — some directives may be scoped to specific sessions and not apply globally"
				inMatchBlock = true
			}
			// Otherwise skip malformed lines, but don't reset inMatchBlock.
			continue
		}
		key := line[:idx]
		val := strings.TrimSpace(line[idx+1:])
		if strings.EqualFold(key, "Include") {
			hasIncludes = true
			continue
		}
		if strings.EqualFold(key, "Match") {
			result["_match"] = "sshd_config contains Match blocks — some directives may be scoped to specific sessions and not apply globally"
			inMatchBlock = true
			continue
		}
		// Per sshd_config(5), a Match block extends until the next Match keyword
		// or EOF — indentation is not part of the spec. Skip all non-Match lines
		// inside an active Match block regardless of indentation.
		if inMatchBlock {
			continue
		}
		// First-match-wins: sshd uses the first occurrence of a directive.
		k := strings.ToLower(key)
		if _, exists := result[k]; !exists {
			result[k] = val
		}
	}
	if err := scanner.Err(); err != nil {
		result["_error"] = fmt.Sprintf("read error: %v", err)
	}
	if hasIncludes {
		result["_include"] = "sshd_config uses Include directives — some settings may be defined in included files and not shown here"
	}
	return result
}

// directive returns the value of a sshd_config directive (case-insensitive
// key lookup), or empty string if not set. Mirrors _check_ssh_directive().
func directive(cfg map[string]string, key string) string {
	return cfg[strings.ToLower(key)]
}

// parseSSHDSeconds converts an OpenSSH time value to seconds.
// OpenSSH accepts bare integers (seconds) or a numeric value followed by
// a unit suffix: s (seconds), m (minutes), h (hours), d (days), w (weeks).
// Returns the number of seconds and true on success, or 0, false on error.
func parseSSHDSeconds(val string) (int, bool) {
	if len(val) == 0 {
		return 0, false
	}
	multipliers := map[byte]int{
		's': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800,
	}
	last := val[len(val)-1]
	if mult, ok := multipliers[last]; ok {
		n, err := strconv.Atoi(val[:len(val)-1])
		if err != nil || n < 0 {
			return 0, false
		}
		return n * mult, true
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return 0, false
	}
	return n, true
}

// checkSSHInt evaluates a numeric sshd_config directive.
// testFn(value) should return true when the value passes the check.
// passMsgFn / failMsgFn produce the detail string given the parsed int.
// When trimSuffix is true the value is treated as an OpenSSH time value
// (e.g. "30s", "1m", "2h") and parsed via parseSSHDSeconds.
func checkSSHInt(
	b *CheckBuilder,
	cfg map[string]string,
	id, name, key string,
	trimSuffix bool,
	testFn func(int) bool,
	passMsgFn func(int) string,
	failMsgFn func(int) string,
	warnMsg string,
	sev Severity,
) {
	val := directive(cfg, key)
	if val == "" {
		b.Warn(id, name, warnMsg, sev)
		return
	}
	var iv int
	if trimSuffix {
		// Use the full OpenSSH time-unit parser (s/m/h/d/w).
		parsed, ok := parseSSHDSeconds(val)
		if !ok {
			b.Warn(id, name, fmt.Sprintf("%s value not parseable: %s", key, val), sev)
			return
		}
		iv = parsed
	} else {
		var err error
		iv, err = strconv.Atoi(val)
		if err != nil {
			b.Warn(id, name, fmt.Sprintf("%s value not parseable: %s", key, val), sev)
			return
		}
	}
	if testFn(iv) {
		b.Pass(id, name, passMsgFn(iv), sev)
	} else {
		b.Fail(id, name, failMsgFn(iv), sev)
	}
}

// checkSSHBool evaluates a yes/no sshd_config directive.
func checkSSHBool(
	b *CheckBuilder,
	cfg map[string]string,
	id, name, key, expected, passMsg, failMsg, warnMsg string,
	sev Severity,
) {
	val := directive(cfg, key)
	if val == "" {
		b.Warn(id, name, warnMsg, sev)
		return
	}
	if strings.EqualFold(val, expected) {
		b.Pass(id, name, passMsg, sev)
	} else {
		b.Fail(id, name, failMsg, sev)
	}
}

// checkSSHAlgo evaluates a comma-separated algorithm list directive.
func checkSSHAlgo(
	b *CheckBuilder,
	cfg map[string]string,
	id, name, key string,
	isWeak func(string) bool,
	passMsgFn func() string,
	failMsgFn func([]string) string,
	warnMsg string,
	sev Severity,
) {
	val := directive(cfg, key)
	if val == "" {
		b.Warn(id, name, warnMsg, sev)
		return
	}
	var found []string
	for _, algo := range strings.Split(val, ",") {
		a := strings.TrimSpace(algo)
		if isWeak(a) {
			found = append(found, a)
		}
	}
	if len(found) > 0 {
		b.Fail(id, name, failMsgFn(found), sev)
	} else {
		b.Pass(id, name, passMsgFn(), sev)
	}
}

// RunSSHChecks executes all SSH-* checks and adds results to b.
//
// platform should be "Darwin" or "Linux".
// remoteLoginEnabled is the result of MacOSRemoteLoginEnabled(); pass
// nil on Linux or when the probe couldn't determine state.
//
// When ssh is not enabled (macOS, Remote Login explicitly off) the
// function returns immediately without adding any checks — no SKIP
// rows, no traces. The calling report layer already surfaces
// "Remote Login: disabled" in the SSH Configuration section.
func RunSSHChecks(b *CheckBuilder, platform string, remoteLoginEnabled *bool) {
	if !SSHEnabled(platform, remoteLoginEnabled) {
		return
	}

	cfg := parseSshdConfig()

	// SSH-000 — can we read sshd_config at all?
	if errMsg, hasErr := cfg["_error"]; hasErr {
		b.Skip("SSH-000", "sshd_config readable", errMsg, SeverityHigh)
		return // no point running directive checks against an empty map
	}
	if len(cfg) == 0 {
		b.Skip("SSH-000", "sshd_config readable",
			"sshd_config is empty or contains no active directives", SeverityHigh)
		return
	}
	// SSH-000 itself only records a result on failure/skip; if we get here
	// the file is readable and non-empty, so we proceed to directive checks.
	// The Python reference omits a PASS row for SSH-000 in the success path —
	// preserve that: don't add a check here, just proceed.

	// SSH-006 — MaxAuthTries ≤ 4
	checkSSHInt(b, cfg, "SSH-006", "MaxAuthTries ≤ 4", "MaxAuthTries",
		false,
		func(v int) bool { return v <= 4 },
		func(v int) string { return fmt.Sprintf("MaxAuthTries = %d", v) },
		func(v int) string { return fmt.Sprintf("MaxAuthTries = %d (should be ≤ 4)", v) },
		"MaxAuthTries not explicitly set (default is 6, should be ≤ 4)",
		SeverityMedium,
	)

	// SSH-008 — LoginGraceTime 1–60s (0 means unlimited, which is insecure)
	checkSSHInt(b, cfg, "SSH-008", "LoginGraceTime ≤ 60s", "LoginGraceTime",
		true,
		func(v int) bool { return v > 0 && v <= 60 },
		func(v int) string { return fmt.Sprintf("LoginGraceTime = %ds", v) },
		func(v int) string {
			return fmt.Sprintf("LoginGraceTime = %ds (should be between 1 and 60 seconds; 0 means unlimited)", v)
		},
		"LoginGraceTime not set (default is 120, should be ≤ 60)",
		SeverityMedium,
	)

	// SSH-014 — KexAlgorithms (no weak KEX)
	checkSSHAlgo(b, cfg, "SSH-014", "KexAlgorithms (no weak KEX)", "KexAlgorithms",
		func(a string) bool { return weakKEX[a] },
		func() string { return fmt.Sprintf("KexAlgorithms: %s", directive(cfg, "KexAlgorithms")) },
		func(weak []string) string {
			return fmt.Sprintf("Weak KEX algorithms found: %s", strings.Join(weak, ", "))
		},
		"KexAlgorithms not explicitly set — defaults may include weak algorithms. Set explicitly to strong algorithms only.",
		SeverityHigh,
	)

	// SSH-015 — Ciphers (no weak ciphers)
	val := directive(cfg, "Ciphers")
	if val == "" {
		b.Warn("SSH-015", "Ciphers (no weak ciphers)",
			"Ciphers not explicitly set — defaults may include weak CBC ciphers. Set explicitly to AEAD ciphers only.",
			SeverityHigh)
	} else {
		var found []string
		for _, a := range strings.Split(val, ",") {
			a = strings.TrimSpace(a)
			if weakCiphers[a] || strings.HasPrefix(a, "arcfour") {
				found = append(found, a)
			}
		}
		if len(found) > 0 {
			b.Fail("SSH-015", "Ciphers (no weak ciphers)",
				fmt.Sprintf("Weak ciphers found: %s", strings.Join(found, ", ")),
				SeverityHigh)
		} else {
			b.Pass("SSH-015", "Ciphers (no weak ciphers)",
				fmt.Sprintf("Ciphers: %s", val),
				SeverityHigh)
		}
	}

	// SSH-016 — MACs (no weak MACs)
	val = directive(cfg, "MACs")
	if val == "" {
		b.Warn("SSH-016", "MACs (no weak MACs)",
			"MACs not explicitly set — defaults may include weak MACs. Set explicitly to ETM variants only.",
			SeverityHigh)
	} else {
		var found []string
		for _, a := range strings.Split(val, ",") {
			a = strings.TrimSpace(a)
			isWeakPrefix := false
			for _, p := range weakMACPrefixes {
				if strings.HasPrefix(a, p) {
					isWeakPrefix = true
					break
				}
			}
			if isWeakPrefix && !strings.Contains(strings.ToLower(a), "etm") {
				found = append(found, a)
			}
		}
		if len(found) > 0 {
			b.Fail("SSH-016", "MACs (no weak MACs)",
				fmt.Sprintf("Weak MACs found: %s", strings.Join(found, ", ")),
				SeverityHigh)
		} else {
			b.Pass("SSH-016", "MACs (no weak MACs)",
				fmt.Sprintf("MACs: %s", val),
				SeverityHigh)
		}
	}

	// SSH-021 — ClientAliveInterval set (> 0 means idle sessions time out)
	checkSSHInt(b, cfg, "SSH-021", "ClientAliveInterval set", "ClientAliveInterval",
		false,
		func(v int) bool { return v > 0 },
		func(v int) string { return fmt.Sprintf("ClientAliveInterval = %ds", v) },
		func(_ int) string { return "ClientAliveInterval = 0 (disabled)" },
		"ClientAliveInterval not set (idle sessions won't be timed out)",
		SeverityMedium,
	)

	// SSH-023 — X11Forwarding disabled
	checkSSHBool(b, cfg, "SSH-023", "X11Forwarding disabled", "X11Forwarding", "no",
		"X11Forwarding = no",
		fmt.Sprintf("X11Forwarding = %s (should be no)", directive(cfg, "X11Forwarding")),
		"X11Forwarding not set (default may be yes on some distros)",
		SeverityMedium,
	)

	// SSH-024 — AllowTcpForwarding disabled
	checkSSHBool(b, cfg, "SSH-024", "AllowTcpForwarding disabled", "AllowTcpForwarding", "no",
		"AllowTcpForwarding = no",
		fmt.Sprintf("AllowTcpForwarding = %s (should be no)", directive(cfg, "AllowTcpForwarding")),
		"AllowTcpForwarding not set (default is yes)",
		SeverityMedium,
	)

	// SSH-029 — PermitUserEnvironment disabled
	val = directive(cfg, "PermitUserEnvironment")
	if val == "" || strings.EqualFold(val, "no") {
		b.Pass("SSH-029", "PermitUserEnvironment disabled",
			"PermitUserEnvironment not set (default is no)", SeverityHigh)
	} else {
		b.Fail("SSH-029", "PermitUserEnvironment disabled",
			fmt.Sprintf("PermitUserEnvironment = %s (should be no)", val), SeverityHigh)
	}

	// SSH-030 — LogLevel VERBOSE or INFO
	val = directive(cfg, "LogLevel")
	if val == "" || strings.EqualFold(val, "VERBOSE") || strings.EqualFold(val, "INFO") {
		b.Pass("SSH-030", "LogLevel VERBOSE or INFO",
			"LogLevel not set (default is INFO)", SeverityMedium)
	} else {
		b.Fail("SSH-030", "LogLevel VERBOSE or INFO",
			fmt.Sprintf("LogLevel = %s (should be VERBOSE or INFO)", val), SeverityMedium)
	}

	// SSH-041/042/043 — file permission checks (also gated on ssh_enabled,
	// same as directive checks above — they are inside RunSSHChecks which
	// already returns early when !SSHEnabled).

	// SSH-041 — ~/.ssh and authorized_keys permissions
	runSSH041(b)

	// SSH-042 — sshd_config ownership & permissions
	runSSH042(b)

	// SSH-043 — host private key permissions (600)
	runSSH043(b)
}

// runSSH041 checks ~/.ssh (mode 700) and authorized_keys (mode 600)
// for all real user accounts found in /etc/passwd.
func runSSH041(b *CheckBuilder) {
	badPerms, err := checkSSHDirPerms()
	if err != nil {
		b.Skip("SSH-041", "SSH dir/authorized_keys permissions",
			fmt.Sprintf("Could not check: %v", err), SeverityHigh)
		return
	}
	if len(badPerms) > 0 {
		b.Fail("SSH-041", "SSH dir/authorized_keys permissions",
			"Bad permissions: "+strings.Join(badPerms, "; "), SeverityHigh)
	} else {
		b.Pass("SSH-041", "SSH dir/authorized_keys permissions",
			"All ~/.ssh (700) and authorized_keys (600) permissions OK", SeverityHigh)
	}
}

// checkSSHDirPerms enumerates real user home directories from
// /etc/passwd and reports permission violations on .ssh/ and
// authorized_keys. Returns the list of violation strings.
func checkSSHDirPerms() ([]string, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("open /etc/passwd: %w", err)
	}
	defer f.Close()

	var bad []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) < 7 {
			continue
		}
		uid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue // malformed passwd entry
		}
		home := parts[5]
		if !filepath.IsAbs(home) {
			continue
		}
		shell := parts[6]
		minUID := 500
		if runtime.GOOS == "linux" {
			minUID = 1000
		}
		if (uid < minUID && uid != 0) || strings.Contains(shell, "nologin") || strings.Contains(shell, "/false") {
			continue
		}
		if _, err := os.Stat(home); err != nil {
			continue
		}

		sshDir := filepath.Join(home, ".ssh")
		akFile := filepath.Join(sshDir, "authorized_keys")

		if st, err := os.Stat(sshDir); err == nil {
			mode := st.Mode().Perm()
			if mode&0o077 != 0 {
				bad = append(bad, fmt.Sprintf("%s mode %04o (should be 0700)", sshDir, mode))
			}
		}
		if st, err := os.Stat(akFile); err == nil {
			mode := st.Mode().Perm()
			if mode&0o177 != 0 {
				bad = append(bad, fmt.Sprintf("%s mode %04o (should be 0600)", akFile, mode))
			}
		}
	}
	return bad, scanner.Err()
}

// runSSH042 checks /etc/ssh/sshd_config ownership and permissions.
func runSSH042(b *CheckBuilder) {
	st, err := os.Stat(sshdConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			b.Skip("SSH-042", "sshd_config ownership & permissions",
				"sshd_config not found", SeverityHigh)
		} else {
			b.Skip("SSH-042", "sshd_config ownership & permissions",
				fmt.Sprintf("Could not stat: %v", err), SeverityHigh)
		}
		return
	}
	mode := st.Mode().Perm()
	ownerUID := fileOwnerUID(st)

	switch {
	case ownerUID != 0:
		b.Fail("SSH-042", "sshd_config ownership & permissions",
			fmt.Sprintf("sshd_config owned by UID %d (should be root/0)", ownerUID), SeverityHigh)
	case mode != 0o600 && mode != 0o644:
		b.Fail("SSH-042", "sshd_config ownership & permissions",
			fmt.Sprintf("sshd_config mode %04o (should be 0600 or 0644)", mode), SeverityHigh)
	default:
		b.Pass("SSH-042", "sshd_config ownership & permissions",
			fmt.Sprintf("sshd_config: root-owned, mode %04o", mode), SeverityHigh)
	}
}

// runSSH043 checks /etc/ssh/ssh_host_*_key files are mode 0600.
func runSSH043(b *CheckBuilder) {
	matches, err := filepath.Glob("/etc/ssh/ssh_host_*_key")
	if err != nil {
		b.Skip("SSH-043", "Host private key permissions (600)",
			fmt.Sprintf("Could not enumerate host keys: %v", err), SeverityCritical)
		return
	}

	var bad []string
	var skipped []string
	for _, kf := range matches {
		st, err := os.Stat(kf)
		if err != nil {
			skipped = append(skipped, filepath.Base(kf))
			continue
		}
		mode := st.Mode().Perm()
		if mode != 0o600 {
			bad = append(bad, fmt.Sprintf("%s mode %04o", filepath.Base(kf), mode))
		}
	}
	switch {
	case len(bad) > 0:
		b.Fail("SSH-043", "Host private key permissions (600)",
			"Bad permissions: "+strings.Join(bad, "; "), SeverityCritical)
	case len(skipped) > 0:
		b.Warn("SSH-043", "Host private key permissions (600)",
			fmt.Sprintf("Could not verify permissions on %d host key file(s) — re-run with sudo", len(skipped)),
			SeverityCritical)
	default:
		b.Pass("SSH-043", "Host private key permissions (600)",
			"All ssh_host_*_key files have mode 0600", SeverityCritical)
	}
}
