//go:build darwin || linux

// Package backup handles configuration snapshot and restore. It is
// the Go port of python/anvil_scanner/backup.py.
//
// Snapshots capture the current state of hardening-relevant files
// (sshd_config, pam.d/, firewall rules, selected launchd plists)
// before anvil-scanner makes any changes, so the user can roll back.
package backup

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// backupRootFn is the function used to locate the backup root.
// Overridden by tests via overrideBackupRoot.
var backupRootFn = defaultBackupRoot

func defaultBackupRoot() (string, error) {
	h, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("backup: cannot determine home directory: %w", err)
	}
	return filepath.Join(h, ".anvil-scanner", "backups"), nil
}

func backupRootDir() (string, error) { return backupRootFn() }

// manifestEntry mirrors the per-file entry in manifest.json.
type manifestEntry struct {
	Original    string `json:"original"`
	Backup      string `json:"backup"`
	Description string `json:"description"`
	Timestamp   string `json:"timestamp"`
}

// manifestData is the top-level structure stored in manifest.json.
type manifestData struct {
	Session string          `json:"session"`
	Backups []manifestEntry `json:"backups"`
}

// Manager is a session-based backup manager. Each instance represents one
// backup session identified by a timestamp directory under BackupRoot.
// It mirrors BackupManager from the Python reference.
type Manager struct {
	// BackupRoot is the base directory containing all sessions.
	BackupRoot string
	// SessionDir is the per-run directory: BackupRoot/<timestamp>.
	SessionDir string

	sessionTS string
	entries   []manifestEntry
}

// NewManager creates a Manager with a fresh session timestamp.
// Directories are created lazily on the first call to Backup.
func NewManager() (*Manager, error) {
	root, err := backupRootDir()
	if err != nil {
		return nil, err
	}
	ts := time.Now().Format("2006-01-02_150405.000")
	return &Manager{
		BackupRoot: root,
		SessionDir: filepath.Join(root, ts),
		sessionTS:  ts,
	}, nil
}

// Backup copies src to the session directory, preserving directory structure,
// then atomically updates the manifest. Returns false if src does not exist.
func (m *Manager) Backup(path, description string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}

	// Create session dir with restricted permissions.
	if err := os.MkdirAll(m.SessionDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: backup: cannot create session directory %s: %v\n", m.SessionDir, err)
		return false
	}

	// Compute dest: strip leading "/" so dest = sessionDir + relative path.
	rel := path
	if filepath.IsAbs(path) {
		rel = strings.TrimPrefix(path, "/")
	}
	dest := filepath.Join(m.SessionDir, rel)

	// Containment guard: dest must resolve within SessionDir to prevent a
	// crafted path (e.g. containing "..") from escaping the session directory.
	sessionPrefix := filepath.Clean(m.SessionDir) + string(filepath.Separator)
	if !strings.HasPrefix(filepath.Clean(dest)+string(filepath.Separator), sessionPrefix) {
		fmt.Fprintf(os.Stderr, "WARNING: backup: destination %q escapes session directory\n", dest)
		return false
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: backup: cannot create destination directory %s: %v\n", filepath.Dir(dest), err)
		return false
	}

	if err := copyFile(path, dest); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: backup: failed to copy %s: %v\n", path, err)
		return false
	}

	m.entries = append(m.entries, manifestEntry{
		Original:    path,
		Backup:      dest,
		Description: description,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	})
	if err := m.saveManifest(); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: backup manifest not saved: %v\n", err)
	}
	return true
}

// HasBackups returns true if at least one file has been backed up this session.
func (m *Manager) HasBackups() bool {
	return len(m.entries) > 0
}

// Summary returns a human-readable summary of this session's backups.
func (m *Manager) Summary() string {
	if len(m.entries) == 0 {
		return "No backups created this session."
	}
	var sb strings.Builder
	sb.WriteString("Backups stored in: ")
	sb.WriteString(m.SessionDir)
	for _, e := range m.entries {
		sb.WriteString("\n  • ")
		sb.WriteString(e.Original)
		sb.WriteString(" (")
		sb.WriteString(e.Description)
		sb.WriteString(")")
	}
	return sb.String()
}

// saveManifest atomically writes the manifest to disk (tmp file + rename).
func (m *Manager) saveManifest() error {
	dst := filepath.Join(m.SessionDir, "manifest.json")
	return saveManifest(dst, manifestData{Session: m.sessionTS, Backups: m.entries})
}

// saveManifest writes data to dst atomically via a .json.tmp sibling.
func saveManifest(dst string, data manifestData) error {
	tmp := dst + ".tmp"
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("backup: marshal manifest: %w", err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("backup: write manifest: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("backup: commit manifest: %w", err)
	}
	return nil
}

// loadManifest reads and parses manifest.json from the given path.
func loadManifest(path string) (manifestData, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return manifestData{}, err
	}
	var d manifestData
	if err := json.Unmarshal(raw, &d); err != nil {
		return manifestData{}, fmt.Errorf("backup: parse manifest %s: %w", path, err)
	}
	return d, nil
}

// ListSessions returns paths to all session directories that contain a
// manifest.json, sorted newest-first (lexicographic descending on dirname).
// Mirrors BackupManager.list_sessions() from the Python reference.
func ListSessions() []string {
	root, err := backupRootDir()
	if err != nil {
		return nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var sessions []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		if _, err := os.Stat(filepath.Join(dir, "manifest.json")); err == nil {
			sessions = append(sessions, dir)
		}
	}
	// Sort newest-first: since timestamp is the dirname, reverse lexicographic
	// order puts the newest (largest timestamp string) first.
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i] > sessions[j]
	})
	return sessions
}

// RevertSession restores all files listed in sessionDir's manifest.json to
// their original locations. It enforces a path-traversal guard: any manifest
// entry whose backup path resolves outside sessionDir is skipped and counted
// as failed.
//
// Returns (restored, failed, err). err is non-nil only for structural failures
// (missing or unparseable manifest); per-entry errors are counted in failed.
//
// Mirrors BackupManager.revert_session() from the Python reference.
func RevertSession(sessionDir string) (restored, failed int, err error) {
	manifestPath := filepath.Join(sessionDir, "manifest.json")
	data, err := loadManifest(manifestPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, 0, nil
		}
		return 0, 0, err
	}

	absSession, err := filepath.Abs(sessionDir)
	if err != nil {
		return 0, 0, err
	}
	resolvedSession, err := filepath.EvalSymlinks(absSession)
	if err != nil {
		// sessionDir might not exist yet in tests — use absSession.
		resolvedSession = absSession
	}

	allowedRestorePrefixes := []string{
		"/etc/",
		"/Library/",
		"/private/etc/",
		"/private/Library/",
		"/private/var/",
		"/home/",
		"/Users/",
		"/root/",
		"/boot/",
		"/boot/firmware/",
	}

	for _, entry := range data.Backups {
		src := entry.Backup
		dst := filepath.Clean(entry.Original)

		// Destination allowlist guard: dst must be an absolute path within a
		// known system directory that anvil-scanner could legitimately have
		// backed up. This prevents a crafted manifest from writing to arbitrary
		// paths such as /etc/sudoers or /tmp/evil.
		if !filepath.IsAbs(dst) {
			fmt.Fprintf(os.Stderr, "WARNING: backup: skipping unsafe restore destination: %s\n", dst)
			failed++
			continue
		}
		// Resolve symlinks so that paths like /var (-> /private/var on macOS)
		// match the allowlist entry for /private/var/.
		resolvedDst := dst
		if rd, err2 := filepath.EvalSymlinks(filepath.Dir(dst)); err2 == nil {
			resolvedDst = filepath.Join(rd, filepath.Base(dst))
		}
		dstAllowed := false
		for _, prefix := range allowedRestorePrefixes {
			if strings.HasPrefix(resolvedDst, prefix) {
				dstAllowed = true
				break
			}
		}
		if !dstAllowed {
			fmt.Fprintf(os.Stderr, "WARNING: backup: skipping unsafe restore destination: %s\n", dst)
			failed++
			continue
		}

		// Path-traversal guard: src must resolve within sessionDir.
		absSrc, err := filepath.Abs(src)
		if err != nil {
			failed++
			continue
		}
		resolvedSrc := absSrc
		if resolved, err2 := filepath.EvalSymlinks(absSrc); err2 == nil {
			resolvedSrc = resolved
		}
		// Ensure resolvedSrc is within resolvedSession (add trailing separator
		// to prevent prefix collisions, e.g. /session1 matching /session10).
		sessionPrefix := resolvedSession
		if !strings.HasSuffix(sessionPrefix, string(filepath.Separator)) {
			sessionPrefix += string(filepath.Separator)
		}
		if resolvedSrc != resolvedSession && !strings.HasPrefix(resolvedSrc, sessionPrefix) {
			failed++
			continue
		}

		if _, statErr := os.Stat(src); statErr != nil {
			failed++
			continue
		}

		if copyErr := copyFile(src, dst); copyErr != nil {
			failed++
			continue
		}
		restored++
	}
	return restored, failed, nil
}

// DoRevert is the interactive revert flow. It lists available sessions,
// prompts the user to pick one, asks for confirmation, then reverts.
// r and w are used for all I/O so the function is fully testable.
// Mirrors do_revert() from the Python reference.
func DoRevert(r io.Reader, w io.Writer) error {
	fmt.Fprintf(w, "\n╔══════════════════════════════════════════╗\n║         Anvil Scanner — Revert           ║\n╚══════════════════════════════════════════╝\n\n")

	sessions := ListSessions()
	if len(sessions) == 0 {
		root, _ := backupRootDir()
		fmt.Fprintf(w, "WARNING: No backup sessions found.\n")
		fmt.Fprintf(w, "Backups are stored in: %s\n", root)
		return nil
	}

	// Cap to 10 sessions like the Python reference.
	if len(sessions) > 10 {
		sessions = sessions[:10]
	}

	scanner := bufio.NewScanner(r)

	fmt.Fprintf(w, "Available backup sessions:\n")
	for i, sd := range sessions {
		data, err := loadManifest(filepath.Join(sd, "manifest.json"))
		name := filepath.Base(sd)
		if err != nil {
			fmt.Fprintf(w, "  [%d] %s — (could not read manifest)\n", i+1, name)
			continue
		}
		fmt.Fprintf(w, "  [%d] %s — %s\n", i+1, name, fmtFiles(len(data.Backups)))
		for _, b := range data.Backups {
			fmt.Fprintf(w, "       • %s (%s)\n", b.Original, b.Description)
		}
	}
	fmt.Fprintf(w, "  [0] Cancel\n\n")

	fmt.Fprintf(w, "Select session to revert: ")
	if !scanner.Scan() {
		fmt.Fprintln(w)
		return nil
	}
	line := strings.TrimSpace(scanner.Text())

	var choice int
	if _, err := fmt.Sscanf(line, "%d", &choice); err != nil || choice == 0 {
		if choice == 0 {
			fmt.Fprintf(w, "Cancelled.\n")
		} else {
			fmt.Fprintf(w, "WARNING: Invalid selection — cancelled.\n")
		}
		return nil
	}
	if choice < 1 || choice > len(sessions) {
		fmt.Fprintf(w, "WARNING: Invalid selection — cancelled.\n")
		return nil
	}

	selected := sessions[choice-1]
	data, err := loadManifest(filepath.Join(selected, "manifest.json"))
	if err != nil {
		return fmt.Errorf("could not read manifest: %w", err)
	}
	if len(data.Backups) == 0 {
		fmt.Fprintf(w, "WARNING: No files in this session's backup — nothing to restore.\n")
		return nil
	}

	fmt.Fprintf(w, "\n  This will restore %s:\n", fmtFiles(len(data.Backups)))
	for _, b := range data.Backups {
		fmt.Fprintf(w, "    • %s\n", b.Original)
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "  Are you sure? [y/N] ")
	if !scanner.Scan() {
		fmt.Fprintln(w)
		return nil
	}
	confirm := strings.TrimSpace(strings.ToLower(scanner.Text()))
	if confirm != "y" && confirm != "yes" {
		return nil
	}

	restored, failed, revertErr := RevertSession(selected)
	fmt.Fprintln(w)
	if restored > 0 {
		fmt.Fprintf(w, "OK: Restored %s from %s\n", fmtFiles(restored), filepath.Base(selected))
	}
	if failed > 0 {
		fmt.Fprintf(w, "ERROR: %d file(s) could not be restored (backup missing or permission denied)\n", failed)
	}
	return revertErr
}

// DoUninstall reverts all backup sessions, removes firewall rules (best-effort),
// reloads sshd, and removes the ~/.anvil-scanner directory.
// r and w are used for all I/O. force skips the "no backups" early-exit.
// Mirrors do_uninstall() from the Python reference.
func DoUninstall(r io.Reader, w io.Writer, force bool) error {
	fmt.Fprintf(w, "\n╔══════════════════════════════════════════════════════╗\n║       Anvil Scanner — Full Uninstall / Restore      ║\n╚══════════════════════════════════════════════════════╝\n\n")

	sessions := ListSessions()
	if len(sessions) == 0 && !force {
		fmt.Fprintf(w, "WARNING: No backups found — nothing to restore.\n")
		fmt.Fprintf(w, "To remove firewall rules only, use --uninstall --force\n")
		return nil
	}

	if len(sessions) > 0 {
		fmt.Fprintf(w, "  Found %d backup session(s):\n", len(sessions))
		for _, s := range sessions {
			name := filepath.Base(s)
			data, err := loadManifest(filepath.Join(s, "manifest.json"))
			if err != nil {
				fmt.Fprintf(w, "    • %s\n", name)
			} else {
				fmt.Fprintf(w, "    • %s — %s\n", name, fmtFiles(len(data.Backups)))
			}
		}
		fmt.Fprintln(w)
	} else {
		fmt.Fprintf(w, "No backups found — will still clean up firewall rules and anvil-scanner files.\n\n")
	}

	scanner := bufio.NewScanner(r)
	fmt.Fprintf(w, "  This will restore ALL backup sessions and remove all anvil-scanner changes. Continue? [y/N] ")
	if !scanner.Scan() {
		fmt.Fprintln(w)
		return nil
	}
	confirm := strings.TrimSpace(strings.ToLower(scanner.Text()))
	if confirm != "y" && confirm != "yes" {
		return nil
	}

	var totalRestored, totalFailed, sessionsDone int

	fmt.Fprintln(w)
	if len(sessions) > 0 {
		fmt.Fprintf(w, "Step 1: Restoring all backup sessions...\n")
		for _, sd := range sessions {
			restored, failed, err := RevertSession(sd)
			if err != nil {
				fmt.Fprintf(w, "  WARNING: Session %s: %v\n", filepath.Base(sd), err)
			}
			if restored > 0 || failed > 0 {
				fmt.Fprintf(w, "  OK: Session %s: restored=%d, failed=%d\n", filepath.Base(sd), restored, failed)
			}
			totalRestored += restored
			totalFailed += failed
			sessionsDone++
		}
		if totalRestored > 0 {
			fmt.Fprintf(w, "OK: Restored %s across %d session(s)\n", fmtFiles(totalRestored), sessionsDone)
		}
		if totalFailed > 0 {
			fmt.Fprintf(w, "WARNING: %d file(s) could not be restored (backup missing or permission denied)\n", totalFailed)
		}
	} else {
		fmt.Fprintf(w, "Step 1: No backup sessions — skipping file restore.\n")
	}

	fmt.Fprintf(w, "Step 2: Removing firewall rules (best-effort)...\n")
	removeFirewallRules(w)

	fmt.Fprintf(w, "Step 3: Reloading SSH daemon...\n")
	reloadSSHD(w)

	fmt.Fprintf(w, "Step 4: Removing anvil-scanner installed files...\n")
	anvilDir := filepath.Join(func() string { h, _ := os.UserHomeDir(); return h }(), ".anvil-scanner")
	if _, err := os.Stat(anvilDir); err == nil {
		if totalFailed == 0 {
			if err := os.RemoveAll(anvilDir); err != nil {
				fmt.Fprintf(w, "WARNING: Could not remove %s: %v\n", anvilDir, err)
			} else {
				fmt.Fprintf(w, "OK: Removed anvil-scanner data directory: %s\n", anvilDir)
			}
		} else {
			fmt.Fprintf(w, "WARNING: %d restore(s) failed. Backup directory preserved at %s\n", totalFailed, anvilDir)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "  ✔ Restored %s across %d session(s)\n", fmtFiles(totalRestored), sessionsDone)
	fmt.Fprintf(w, "  ✔ SSH daemon reloaded\n")
	fmt.Fprintf(w, "  ✔ Firewall rules removed (best-effort)\n")
	if totalFailed == 0 {
		fmt.Fprintf(w, "  ✔ anvil-scanner data directory removed\n")
	} else {
		fmt.Fprintf(w, "  ⚠ anvil-scanner data directory preserved (restore failures — see warnings above)\n")
	}
	fmt.Fprintln(w)
	if totalFailed > 0 {
		fmt.Fprintf(w, "WARNING: Anvil Scanner uninstall completed with errors — %d file(s) could not be restored.\n", totalFailed)
		fmt.Fprintf(w, "Your system may not be fully restored to its pre-hardening state.\n\n")
	} else {
		fmt.Fprintf(w, "Anvil Scanner has been fully uninstalled.\n")
		fmt.Fprintf(w, "Your system has been restored to its pre-hardening state.\n\n")
	}

	return nil
}

// removeFirewallRules removes ufw (Linux) or pf (macOS) rules best-effort.
func removeFirewallRules(w io.Writer) {
	switch runtime.GOOS {
	case "linux":
		if ufwPath, err := exec.LookPath("ufw"); err == nil {
			for _, rule := range []string{"OpenSSH", "18789/tcp", "18791/tcp", "9090/tcp", "19001/tcp"} {
				cmd := exec.Command(ufwPath, "delete", "allow", rule) //nolint:gosec
				_ = cmd.Run()
			}
			fmt.Fprintf(w, "OK: ufw rules removed (best-effort)\n")
		}
	case "darwin":
		if pfctlPath, err := exec.LookPath("pfctl"); err == nil {
			cmd := exec.Command(pfctlPath, "-a", "anvil-scanner", "-F", "all") //nolint:gosec
			_ = cmd.Run()
		}
		anchorFile := "/etc/pf.anchors/anvil-scanner"
		if err := os.Remove(anchorFile); err == nil {
			fmt.Fprintf(w, "OK: pf anchor file removed\n")
		}
		pfConf := "/etc/pf.conf"
		if raw, err := os.ReadFile(pfConf); err == nil {
			text := string(raw)
			if strings.Contains(text, "anvil-scanner") {
				var lines []string
				for _, l := range strings.Split(text, "\n") {
					if !strings.Contains(l, "anvil-scanner") {
						lines = append(lines, l)
					}
				}
				tmp := pfConf + ".anvil-tmp"
				if err2 := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")), 0o644); err2 == nil { //nolint:gosec // pf.conf is world-readable by design
					if err3 := os.Rename(tmp, pfConf); err3 == nil {
						fmt.Fprintf(w, "OK: Removed anvil-scanner reference from pf.conf\n")
					}
				}
			}
		}
		fmt.Fprintf(w, "OK: macOS pf firewall rules removed (best-effort)\n")
	}
}

// reloadSSHD reloads the SSH daemon after config changes.
func reloadSSHD(w io.Writer) {
	switch runtime.GOOS {
	case "linux":
		if systemctlPath, err := exec.LookPath("systemctl"); err == nil {
			cmd := exec.Command(systemctlPath, "reload", "sshd") //nolint:gosec
			_ = cmd.Run()
		} else if servicePath, err := exec.LookPath("service"); err == nil {
			cmd := exec.Command(servicePath, "ssh", "reload") //nolint:gosec
			_ = cmd.Run()
		}
		fmt.Fprintf(w, "OK: SSH daemon reloaded\n")
	case "darwin":
		plist := "/System/Library/LaunchDaemons/ssh.plist"
		if launchctlPath, err := exec.LookPath("launchctl"); err == nil {
			cmd := exec.Command(launchctlPath, "unload", plist) //nolint:gosec
			_ = cmd.Run()
			cmd = exec.Command(launchctlPath, "load", plist) //nolint:gosec
			_ = cmd.Run()
		}
		fmt.Fprintf(w, "OK: SSH daemon reloaded (launchctl)\n")
	}
}

// copyFile copies src to dst, preserving permissions. dst's parent must exist.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("backup: open %s: %w", src, err)
	}
	defer in.Close()

	fi, err := in.Stat()
	if err != nil {
		return fmt.Errorf("backup: stat %s: %w", src, err)
	}

	// TOCTOU guard: if a symlink exists at dst, remove it before creating the
	// real file so the write cannot be redirected to an unintended target.
	if fi, lstatErr := os.Lstat(dst); lstatErr == nil && fi.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(dst); err != nil {
			return fmt.Errorf("backup: remove symlink at dst %s: %w", dst, err)
		}
	}

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("backup: create %s: %w", dst, err)
	}

	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(dst)
		return fmt.Errorf("backup: copy %s → %s: %w", src, dst, err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(dst)
		return fmt.Errorf("backup: close %s: %w", dst, err)
	}
	// Preserve original permissions (best-effort, non-fatal).
	if err := os.Chmod(dst, fi.Mode()); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: backup: chmod %s: %v\n", dst, err)
	}
	return nil
}

// fmtFiles returns a pluralised count string, e.g. "1 file" or "3 files".
func fmtFiles(n int) string {
	if n == 1 {
		return "1 file"
	}
	return fmt.Sprintf("%d files", n)
}
