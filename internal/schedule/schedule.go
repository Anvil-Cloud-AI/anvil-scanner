//go:build darwin || linux

// Package schedule installs and removes the anvil-scanner hourly scheduled job.
// On macOS it uses a launchd LaunchAgent plist; on Linux it edits the user crontab.
package schedule

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	iexec "github.com/Anvil-Cloud-AI/anvil-scanner/internal/exec"
)

const (
	plistLabel  = "com.anvil-scanner.scan"
	cronComment = "# anvil-scanner"
)

// Setup installs the scheduled job for the current platform.
// binaryPath is the absolute path to the anvil-scanner binary.
// dryRun prints what would happen without making changes.
func Setup(binaryPath string, dryRun bool) error {
	if runtime.GOOS == "darwin" {
		return setupMacOS(binaryPath, dryRun)
	}
	return setupLinux(binaryPath, dryRun)
}

// Remove uninstalls the scheduled job for the current platform.
func Remove() error {
	if runtime.GOOS == "darwin" {
		return removeMacOS()
	}
	return removeLinux()
}

// plistPath returns ~/Library/LaunchAgents/com.anvil-scanner.scan.plist.
func plistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", plistLabel+".plist"), nil
}

// buildPlist returns the launchd plist XML for the given binary path.
// Path values are XML-escaped to prevent plist injection (SEC-M05).
func buildPlist(binaryPath string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	logDir := filepath.Join(home, ".anvil-scanner")
	xe := html.EscapeString
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>--no-ai</string>
    </array>
    <key>StartInterval</key>
    <integer>3600</integer>
    <key>RunAtLoad</key>
    <false/>
    <key>StandardOutPath</key>
    <string>%s</string>
    <key>StandardErrorPath</key>
    <string>%s</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin</string>
    </dict>
</dict>
</plist>
`, plistLabel,
		xe(binaryPath),
		xe(filepath.Join(logDir, "anvil-scanner.stdout.log")),
		xe(filepath.Join(logDir, "anvil-scanner.stderr.log")),
	), nil
}

func setupMacOS(binaryPath string, dryRun bool) error {
	pp, err := plistPath()
	if err != nil {
		return err
	}

	content, err := buildPlist(binaryPath)
	if err != nil {
		return err
	}

	if dryRun {
		fmt.Printf("[DRY-RUN] Would write LaunchAgent plist: %s\n", pp)
		fmt.Printf("[DRY-RUN] Would load with: launchctl load %s\n", pp)
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(pp), 0o700); err != nil {
		return fmt.Errorf("creating LaunchAgents dir: %w", err)
	}
	// Ensure log dir exists. plistPath() already succeeds above so
	// UserHomeDir() is unlikely to fail here, but propagate the error
	// rather than silently using an empty home directory.
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("getting home directory for log dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".anvil-scanner"), 0o700); err != nil {
		return fmt.Errorf("creating log dir: %w", err)
	}

	if err := os.WriteFile(pp, []byte(content), 0o600); err != nil {
		return fmt.Errorf("writing plist: %w", err)
	}
	fmt.Printf("LaunchAgent plist written: %s\n", pp)

	res := iexec.Run("launchctl", "load", pp)
	if res.ExitCode == 0 {
		fmt.Println("LaunchAgent loaded (runs hourly)")
	} else {
		fmt.Fprintf(os.Stderr, "Warning: could not load LaunchAgent: %s\n", strings.TrimSpace(res.Stderr))
		fmt.Printf("Load manually: launchctl load %s\n", pp)
	}
	return nil
}

func removeMacOS() error {
	pp, err := plistPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(pp); os.IsNotExist(err) {
		fmt.Println("No scheduled job found.")
		return nil
	}
	if res := iexec.Run("launchctl", "unload", pp); !res.Success() && res.ExitCode != -1 {
		// Exit -1 means launchctl not found; non-zero means the plist wasn't loaded,
		// which is expected if the job was never started. Only warn on unexpected errors.
		if !strings.Contains(res.Stderr, "Could not find specified service") &&
			!strings.Contains(res.Stderr, "No such process") {
			fmt.Fprintf(os.Stderr, "WARNING: launchctl unload: %s\n", strings.TrimSpace(res.Stderr))
		}
	}
	if err := os.Remove(pp); err != nil {
		return fmt.Errorf("removing plist: %w", err)
	}
	fmt.Printf("Scheduled job removed: %s\n", pp)
	return nil
}

// cronEntry returns the crontab line to install.
// The binary path is double-quoted so paths containing spaces are handled
// correctly by cron(8). Single quotes are not used because the path itself
// might contain a single quote (unusual but possible).
func cronEntry(binaryPath string) (string, error) {
	if strings.ContainsAny(binaryPath, "\"\\\n") {
		return "", fmt.Errorf("binary path contains characters unsafe for cron quoting: %s", binaryPath)
	}
	return fmt.Sprintf(`0 * * * * "%s" --no-ai  %s`, binaryPath, cronComment), nil
}

func setupLinux(binaryPath string, dryRun bool) error {
	entry, err := cronEntry(binaryPath)
	if err != nil {
		return err
	}

	if dryRun {
		fmt.Printf("[DRY-RUN] Would add crontab entry: %s\n", entry)
		return nil
	}

	existing := currentCrontab()
	// Remove any old anvil-scanner entry first
	filtered := filterCron(existing)
	filtered = append(filtered, entry)
	newTab := strings.Join(filtered, "\n") + "\n"

	return writeCrontab(newTab)
}

func removeLinux() error {
	existing := currentCrontab()
	filtered := filterCron(existing)
	if len(filtered) == len(existing) {
		fmt.Println("No scheduled job found.")
		return nil
	}
	newTab := strings.Join(filtered, "\n") + "\n"
	if err := writeCrontab(newTab); err != nil {
		return err
	}
	fmt.Println("Scheduled job removed.")
	return nil
}

func currentCrontab() []string {
	res := iexec.Run("crontab", "-l")
	if res.ExitCode != 0 {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(res.Stdout, "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func filterCron(lines []string) []string {
	var out []string
	for _, l := range lines {
		if !strings.Contains(l, cronComment) {
			out = append(out, l)
		}
	}
	return out
}

func writeCrontab(content string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("writeCrontab: cannot determine home dir: %w", err)
	}
	anvilDir := filepath.Join(home, ".anvil-scanner")
	if err := os.MkdirAll(anvilDir, 0o700); err != nil {
		return fmt.Errorf("writeCrontab: creating dir: %w", err)
	}
	tmp, err := os.CreateTemp(anvilDir, "anvil-crontab-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return fmt.Errorf("writing crontab: %w", err)
	}
	tmp.Close()

	res := iexec.Run("crontab", tmp.Name())
	if res.ExitCode != 0 {
		return fmt.Errorf("installing crontab: %s", strings.TrimSpace(res.Stderr))
	}
	return nil
}
