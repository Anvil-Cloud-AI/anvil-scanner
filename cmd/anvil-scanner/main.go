//go:build darwin || linux

// Command anvil-scanner is the CLI entry point for the Anvil Scanner
// security hardening tool. See docs/adr/0001-go-migration.md for the
// architecture decision record.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/ai"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/backup"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/container"
	iexec "github.com/Anvil-Cloud-AI/anvil-scanner/internal/exec"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/hardening"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/openclaw"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/report"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/schedule"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/secrets"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/threat"
)

// Version is set at build time by goreleaser via -ldflags.
var Version = "0.0.0-dev"

// stringSliceFlag is a flag.Value that accumulates repeated occurrences of a
// string flag (e.g. --scan-image a --scan-image b).
type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }

func (s *stringSliceFlag) Set(v string) error {
	if err := container.ValidateImageRef(v); err != nil {
		return fmt.Errorf("--scan-image: %w", err)
	}
	*s = append(*s, v)
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "anvil-scanner:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("anvil-scanner", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	showVersion := fs.Bool("version", false, "Print version and exit")
	fs.BoolVar(showVersion, "v", false, "Short alias for --version")
	noAI := fs.Bool("no-ai", false, "Skip AI risk analysis")
	noThreatIntel := fs.Bool("no-threat-intel", false, "Skip threat intelligence checks (Shodan, AbuseIPDB, CVE, CISA KEV, local IoC)")
	noOpenClaw := fs.Bool("no-openclaw", false, "Skip OpenClaw security audit")
	noContainerScan := fs.Bool("no-container-scan", false, "Skip container runtime hardening and image CVE scanning")
	var scanImageRefs stringSliceFlag
	fs.Var(&scanImageRefs, "scan-image", "Scan an additional image reference for CVEs (repeatable; e.g. --scan-image alpine:3.19). The scanner pulls registry refs directly — only pass trusted references.")
	jsonOut := fs.Bool("json", false, "Print JSON report to stdout (HTML report also written unless suppressed by --html)")
	htmlPath := fs.String("html", "", "Write HTML report to this path (default: ~/anvil-scanner-reports/)")
	jsonPath := fs.String("json-output", "", "Write JSON report to this path (HTML report also written unless suppressed by --html)")
	doTelemetry := fs.Bool("telemetry", false, "Send anonymized scan summary to Anvil telemetry (opt-in; also enabled by ANVIL_TELEMETRY=1)")
	doSchedule := fs.Bool("schedule", false, "Install hourly scheduled scan (launchd on macOS, crontab on Linux)")
	doUnschedule := fs.Bool("unschedule", false, "Remove the scheduled scan job")
	scheduleDry := fs.Bool("schedule-dry-run", false, "Show what --schedule would install without making changes (implies --schedule)")
	doRevert := fs.Bool("revert", false, "Interactively restore files from a backup session")
	doUninstall := fs.Bool("uninstall", false, "Restore all backup sessions and remove all anvil-scanner changes")
	forceUninstall := fs.Bool("force", false, "With --uninstall: proceed even when no backups are found")
	doInitSecrets := fs.Bool("init-secrets", false, "Encrypt API keys into the secrets container (interactive wizard)")
	encryptSrc := fs.String("encrypt", "", "Encrypt a .env file into the secrets container")
	decryptDest := fs.String("decrypt", "", "Decrypt the secrets container to a .env file")
	rotateBackend := fs.String("rotate-key-backend", "", "Re-encrypt the secrets container under a new backend (keyring|passphrase|file)")
	secretsBackend := fs.String("backend", "", "Key backend for --init-secrets / --encrypt (keyring|passphrase|file)")
	doStoreKeyring := fs.Bool("store-keyring", false, "Copy secrets from the container into individual OS keyring entries")
	doHarden := fs.Bool("harden", false, "Apply auto-fixable hardening remediation for failing checks (prompts for sudo when needed)")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil // --help exits 0
		}
		return err
	}

	// Warn about flags that only make sense with a companion flag.
	if *forceUninstall && !*doUninstall {
		fmt.Fprintln(os.Stderr, "Warning: --force has no effect without --uninstall")
	}
	if *secretsBackend != "" && *encryptSrc == "" && !*doInitSecrets {
		fmt.Fprintln(os.Stderr, "Warning: --backend has no effect without --init-secrets or --encrypt")
	}

	if *showVersion {
		fmt.Println("anvil-scanner", Version)
		return nil
	}

	// Subcommands that don't run a scan — handle before scan starts.
	if *doUnschedule {
		return schedule.Remove()
	}
	if *doSchedule || *scheduleDry {
		bin, err := os.Executable()
		if err != nil {
			return fmt.Errorf("resolving binary path: %w", err)
		}
		return schedule.Setup(bin, *scheduleDry)
	}
	if *doRevert {
		return backup.DoRevert(os.Stdin, os.Stdout)
	}
	if *doUninstall {
		return backup.DoUninstall(os.Stdin, os.Stdout, *forceUninstall)
	}
	if *rotateBackend != "" {
		return secrets.RotateKeyBackend(*rotateBackend)
	}
	if *encryptSrc != "" {
		return secrets.EncryptSecrets(*encryptSrc, *secretsBackend)
	}
	if *decryptDest != "" {
		return secrets.DecryptSecrets(*decryptDest)
	}
	if *doInitSecrets {
		return secrets.InitSecrets("", *secretsBackend, false)
	}
	if *doStoreKeyring {
		return secrets.StoreSecretsKeyring()
	}

	// When --json is set, progress output goes to stderr so stdout is clean JSON.
	progress := os.Stdout
	if *jsonOut {
		progress = os.Stderr
	}

	if os.Getuid() == 0 {
		fmt.Fprintln(os.Stderr, "⚠  WARNING: Running as root.")
		fmt.Fprintln(os.Stderr, "   Most checks do not require root and run correctly as a normal user.")
		sudoUser := os.Getenv("SUDO_USER")
		if sudoUser != "" {
			if matched, _ := regexp.MatchString(`^[a-zA-Z0-9_.\-]{1,64}$`, sudoUser); !matched {
				sudoUser = ""
			}
		}
		if sudoUser != "" {
			fmt.Fprintf(os.Stderr, "   (detected sudo from user: %s — reports will be owned by that user)\n", sudoUser)
		} else {
			fmt.Fprintln(os.Stderr, "   Reports will be written to root's home directory unless you use --html.")
		}
		fmt.Fprintln(os.Stderr)
	}

	fmt.Fprintf(progress, "Anvil Scanner %s — hardening scan\n", Version)
	fmt.Fprintf(progress, "Platform: %s\n\n", scan.Platform())

	// Load stored API keys into os.Environ before AI provider detection.
	secrets.LoadSecrets()

	// AI provider preflight — announce before the scan so the user knows upfront.
	var aiProvider ai.Provider
	var aiProviderName string
	if !*noAI {
		aiProvider, aiProviderName = ai.DetectProvider()
		if aiProvider == ai.ProviderNone {
			fmt.Fprintln(os.Stderr, "ℹ  No AI provider available — AI section will be empty.")
			fmt.Fprintln(os.Stderr, "   • Install Ollama for free local inference, then run: ollama serve")
			fmt.Fprintln(os.Stderr, "   • Or set CLAUDE_KEY, OPENAI_KEY, or GROK_KEY")
			if os.Getuid() == 0 && os.Getenv("SUDO_USER") != "" {
				fmt.Fprintln(os.Stderr, "   ⚠  Running via sudo — shell env vars are stripped by default.")
				fmt.Fprintln(os.Stderr, "      Use: sudo -E anvil-scanner   (preserves your environment)")
				fmt.Fprintln(os.Stderr, "      Or store keys permanently: sudo anvil-scanner --init-secrets")
			}
			fmt.Fprintln(os.Stderr, "   Continuing scan without AI — the report will flag this prominently.")
		} else {
			fmt.Fprintf(progress, "AI analysis will use: %s\n\n", aiProviderName)
		}
	}

	// Hardening checks
	b := scan.NewBuilder(scan.WithClock(func() time.Time { return time.Now().UTC() }))
	scan.RunAllChecksInto(b)
	isRPi, rpiModel := runRPIChecks(b)
	result := b.Build()
	printSummaryTo(progress, result)

	openPorts := scan.GetOpenPorts()
	pendingUpdates := scan.GetPendingUpdates()

	if *doHarden {
		if os.Getuid() != 0 {
			// Re-warm in case the sudo ticket expired during a long scan.
			if err := iexec.WarmSudoCredentials(); err != nil {
				fmt.Fprintln(os.Stderr, "Error: could not obtain sudo credentials for hardening — check your sudo access")
				return nil
			}
		}
		// On macOS, warn when Remote Login state is unknown (MACOS-005 SKIPped).
		// This happens when the scanner runs under sudo — systemsetup requires a
		// non-root admin session. SSH hardening still writes sshd_config, which is
		// harmless if Remote Login is off, but will take effect if it is ever enabled.
		if scan.Platform() == "Darwin" {
			for _, c := range result.Checks {
				if string(c.ID) == "MACOS-005" && c.Status == scan.StatusSkip {
					fmt.Fprintln(progress, "\n⚠  Note: Remote Login (SSH server) state could not be verified on this Mac.")
					fmt.Fprintln(progress, "   SSH config changes will be written to /etc/ssh/sshd_config.")
					fmt.Fprintln(progress, "   They are harmless if Remote Login is disabled, but will take effect if you enable it.")
					fmt.Fprintln(progress, "   Re-run without sudo to detect Remote Login state automatically.")
					break
				}
			}
		}
		fmt.Fprintln(progress, "\nApplying hardening fixes...")
		bkup, err := backup.NewManager()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not create backup manager: %v — skipping hardening\n", err)
		} else {
			hr := hardening.Apply(result.Checks, bkup, scan.Platform(), isRPi)
			printHardeningResult(progress, hr)

			// Re-scan so the report reflects the post-harden state.  Without
			// this the HTML report still shows the original FAIL/WARN findings
			// for items we just fixed, which is confusing.
			fmt.Fprintln(progress, "\nRe-scanning to reflect applied changes...")
			b2 := scan.NewBuilder(scan.WithClock(func() time.Time { return time.Now().UTC() }))
			scan.RunAllChecksInto(b2)
			runRPIChecks(b2)
			result = b2.Build()

			// Print a post-harden summary so the user can see the final state
			// without scrolling up.  Without this, the pre-harden FAIL/WARN
			// findings stay visible above as the most prominent output and the
			// fact that things are now passing is buried in the harden lines.
			fmt.Fprintln(progress, "\nPost-harden state:")
			printSummaryTo(progress, result)
		}
	}

	// Container scanning (on by default unless --no-container-scan). Runs after
	// the harden block so the CONTAINER-* checks survive the post-harden
	// re-scan that rebuilds `result`.
	var containerCVEs *container.ImageCVEResult
	if !*noContainerScan {
		fmt.Fprint(progress, "\nScanning containers...")
		cb := scan.NewBuilder(scan.WithClock(func() time.Time { return time.Now().UTC() }))
		container.RunRuntimeChecks(cb)
		containerCVEs = container.ScanImages(ctx, scanImageRefs)
		container.RunImageCVECheck(cb, containerCVEs)
		containerChecks := cb.Build().Checks
		result.Checks = append(result.Checks, containerChecks...)
		printContainerSummaryTo(progress, containerCVEs, containerChecks)
	}

	// OpenClaw audit (always on unless --no-openclaw)
	var ocChecks []scan.Check
	var ocVulnResult *openclaw.OCVulnResult
	if !*noOpenClaw {
		fmt.Fprint(progress, "\nRunning OpenClaw security audit...")
		ob := scan.NewBuilder(scan.WithClock(func() time.Time { return time.Now().UTC() }))
		openclaw.RunAudit(ob)
		openclaw.RunContainerAudits(ob)
		ocResult := ob.Build()
		ocChecks = ocResult.Checks
		if len(ocChecks) > 0 && ocChecks[0].Status == scan.StatusSkip {
			fmt.Fprintln(progress, " (skipped — openclaw not installed)")
		} else {
			fmt.Fprintf(progress, " %d finding(s)\n", len(ocChecks))
		}
		fmt.Fprint(progress, "Checking OpenClaw for known CVEs...")
		ocVulnResult = openclaw.RunVulnCheck()
		if ocVulnResult == nil {
			fmt.Fprintln(progress, " (skipped — openclaw not installed)")
		} else if ocVulnResult.Error != "" {
			fmt.Fprintln(progress, " (error: "+ocVulnResult.Error+")")
		} else if len(ocVulnResult.Findings) == 0 {
			fmt.Fprintf(progress, " clean (%d advisories checked)\n", ocVulnResult.Checked)
		} else {
			fmt.Fprintf(progress, " %d vulnerabilities found\n", len(ocVulnResult.Findings))
		}
	}

	// Threat intel (on by default; skip with --no-threat-intel)
	var threatResult *threat.Result
	if !*noThreatIntel {
		fmt.Fprintln(progress, "\nRunning threat intelligence scan...")
		tr := threat.Scan(ctx)
		threatResult = &tr
		printThreatSummaryTo(progress, tr)
	}

	// AI analysis — provider was already detected in preflight above.
	var analysis ai.Analysis
	if *noAI {
		analysis = ai.Analysis{Skipped: true}
	} else if aiProvider == ai.ProviderNone {
		analysis = ai.Analysis{
			Error:       "No AI provider available",
			Remediation: "Set CLAUDE_KEY, OPENAI_KEY, or GROK_KEY, or run `ollama serve` locally.",
		}
	} else {
		fmt.Fprintf(progress, "\nRunning AI analysis via %s...\n", aiProviderName)
		sc := buildScanContext(scan.Platform(), openPorts, pendingUpdates, result.Checks, ocChecks, ocVulnResult, threatResult)
		prompt, promptErr := ai.BuildPrompt(sc)
		if promptErr != nil {
			fmt.Fprintf(os.Stderr, "AI prompt error: %s\n", promptErr)
			analysis = ai.Analysis{Error: promptErr.Error()}
		} else {
			analysis = ai.Analyze(ctx, prompt, false, aiProvider)
		}
		if analysis.Error != "" {
			fmt.Fprintf(os.Stderr, "AI analysis error: %s\n", analysis.Error)
		} else if analysis.RiskScore != nil {
			fmt.Fprintf(progress, "AI risk score: %d/10\n", *analysis.RiskScore)
			if analysis.Overview != "" {
				fmt.Fprintf(progress, "Overview: %s\n", analysis.Overview)
			}
		}
	}

	rd := buildReportData(result, ocChecks, ocVulnResult, threatResult, containerCVEs, analysis, scan.Platform(), openPorts, pendingUpdates, isRPi, rpiModel)

	if *jsonOut {
		data, err := report.MarshalJSON(rd)
		if err != nil {
			return fmt.Errorf("json marshal: %w", err)
		}
		fmt.Println(string(data))
		// Continue — --json-output and --html may also be set.
	}

	if *jsonPath != "" {
		if err := report.WriteJSON(rd, *jsonPath); err != nil {
			return fmt.Errorf("writing JSON report: %w", err)
		}
		fmt.Fprintf(progress, "\nJSON report written to: %s\n", *jsonPath)
	}

	euser := effectiveUser()
	runningAsRoot := os.Getuid() == 0
	htmlOut := *htmlPath
	if htmlOut == "" {
		dir := filepath.Join(euser.home, "anvil-scanner-reports")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not create reports dir: %v\n", err)
		} else {
			if runningAsRoot {
				_ = os.Chown(dir, euser.uid, euser.gid)
			}
			ts := time.Now().UTC().Format("2006-01-02T15-04-05Z")
			htmlOut = filepath.Join(dir, fmt.Sprintf("anvil-scanner-%s.html", ts))
		}
	}
	if htmlOut != "" {
		if err := report.WriteHTML(rd, htmlOut); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not write HTML report: %v\n", err)
		} else {
			if runningAsRoot {
				_ = os.Chown(htmlOut, euser.uid, euser.gid)
			}
			fmt.Fprintf(progress, "\nHTML report written to: %s\n", htmlOut)
		}
	}

	if *doTelemetry || isTelemetryEnabled() {
		fmt.Fprintln(progress, "Submitting telemetry...")
		submitTelemetry(rd)
	}

	return nil
}

func printSummaryTo(w io.Writer, result scan.Result) {
	checks := result.Checks
	pass, fail, warn, skip := 0, 0, 0, 0
	for _, c := range checks {
		switch c.Status {
		case scan.StatusPass:
			pass++
		case scan.StatusFail:
			fail++
		case scan.StatusWarn:
			warn++
		case scan.StatusSkip:
			skip++
		}
	}
	fmt.Fprintf(w, "Checks: %d total  ✅ %d passed  ❌ %d failed  ⚠️  %d warnings  ⏭  %d skipped\n",
		len(checks), pass, fail, warn, skip)

	priority := report.PriorityFindings(checks)
	if len(priority) == 0 {
		fmt.Fprintln(w, "✅ No priority findings — system is well-hardened.")
		return
	}
	fmt.Fprintf(w, "\n🔴 Priority Findings (%d):\n", len(priority))
	for _, c := range priority {
		icon := "❌"
		if c.Status == scan.StatusWarn {
			icon = "⚠️ "
		}
		fmt.Fprintf(w, "  %s [%s] %s — %s\n", icon,
			strings.ToUpper(string(c.Severity)),
			string(c.ID), c.Name)
		fmt.Fprintf(w, "     %s\n", c.Detail)
	}
}

func printThreatSummaryTo(w io.Writer, r threat.Result) {
	iocTotal := len(r.LocalIOC.SuspiciousCron) + len(r.LocalIOC.SuspiciousProcesses) +
		len(r.LocalIOC.SuspiciousTempFiles) + len(r.LocalIOC.SSHPersistence) +
		len(r.LocalIOC.ListeningBackdoors) + len(r.LocalIOC.AuthAnomalies)

	if iocTotal > 0 {
		fmt.Fprintf(w, "  ⚠️  %d local IoC indicator(s) found\n", iocTotal)
	} else {
		fmt.Fprintln(w, "  ✅ No local IoC indicators found")
	}
	if len(r.CVE.Findings) > 0 {
		fmt.Fprintf(w, "  ⚠️  %d CVE exposure(s) detected\n", len(r.CVE.Findings))
	} else {
		fmt.Fprintf(w, "  ✅ No CVE exposure (%d packages checked)\n", len(r.CVE.PackagesChecked))
	}
	if len(r.CISAKEV.Matched) > 0 {
		fmt.Fprintf(w, "  🔴 %d CISA KEV match(es) — actively exploited vulnerabilities!\n", len(r.CISAKEV.Matched))
	}
	if !r.Shodan.Skipped && r.Shodan.Error == "" {
		fmt.Fprintf(w, "  🔍 Shodan: %d open port(s), %d CVE(s) flagged\n", len(r.Shodan.Ports), len(r.Shodan.Vulns))
	}
}

func printContainerSummaryTo(w io.Writer, r *container.ImageCVEResult, checks []scan.Check) {
	switch {
	case r == nil:
		fmt.Fprintln(w, " skipped")
	case r.Skipped:
		fmt.Fprintf(w, " image CVE scan skipped (%s)\n", r.SkipReason)
	case len(r.Scans) == 0:
		fmt.Fprintln(w, " no images to scan")
	default:
		crit, high, total := r.SeverityCounts()
		fmt.Fprintf(w, " %d image(s) scanned via %s — %d CVE(s) (%d critical, %d high)\n",
			len(r.Scans), r.Scanner, total, crit, high)
	}

	// Surface any actionable container findings (runtime hardening + the CVE
	// rollup) in the terminal — they are appended to result.Checks after the
	// main summary already printed, so without this they'd be report-only.
	priority := report.PriorityFindings(checks)
	for _, c := range priority {
		icon := "❌"
		if c.Status == scan.StatusWarn {
			icon = "⚠️ "
		}
		fmt.Fprintf(w, "  %s [%s] %s — %s\n", icon,
			strings.ToUpper(string(c.Severity)), string(c.ID), c.Name)
	}
}

func buildReportData(result scan.Result, ocChecks []scan.Check, ocVulnResult *openclaw.OCVulnResult, threatResult *threat.Result, containerCVEs *container.ImageCVEResult, analysis ai.Analysis, platform string, openPorts []string, pendingUpdates int, isRPi bool, rpiModel string) report.Data {
	ra := report.AIAnalysis{
		Overview:        analysis.Overview,
		Risks:           analysis.Risks,
		Recommendations: analysis.Recommendations,
		Error:           analysis.Error,
		Remediation:     analysis.Remediation,
		Skipped:         analysis.Skipped,
	}
	if analysis.RiskScore != nil {
		n := *analysis.RiskScore
		ra.RiskScore = &n
	}

	ts := time.Now().UTC()
	if len(result.Checks) > 0 {
		ts = result.Checks[0].Timestamp
	}

	sshDirs := scan.GetSSHDirectives()
	remoteLogin := remoteLoginState(result.Checks)
	exposedOCPorts := filterExposedOCPorts(openPorts)

	return report.Data{
		Platform:       platform,
		Timestamp:      ts,
		Checks:         result.Checks,
		Analysis:       ra,
		OCChecks:       ocChecks,
		OCVulnResult:   ocVulnResult,
		ThreatResult:   threatResult,
		ContainerCVEs:  containerCVEs,
		OpenPorts:      openPorts,
		PendingUpdates: pendingUpdates,
		SSHDirectives:  sshDirs,
		RemoteLogin:    remoteLogin,
		ExposedOCPorts: exposedOCPorts,
		Fail2ban:       collectFail2ban(),
		IsRPi:          isRPi,
		RPiModel:       rpiModel,
	}
}

// remoteLoginState derives the macOS Remote Login toggle from the MACOS-005
// check result so we don't need a second subprocess call.
func remoteLoginState(checks []scan.Check) *bool {
	for _, c := range checks {
		if string(c.ID) != "MACOS-005" {
			continue
		}
		switch c.Status {
		case scan.StatusPass:
			v := false
			return &v
		case scan.StatusWarn:
			v := true
			return &v
		}
		return nil // SKIP — could not determine
	}
	return nil
}

type userInfo struct {
	home string
	uid  int
	gid  int
}

// effectiveUser returns the invoking user's info even when running under sudo,
// so reports are owned by and placed in the real user's home directory.
// On macOS regular users are not in /etc/passwd, so we fall back to id(1).
func effectiveUser() userInfo {
	if os.Getuid() == 0 {
		sudoUser := os.Getenv("SUDO_USER")
		if sudoUser != "" {
			if matched, _ := regexp.MatchString(`^[a-zA-Z0-9_.\-]{1,64}$`, sudoUser); !matched {
				sudoUser = ""
			}
		}
		if sudoUser != "" {
			if info, err := lookupPasswd(sudoUser); err == nil {
				return info
			}
			// /etc/passwd missing the user (common on macOS) — use os/user.Lookup.
			if info, err := lookupByID(sudoUser); err == nil {
				return info
			}
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return userInfo{home: home, uid: os.Getuid(), gid: os.Getgid()}
}

// lookupPasswd parses /etc/passwd for uid, gid, and home.  Works on Linux;
// on macOS regular users are absent so lookupByID is the fallback.
func lookupPasswd(username string) (userInfo, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return userInfo{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1*1024*1024))
	if err != nil {
		return userInfo{}, fmt.Errorf("reading /etc/passwd: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.SplitN(line, ":", 7)
		if len(fields) < 6 || fields[0] != username {
			continue
		}
		uid, err1 := strconv.Atoi(fields[2])
		gid, err2 := strconv.Atoi(fields[3])
		if err1 != nil || err2 != nil {
			return userInfo{}, fmt.Errorf("malformed passwd entry for %q", username)
		}
		return userInfo{home: fields[5], uid: uid, gid: gid}, nil
	}
	return userInfo{}, fmt.Errorf("user %q not found in /etc/passwd", username)
}

// lookupByID resolves uid, gid, and home via os/user.Lookup, which works on
// macOS and Linux regardless of whether the user appears in /etc/passwd.
// The username must already be validated before this function is called.
func lookupByID(username string) (userInfo, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return userInfo{}, fmt.Errorf("user.Lookup %q: %w", username, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return userInfo{}, fmt.Errorf("user.Lookup %q: non-integer uid %q", username, u.Uid)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return userInfo{}, fmt.Errorf("user.Lookup %q: non-integer gid %q", username, u.Gid)
	}
	home := u.HomeDir
	if home == "" || home == "/var/root" {
		home = filepath.Join("/Users", username) // macOS fallback
	}
	return userInfo{home: home, uid: uid, gid: gid}, nil
}

func printHardeningResult(w io.Writer, hr hardening.Result) {
	for _, a := range hr.Applied {
		fmt.Fprintf(w, "  ✅ [%s] %s — %s\n", a.CheckID, a.Name, a.Detail)
	}
	for _, a := range hr.Failed {
		fmt.Fprintf(w, "  ❌ [%s] %s — %s\n", a.CheckID, a.Name, a.Detail)
	}
	for _, a := range hr.Skipped {
		fmt.Fprintf(w, "  ⏭  [%s] %s — %s\n", a.CheckID, a.Name, a.Detail)
	}
	fmt.Fprintf(w, "Hardening complete: %d applied, %d failed, %d skipped\n",
		len(hr.Applied), len(hr.Failed), len(hr.Skipped))
}

var ocPortSet = map[string]bool{"18789": true, "18791": true, "9090": true, "19001": true}

func filterExposedOCPorts(openPorts []string) []string {
	var exposed []string
	for _, p := range openPorts {
		if ocPortSet[p] {
			exposed = append(exposed, p)
		}
	}
	return exposed
}

// buildScanContext translates live scan types into the flat ai.ScanContext
// so the ai package stays decoupled from scan/openclaw/threat.
func buildScanContext(
	platform string,
	openPorts []string,
	pendingUpdates int,
	checks []scan.Check,
	ocChecks []scan.Check,
	ocVuln *openclaw.OCVulnResult,
	tr *threat.Result,
) ai.ScanContext {
	sc := ai.ScanContext{
		Platform:       platform,
		OpenPorts:      openPorts,
		PendingUpdates: pendingUpdates,
	}

	// System hardening — collect failing/warning checks, cap at 20
	for _, c := range checks {
		if c.Status != scan.StatusFail && c.Status != scan.StatusWarn {
			continue
		}
		detail := c.Detail
		if len(detail) > 120 {
			detail = detail[:117] + "..."
		}
		sc.FailingChecks = append(sc.FailingChecks, ai.CheckSummary{
			ID:       string(c.ID),
			Severity: string(c.Severity),
			Detail:   detail,
		})
		if len(sc.FailingChecks) >= 20 {
			break
		}
	}

	// OpenClaw audit findings
	for _, c := range ocChecks {
		if c.Status == scan.StatusSkip {
			continue
		}
		detail := c.Detail
		if len(detail) > 150 {
			detail = detail[:147] + "..."
		}
		sc.OCFindings = append(sc.OCFindings, ai.CheckSummary{
			ID:       string(c.ID),
			Severity: string(c.Severity),
			Detail:   detail,
		})
	}

	// OpenClaw CVE data
	if ocVuln != nil {
		sc.OCVersion = ocVuln.Version
		for _, f := range ocVuln.Findings {
			sev := strings.ToLower(f.Severity)
			switch sev {
			case "critical", "high":
				sc.OCCVEHigh++
			case "medium":
				sc.OCCVEMedium++
			default:
				sc.OCCVELow++
			}
			if len(sc.OCTopCVEs) < 10 && (sev == "critical" || sev == "high") {
				desc := f.Desc
				if len(desc) > 100 {
					desc = desc[:97] + "..."
				}
				sc.OCTopCVEs = append(sc.OCTopCVEs, ai.CVESummary{
					ID:       f.ID,
					Severity: sev,
					Desc:     desc,
				})
			}
		}
	}

	// Threat intelligence
	if tr != nil && !tr.Skipped {
		for _, p := range tr.Shodan.Ports {
			sc.ShodanPorts = append(sc.ShodanPorts, fmt.Sprintf("%d", p))
		}
		sc.ShodanCVEs = tr.Shodan.Vulns
		sc.ShodanTags = tr.Shodan.Tags
		sc.AbuseScore = tr.AbuseIPDB.AbuseScore
		sc.AbuseHasKey = !tr.AbuseIPDB.Skipped

		allIoC := flatten(
			tr.LocalIOC.SuspiciousCron,
			tr.LocalIOC.SuspiciousProcesses,
			tr.LocalIOC.SuspiciousTempFiles,
			tr.LocalIOC.SSHPersistence,
			tr.LocalIOC.ListeningBackdoors,
			tr.LocalIOC.AuthAnomalies,
		)
		sc.HasIoC = len(allIoC) > 0
		if len(allIoC) > 5 {
			allIoC = allIoC[:5]
		}
		sc.IoCItems = allIoC
	}

	return sc
}

func flatten(slices ...[]string) []string {
	var out []string
	for _, s := range slices {
		out = append(out, s...)
	}
	return out
}
