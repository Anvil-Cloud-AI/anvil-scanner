//go:build windows

// Command anvil-scanner on Windows is a Tier-0 placeholder entry point. The
// full Unix CLI (main.go) is deeply coupled to sudo, the OS keyring, launchd/
// cron scheduling, backup/revert, and /etc-based hardening, none of which have
// Windows implementations yet. This file provides a minimal but coherent
// runnable program: it parses a small set of flags, runs the (placeholder)
// scan, and writes HTML/JSON reports using the shared report package. Real
// Windows hardening checks and the matching CLI surface land in a later phase.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/report"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
)

// Version is set at build time by goreleaser via -ldflags.
var Version = "0.0.0-dev"

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "anvil-scanner:", err)
		os.Exit(1)
	}
}

func run(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("anvil-scanner", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	showVersion := fs.Bool("version", false, "Print version and exit")
	fs.BoolVar(showVersion, "v", false, "Short alias for --version")
	jsonOut := fs.Bool("json", false, "Print JSON report to stdout")
	htmlPath := fs.String("html", "", "Write HTML report to this path (default: %USERPROFILE%\\anvil-scanner-reports\\)")
	jsonPath := fs.String("json-output", "", "Write JSON report to this path")

	// Accepted-and-ignored on Windows so common cross-platform invocations do
	// not error. The features they gate are not yet implemented on Windows.
	_ = fs.Bool("no-ai", false, "Skip AI risk analysis (no effect on Windows yet)")
	_ = fs.Bool("no-threat-intel", false, "Skip threat intelligence checks (no effect on Windows yet)")
	_ = fs.Bool("no-openclaw", false, "Skip OpenClaw security audit (no effect on Windows yet)")
	_ = fs.Bool("no-container-scan", false, "Skip container scanning (no effect on Windows yet)")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil // --help exits 0
		}
		return err
	}

	if *showVersion {
		fmt.Println("anvil-scanner", Version)
		return nil
	}

	progress := os.Stdout
	if *jsonOut {
		progress = os.Stderr
	}

	fmt.Fprintf(progress, "Anvil Scanner %s — hardening scan\n", Version)
	fmt.Fprintf(progress, "Platform: %s\n\n", scan.Platform())
	fmt.Fprintln(progress, "Note: Windows support is a Tier-0 placeholder — no real hardening checks run yet.")

	b := scan.NewBuilder(scan.WithClock(func() time.Time { return time.Now().UTC() }))
	scan.RunAllChecksInto(b)
	result := b.Build()

	rd := buildReportData(result)

	if *jsonOut {
		data, err := report.MarshalJSON(rd)
		if err != nil {
			return fmt.Errorf("json marshal: %w", err)
		}
		fmt.Println(string(data))
	}

	if *jsonPath != "" {
		if err := report.WriteJSON(rd, *jsonPath); err != nil {
			return fmt.Errorf("writing JSON report: %w", err)
		}
		fmt.Fprintf(progress, "\nJSON report written to: %s\n", *jsonPath)
	}

	htmlOut := *htmlPath
	if htmlOut == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		dir := filepath.Join(home, "anvil-scanner-reports")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not create reports dir: %v\n", err)
		} else {
			ts := time.Now().UTC().Format("2006-01-02T15-04-05Z")
			htmlOut = filepath.Join(dir, fmt.Sprintf("anvil-scanner-%s.html", ts))
		}
	}
	if htmlOut != "" {
		if err := report.WriteHTML(rd, htmlOut); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not write HTML report: %v\n", err)
		} else {
			fmt.Fprintf(progress, "\nHTML report written to: %s\n", htmlOut)
		}
	}

	return nil
}

// buildReportData assembles the minimal report.Data the Windows placeholder
// scan produces. Most optional sections (AI, threat intel, OpenClaw, container
// CVEs) are absent until those subsystems gain Windows support.
func buildReportData(result scan.Result) report.Data {
	ts := time.Now().UTC()
	if len(result.Checks) > 0 {
		ts = result.Checks[0].Timestamp
	}
	return report.Data{
		Platform:  scan.Platform(),
		Timestamp: ts,
		Checks:    result.Checks,
		Analysis:  report.AIAnalysis{Skipped: true},
	}
}
