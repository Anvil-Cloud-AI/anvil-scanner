// Package report generates HTML and JSON scan reports from hardening check results.
//
// Priority Findings filter:
//
//	status ∈ {FAIL, WARN} AND severity ∈ {critical, high}
//
// Medium severity never promotes regardless of status.
//
// The HTML report includes a sticky subnav, per-section anchors, and an
// IntersectionObserver-based scroll-spy that highlights the active section.
package report

import (
	"encoding/json"
	"os"
	"time"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/container"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/openclaw"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/threat"
)

// Data is all inputs needed to render a scan report.
type Data struct {
	Platform       string
	Timestamp      time.Time
	Checks         []scan.Check
	Analysis       AIAnalysis
	OpenPorts      []string
	PendingUpdates int
	// ExposedOCPorts is the subset of OpenPorts that are well-known OpenClaw
	// ports. It is derived from OpenPorts (which is in the JSON output) and is
	// therefore HTML-only — adding it to jsonReport would be redundant.
	ExposedOCPorts []string
	// SSHDirectives holds PermitRootLogin and PasswordAuthentication from sshd_config.
	// HTML-only: the raw Checks slice already carries SSH finding detail in the JSON.
	SSHDirectives map[string]string
	// RemoteLogin is the macOS Remote Login state (nil = unknown).
	// HTML-only: the MACOS-005 check in Checks carries the same information in JSON.
	RemoteLogin *bool
	// Fail2ban is the Linux fail2ban service state. HTML-only: not included in the
	// JSON report because it is a point-in-time service snapshot, not a check result.
	Fail2ban *Fail2banInfo
	// IsRPi and RPiModel identify Raspberry Pi hardware for the HTML platform label.
	// HTML-only: the platform string in the JSON output is sufficient for consumers.
	IsRPi    bool
	RPiModel string
	// OCChecks are findings from `openclaw security audit --json`, translated to Checks.
	OCChecks []scan.Check
	// OCVulnResult is the bundled-DB vulnerability check for the installed openclaw version.
	OCVulnResult *openclaw.OCVulnResult
	// ThreatResult is the optional threat intelligence scan output.
	ThreatResult *threat.Result
	// ContainerCVEs is the optional container image CVE scan output (grype/trivy).
	// The CONTAINER-* runtime-hardening findings live in Checks; this carries the
	// detailed per-image vulnerability tables for the Containers section.
	ContainerCVEs *container.ImageCVEResult
}

// AIAnalysis holds the result from an AI risk analysis pass.
type AIAnalysis struct {
	RiskScore       *int
	Overview        string
	Risks           []string
	Recommendations []string
	Error           string
	Remediation     string
	Skipped         bool
}

// Fail2banInfo holds the fail2ban service state for Linux reports.
type Fail2banInfo struct {
	Installed bool
	Running   bool
	Jails     []string
}

// WriteHTML renders the report as an HTML file at path with 0o600 permissions.
func WriteHTML(d Data, path string) error {
	content := renderHTML(d)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := f.WriteString(content)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

// WriteJSON renders the report as a JSON file at path with 0o600 permissions.
func WriteJSON(d Data, path string) error {
	data, err := json.MarshalIndent(buildJSONPayload(d), "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

// MarshalJSON renders the report data as JSON bytes.
func MarshalJSON(d Data) ([]byte, error) {
	return json.MarshalIndent(buildJSONPayload(d), "", "  ")
}

type jsonReport struct {
	Platform         string          `json:"platform"`
	Timestamp        string          `json:"timestamp"`
	Checks           []scan.Check    `json:"checks"`
	Summary          jsonSummary     `json:"summary"`
	PriorityFindings []scan.Check    `json:"priority_findings"`
	OpenPorts        []string        `json:"open_ports"`
	PendingUpdates   int             `json:"pending_updates"`
	AI               *jsonAI         `json:"ai_analysis,omitempty"`
	Containers       *jsonContainers `json:"containers,omitempty"`
}

type jsonContainers struct {
	Scanner string               `json:"scanner,omitempty"`
	Skipped bool                 `json:"skipped,omitempty"`
	Images  []jsonContainerImage `json:"images,omitempty"`
}

type jsonContainerImage struct {
	Ref      string `json:"ref"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Unknown  int    `json:"unknown,omitempty"`
	Error    string `json:"error,omitempty"`
}

type jsonSummary struct {
	Total int `json:"total"`
	Pass  int `json:"pass"`
	Fail  int `json:"fail"`
	Warn  int `json:"warn"`
	Skip  int `json:"skip"`
}

type jsonAI struct {
	RiskScore       *int     `json:"risk_score,omitempty"`
	Overview        string   `json:"overview,omitempty"`
	Risks           []string `json:"risks,omitempty"`
	Recommendations []string `json:"recommendations,omitempty"`
	Error           string   `json:"error,omitempty"`
	Skipped         bool     `json:"skipped,omitempty"`
}

func buildJSONPayload(d Data) jsonReport {
	var pass, fail, warn, skip int
	for _, c := range d.Checks {
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

	priority := PriorityFindings(d.Checks)
	if priority == nil {
		priority = []scan.Check{}
	}

	ports := d.OpenPorts
	if ports == nil {
		ports = []string{}
	}

	ts := d.Timestamp.UTC().Format(time.RFC3339)
	if d.Timestamp.IsZero() {
		ts = time.Now().UTC().Format(time.RFC3339)
	}

	r := jsonReport{
		Platform:  d.Platform,
		Timestamp: ts,
		Checks:    d.Checks,
		Summary: jsonSummary{
			Total: len(d.Checks),
			Pass:  pass,
			Fail:  fail,
			Warn:  warn,
			Skip:  skip,
		},
		PriorityFindings: priority,
		OpenPorts:        ports,
		PendingUpdates:   d.PendingUpdates,
	}
	if !d.Analysis.Skipped || d.Analysis.Error != "" {
		r.AI = &jsonAI{
			RiskScore:       d.Analysis.RiskScore,
			Overview:        d.Analysis.Overview,
			Risks:           d.Analysis.Risks,
			Recommendations: d.Analysis.Recommendations,
			Error:           d.Analysis.Error,
			Skipped:         d.Analysis.Skipped,
		}
	}
	if d.ContainerCVEs != nil {
		r.Containers = buildJSONContainers(d.ContainerCVEs)
	}
	return r
}

func buildJSONContainers(c *container.ImageCVEResult) *jsonContainers {
	jc := &jsonContainers{Scanner: c.Scanner, Skipped: c.Skipped}
	for _, s := range c.Scans {
		img := jsonContainerImage{Ref: s.Ref, Error: s.Error}
		for _, f := range s.Findings {
			switch f.Severity {
			case "CRITICAL":
				img.Critical++
			case "HIGH":
				img.High++
			case "MEDIUM":
				img.Medium++
			case "LOW":
				img.Low++
			default:
				img.Unknown++
			}
		}
		jc.Images = append(jc.Images, img)
	}
	return jc
}

// PriorityFindings returns the subset of checks that have an actionable
// status (FAIL or WARN) and high severity (critical or high).
func PriorityFindings(checks []scan.Check) []scan.Check {
	out := make([]scan.Check, 0)
	for _, c := range checks {
		actionable := c.Status == scan.StatusFail || c.Status == scan.StatusWarn
		highSev := c.Severity == scan.SeverityCritical || c.Severity == scan.SeverityHigh
		if actionable && highSev {
			out = append(out, c)
		}
	}
	return out
}
