//go:build darwin || linux

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/report"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
)

const telemetryEndpoint = "https://telemetry.anvilcloud.ai/v1/ingest"

type telemetryPayload struct {
	DeploymentID string           `json:"deployment_id"`
	AnvilVersion string           `json:"anvil_version"`
	Platform     string           `json:"platform"`
	Timestamp    string           `json:"timestamp"`
	Scan         telemetryScan    `json:"scan"`
	IOC          telemetryIOC     `json:"ioc"`
	KEVMatches   int              `json:"kev_matches"`
}

type telemetryScan struct {
	Summary telemetrySummary `json:"summary"`
}

type telemetrySummary struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
	Warn int `json:"warn"`
	Skip int `json:"skip"`
}

type telemetryIOC struct {
	SuspiciousProcesses int `json:"suspicious_processes"`
	SuspiciousTempFiles int `json:"suspicious_temp_files"`
	ListeningBackdoors  int `json:"listening_backdoors"`
	SSHPersistence      int `json:"ssh_persistence"`
	AuthAnomalies       int `json:"auth_anomalies"`
}

// getDeploymentID returns a persistent UUID for this installation,
// creating it on first run at ~/.anvil-scanner/deployment_id.
func getDeploymentID() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "unknown"
	}
	dir := filepath.Join(home, ".anvil-scanner")
	idFile := filepath.Join(dir, "deployment_id")

	if data, err := os.ReadFile(idFile); err == nil {
		if id := string(data); id != "" {
			return id
		}
	}

	id := generateUUID()
	_ = os.MkdirAll(dir, 0o700)
	_ = os.WriteFile(idFile, []byte(id), 0o600)
	return id
}

// generateUUID builds a UUID v4 from /dev/urandom bytes.
func generateUUID() string {
	f, err := os.Open("/dev/urandom")
	if err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	defer f.Close()
	b := make([]byte, 16)
	if _, err := f.Read(b); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func buildTelemetryPayload(rd report.Data) telemetryPayload {
	var pass, fail, warn, skip int
	for _, c := range rd.Checks {
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

	ioc := telemetryIOC{}
	kevMatches := 0
	if rd.ThreatResult != nil {
		tr := rd.ThreatResult
		ioc = telemetryIOC{
			SuspiciousProcesses: len(tr.LocalIOC.SuspiciousProcesses),
			SuspiciousTempFiles: len(tr.LocalIOC.SuspiciousTempFiles),
			ListeningBackdoors:  len(tr.LocalIOC.ListeningBackdoors),
			SSHPersistence:      len(tr.LocalIOC.SSHPersistence),
			AuthAnomalies:       len(tr.LocalIOC.AuthAnomalies),
		}
		kevMatches = len(tr.CISAKEV.Matched)
	}

	return telemetryPayload{
		DeploymentID: getDeploymentID(),
		AnvilVersion: Version,
		Platform:     rd.Platform,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Scan: telemetryScan{
			Summary: telemetrySummary{Pass: pass, Fail: fail, Warn: warn, Skip: skip},
		},
		IOC:        ioc,
		KEVMatches: kevMatches,
	}
}

// submitTelemetry fires an anonymized payload to the telemetry endpoint.
// Runs synchronously but must not surface errors — telemetry never affects scan outcome.
func submitTelemetry(rd report.Data) {
	payload := buildTelemetryPayload(rd)
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	req, err := http.NewRequest("POST", telemetryEndpoint, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "anvil-scanner/"+Version)
	req.Header.Set("X-Deployment-ID", payload.DeploymentID)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// isTelemetryEnabled returns true when ANVIL_TELEMETRY=1 env var is set.
func isTelemetryEnabled() bool {
	return os.Getenv("ANVIL_TELEMETRY") == "1"
}
