// Package ai provides AI-powered risk analysis from scan results.
// It is the Go port of python/anvil_scanner/ai_analysis.py.
//
// Provider precedence (Ollama-first, 2026-04-19):
//
//  1. AI_PROVIDER env var (explicit, no fallback)
//  2. Ollama reachability probe (500ms) — local-first, no key required
//  3. CLAUDE_KEY → Claude
//  4. OPENAI_KEY → OpenAI
//  5. GROK_KEY   → Grok (xAI)
//  6. None       → loud NO_PROVIDER banner in report
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/safehttp"
)

// Provider identifies an AI provider.
type Provider string

const (
	ProviderOllama  Provider = "ollama"
	ProviderClaude  Provider = "claude"
	ProviderOpenAI  Provider = "openai"
	ProviderGrok    Provider = "grok"
	ProviderNone    Provider = "none"
)

const (
	defaultOllamaURL   = "http://localhost:11434"
	defaultOllamaModel = "llama3"
	defaultClaudeModel = "claude-sonnet-4-6"
	defaultOpenAIModel = "gpt-4o-mini"
	defaultGrokModel   = "grok-3-mini"
	defaultXAIURL      = "https://api.x.ai/v1"
	ollamaProbeTimeout = 500 * time.Millisecond
	providerCallTimeout = 120 * time.Second
	maxResponseBody     = 1 << 20 // 1 MiB
	maxErrorSnippet     = 200
)

// privateCIDRs is initialised once and reused by validateExternalAPIURL.
var privateCIDRs []*net.IPNet

// Analysis holds the result of an AI risk analysis pass.
type Analysis struct {
	Provider        Provider
	RiskScore       *int
	Overview        string
	Risks           []string
	Recommendations []string
	Error           string
	Remediation     string
	Skipped         bool
}

// CheckSummary is a condensed view of one scan check for prompt construction.
type CheckSummary struct {
	ID       string
	Severity string
	Detail   string
}

// CVESummary is a condensed view of one known CVE for prompt construction.
type CVESummary struct {
	ID       string
	Severity string
	Desc     string
}

// ScanContext contains all scan data needed to build a rich AI prompt.
// Main populates this from the live scan result types; the ai package
// does not import scan/openclaw/threat to avoid coupling.
type ScanContext struct {
	Platform       string
	OpenPorts      []string
	PendingUpdates int

	// System hardening — failing/warning checks only, all categories
	FailingChecks []CheckSummary

	// OpenClaw audit findings (from openclaw security audit)
	OCFindings []CheckSummary

	// OpenClaw version and known CVE counts for that version
	OCVersion   string
	OCCVEHigh   int
	OCCVEMedium int
	OCCVELow    int
	OCTopCVEs   []CVESummary // up to 10 high/critical entries

	// Threat intelligence
	ShodanPorts []string
	ShodanCVEs  []string
	ShodanTags  []string
	AbuseScore  int
	AbuseHasKey bool
	HasIoC      bool
	IoCItems    []string // up to 5 notable IoC findings
}

var noProviderRemediation = strings.TrimSpace(`
No AI provider available. To enable AI analysis, either:
  • Install Ollama and start it locally (free, private): https://ollama.com — then run: ollama serve
  • Or set CLAUDE_KEY / OPENAI_KEY / GROK_KEY in your environment.
`)

// DetectProvider implements the Ollama-first provider precedence from ai_analysis.py.
func DetectProvider() (Provider, string) {
	explicit := strings.ToLower(os.Getenv("AI_PROVIDER"))
	switch Provider(explicit) {
	case ProviderOllama:
		return ProviderOllama, "Ollama (local)"
	case ProviderClaude:
		return ProviderClaude, "Claude"
	case ProviderOpenAI:
		return ProviderOpenAI, "OpenAI"
	case ProviderGrok:
		return ProviderGrok, "Grok (xAI)"
	}

	if OllamaReachable() {
		return ProviderOllama, "Ollama (local)"
	}
	if os.Getenv("CLAUDE_KEY") != "" {
		return ProviderClaude, "Claude"
	}
	if os.Getenv("OPENAI_KEY") != "" {
		return ProviderOpenAI, "OpenAI"
	}
	if os.Getenv("GROK_KEY") != "" {
		return ProviderGrok, "Grok (xAI)"
	}
	return ProviderNone, "no provider available"
}

// validateOllamaURL rejects any Ollama URL that is not strictly localhost http.
// This prevents SSRF-style attacks via a malicious OLLAMA_URL environment variable.
func validateOllamaURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid OLLAMA_URL: %w", err)
	}
	if u.Scheme != "http" {
		return fmt.Errorf("OLLAMA_URL scheme must be http, got %q", u.Scheme)
	}
	hostname := u.Hostname()
	switch hostname {
	case "localhost", "127.0.0.1", "::1":
		// allowed
	default:
		return fmt.Errorf("OLLAMA_URL hostname must be localhost, 127.0.0.1, or ::1, got %q", hostname)
	}
	return nil
}

// OllamaReachable returns true if an Ollama server responds at OLLAMA_URL within
// 500ms. Uses /api/tags — the lightest documented Ollama endpoint.
func OllamaReachable() bool {
	ollamaBase := defaultOllamaURL
	if u := os.Getenv("OLLAMA_URL"); u != "" {
		ollamaBase = u
	}
	if err := validateOllamaURL(ollamaBase); err != nil {
		return false
	}
	base := strings.TrimRight(ollamaBase, "/")
	ctx, cancel := context.WithTimeout(context.Background(), ollamaProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/tags", nil)
	if err != nil {
		return false
	}
	probeClient := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		},
	}
	resp, err := probeClient.Do(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// Analyze runs an AI risk analysis for the given prompt using the supplied
// provider (already detected by the caller). Returns a skip result when skip is true.
func Analyze(ctx context.Context, prompt string, skip bool, provider Provider) Analysis {
	if skip {
		return Analysis{Skipped: true}
	}
	if provider == ProviderNone {
		return Analysis{
			Provider:    ProviderNone,
			Error:       "No AI provider available",
			Remediation: noProviderRemediation,
		}
	}

	raw, err := callProvider(ctx, provider, prompt)
	if err != nil {
		return Analysis{Provider: provider, Error: err.Error()}
	}
	return parseResponse(raw, provider)
}

// BuildPrompt constructs a rich, OpenClaw-focused AI prompt from full scan data.
func BuildPrompt(sc ScanContext) (string, error) {
	var b strings.Builder

	b.WriteString("You are a security analyst specialising in AI agent deployments. ")
	b.WriteString("You are reviewing an automated security scan of a live OpenClaw deployment.\n\n")

	b.WriteString("BACKGROUND: OpenClaw is an AI gateway/runtime that connects AI models to powerful tools ")
	b.WriteString("(shell execution, filesystem access, browser control, external APIs). ")
	b.WriteString("Misconfigurations create prompt-injection attack surfaces that can escalate to ")
	b.WriteString("arbitrary command execution or data exfiltration. Many risks are OpenClaw-specific ")
	b.WriteString("and will not appear in generic host hardening scanners.\n\n")

	// Deployment header
	b.WriteString("── DEPLOYMENT ─────────────────────────────────────────────────────────────\n")
	b.WriteString(fmt.Sprintf("Platform:        %s\n", sc.Platform))
	if sc.OCVersion != "" {
		b.WriteString(fmt.Sprintf("OpenClaw:        %s\n", sc.OCVersion))
	}
	b.WriteString(fmt.Sprintf("Open ports:      %d  %s\n", len(sc.OpenPorts), joinOrNone(sc.OpenPorts)))
	b.WriteString(fmt.Sprintf("Pending updates: %d\n\n", sc.PendingUpdates))

	// OpenClaw audit findings
	if len(sc.OCFindings) > 0 {
		b.WriteString(fmt.Sprintf("── OPENCLAW AUDIT (%d findings) ────────────────────────────────────────────\n", len(sc.OCFindings)))
		for _, f := range sc.OCFindings {
			b.WriteString(fmt.Sprintf("[%-8s] %-40s %s\n", strings.ToUpper(f.Severity), f.ID, f.Detail))
		}
		b.WriteString("\n")
	} else {
		b.WriteString("── OPENCLAW AUDIT ──────────────────────────────────────────────────────────\n")
		b.WriteString("No OpenClaw audit findings (openclaw not installed or audit skipped).\n\n")
	}

	// Known CVEs for this version
	if sc.OCVersion != "" && (sc.OCCVEHigh+sc.OCCVEMedium+sc.OCCVELow > 0) {
		b.WriteString(fmt.Sprintf("── KNOWN CVEs FOR INSTALLED VERSION (%dH / %dM / %dL) ────────────────────────\n",
			sc.OCCVEHigh, sc.OCCVEMedium, sc.OCCVELow))
		for _, cve := range sc.OCTopCVEs {
			b.WriteString(fmt.Sprintf("[%-8s] %-20s %s\n", strings.ToUpper(cve.Severity), cve.ID, cve.Desc))
		}
		if len(sc.OCTopCVEs) < sc.OCCVEHigh+sc.OCCVEMedium+sc.OCCVELow {
			b.WriteString(fmt.Sprintf("... and %d additional medium/low advisories (upgrade resolves all)\n",
				sc.OCCVEHigh+sc.OCCVEMedium+sc.OCCVELow-len(sc.OCTopCVEs)))
		}
		b.WriteString("\n")
	} else if sc.OCVersion != "" {
		b.WriteString("── KNOWN CVEs ──────────────────────────────────────────────────────────────\n")
		b.WriteString("No known CVEs for this OpenClaw version.\n\n")
	}

	// System hardening gaps
	if len(sc.FailingChecks) > 0 {
		b.WriteString(fmt.Sprintf("── SYSTEM HARDENING GAPS (%d failing/warning checks) ───────────────────────\n", len(sc.FailingChecks)))
		for _, f := range sc.FailingChecks {
			b.WriteString(fmt.Sprintf("[%-8s] %-12s %s\n", strings.ToUpper(f.Severity), f.ID, f.Detail))
		}
		b.WriteString("\n")
	} else {
		b.WriteString("── SYSTEM HARDENING ────────────────────────────────────────────────────────\n")
		b.WriteString("All system hardening checks passed.\n\n")
	}

	// Threat intelligence
	b.WriteString("── THREAT INTELLIGENCE ─────────────────────────────────────────────────────\n")
	if len(sc.ShodanCVEs) > 0 {
		b.WriteString(fmt.Sprintf("Shodan CVEs for public IP: %s\n", strings.Join(sc.ShodanCVEs, ", ")))
	} else if len(sc.ShodanPorts) > 0 {
		b.WriteString(fmt.Sprintf("Shodan open ports: %s  (no CVEs flagged)\n", strings.Join(sc.ShodanPorts, ", ")))
	} else {
		b.WriteString("Shodan: no findings for public IP\n")
	}
	if sc.AbuseHasKey {
		b.WriteString(fmt.Sprintf("AbuseIPDB score: %d/100\n", sc.AbuseScore))
	} else {
		b.WriteString("AbuseIPDB: skipped (no API key)\n")
	}
	if sc.HasIoC {
		b.WriteString("Local IoC: FINDINGS DETECTED\n")
		for _, item := range sc.IoCItems {
			b.WriteString(fmt.Sprintf("  • %s\n", item))
		}
	} else {
		b.WriteString("Local IoC: clean\n")
	}
	b.WriteString("\n")

	// Instructions
	b.WriteString("── ANALYSIS REQUEST ────────────────────────────────────────────────────────\n")
	b.WriteString("Analyse this specific deployment. Prioritise OpenClaw-specific risks over generic host hardening advice.\n")
	b.WriteString("Focus on:\n")
	b.WriteString("1. Configuration risks specific to this OpenClaw setup (channel policies, tool permissions, trust boundaries)\n")
	b.WriteString("2. Exploit potential of the outstanding CVEs given this observed configuration\n")
	b.WriteString("3. How system hardening gaps increase OpenClaw's attack surface\n")
	b.WriteString("\nRespond ONLY with a valid JSON object — no markdown fencing, no explanation outside the JSON:\n")
	b.WriteString("{\n")
	b.WriteString(`  "risk_score": <integer 1-10, where 10 is critical>,` + "\n")
	b.WriteString(`  "overview": "<2-4 sentences on OpenClaw deployment risk — not generic host hardening>",` + "\n")
	b.WriteString(`  "risks": ["<specific risk>", ...],` + "\n")
	b.WriteString(`  "recommendations": ["<prioritised fix, highest impact first>", ...]` + "\n")
	b.WriteString("}\n")

	return b.String(), nil
}

// joinOrNone returns a comma-joined string or "(none)" for an empty slice.
func joinOrNone(ss []string) string {
	if len(ss) == 0 {
		return "(none)"
	}
	return "(" + strings.Join(ss, ", ") + ")"
}

// validateExternalAPIURL checks that rawURL is HTTPS and that its hostname
// does not resolve to a private, loopback, or link-local address (SSRF guard).
func validateExternalAPIURL(rawURL string) error {
	if !strings.HasPrefix(rawURL, "https://") {
		return fmt.Errorf("URL must use HTTPS")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL has no host")
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		// Cannot resolve — treat as safe (DNS failure at config time should not block startup).
		return nil
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		for _, n := range privateCIDRs {
			if n.Contains(ip) {
				return fmt.Errorf("URL resolves to a private/internal address (%s): SSRF risk", addr)
			}
		}
	}
	return nil
}

func callProvider(ctx context.Context, provider Provider, prompt string) (string, error) {
	switch provider {
	case ProviderOllama:
		return callOllama(ctx, prompt)
	case ProviderClaude:
		return callClaude(ctx, prompt)
	case ProviderOpenAI:
		return callOpenAI(ctx, prompt, defaultOpenAIModel, os.Getenv("OPENAI_KEY"), "https://api.openai.com/v1")
	case ProviderGrok:
		base := os.Getenv("XAI_API_URL")
		if base == "" {
			base = defaultXAIURL
		}
		if err := validateExternalAPIURL(base); err != nil {
			return "", fmt.Errorf("XAI_API_URL rejected: %w", err)
		}
		return callOpenAI(ctx, prompt, defaultGrokModel, os.Getenv("GROK_KEY"), base)
	default:
		return "", fmt.Errorf("unknown provider: %s", provider)
	}
}

func callOllama(ctx context.Context, prompt string) (string, error) {
	ollamaBase := defaultOllamaURL
	if u := os.Getenv("OLLAMA_URL"); u != "" {
		ollamaBase = u
	}
	if err := validateOllamaURL(ollamaBase); err != nil {
		return "", fmt.Errorf("ollama URL validation failed: %w", err)
	}
	base := strings.TrimRight(ollamaBase, "/")
	model := os.Getenv("AI_MODEL")
	if model == "" {
		model = defaultOllamaModel
	}
	payload := map[string]any{
		"model":  model,
		"prompt": prompt,
		"stream": false,
		"format": "json",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, providerCallTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/generate",
		bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create ollama request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Use a plain transport: validateOllamaURL already enforces localhost-only,
	// so ssrfSafeTransport's private-IP guard is not needed (and would block loopback).
	ollamaClient := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		},
	}
	resp, err := ollamaClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorSnippet))
		return "", fmt.Errorf("ollama API error %d: %s", resp.StatusCode, strings.TrimSpace(string(errBody)))
	}
	var result struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBody)).Decode(&result); err != nil {
		return "", fmt.Errorf("ollama response parse error: %w", err)
	}
	return result.Response, nil
}

func callClaude(ctx context.Context, prompt string) (string, error) {
	key := os.Getenv("CLAUDE_KEY")
	if key == "" {
		return "", fmt.Errorf("CLAUDE_KEY not set")
	}
	model := os.Getenv("AI_MODEL")
	if model == "" {
		model = defaultClaudeModel
	}
	payload := map[string]any{
		"model":      model,
		"max_tokens": 1500,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, providerCallTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create claude request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", key)
	req.Header.Set("anthropic-version", "2023-06-01")
	// Use the centralized SSRF-safe client.
	client := safehttp.SafeClient(providerCallTimeout)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("claude request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var apiErr struct {
			Error struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if jsonErr := json.Unmarshal(respBody, &apiErr); jsonErr == nil && apiErr.Error.Type != "" {
			msg := apiErr.Error.Type
			if apiErr.Error.Message != "" {
				msg += ": " + apiErr.Error.Message
			}
			return "", fmt.Errorf("claude API error %d: %s", resp.StatusCode, msg)
		}
		return "", fmt.Errorf("claude API error %d", resp.StatusCode)
	}
	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("claude response parse error: %w", err)
	}
	if len(result.Content) == 0 {
		return "", fmt.Errorf("claude returned empty content")
	}
	return result.Content[0].Text, nil
}

// callOpenAI handles OpenAI-compatible APIs (OpenAI + xAI Grok).
func callOpenAI(ctx context.Context, prompt, model, key, baseURL string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("API key not set")
	}
	if m := os.Getenv("AI_MODEL"); m != "" {
		model = m
	}
	payload := map[string]any{
		"model":      model,
		"max_tokens": 1500,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, providerCallTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(baseURL, "/")+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create API request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	// Use the centralized SSRF-safe client.
	resp, err := safehttp.SafeClient(providerCallTimeout).Do(req)
	if err != nil {
		return "", fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var apiErr struct {
			Error struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if jsonErr := json.Unmarshal(respBody, &apiErr); jsonErr == nil && apiErr.Error.Type != "" {
			return "", fmt.Errorf("API error %d: %s", resp.StatusCode, apiErr.Error.Type)
		}
		return "", fmt.Errorf("API error %d", resp.StatusCode)
	}
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("response parse error: %w", err)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("API returned no choices")
	}
	return result.Choices[0].Message.Content, nil
}

var jsonFenceRE = regexp.MustCompile(`(?s)^\s*` + "```" + `(?:json)?\s*(.*?)\s*` + "```" + `\s*$`)
var jsonObjectRE = regexp.MustCompile(`(?s)\{.*\}`)

func parseResponse(raw string, provider Provider) Analysis {
	text := raw
	if m := jsonFenceRE.FindStringSubmatch(text); m != nil {
		text = m[1]
	}
	text = strings.TrimSpace(text)

	var data map[string]any
	if err := json.Unmarshal([]byte(text), &data); err != nil {
		// Fallback: extract first JSON object
		if m := jsonObjectRE.FindString(text); m != "" {
			if err2 := json.Unmarshal([]byte(m), &data); err2 != nil {
				return Analysis{Provider: provider, Error: "could not parse AI response as JSON: " + err2.Error()}
			}
		} else {
			return Analysis{Provider: provider, Error: "no JSON object found in AI response"}
		}
	}

	if data == nil {
		return Analysis{Provider: provider, Error: "AI response parsed as null"}
	}

	a := Analysis{Provider: provider}

	if v, ok := data["risk_score"]; ok {
		switch score := v.(type) {
		case float64:
			n := int(score)
			a.RiskScore = &n
		}
	}
	if v, ok := data["overview"].(string); ok {
		a.Overview = v
	}
	if v, ok := data["risks"].([]any); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				a.Risks = append(a.Risks, s)
			}
		}
	}
	if v, ok := data["recommendations"].([]any); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				a.Recommendations = append(a.Recommendations, s)
			}
		}
	}
	return a
}
