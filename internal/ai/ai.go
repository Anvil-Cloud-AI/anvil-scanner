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

// ssrfSafeTransport closes the DNS-rebinding TOCTOU window by re-validating
// the resolved IP at DialContext time rather than only at validation time.
// Used by callOpenAI so a user-supplied XAI_API_URL cannot be redirected to
// a private address between the pre-flight validateExternalAPIURL check and
// the actual HTTP connection.
var ssrfSafeTransport *http.Transport

func init() {
	for _, cidr := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
	} {
		_, n, err := net.ParseCIDR(cidr)
		if err == nil {
			privateCIDRs = append(privateCIDRs, n)
		}
	}

	baseDialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	ssrfSafeTransport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("parse dial addr: %w", err)
			}
			ips, err := net.DefaultResolver.LookupHost(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("resolve %s: %w", host, err)
			}
			for _, ipStr := range ips {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					continue
				}
				for _, n := range privateCIDRs {
					if n.Contains(ip) {
						return nil, fmt.Errorf("SSRF guard: %s resolves to private address %s", host, ipStr)
					}
				}
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("no addresses resolved for %s", host)
			}
			return baseDialer.DialContext(ctx, network, net.JoinHostPort(ips[0], port))
		},
	}
}

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
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
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

// BuildPrompt constructs the AI analysis prompt from a simplified scan summary.
func BuildPrompt(platform string, openPorts []string, pendingUpdates int, priorityCount int) (string, error) {
	summary := map[string]any{
		"platform":             platform,
		"open_ports":           openPorts,
		"pending_update_count": pendingUpdates,
		"priority_findings":    priorityCount,
	}
	summaryJSON, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return "", fmt.Errorf("buildPrompt: marshal: %w", err)
	}
	return fmt.Sprintf(`You are a senior %s security engineer reviewing an automated host hardening scan.

SCAN DATA:
%s

Respond ONLY with a valid JSON object (no markdown, no explanation) in this exact schema:
{
  "risk_score": <integer 1-10, where 10 is most dangerous>,
  "overview": "<2-4 sentence plain-English summary>",
  "risks": ["<risk #1>", "<risk #2>"],
  "recommendations": ["<fix #1>", "<fix #2>"]
}

Rules:
- risks and recommendations may be empty arrays [] if there are genuinely none.
- overview must always be present and non-empty.
- Do not suggest specific shell commands to run.
`, platform, string(summaryJSON)), nil
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
	resp, err := http.DefaultClient.Do(req)
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
		"max_tokens": 768,
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
	client := &http.Client{Transport: ssrfSafeTransport}
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
			return "", fmt.Errorf("claude API error %d: %s", resp.StatusCode, apiErr.Error.Type)
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
		"max_tokens": 768,
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
	resp, err := (&http.Client{Transport: ssrfSafeTransport}).Do(req)
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
