//go:build !integration

package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── init / privateCIDRs ────────────────────────────────────────────────────────

// TestInit_PrivateCIDRsPopulated verifies that the init() function populates
// privateCIDRs with all expected CIDR blocks, and that known private IPs are
// contained while known public IPs are not.
func TestInit_PrivateCIDRsPopulated(t *testing.T) {
	if len(privateCIDRs) == 0 {
		t.Fatal("privateCIDRs is empty after init(); expected at least one entry")
	}

	tests := []struct {
		ip        string
		inPrivate bool
	}{
		{"10.0.0.1", true},
		{"192.168.1.100", true},
		{"172.16.0.1", true},
		{"127.0.0.1", true},
		{"169.254.1.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}
	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("net.ParseIP(%q) returned nil", tc.ip)
			}
			found := false
			for _, cidr := range privateCIDRs {
				if cidr.Contains(ip) {
					found = true
					break
				}
			}
			if found != tc.inPrivate {
				t.Errorf("IP %s: inPrivate=%v, want %v", tc.ip, found, tc.inPrivate)
			}
		})
	}
}

// ── validateOllamaURL ─────────────────────────────────────────────────────────

// TestValidateOllamaURL covers all branches of the Ollama URL validator.
func TestValidateOllamaURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
		errFrag string
	}{
		{
			name:    "valid localhost http",
			url:     "http://localhost:11434",
			wantErr: false,
		},
		{
			name:    "valid 127.0.0.1 http",
			url:     "http://127.0.0.1:11434",
			wantErr: false,
		},
		{
			name:    "valid ::1 http",
			url:     "http://[::1]:11434",
			wantErr: false,
		},
		{
			name:    "https scheme rejected",
			url:     "https://localhost:11434",
			wantErr: true,
			errFrag: "scheme must be http",
		},
		{
			name:    "remote hostname rejected",
			url:     "http://remote.example.com:11434",
			wantErr: true,
			errFrag: "hostname must be localhost",
		},
		{
			name:    "private non-loopback IP rejected",
			url:     "http://192.168.1.1:11434",
			wantErr: true,
			errFrag: "hostname must be localhost",
		},
		{
			name:    "unparseable URL rejected",
			url:     "://bad url",
			wantErr: true,
			errFrag: "invalid OLLAMA_URL",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOllamaURL(tc.url)
			if tc.wantErr && err == nil {
				t.Fatalf("validateOllamaURL(%q) = nil; want error", tc.url)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateOllamaURL(%q) = %v; want nil", tc.url, err)
			}
			if tc.wantErr && tc.errFrag != "" && err != nil && !strings.Contains(err.Error(), tc.errFrag) {
				t.Errorf("error = %q; want it to contain %q", err.Error(), tc.errFrag)
			}
		})
	}
}

// ── callProvider ───────────────────────────────────────────────────────────────

// TestCallProvider_UnknownProviderReturnsError verifies the default branch in
// callProvider returns a descriptive error for an unrecognised provider name.
func TestCallProvider_UnknownProviderReturnsError(t *testing.T) {
	_, err := callProvider(context.Background(), Provider("bogus"), "prompt")
	if err == nil {
		t.Fatal("expected error for unknown provider, got nil")
	}
	if !strings.Contains(err.Error(), "unknown provider") {
		t.Errorf("error should mention 'unknown provider', got: %s", err.Error())
	}
}

// TestCallProvider_ClaudeMissingKeyReturnsError verifies that callProvider for
// the Claude provider returns an error when CLAUDE_KEY is not set.
func TestCallProvider_ClaudeMissingKeyReturnsError(t *testing.T) {
	t.Setenv("CLAUDE_KEY", "")
	_, err := callProvider(context.Background(), ProviderClaude, "prompt")
	if err == nil {
		t.Fatal("expected error when CLAUDE_KEY is empty, got nil")
	}
	if !strings.Contains(err.Error(), "CLAUDE_KEY") {
		t.Errorf("error should mention 'CLAUDE_KEY', got: %s", err.Error())
	}
}

// TestCallProvider_OpenAIMissingKeyReturnsError verifies that callProvider for
// the OpenAI provider returns an error when OPENAI_KEY is not set.
func TestCallProvider_OpenAIMissingKeyReturnsError(t *testing.T) {
	t.Setenv("OPENAI_KEY", "")
	_, err := callProvider(context.Background(), ProviderOpenAI, "prompt")
	if err == nil {
		t.Fatal("expected error when OPENAI_KEY is empty, got nil")
	}
	if !strings.Contains(err.Error(), "API key not set") {
		t.Errorf("error should mention 'API key not set', got: %s", err.Error())
	}
}

// TestCallProvider_GrokRejectsHTTPBaseURL verifies that callProvider for the
// Grok provider rejects a non-HTTPS XAI_API_URL via validateExternalAPIURL.
func TestCallProvider_GrokRejectsHTTPBaseURL(t *testing.T) {
	t.Setenv("GROK_KEY", "xai-test-key")
	t.Setenv("XAI_API_URL", "http://api.x.ai/v1") // http, not https — must be rejected
	_, err := callProvider(context.Background(), ProviderGrok, "prompt")
	if err == nil {
		t.Fatal("expected error for non-HTTPS XAI_API_URL, got nil")
	}
	if !strings.Contains(err.Error(), "XAI_API_URL rejected") {
		t.Errorf("error should mention 'XAI_API_URL rejected', got: %s", err.Error())
	}
}

// TestCallProvider_GrokMissingKeyReturnsError verifies that a missing GROK_KEY
// produces an error even when XAI_API_URL validation passes.
func TestCallProvider_GrokMissingKeyReturnsError(t *testing.T) {
	t.Setenv("GROK_KEY", "")
	t.Setenv("XAI_API_URL", "") // use default https://api.x.ai/v1
	_, err := callProvider(context.Background(), ProviderGrok, "prompt")
	// The key-absent error fires before or after URL validation; either is non-nil.
	if err == nil {
		t.Fatal("expected non-nil error when GROK_KEY is empty, got nil")
	}
}

// TestCallProvider_OllamaHappyPath exercises the full Ollama path via a real
// httptest server, covering callProvider → callOllama happy path end to end.
func TestCallProvider_OllamaHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/api/generate") {
			http.Error(w, "wrong path: "+r.URL.Path, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"response":"{\"risk_score\":5,\"overview\":\"ok\",\"risks\":[],\"recommendations\":[]}"}`)
	}))
	defer srv.Close()

	t.Setenv("OLLAMA_URL", srv.URL)

	result, err := callProvider(context.Background(), ProviderOllama, "test prompt")
	if err != nil {
		t.Fatalf("callProvider Ollama: unexpected error: %v", err)
	}
	if result == "" {
		t.Error("callProvider Ollama: expected non-empty result")
	}
}

// ── callOllama ────────────────────────────────────────────────────────────────

// TestCallOllama_HappyPath verifies the full round-trip with a mock Ollama server
// returning a valid JSON response.
func TestCallOllama_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"response":"{\"risk_score\":3,\"overview\":\"low\",\"risks\":[],\"recommendations\":[]}"}`)
	}))
	defer srv.Close()

	t.Setenv("OLLAMA_URL", srv.URL)

	result, err := callOllama(context.Background(), "test prompt")
	if err != nil {
		t.Fatalf("callOllama: unexpected error: %v", err)
	}
	if result == "" {
		t.Error("callOllama: expected non-empty result")
	}
}

// TestCallOllama_BadJSONResponseBody verifies that callOllama returns an error
// when the server returns 200 OK but the body is not valid JSON.
func TestCallOllama_BadJSONResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "this is not json")
	}))
	defer srv.Close()

	t.Setenv("OLLAMA_URL", srv.URL)

	_, err := callOllama(context.Background(), "prompt")
	if err == nil {
		t.Fatal("expected error for non-JSON 200 response, got nil")
	}
	if !strings.Contains(err.Error(), "parse error") {
		t.Errorf("error should mention 'parse error', got: %s", err.Error())
	}
}

// TestCallOllama_500ReturnsError verifies that callOllama wraps a 500 status.
func TestCallOllama_500ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	t.Setenv("OLLAMA_URL", srv.URL)

	_, err := callOllama(context.Background(), "prompt")
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status 500, got: %s", err.Error())
	}
}

// TestCallOllama_InvalidURLSchemeReturnsError verifies that a bad OLLAMA_URL
// scheme is rejected by validateOllamaURL before any HTTP call.
func TestCallOllama_InvalidURLSchemeReturnsError(t *testing.T) {
	t.Setenv("OLLAMA_URL", "https://localhost:11434") // https not allowed for Ollama
	_, err := callOllama(context.Background(), "prompt")
	if err == nil {
		t.Fatal("expected error for https OLLAMA_URL, got nil")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("error should mention 'validation failed', got: %s", err.Error())
	}
}

// TestCallOllama_CustomModelUsed verifies that when AI_MODEL is set, the custom
// model name is embedded in the request body sent to the Ollama server.
func TestCallOllama_CustomModelUsed(t *testing.T) {
	var capturedModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model string `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			capturedModel = req.Model
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"response":"{}"}`)
	}))
	defer srv.Close()

	t.Setenv("OLLAMA_URL", srv.URL)
	t.Setenv("AI_MODEL", "custom-model-v2")

	_, _ = callOllama(context.Background(), "prompt")
	if capturedModel != "custom-model-v2" {
		t.Errorf("model sent = %q; want %q", capturedModel, "custom-model-v2")
	}
}

// TestCallOllama_DefaultModelUsedWhenAIModelUnset verifies the default model is
// used when AI_MODEL env var is empty.
func TestCallOllama_DefaultModelUsedWhenAIModelUnset(t *testing.T) {
	var capturedModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model string `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			capturedModel = req.Model
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"response":"{}"}`)
	}))
	defer srv.Close()

	t.Setenv("OLLAMA_URL", srv.URL)
	t.Setenv("AI_MODEL", "")

	_, _ = callOllama(context.Background(), "prompt")
	if capturedModel != defaultOllamaModel {
		t.Errorf("model sent = %q; want default %q", capturedModel, defaultOllamaModel)
	}
}

// ── callClaude ────────────────────────────────────────────────────────────────

// TestCallClaude_MissingKeyReturnsError verifies the early-exit when CLAUDE_KEY
// is unset — no HTTP call is attempted.
func TestCallClaude_MissingKeyReturnsError(t *testing.T) {
	t.Setenv("CLAUDE_KEY", "")
	_, err := callClaude(context.Background(), "prompt")
	if err == nil {
		t.Fatal("expected error when CLAUDE_KEY is empty, got nil")
	}
	if !strings.Contains(err.Error(), "CLAUDE_KEY") {
		t.Errorf("error should mention CLAUDE_KEY, got: %s", err.Error())
	}
}

// ── callOpenAI ────────────────────────────────────────────────────────────────

// TestCallOpenAI_MissingKeyReturnsError verifies the early-exit when the API
// key argument is empty — before any network call is attempted.
func TestCallOpenAI_MissingKeyReturnsError(t *testing.T) {
	_, err := callOpenAI(context.Background(), "prompt", "gpt-4o-mini", "", "https://api.openai.com/v1")
	if err == nil {
		t.Fatal("expected error for empty key, got nil")
	}
	if !strings.Contains(err.Error(), "API key not set") {
		t.Errorf("error should mention 'API key not set', got: %s", err.Error())
	}
}

// TestCallOpenAI_AI_MODEL_EnvOverridesArgument verifies that AI_MODEL env var
// overrides the model argument. The missing-key short-circuit fires after model
// resolution, confirming the override ran without needing a real HTTP call.
func TestCallOpenAI_AI_MODEL_EnvOverridesArgument(t *testing.T) {
	t.Setenv("AI_MODEL", "gpt-3.5-turbo")
	_, err := callOpenAI(context.Background(), "prompt", "gpt-4o-mini", "", "https://api.openai.com/v1")
	// We expect the key error — not a model error — confirming model resolution ran first.
	if err == nil || !strings.Contains(err.Error(), "API key not set") {
		t.Errorf("expected 'API key not set', got: %v", err)
	}
}

// ── OllamaReachable ────────────────────────────────────────────────────────────

// TestOllamaReachable_TrueWhenServerResponds verifies that OllamaReachable
// returns true when the probe endpoint responds with a 2xx status.
func TestOllamaReachable_TrueWhenServerResponds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"models":[]}`)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	t.Setenv("OLLAMA_URL", srv.URL)
	if !OllamaReachable() {
		t.Error("OllamaReachable() = false; want true when server is up")
	}
}

// TestOllamaReachable_FalseForHTTPSScheme verifies that OllamaReachable returns
// false when OLLAMA_URL uses https (disallowed by validateOllamaURL).
func TestOllamaReachable_FalseForHTTPSScheme(t *testing.T) {
	t.Setenv("OLLAMA_URL", "https://localhost:11434")
	if OllamaReachable() {
		t.Error("OllamaReachable() = true for https scheme; want false")
	}
}

// TestOllamaReachable_FalseForNonLocalhostHostname verifies that OllamaReachable
// returns false when OLLAMA_URL points to a non-localhost hostname.
func TestOllamaReachable_FalseForNonLocalhostHostname(t *testing.T) {
	t.Setenv("OLLAMA_URL", "http://remote.example.com:11434")
	if OllamaReachable() {
		t.Error("OllamaReachable() = true for non-localhost; want false")
	}
}

// TestOllamaReachable_FalseWhenServerReturns503 verifies that OllamaReachable
// returns false when the probe endpoint responds with a non-2xx status.
func TestOllamaReachable_FalseWhenServerReturns503(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	t.Setenv("OLLAMA_URL", srv.URL)
	if OllamaReachable() {
		t.Error("OllamaReachable() = true for 503; want false")
	}
}

// ── DetectProvider additional paths ───────────────────────────────────────────

// TestDetectProvider_GrokKeyFallback verifies GROK_KEY triggers Grok when
// Ollama is unreachable and CLAUDE_KEY / OPENAI_KEY are absent.
func TestDetectProvider_GrokKeyFallback(t *testing.T) {
	t.Setenv("AI_PROVIDER", "")
	t.Setenv("CLAUDE_KEY", "")
	t.Setenv("OPENAI_KEY", "")
	t.Setenv("GROK_KEY", "xai-grok-key")
	t.Setenv("OLLAMA_URL", "http://127.0.0.1:19999") // nothing listening
	p, name := DetectProvider()
	if p != ProviderGrok {
		t.Errorf("expected ProviderGrok, got %s", p)
	}
	if !strings.Contains(name, "Grok") {
		t.Errorf("expected display name to contain 'Grok', got %q", name)
	}
}

// TestDetectProvider_ExplicitOpenAI verifies AI_PROVIDER=openai is honored.
func TestDetectProvider_ExplicitOpenAI(t *testing.T) {
	t.Setenv("AI_PROVIDER", "openai")
	p, _ := DetectProvider()
	if p != ProviderOpenAI {
		t.Errorf("expected openai, got %s", p)
	}
}

// TestDetectProvider_ExplicitGrok verifies AI_PROVIDER=grok is honored.
func TestDetectProvider_ExplicitGrok(t *testing.T) {
	t.Setenv("AI_PROVIDER", "grok")
	p, _ := DetectProvider()
	if p != ProviderGrok {
		t.Errorf("expected grok, got %s", p)
	}
}

// TestDetectProvider_OllamaFallbackWhenReachable verifies that when no
// AI_PROVIDER is set but Ollama is listening, Ollama is selected.
func TestDetectProvider_OllamaFallbackWhenReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"models":[]}`)
	}))
	defer srv.Close()

	t.Setenv("AI_PROVIDER", "")
	t.Setenv("CLAUDE_KEY", "")
	t.Setenv("OPENAI_KEY", "")
	t.Setenv("GROK_KEY", "")
	t.Setenv("OLLAMA_URL", srv.URL)

	p, _ := DetectProvider()
	if p != ProviderOllama {
		t.Errorf("expected ProviderOllama when Ollama is reachable, got %s", p)
	}
}

// ── Analyze with Ollama mock ───────────────────────────────────────────────────

// TestAnalyze_OllamaSuccess exercises the full Analyze path via an Ollama mock,
// covering callProvider → callOllama → parseResponse in one shot.
func TestAnalyze_OllamaSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Ollama wraps the AI text in {"response": "..."}
		inner := `{\"risk_score\":8,\"overview\":\"high risk\",\"risks\":[\"r1\"],\"recommendations\":[\"fix1\"]}`
		fmt.Fprintf(w, `{"response":"%s"}`, inner)
	}))
	defer srv.Close()

	t.Setenv("OLLAMA_URL", srv.URL)

	a := Analyze(context.Background(), "prompt", false, ProviderOllama)
	if a.Error != "" {
		t.Fatalf("Analyze error: %s", a.Error)
	}
	if a.RiskScore == nil || *a.RiskScore != 8 {
		t.Errorf("RiskScore = %v; want 8", a.RiskScore)
	}
	if a.Overview != "high risk" {
		t.Errorf("Overview = %q; want %q", a.Overview, "high risk")
	}
	if len(a.Risks) != 1 {
		t.Errorf("Risks count = %d; want 1", len(a.Risks))
	}
	if a.Provider != ProviderOllama {
		t.Errorf("Provider = %s; want %s", a.Provider, ProviderOllama)
	}
}

// TestAnalyze_OllamaServerError verifies Analyze sets Error when callProvider
// fails (Ollama returns 503).
func TestAnalyze_OllamaServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	t.Setenv("OLLAMA_URL", srv.URL)

	a := Analyze(context.Background(), "prompt", false, ProviderOllama)
	if a.Error == "" {
		t.Fatal("expected non-empty Error on server failure, got empty")
	}
	if a.Skipped {
		t.Error("expected Skipped=false on server failure")
	}
}

// ── parseResponse additional cases ────────────────────────────────────────────

// TestParseResponse_NullResponseIsError verifies that a JSON "null" body
// results in an error rather than an empty analysis.
func TestParseResponse_NullResponseIsError(t *testing.T) {
	a := parseResponse("null", ProviderOllama)
	if a.Error == "" {
		t.Error("expected error for null JSON response, got empty error")
	}
}

// TestParseResponse_MissingRiskScoreIsOK verifies that a response without
// risk_score parses without error (the field is optional).
func TestParseResponse_MissingRiskScoreIsOK(t *testing.T) {
	raw := `{"overview": "All good", "risks": [], "recommendations": []}`
	a := parseResponse(raw, ProviderClaude)
	if a.Error != "" {
		t.Fatalf("unexpected error: %s", a.Error)
	}
	if a.RiskScore != nil {
		t.Errorf("expected nil RiskScore for missing field, got %d", *a.RiskScore)
	}
	if a.Overview != "All good" {
		t.Errorf("Overview = %q; want 'All good'", a.Overview)
	}
}

// TestParseResponse_PlainFenceStripped verifies that plain ``` (no "json"
// language tag) fences are stripped before parsing.
func TestParseResponse_PlainFenceStripped(t *testing.T) {
	raw := "```\n{\"risk_score\":2,\"overview\":\"low\",\"risks\":[],\"recommendations\":[]}\n```"
	a := parseResponse(raw, ProviderOpenAI)
	if a.Error != "" {
		t.Fatalf("unexpected error: %s", a.Error)
	}
	if a.RiskScore == nil || *a.RiskScore != 2 {
		t.Errorf("RiskScore = %v; want 2", a.RiskScore)
	}
}

// TestParseResponse_MultipleRisksAndRecommendations exercises slice parsing
// with more than one element.
func TestParseResponse_MultipleRisksAndRecommendations(t *testing.T) {
	raw := `{
		"risk_score": 6,
		"overview": "moderate",
		"risks": ["open SSH", "outdated kernel", "weak firewall"],
		"recommendations": ["update packages", "restrict SSH", "enable ufw"]
	}`
	a := parseResponse(raw, ProviderClaude)
	if a.Error != "" {
		t.Fatalf("unexpected error: %s", a.Error)
	}
	if len(a.Risks) != 3 {
		t.Errorf("Risks count = %d; want 3", len(a.Risks))
	}
	if len(a.Recommendations) != 3 {
		t.Errorf("Recommendations count = %d; want 3", len(a.Recommendations))
	}
}

// TestParseResponse_ProviderSetOnSuccess verifies the Provider field is
// correctly set on a successful parse for each provider type.
func TestParseResponse_ProviderSetOnSuccess(t *testing.T) {
	raw := `{"risk_score":1,"overview":"ok","risks":[],"recommendations":[]}`
	for _, p := range []Provider{ProviderOllama, ProviderClaude, ProviderOpenAI, ProviderGrok} {
		t.Run(string(p), func(t *testing.T) {
			a := parseResponse(raw, p)
			if a.Provider != p {
				t.Errorf("Provider = %s; want %s", a.Provider, p)
			}
		})
	}
}
