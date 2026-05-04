package ai

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestDetectProvider_ExplicitOllama verifies that AI_PROVIDER=ollama is honored
// without a reachability probe.
func TestDetectProvider_ExplicitOllama(t *testing.T) {
	t.Setenv("AI_PROVIDER", "ollama")
	p, name := DetectProvider()
	if p != ProviderOllama {
		t.Errorf("expected ollama, got %s", p)
	}
	if name == "" {
		t.Error("expected non-empty display name")
	}
}

// TestDetectProvider_ExplicitClaude verifies AI_PROVIDER=claude is honored
// even without CLAUDE_KEY set (key validation is at call time, not detection time).
func TestDetectProvider_ExplicitClaude(t *testing.T) {
	t.Setenv("AI_PROVIDER", "claude")
	p, _ := DetectProvider()
	if p != ProviderClaude {
		t.Errorf("expected claude, got %s", p)
	}
}

// TestDetectProvider_NoneWhenNoKeys returns None when no keys and Ollama unreachable.
// We ensure Ollama is "unreachable" by pointing it at an invalid URL.
func TestDetectProvider_NoneWhenNoKeys(t *testing.T) {
	os.Unsetenv("AI_PROVIDER")
	os.Unsetenv("CLAUDE_KEY")
	os.Unsetenv("OPENAI_KEY")
	os.Unsetenv("GROK_KEY")
	t.Setenv("OLLAMA_URL", "http://127.0.0.1:19999") // nothing listening
	p, _ := DetectProvider()
	if p != ProviderNone {
		t.Errorf("expected ProviderNone when no keys and Ollama down, got %s", p)
	}
}

// TestDetectProvider_ClaudeKeyFallback verifies CLAUDE_KEY triggers Claude
// when Ollama is not reachable.
func TestDetectProvider_ClaudeKeyFallback(t *testing.T) {
	os.Unsetenv("AI_PROVIDER")
	os.Unsetenv("OPENAI_KEY")
	os.Unsetenv("GROK_KEY")
	t.Setenv("CLAUDE_KEY", "sk-test-key")
	t.Setenv("OLLAMA_URL", "http://127.0.0.1:19999") // nothing listening
	p, _ := DetectProvider()
	if p != ProviderClaude {
		t.Errorf("expected claude via CLAUDE_KEY fallback, got %s", p)
	}
}

// TestDetectProvider_OpenAIBeforeGrok verifies key precedence: OPENAI before GROK.
func TestDetectProvider_OpenAIBeforeGrok(t *testing.T) {
	os.Unsetenv("AI_PROVIDER")
	os.Unsetenv("CLAUDE_KEY")
	t.Setenv("OPENAI_KEY", "sk-openai-key")
	t.Setenv("GROK_KEY", "xai-grok-key")
	t.Setenv("OLLAMA_URL", "http://127.0.0.1:19999")
	p, _ := DetectProvider()
	if p != ProviderOpenAI {
		t.Errorf("expected openai before grok, got %s", p)
	}
}

// TestOllamaReachable_FalseOnBadPort confirms the probe returns false promptly
// on a port with nothing listening.
func TestOllamaReachable_FalseOnBadPort(t *testing.T) {
	t.Setenv("OLLAMA_URL", "http://127.0.0.1:19999")
	if OllamaReachable() {
		t.Error("expected OllamaReachable=false on port 19999")
	}
}

// TestParseResponse_ValidJSON exercises the happy path.
func TestParseResponse_ValidJSON(t *testing.T) {
	raw := `{"risk_score": 7, "overview": "High risk host", "risks": ["r1", "r2"], "recommendations": ["fix1"]}`
	a := parseResponse(raw, ProviderClaude)
	if a.Error != "" {
		t.Fatalf("unexpected error: %s", a.Error)
	}
	if a.RiskScore == nil || *a.RiskScore != 7 {
		t.Errorf("expected risk_score=7, got %v", a.RiskScore)
	}
	if a.Overview != "High risk host" {
		t.Errorf("unexpected overview: %s", a.Overview)
	}
	if len(a.Risks) != 2 {
		t.Errorf("expected 2 risks, got %d", len(a.Risks))
	}
	if len(a.Recommendations) != 1 {
		t.Errorf("expected 1 recommendation, got %d", len(a.Recommendations))
	}
}

// TestParseResponse_MarkdownFence exercises stripping ```json fences.
func TestParseResponse_MarkdownFence(t *testing.T) {
	raw := "```json\n{\"risk_score\": 3, \"overview\": \"Low risk\", \"risks\": [], \"recommendations\": []}\n```"
	a := parseResponse(raw, ProviderOllama)
	if a.Error != "" {
		t.Fatalf("unexpected error parsing fenced JSON: %s", a.Error)
	}
	if a.RiskScore == nil || *a.RiskScore != 3 {
		t.Errorf("expected risk_score=3, got %v", a.RiskScore)
	}
}

// TestParseResponse_EmbeddedJSON exercises the fallback JSON-object extraction.
func TestParseResponse_EmbeddedJSON(t *testing.T) {
	raw := `Here is my analysis: {"risk_score": 5, "overview": "Moderate", "risks": [], "recommendations": []} — done.`
	a := parseResponse(raw, ProviderOllama)
	if a.Error != "" {
		t.Fatalf("unexpected error: %s", a.Error)
	}
	if a.RiskScore == nil || *a.RiskScore != 5 {
		t.Errorf("expected risk_score=5, got %v", a.RiskScore)
	}
}

// TestParseResponse_InvalidJSON verifies error is set for unparseable responses.
func TestParseResponse_InvalidJSON(t *testing.T) {
	a := parseResponse("not json at all", ProviderOllama)
	if a.Error == "" {
		t.Error("expected error for invalid JSON response")
	}
}

// TestAnalyze_SkipReturnsSkipResult verifies that skip=true short-circuits.
func TestAnalyze_SkipReturnsSkipResult(t *testing.T) {
	a := Analyze(context.Background(), "ignored prompt", true, ProviderNone)
	if !a.Skipped {
		t.Error("expected Skipped=true")
	}
	if a.Error != "" {
		t.Errorf("expected no error on skip, got: %s", a.Error)
	}
}

// TestAnalyze_NoneProviderLoudBanner ensures the NO_PROVIDER state returns an
// error (not just a Skipped result) so the report renders a loud banner.
func TestAnalyze_NoneProviderLoudBanner(t *testing.T) {
	os.Unsetenv("AI_PROVIDER")
	os.Unsetenv("CLAUDE_KEY")
	os.Unsetenv("OPENAI_KEY")
	os.Unsetenv("GROK_KEY")
	t.Setenv("OLLAMA_URL", "http://127.0.0.1:19999")

	a := Analyze(context.Background(), "prompt", false, ProviderNone)
	if a.Skipped {
		t.Error("NO_PROVIDER should set Error, not Skipped — it's a loud banner, not a quiet skip")
	}
	if a.Error == "" {
		t.Error("expected non-empty Error for NO_PROVIDER sentinel")
	}
	if a.Remediation == "" {
		t.Error("expected non-empty Remediation for NO_PROVIDER sentinel")
	}
}

// TestCallOllama_Non200ReturnsError verifies that callOllama returns a non-nil
// error containing the status code when the server responds with 404.
func TestCallOllama_Non200ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	t.Setenv("OLLAMA_URL", srv.URL)

	_, err := callOllama(context.Background(), "test prompt")
	if err == nil {
		t.Fatal("expected non-nil error for 404 response, got nil")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("%d", http.StatusNotFound)) {
		t.Errorf("error should mention status code 404, got: %s", err.Error())
	}
}

// TestBuildPrompt_ContainsKeyFields verifies the prompt includes scan data.
func TestBuildPrompt_ContainsKeyFields(t *testing.T) {
	prompt, err := BuildPrompt("Darwin", []string{"22", "443"}, 5, 3)
	if err != nil {
		t.Fatalf("BuildPrompt returned unexpected error: %v", err)
	}
	for _, want := range []string{"Darwin", "22", "443", "pending_update_count", "priority_findings"} {
		if len(prompt) == 0 {
			t.Fatal("empty prompt")
		}
		found := false
		for i := 0; i < len(prompt)-len(want)+1; i++ {
			if prompt[i:i+len(want)] == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q in prompt, prompt snippet: %.200s", want, prompt)
		}
	}
}
