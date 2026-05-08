// Package ai provides AI risk analysis via the Anthropic and Ollama
// APIs. It is the Go port of python/anvil_scanner/ai_analysis.py.
//
// Structure (planned):
//
//   - provider.go: Provider interface + precedence logic. Precedence
//     order is preserved from Python: Ollama > CLAUDE_KEY > OPENAI_KEY
//     > GROK_KEY > NONE. A 500ms reachability probe gates Ollama
//     selection.
//   - anthropic.go: Direct HTTP client for /v1/messages. No SDK
//     dependency — the SDK surface we actually use is ~1 endpoint.
//   - ollama.go: Ollama local API client.
//
// The NO_PROVIDER sentinel path renders a loud failure banner in
// the report (see report/ package). This is not an error — it is a
// visible user-facing signal that AI analysis was unavailable.
//
// Pre-scan AI provider preflight (from python/anvil_scanner/cli.py::_preflight_ai_provider)
// also lives here rather than in cmd/anvil-scanner, so the CLI
// stays thin.
package ai
