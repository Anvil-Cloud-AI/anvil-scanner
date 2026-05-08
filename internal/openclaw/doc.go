// Package openclaw performs the OpenClaw configuration and runtime
// audit. It is the Go port of python/anvil_scanner/openclaw_audit.py.
//
// In the Go release this package is the in-tree reference
// implementation, but it also ships as a stand-alone binary
// ("anvil-plugin-openclaw") that demonstrates the subprocess plugin
// protocol. See docs/plugin-protocol.md (to be written) for the
// JSON-over-stdio contract.
//
// Install-channel awareness (system-wide vs user-local) and the
// JSON audit schema are inherited from the Python implementation.
// See python/tests/fixtures/openclaw_audit_real.json for a
// reference audit payload.
package openclaw
