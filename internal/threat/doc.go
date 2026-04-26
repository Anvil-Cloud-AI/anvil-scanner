// Package threat handles CVE feed parsing and advisory matching
// against the installed software inventory. It is the Go port of
// python/anvil_scanner/threat_intel.py.
//
// The shared vulnerability data at ../../vulndb/ (openclaw-gateway.json
// and index.json) is the same format consumed by the Python
// implementation. No schema change on the port — the on-disk format
// is treated as stable.
package threat
