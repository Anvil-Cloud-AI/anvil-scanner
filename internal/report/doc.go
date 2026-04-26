// Package report generates HTML and JSON scan reports. It is the Go
// port of python/anvil_scanner/reporting.py.
//
// Structure (planned):
//
//   - html.go: HTML report rendering via html/template.
//   - json.go: JSON report serialization.
//   - template.html: report template, loaded via go:embed.
//   - assets/: CSS + scroll-spy JS, loaded via go:embed.
//
// The HTML report includes a sticky topbar + subnav with scroll-spy
// tab highlighting (IntersectionObserver-based). Priority Findings
// filter is preserved exactly from the Python implementation:
// status ∈ {FAIL, WARN} AND severity ∈ {critical, high}. Medium
// never promotes regardless of status.
//
// See python/tests/test_refactor_guardrails.py::TestReportRedesignSubnavAndScrollSpy
// for the HTML structural contract.
package report
