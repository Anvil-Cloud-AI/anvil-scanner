package report

import (
	"fmt"
	"strings"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/openclaw"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/threat"
)

// renderStatusPills renders a row of coloured status-count pills.
// When hideEmpty is true, categories with a zero count are omitted.
func renderStatusPills(counts map[string]int, hideEmpty bool) string {
	type def struct {
		key, color, tmpl string
	}
	defs := []def{
		{"PASS", "#16a34a", "✅ %d passed"},
		{"FAIL", "#dc2626", "❌ %d failed"},
		{"WARN", "#d97706", "⚠️ %d warnings"},
		{"SKIP", "#6b7280", "⏭️ %d skipped"},
	}
	pills := ""
	for _, d := range defs {
		n := counts[d.key]
		if hideEmpty && n == 0 {
			continue
		}
		pills += fmt.Sprintf(
			`<span style="color:%s;font-weight:700;">%s</span>`,
			d.color, fmt.Sprintf(d.tmpl, n),
		)
	}
	return fmt.Sprintf(`<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px;">%s</div>`, pills)
}

const aiDisclaimer = `<div class="ai-disclaimer"><strong>⚠ About AI-generated analysis:</strong> ` +
	`LLM output is probabilistic — the same scan can produce different ` +
	`narratives on re-run, and the model can miss issues, invent details, ` +
	`or recommend changes that don&#39;t fit your environment. Treat this ` +
	`section as a starting point for investigation, not authoritative ` +
	`guidance. Verify critical findings against the raw scan data above ` +
	`and official documentation before acting.</div>`

// renderSSHConfig renders the SSH configuration table rows for the System section.
func renderSSHConfig(d Data, platform string) string {
	isMacOS := strings.EqualFold(platform, "darwin") || strings.EqualFold(platform, "macos")
	if isMacOS && d.RemoteLogin != nil && !*d.RemoteLogin {
		return `<tr><td>Remote Login (SSH)</td><td>🟢 <code>disabled</code> — SSH server is off on this Mac (System Settings → General → Sharing → Remote Login)</td></tr>`
	}

	safe := map[string][]string{
		"PermitRootLogin":        {"no", "prohibit-password"},
		"PasswordAuthentication": {"no"},
	}
	sshRow := func(directive string) string {
		val := "not set (default applies)"
		if d.SSHDirectives != nil {
			if v, ok := d.SSHDirectives[strings.ToLower(directive)]; ok {
				val = v
			} else if v, ok := d.SSHDirectives[directive]; ok {
				val = v
			}
		}
		dot := "🔴"
		for _, s := range safe[directive] {
			if strings.EqualFold(val, s) {
				dot = "🟢"
				break
			}
		}
		return fmt.Sprintf(`<tr><td>%s</td><td>%s <code>%s</code></td></tr>`, e(directive), dot, e(val))
	}

	// If sshd_config couldn't be read, surface the reason.
	if errMsg, ok := d.SSHDirectives["_error"]; ok {
		return fmt.Sprintf(
			`<tr><td colspan="2" style="color:#94a3b8;font-size:.83rem;">⚠ %s</td></tr>`,
			e(errMsg),
		)
	}

	// Diagnostic from sshd -T failure (new in recent versions) — show it + still render the rows.
	if diag, ok := d.SSHDirectives["_sshd_t_error"]; ok {
		rows := ""
		if includeMsg, ok := d.SSHDirectives["_include"]; ok {
			rows += fmt.Sprintf(
				`<tr><td colspan="2" style="color:#d97706;font-size:.83rem;">⚠ %s</td></tr>`,
				e(includeMsg),
			)
		}
		rows += fmt.Sprintf(
			`<tr><td colspan="2" style="color:#94a3b8;font-size:.83rem;">ℹ %s</td></tr>`,
			e(diag),
		)
		rows += sshRow("PermitRootLogin") + sshRow("PasswordAuthentication")
		if isMacOS && d.RemoteLogin != nil && *d.RemoteLogin {
			rows = `<tr><td>Remote Login (SSH)</td><td>🟡 <code>enabled</code> — SSH server is on; directives below apply.</td></tr>` + rows
		}
		return rows
	}

	// Normal path
	rows := sshRow("PermitRootLogin") + sshRow("PasswordAuthentication")

	if isMacOS {
		if d.RemoteLogin != nil && *d.RemoteLogin {
			rows = `<tr><td>Remote Login (SSH)</td><td>🟡 <code>enabled</code> — SSH server is on; directives below apply.</td></tr>` + rows
		} else if d.RemoteLogin == nil {
			// Common when running under sudo on macOS
			rows = `<tr><td colspan="2" style="color:#94a3b8;font-size:.83rem;">ℹ Remote Login state unknown (scan ran under sudo). The values below reflect /etc/ssh/sshd_config only.</td></tr>` + rows
		}
		// On macOS we rarely have the Linux-style Include noise, so we skip the generic include warning.
		return rows
	}

	if includeMsg, ok := d.SSHDirectives["_include"]; ok {
		rows += fmt.Sprintf(
			`<tr><td colspan="2" style="color:#d97706;font-size:.83rem;">⚠ %s</td></tr>`,
			e(includeMsg),
		)
	}
	return rows
}

// renderExtendedChecks renders the Extended Hardening Checks section.
// platform and remoteLogin are used to annotate the SSH section on macOS
// when Remote Login state could not be determined.
func renderExtendedChecks(checks []scan.Check, platform string, remoteLogin *bool) string {
	if len(checks) == 0 {
		return ""
	}

	// Group by ID prefix
	cats := map[string][]scan.Check{}
	for _, c := range checks {
		parts := strings.SplitN(string(c.ID), "-", 2)
		prefix := parts[0]
		cats[prefix] = append(cats[prefix], c)
	}

	// Status counts
	statusCounts := map[string]int{"PASS": 0, "FAIL": 0, "WARN": 0, "SKIP": 0}
	for _, c := range checks {
		statusCounts[string(c.Status)]++
	}

	pills := renderStatusPills(statusCounts, false)

	catTables := ""
	passTotal := statusCounts["PASS"]
	for _, prefix := range catOrder {
		cc, ok := cats[prefix]
		if !ok || len(cc) == 0 {
			continue
		}
		label, ok2 := catLabels[prefix]
		if !ok2 {
			label = prefix
		}
		rows := ""
		hasFailWarnSkip := false
		for _, c := range cc {
			if c.Status == scan.StatusPass {
				continue
			}
			hasFailWarnSkip = true
			sc := statusColors[c.Status]
			svc := severityColors[c.Severity]
			if sc == "" {
				sc = "#6b7280"
			}
			if svc == "" {
				svc = "#6b7280"
			}
			detailCell := fmt.Sprintf(`<span style="font-size:.83rem;color:#94a3b8;">%s</span>`, e(c.Detail))
			if c.Status == scan.StatusFail || c.Status == scan.StatusWarn {
				if docPath, ok := findingDocs[prefix]; ok {
					detailCell += fmt.Sprintf(
						` <a href="%s%s" target="_blank" style="color:#60a5fa;font-size:.8em;white-space:nowrap;">How to fix →</a>`,
						findingDocsBase, docPath,
					)
				}
			}
			rows += fmt.Sprintf(
				`<tr><td><code>%s</code></td><td>%s</td><td><span style="color:%s;font-weight:700;white-space:nowrap;">%s</span></td><td>%s</td><td><span style="color:%s;font-weight:600;font-size:.8rem;text-transform:uppercase;white-space:nowrap;">%s</span></td></tr>`,
				e(string(c.ID)), e(c.Name),
				sc, e(string(c.Status)),
				detailCell,
				svc, e(string(c.Severity)),
			)
		}
		if !hasFailWarnSkip {
			continue
		}
		catTable := fmt.Sprintf(
			`<h3 style="margin:18px 0 8px;font-size:.92rem;color:#cbd5e1;">%s</h3>`+
				`<table><tr><th style="width:80px;">ID</th><th>Check</th><th style="width:90px;">Status</th>`+
				`<th>Detail</th><th style="width:90px;">Severity</th></tr>%s</table>`,
			e(label), rows,
		)

		// Quick-fix hint and contextual notes for SSH findings.
		if prefix == "SSH" {
			// On macOS, when Remote Login state is unknown (nil), SSH checks ran
			// conservatively because the scanner couldn't confirm Remote Login was off
			// (typically because systemsetup requires a non-root admin session).
			// Surface this so users understand why SSH findings appear on a Mac
			// that may not be running sshd.
			if strings.EqualFold(platform, "darwin") && remoteLogin == nil {
				catTable = `<div style="background:#0f1f30;border:1px solid #1e3a5f;border-left:3px solid #5fb4ff;border-radius:0 8px 8px 0;padding:10px 14px;margin-bottom:10px;font-size:.85rem;color:#93c5fd;">` +
					`ℹ <strong>Remote Login status unknown</strong> — SSH checks ran as a precaution because the scanner could not verify whether Remote Login (SSH server) is enabled on this Mac. ` +
					`These findings only apply if Remote Login is on. Re-run <em>without</em> <code>sudo</code> to detect this automatically.</div>` + catTable
			}
			restartCmd := "sudo sshd -t &amp;&amp; sudo systemctl restart sshd"
			if strings.EqualFold(platform, "darwin") {
				restartCmd = "sudo sshd -t &amp;&amp; sudo launchctl kickstart -k system/com.openssh.sshd"
			}
			catTable += `<div style="background:#1c1917;border:1px solid #44403c;border-radius:8px;padding:14px 18px;margin-top:8px;">` +
				`<p style="color:#94a3b8;margin:0 0 8px;">Fix SSH findings — back up first, then edit sshd_config:</p>` +
				`<code style="display:block;background:#0f172a;padding:10px 14px;border-radius:6px;color:#7dd3fc;font-size:.9rem;white-space:pre;">sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak&#10;sudo $EDITOR /etc/ssh/sshd_config&#10;` + restartCmd + `</code>` +
				`<p style="color:#64748b;font-size:.8rem;margin:8px 0 0;">Use the <em>How to fix</em> links above for each setting. <code>sshd -t</code> validates config before restart.</p></div>`
		}
		if prefix == "RPI" {
			catTable += `<div style="background:#1c1917;border:1px solid #44403c;border-radius:8px;padding:14px 18px;margin-top:8px;">` +
				`<p style="color:#94a3b8;margin:0 0 8px;">Common Pi hardening steps:</p>` +
				`<code style="display:block;background:#0f172a;padding:10px 14px;border-radius:6px;color:#7dd3fc;font-size:.9rem;">sudo raspi-config  # Interface Options, System Options</code>` +
				`<p style="color:#64748b;font-size:.8rem;margin:8px 0 0;">Change default password, disable unused interfaces, configure boot options.</p></div>`
		}
		catTables += catTable
	}

	passNote := ""
	if passTotal > 0 {
		passNote = fmt.Sprintf(
			`<p style="color:#64748b;font-size:.8rem;margin:12px 0 0;">✅ %d passing checks not shown — `+
				`<a href="%s" target="_blank" style="color:#60a5fa;">full check list →</a></p>`,
			passTotal, findingDocsBase+"README.md",
		)
	}

	return fmt.Sprintf(
		`<section><h2>🔬 Extended Hardening Checks (%d checks)</h2>%s%s%s</section>`,
		len(checks), pills, catTables, passNote,
	)
}

// renderAISection renders the AI Risk Analysis section.
func renderAISection(a AIAnalysis) string {
	if a.Skipped {
		return `<div class="ai-skip">AI analysis not run — pass <code>--ai-analysis</code> to include a narrative summary, top risks, and recommended fixes.</div>`
	}
	if a.Error != "" {
		remHTML := ""
		if a.Remediation != "" {
			items := ""
			for _, line := range strings.Split(a.Remediation, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "•") {
					items += fmt.Sprintf("<li>%s</li>", e(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "•"))))
				}
			}
			head := strings.SplitN(a.Remediation, "\n", 2)[0]
			if items != "" {
				remHTML = fmt.Sprintf("<p>%s</p><ul>%s</ul>", e(strings.TrimRight(head, ":")), items)
			} else {
				remHTML = fmt.Sprintf("<p>%s</p>", e(a.Remediation))
			}
		}
		return fmt.Sprintf(
			`<div class="ai-fail" role="alert"><strong>⚠ AI analysis failed</strong><p>%s</p>%s</div>%s`,
			e(a.Error), remHTML, aiDisclaimer,
		)
	}

	overviewHTML := ""
	if a.Overview != "" {
		overviewHTML = fmt.Sprintf(`<div class="ovbox"><p>%s</p></div>`, e(a.Overview))
	}

	risks := `<p class="mut">No findings reported.</p>`
	if len(a.Risks) > 0 {
		items := ""
		for _, r := range a.Risks {
			items += fmt.Sprintf("<li>%s</li>", e(r))
		}
		risks = "<ul>" + items + "</ul>"
	}

	recs := `<p class="mut">No recommendations at this time.</p>`
	if len(a.Recommendations) > 0 {
		items := ""
		for _, r := range a.Recommendations {
			items += fmt.Sprintf("<li>%s</li>", e(r))
		}
		recs = "<ul>" + items + "</ul>"
	}

	return fmt.Sprintf(
		`%s<div class="ac"><div><h3>⚠️ Top Risks</h3>%s</div><div><h3>✅ Recommendations</h3>%s</div></div>%s`,
		overviewHTML, risks, recs, aiDisclaimer,
	)
}

// renderOCChecks renders the OpenClaw security checks section.
func renderOCChecks(checks []scan.Check) string {
	if len(checks) == 0 {
		return ""
	}
	statusCounts := map[string]int{}
	for _, c := range checks {
		statusCounts[string(c.Status)]++
	}
	pills := renderStatusPills(statusCounts, true)

	label := "findings"
	if len(checks) == 1 {
		label = "finding"
	}

	rows := ""
	passCount := 0
	for _, c := range checks {
		if c.Status == scan.StatusPass {
			passCount++
			continue
		}
		sc := statusColors[c.Status]
		svc := severityColors[c.Severity]
		if sc == "" {
			sc = "#6b7280"
		}
		if svc == "" {
			svc = "#6b7280"
		}
		detailHTML := strings.ReplaceAll(e(c.Detail), "\n", "<br>")
		detailCell := fmt.Sprintf(`<span style="font-size:.83rem;color:#94a3b8;">%s</span>`, detailHTML)
		if c.Status == scan.StatusFail || c.Status == scan.StatusWarn {
			detailCell += ` <a href="https://docs.openclaw.ai/security" target="_blank" style="color:#60a5fa;font-size:.8em;white-space:nowrap;">OpenClaw docs →</a>`
		}
		rows += fmt.Sprintf(
			`<tr><td><code>%s</code></td><td>%s</td><td><span style="color:%s;font-weight:700;white-space:nowrap;">%s</span></td><td>%s</td><td><span style="color:%s;font-weight:600;font-size:.8rem;text-transform:uppercase;white-space:nowrap;">%s</span></td></tr>`,
			e(string(c.ID)), e(c.Name),
			sc, e(string(c.Status)),
			detailCell,
			svc, e(string(c.Severity)),
		)
	}

	passNote := ""
	if passCount > 0 {
		passNote = fmt.Sprintf(
			`<p style="color:#64748b;font-size:.8rem;margin:12px 0 0;">✅ %d passing checks not shown — `+
				`<a href="https://docs.openclaw.ai/security" target="_blank" style="color:#60a5fa;">OpenClaw security docs →</a></p>`,
			passCount,
		)
	}

	if rows == "" {
		return fmt.Sprintf(
			`    <section><h2>🦞 OpenClaw Security (%d %s)</h2>%s`+
				`<p style="color:#16a34a;font-weight:600;">✅ All checks passed</p>%s</section>`,
			len(checks), label, pills, passNote,
		)
	}
	return fmt.Sprintf(
		`    <section><h2>🦞 OpenClaw Security (%d %s)</h2>%s`+
			`<table><tr><th style="width:220px;">ID</th><th>Check</th>`+
			`<th style="width:90px;">Status</th><th>Detail</th>`+
			`<th style="width:90px;">Severity</th></tr>%s</table>%s</section>`,
		len(checks), label, pills, rows, passNote,
	)
}

// renderOCVulns renders the OpenClaw known-vulnerability section.
func renderOCVulns(r *openclaw.OCVulnResult) string {
	if r == nil {
		return ""
	}

	if r.Error != "" {
		return fmt.Sprintf(
			`    <section><h2>🛡️ OpenClaw Known Vulnerabilities</h2>`+
				`<p style="color:#d97706;">⚠️ %s</p></section>`,
			e(r.Error),
		)
	}

	// dbFooterHTML builds the footer line as safe HTML. The repo link is a
	// hardcoded constant; user-controlled fields go through e().
	dbFooterHTML := func() string {
		s := fmt.Sprintf("%d advisories checked · source: %s", r.Checked, e(r.DBSource))
		if r.DBUpdated != "" {
			s += " · newest advisory: " + e(r.DBUpdated)
		}
		s += fmt.Sprintf(
			` · feed: <a href="%s" target="_blank" rel="noopener noreferrer" style="color:#94a3b8;">github.com/jgamblin/OpenClawCVEs</a>`,
			openclaw.CVEFeedRepoURL,
		)
		return s
	}

	if len(r.Findings) == 0 {
		return fmt.Sprintf(
			`    <section><h2>🛡️ OpenClaw Known Vulnerabilities — %s</h2>`+
				`<p style="color:#16a34a;">✅ No known vulnerabilities</p>`+
				`<p style="color:#94a3b8;font-size:.85rem;">%s</p>`+
				`</section>`,
			e(r.Version), dbFooterHTML(),
		)
	}

	critCount, highCount, medCount, lowCount := 0, 0, 0, 0
	for _, f := range r.Findings {
		switch f.Severity {
		case "CRITICAL":
			critCount++
		case "HIGH":
			highCount++
		case "MEDIUM":
			medCount++
		default:
			lowCount++
		}
	}

	// Only show the CVSS column when at least one finding has a score.
	hasCVSS := false
	for _, f := range r.Findings {
		if f.CVSS > 0 {
			hasCVSS = true
			break
		}
	}

	colorFor := func(sev string) string {
		switch sev {
		case "CRITICAL":
			return "#dc2626"
		case "HIGH":
			return "#f97316"
		case "MEDIUM":
			return "#eab308"
		default:
			return "#6b7280"
		}
	}

	rows := ""
	for _, f := range r.Findings {
		sc := colorFor(f.Severity)
		cvssCell := ""
		if hasCVSS {
			if f.CVSS > 0 {
				cvssCell = fmt.Sprintf("%.1f", f.CVSS)
			} else {
				cvssCell = "—"
			}
		}
		rowStyle := ""
		if f.Severity == "MEDIUM" || f.Severity == "LOW" {
			rowStyle = ` style="opacity:.75;"`
		}
		idCell := fmt.Sprintf(`<td><code>%s</code></td>`, e(f.ID))
		sevCell := fmt.Sprintf(`<td><span style="color:%s;font-weight:700;white-space:nowrap;">%s</span></td>`, sc, e(f.Severity))
		descCell := fmt.Sprintf(`<td style="font-size:.83rem;">%s</td>`, e(f.Desc))
		if hasCVSS {
			rows += fmt.Sprintf(`<tr%s>%s%s<td style="font-size:.83rem;color:#94a3b8;">%s</td>%s</tr>`,
				rowStyle, idCell, sevCell, e(cvssCell), descCell)
		} else {
			rows += fmt.Sprintf(`<tr%s>%s%s%s</tr>`, rowStyle, idCell, sevCell, descCell)
		}
	}

	parts := []string{}
	if critCount > 0 {
		parts = append(parts, fmt.Sprintf("%d CRITICAL", critCount))
	}
	if highCount > 0 {
		parts = append(parts, fmt.Sprintf("%d HIGH", highCount))
	}
	if medCount > 0 {
		parts = append(parts, fmt.Sprintf("%d MEDIUM", medCount))
	}
	if lowCount > 0 {
		parts = append(parts, fmt.Sprintf("%d LOW", lowCount))
	}
	summary := strings.Join(parts, ", ")

	tableHeader := `<table><tr><th style="width:220px;">Advisory</th><th style="width:90px;">Severity</th>`
	if hasCVSS {
		tableHeader += `<th style="width:60px;">CVSS</th>`
	}
	tableHeader += `<th>Description</th></tr>`

	return fmt.Sprintf(
		`    <section><h2>🔴 OpenClaw Known Vulnerabilities — %s</h2>`+
			`<div class="wbox">⚠️ <strong>%s vulnerabilities — upgrade OpenClaw to the latest available version</strong></div>`+
			`<p style="color:#94a3b8;font-size:.82rem;margin:8px 0 12px;">Each row below is a known CVE or security advisory that affects your installed version. `+
			`<strong style="color:#cbd5e1;">Severity</strong> reflects the advisory rating (CRITICAL → LOW) — all listed items require an upgrade to resolve.</p>`+
			`%s%s</table>`+
			`<p class="mut">%s</p>`+
			`</section>`,
		e(r.Version), e(summary), tableHeader, rows, dbFooterHTML(),
	)
}

// renderThreatIntel renders the Threat Intelligence section.
func renderThreatIntel(r *threat.Result) string {
	if r == nil {
		return `    <section><h2>🛡️ Threat Intelligence</h2><div style="background:#1c1917;border:1px solid #44403c;border-radius:12px;padding:24px;text-align:center;color:#a8a29e;">Threat Intelligence scan not run. Use <code>--no-threat-intel</code> to skip it, or re-run without that flag to include breach databases, IoC indicators, and CVE exposure.</div></section>`
	}

	var sections strings.Builder

	// Shodan
	if r.Shodan.Skipped {
		sections.WriteString(fmt.Sprintf(`<h3>🔍 Shodan InternetDB</h3><p class="mut">Skipped: %s</p>`, e(r.Shodan.SkipReason)))
	} else if r.Shodan.Error != "" {
		sections.WriteString(fmt.Sprintf(`<h3>🔍 Shodan InternetDB</h3><p style="color:#f87171;">Error: %s</p>`, e(r.Shodan.Error)))
	} else {
		portPills := `<span class="mut">none</span>`
		if len(r.Shodan.Ports) > 0 {
			pills := ""
			for _, p := range r.Shodan.Ports {
				pills += fmt.Sprintf(`<span class="pp">%d</span>`, p)
			}
			portPills = `<div class="pills">` + pills + `</div>`
		}
		vulnItems := `<li class="mut">No CVEs flagged</li>`
		if len(r.Shodan.Vulns) > 0 {
			vulnItems = ""
			for _, v := range r.Shodan.Vulns {
				vulnItems += fmt.Sprintf(`<li style="color:#f87171;"><code>%s</code></li>`, e(v))
			}
		}
		tags := "none"
		if len(r.Shodan.Tags) > 0 {
			tags = e(strings.Join(r.Shodan.Tags, ", "))
		}
		hosts := "none"
		if len(r.Shodan.Hostnames) > 0 {
			parts := make([]string, len(r.Shodan.Hostnames))
			for i, h := range r.Shodan.Hostnames {
				parts[i] = fmt.Sprintf("<code>%s</code>", e(h))
			}
			hosts = strings.Join(parts, ", ")
		}
		sections.WriteString(fmt.Sprintf(
			`<h3>🔍 Shodan InternetDB</h3><table>`+
				`<tr><td style="width:140px;">Open Ports</td><td>%s</td></tr>`+
				`<tr><td>CVEs</td><td><ul style="margin:0;padding-left:18px;">%s</ul></td></tr>`+
				`<tr><td>Tags</td><td>%s</td></tr>`+
				`<tr><td>Hostnames</td><td>%s</td></tr></table>`,
			portPills, vulnItems, tags, hosts,
		))
	}

	// AbuseIPDB
	if r.AbuseIPDB.Skipped {
		sections.WriteString(fmt.Sprintf(`<h3>🚨 AbuseIPDB</h3><p class="mut">Skipped: %s</p>`, e(r.AbuseIPDB.SkipReason)))
	} else if r.AbuseIPDB.Error != "" {
		sections.WriteString(fmt.Sprintf(`<h3>🚨 AbuseIPDB</h3><p style="color:#f87171;">Error: %s</p>`, e(r.AbuseIPDB.Error)))
	} else {
		score := r.AbuseIPDB.AbuseScore
		barColor := "#16a34a"
		if score >= 50 {
			barColor = "#dc2626"
		} else if score >= 20 {
			barColor = "#d97706"
		}
		ispRow := ""
		if r.AbuseIPDB.ISP != "" {
			ispRow = fmt.Sprintf(`<tr><td>ISP</td><td>%s</td></tr>`, e(r.AbuseIPDB.ISP))
		}
		sections.WriteString(fmt.Sprintf(
			`<h3>🚨 AbuseIPDB</h3>`+
				`<div style="margin-bottom:12px;">`+
				`<div style="font-size:.85rem;margin-bottom:4px;">Abuse Confidence Score: <strong style="color:%s;">%d%%</strong></div>`+
				`<div style="background:#334155;border-radius:6px;height:16px;overflow:hidden;">`+
				`<div style="background:%s;height:100%%;width:%d%%;border-radius:6px;"></div></div></div>`+
				`<table><tr><td>Total Reports</td><td>%d</td></tr>`+
				`<tr><td>Last Reported</td><td>%s</td></tr>%s</table>`,
			barColor, score,
			barColor, min(score, 100),
			r.AbuseIPDB.TotalReports,
			e(r.AbuseIPDB.LastReported),
			ispRow,
		))
	}

	// Local IoC
	iocTotal := len(r.LocalIOC.SuspiciousCron) + len(r.LocalIOC.SuspiciousProcesses) +
		len(r.LocalIOC.SuspiciousTempFiles) + len(r.LocalIOC.SSHPersistence) +
		len(r.LocalIOC.ListeningBackdoors) + len(r.LocalIOC.AuthAnomalies)
	if iocTotal > 0 {
		sections.WriteString(fmt.Sprintf(`<h3>🔎 Local Indicators of Compromise</h3><div class="wbox">⚠️ <strong>%d indicator(s) found</strong></div>`, iocTotal))
		for _, cat := range []struct {
			label string
			items []string
		}{
			{"Suspicious Cron Jobs", r.LocalIOC.SuspiciousCron},
			{"Suspicious Processes", r.LocalIOC.SuspiciousProcesses},
			{"Suspicious Temp Files", r.LocalIOC.SuspiciousTempFiles},
			{"SSH Persistence", r.LocalIOC.SSHPersistence},
			{"Listening Backdoors", r.LocalIOC.ListeningBackdoors},
			{"Auth Log Anomalies", r.LocalIOC.AuthAnomalies},
		} {
			if len(cat.items) == 0 {
				continue
			}
			rows := ""
			for _, item := range cat.items {
				rows += fmt.Sprintf(`<tr><td style="color:#f87171;">✖ %s</td></tr>`, e(item))
			}
			sections.WriteString(fmt.Sprintf(
				`<h4 style="color:#f87171;margin:10px 0 4px;">%s (%d)</h4><table>%s</table>`,
				e(cat.label), len(cat.items), rows,
			))
		}
	} else {
		sections.WriteString(`<h3>🔎 Local Indicators of Compromise</h3><p class="ok">✅ No indicators of compromise found</p>`)
	}

	// CVE Exposure
	if len(r.CVE.Findings) > 0 {
		rows := ""
		for _, f := range r.CVE.Findings {
			col := "#f97316"
			if strings.EqualFold(f.Severity, "critical") {
				col = "#dc2626"
			}
			rows += fmt.Sprintf(
				`<tr><td><span style="color:%s;font-weight:700;">%s</span></td>`+
					`<td><code>%s</code></td><td>%s <code>%s</code></td>`+
					`<td>%s</td><td><code>%s</code></td></tr>`,
				col, e(strings.ToUpper(f.Severity)),
				e(f.CVE), e(f.Package), e(f.Version),
				e(f.Desc), e(f.Fix),
			)
		}
		sections.WriteString(fmt.Sprintf(
			`<h3>🩹 CVE Exposure</h3><table>`+
				`<tr><th>Severity</th><th>CVE</th><th>Package</th><th>Description</th><th>Fix</th></tr>`+
				`%s</table>`, rows,
		))
	} else {
		sections.WriteString(fmt.Sprintf(
			`<h3>🩹 CVE Exposure</h3><p class="ok">✅ No known CVE exposure detected (%d packages checked)</p>`,
			len(r.CVE.PackagesChecked),
		))
	}

	// CISA KEV
	if r.CISAKEV.Error != "" {
		sections.WriteString(`<h3>⚫ CISA KEV — Active Exploits</h3><p style="color:#a8a29e;">CISA KEV feed unavailable — check network connectivity.</p>`)
	} else if len(r.CISAKEV.Matched) > 0 {
		rows := ""
		for _, m := range r.CISAKEV.Matched {
			rows += fmt.Sprintf(
				`<tr><td><span style="color:#dc2626;font-weight:700;">EXPLOITED</span></td>`+
					`<td><code>%s</code></td><td>%s <code>%s</code></td>`+
					`<td>%s</td><td>Due: %s</td></tr>`,
				e(m.CVE), e(m.InstalledPackage), e(m.InstalledVersion),
				e(m.Name), e(m.DueDate),
			)
		}
		sections.WriteString(fmt.Sprintf(
			`<h3>🔴 CISA KEV — Active Exploits (%d found)</h3>`+
				`<div class="wbox">⚠️ These vulnerabilities are being actively exploited in the wild. Patch immediately.</div>`+
				`<table><tr><th>Status</th><th>CVE</th><th>Package</th><th>Vulnerability</th><th>Remediation</th></tr>`+
				`%s</table>`,
			len(r.CISAKEV.Matched), rows,
		))
	} else {
		sections.WriteString(fmt.Sprintf(
			`<h3>🟢 CISA KEV — Active Exploits</h3><p class="ok">✅ No active KEV exploits detected in installed packages (%d entries checked)</p>`,
			r.CISAKEV.KEVTotal,
		))
	}

	return fmt.Sprintf(`    <section><h2>🛡️ Threat Intelligence</h2>%s</section>`, sections.String())
}

