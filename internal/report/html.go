package report

import (
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
)

var statusColors = map[scan.Status]string{
	scan.StatusPass: "#16a34a",
	scan.StatusFail: "#dc2626",
	scan.StatusWarn: "#d97706",
	scan.StatusSkip: "#6b7280",
}

var severityColors = map[scan.Severity]string{
	scan.SeverityCritical: "#dc2626",
	scan.SeverityHigh:     "#f97316",
	scan.SeverityMedium:   "#d97706",
	scan.SeverityLow:      "#6b7280",
}

var catOrder = []string{"SSH", "FW", "MACOS", "RPI"}

var catLabels = map[string]string{
	"SSH":   "🔑 SSH Hardening",
	"FW":    "🛡️ Firewall",
	"MACOS": "🍎 macOS Security",
	"RPI":   "🍓 Raspberry Pi Security",
}

var findingDocs = map[string]string{
	"SSH":   "docs/ssh-hardening.md",
	"MACOS": "docs/macos-hardening.md",
	"RPI":   "docs/raspberry-pi-hardening.md",
}

const findingDocsBase = "https://github.com/Anvil-Cloud-AI/anvil-scanner/blob/main/"

func e(s string) string { return html.EscapeString(s) }

func renderHTML(d Data) string {
	platform := d.Platform
	if platform == "" {
		platform = "unknown"
	}
	if d.IsRPi && d.RPiModel != "" {
		platform = d.RPiModel
	} else if d.IsRPi {
		platform = "Raspberry Pi"
	}

	ts := d.Timestamp.UTC().Format(time.RFC3339)
	if d.Timestamp.IsZero() {
		ts = time.Now().UTC().Format(time.RFC3339)
	}
	tsDate := ts[:10]

	priority := PriorityFindings(d.Checks)
	critCount := 0
	highCount := 0
	for _, c := range priority {
		if c.Severity == scan.SeverityCritical {
			critCount++
		} else {
			highCount++
		}
	}

	// Subnav tabs — only show tabs for non-empty sections.
	hasOCChecks := len(d.OCChecks) > 0
	hasOCVulns := d.OCVulnResult != nil
	showOCSection := hasOCChecks || hasOCVulns
	hasThreat := d.ThreatResult != nil

	type tab struct{ id, label string }
	tabs := []tab{{"summary", "Summary"}}
	if len(priority) > 0 {
		tabs = append(tabs, tab{"priority", "Priority"})
	}
	tabs = append(tabs, tab{"system", "System"})
	if showOCSection {
		tabs = append(tabs, tab{"openclaw", "OpenClaw"})
	}
	if hasThreat {
		tabs = append(tabs, tab{"threats", "Threat Intel"})
	}
	tabs = append(tabs, tab{"ai", "AI Analysis"})

	subnav := ""
	for _, t := range tabs {
		subnav += fmt.Sprintf(`<a href="#%s">%s</a>`, t.id, e(t.label))
	}

	// Risk score ring
	scoreNum := "N/A"
	scoreColor := "#6b7280"
	scoreLevel := "Unavailable"
	scoreDisplay := "N/A"
	scorePercent := 0
	if d.Analysis.RiskScore != nil {
		s := *d.Analysis.RiskScore
		scoreNum = fmt.Sprintf("%d", s)
		scoreDisplay = fmt.Sprintf("%d/10", s)
		scorePercent = s * 10
		switch {
		case s >= 7:
			scoreColor = "#dc2626"
			scoreLevel = "Critical"
		case s >= 4:
			scoreColor = "#d97706"
			scoreLevel = "Moderate"
		default:
			scoreColor = "#16a34a"
			scoreLevel = "Low"
		}
	}

	// Scoreboard
	scard := func(lbl, val, col string) string {
		return fmt.Sprintf(
			`<div class="sc"><div class="sv" style="color:%s;">%s</div><div class="sl">%s</div></div>`,
			col, e(val), e(lbl),
		)
	}

	portColor := "#4ade80"
	if len(d.OpenPorts) > 0 {
		portColor = "#f59e0b"
	}
	updColor := "#4ade80"
	if d.PendingUpdates > 0 {
		updColor = "#f87171"
	}

	scorecard := fmt.Sprintf(
		`<div class="sc">
  <div class="ring"><div class="inner" style="color:%s;">%s</div></div>
  <div class="sl">Risk Score (%s)</div>
  <div style="margin-top:6px;font-size:.8rem;font-weight:600;color:%s;">%s</div>
</div>`,
		scoreColor, e(scoreNum),
		e(scoreDisplay),
		scoreColor, e(scoreLevel),
	)

	priorityCard := renderPriorityCard(critCount, highCount)

	scoreboard := fmt.Sprintf(`<div class="stats">
  %s
  %s
  %s
  %s
  %s
</div>`,
		scorecard,
		scard("Platform", platform, "#a78bfa"),
		scard("Open Ports", fmt.Sprintf("%d", len(d.OpenPorts)), portColor),
		scard("Pending Updates", fmt.Sprintf("%d", d.PendingUpdates), updColor),
		priorityCard,
	)

	// Priority Findings section
	priorityHTML := ""
	if len(priority) > 0 {
		items := ""
		for _, f := range priority {
			sc := severityColors[f.Severity]
			prefix := strings.SplitN(string(f.ID), "-", 2)[0]
			fixLink := ""
			if docPath, ok := findingDocs[prefix]; ok {
				fixLink = fmt.Sprintf(
					` <a href="%s%s" target="_blank" style="color:#60a5fa;font-size:.85em;white-space:nowrap;">How to fix →</a>`,
					findingDocsBase, docPath,
				)
			}
			detail := e(f.Detail)
			if f.Remediation != "" {
				detail += "<br><em>" + e(f.Remediation) + "</em>"
			}
			items += fmt.Sprintf(
				`<div class="finding"><div class="fh"><span class="fsev" style="background:%s;">%s</span><strong>[%s] %s</strong></div><p>%s%s</p></div>`,
				sc, e(strings.ToUpper(string(f.Severity))),
				e(string(f.ID)), e(f.Name),
				detail, fixLink,
			)
		}
		icon := "🟠"
		if critCount > 0 {
			icon = "🔴"
		}
		parts := []string{}
		if critCount > 0 {
			parts = append(parts, fmt.Sprintf("%d Critical", critCount))
		}
		if highCount > 0 {
			parts = append(parts, fmt.Sprintf("%d High", highCount))
		}
		hdrBreakdown := strings.Join(parts, ", ")
		priorityHTML = fmt.Sprintf(
			`<div id="priority" data-nav-section>
  <section>
    <h2>%s Priority Findings — %s — Action Required</h2>
    <div class="alert-box">%s</div>
  </section>
</div>`,
			icon, e(hdrBreakdown), items,
		)
	}

	// Open Ports
	portPills := `<span class="mut">none detected</span>`
	if len(d.OpenPorts) > 0 {
		exposedSet := make(map[string]bool, len(d.ExposedOCPorts))
		for _, p := range d.ExposedOCPorts {
			exposedSet[p] = true
		}
		pills := ""
		for _, p := range d.OpenPorts {
			cls := "pp"
			if exposedSet[p] {
				cls = "pp ppw"
			}
			pills += fmt.Sprintf(`<span class="%s">%s</span>`, cls, e(p))
		}
		portPills = pills
	}

	ocWarnHTML := ""
	if len(d.ExposedOCPorts) > 0 {
		items := ""
		for _, p := range d.ExposedOCPorts {
			items += fmt.Sprintf(
				`<li>Port <code>%s</code> — restrict to trusted IPs or place behind a reverse proxy/VPN</li>`,
				e(p),
			)
		}
		ocWarnHTML = fmt.Sprintf(`<div class="wbox"><strong>⚠️ Exposed OpenClaw Ports</strong><ul>%s</ul></div>`, items)
	}

	// SSH config table
	sshConfigHTML := renderSSHConfig(d, platform)

	// Fail2ban (Linux only)
	isMacOS := strings.EqualFold(platform, "darwin") || strings.EqualFold(platform, "macos")
	fail2banHTML := ""
	if !isMacOS && d.Fail2ban != nil {
		f2bInst := "🔴 No"
		if d.Fail2ban.Installed {
			f2bInst = "🟢 Yes"
		}
		f2bRun := "🔴 No"
		if d.Fail2ban.Running {
			f2bRun = "🟢 Yes"
		}
		jails := "none"
		if len(d.Fail2ban.Jails) > 0 {
			jails = e(strings.Join(d.Fail2ban.Jails, ", "))
		}
		fail2banHTML = fmt.Sprintf(`
  <section>
    <h2>🚫 fail2ban</h2>
    <table>
      <tr><th>Check</th><th>Status</th></tr>
      <tr><td>Installed</td><td>%s</td></tr>
      <tr><td>Running</td><td>%s</td></tr>
      <tr><td>Active Jails</td><td>%s</td></tr>
    </table>
  </section>`, f2bInst, f2bRun, jails)
	}

	// Extended Hardening Checks
	extHTML := renderExtendedChecks(d.Checks)

	// AI section
	aiHTML := renderAISection(d.Analysis)

	var b strings.Builder
	b.WriteString(fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Anvil Scanner Report — %s</title>
<style>
:root{--bg-0:#0a0c11;--bg-1:#10131a;--bg-2:#171b24;--bg-3:#1f2430;--border:#252b37;--border-soft:#1b1f29;--text:#e5e9f0;--text-dim:#a0a8b8;--text-mut:#6b7385;--accent:#5fb4ff;--accent-dim:#3b82f6;--crit:#ef4444;--high:#f97316;--med:#eab308;--low:#60a5fa;--ok:#4ade80;--pass:#22c55e}
*,*::before,*::after{box-sizing:border-box}
html{scroll-behavior:smooth}
body{font-family:-apple-system,BlinkMacSystemFont,"Inter","Segoe UI",sans-serif;background:var(--bg-0);color:var(--text);margin:0;padding:0;font-size:15px;line-height:1.55;-webkit-font-smoothing:antialiased}
.topbar{position:sticky;top:0;z-index:50;background:rgba(16,19,26,.88);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px;padding:14px 32px}
.topbar-inner{max-width:1040px;margin:0 auto;width:100%%;display:flex;align-items:center;gap:12px}
.brand{display:flex;align-items:center;gap:10px}
.brand-mark{width:26px;height:26px;border-radius:6px;background:linear-gradient(135deg,var(--accent) 0%%,#8b5cf6 100%%);display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;color:#0a0c11}
.topbar h1{margin:0;font-size:1.05rem;color:#f3f5f9;font-weight:600;letter-spacing:-.01em}
.topbar-meta{color:var(--text-dim);font-size:.8rem;margin-left:auto;display:flex;align-items:center;gap:14px;font-variant-numeric:tabular-nums}
.subnav{position:sticky;top:55px;z-index:49;background:rgba(10,12,17,.92);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);border-bottom:1px solid var(--border);padding:0 32px;overflow-x:auto;scrollbar-width:none}
.subnav::-webkit-scrollbar{display:none}
.subnav-inner{max-width:1040px;margin:0 auto;display:flex;gap:4px;align-items:center}
.subnav a{display:inline-block;padding:12px 14px;color:var(--text-dim);font-size:.83rem;text-decoration:none;border-bottom:2px solid transparent;white-space:nowrap;transition:color .15s ease,border-color .15s ease;font-weight:500}
.subnav a:hover{color:var(--text)}
.subnav a.active{color:var(--accent);border-bottom-color:var(--accent)}
.wrap{max-width:1040px;margin:0 auto;padding:28px 24px 40px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px;margin-bottom:24px}
.sc{background:var(--bg-1);border:1px solid var(--border);border-radius:10px;padding:18px 16px;text-align:center;transition:border-color .15s ease}
.sc:hover{border-color:var(--bg-3)}
.sv{font-size:1.55rem;font-weight:700;line-height:1;letter-spacing:-.02em}
.sl{font-size:.7rem;color:var(--text-mut);margin-top:6px;text-transform:uppercase;letter-spacing:.06em;font-weight:600}
.ring{width:86px;height:86px;border-radius:50%%;background:conic-gradient(%s %d%%,var(--bg-3) 0%%);display:flex;align-items:center;justify-content:center;margin:0 auto 8px}
.inner{width:64px;height:64px;border-radius:50%%;background:var(--bg-1);display:flex;align-items:center;justify-content:center;font-size:1.3rem;font-weight:700;letter-spacing:-.02em}
section{background:var(--bg-1);border:1px solid var(--border);border-radius:12px;padding:22px 24px;margin-bottom:18px;overflow-x:auto;scroll-margin-top:120px}
section h2{margin:0 0 14px;font-size:1.0rem;color:#f1f5f9;border-bottom:1px solid var(--border);padding-bottom:10px;font-weight:600;letter-spacing:-.01em}
section h3{font-size:.88rem;color:#d4d9e2;margin:16px 0 8px;font-weight:600;letter-spacing:-.005em}
table{width:100%%;border-collapse:collapse;font-size:.86rem;table-layout:fixed}
th{text-align:left;padding:9px 12px;background:var(--bg-0);color:var(--text-mut);font-weight:600;font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;word-break:break-word;overflow-wrap:anywhere;border-bottom:1px solid var(--border)}
td{padding:10px 12px;border-top:1px solid var(--border-soft);word-break:break-word;overflow-wrap:anywhere;color:var(--text)}
td code,.finding code{white-space:pre-wrap;overflow-wrap:anywhere;display:inline-block;max-width:100%%}
code{background:var(--bg-0);padding:2px 6px;border-radius:4px;font-size:.82em;color:#7dd3fc;font-family:"SF Mono",Menlo,Consolas,monospace}
ul{margin:4px 0;padding-left:20px}
li{margin-bottom:6px;line-height:1.55}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.pills{display:flex;flex-wrap:wrap;gap:8px}
.pp{background:var(--bg-0);border:1px solid var(--border);color:#7dd3fc;padding:4px 12px;border-radius:20px;font-family:"SF Mono",Menlo,Consolas,monospace;font-size:.82em}
.ppw{border-color:#dc2626!important;color:#fca5a5!important;background:#3b0a0a!important}
.alert-box{border-left:3px solid var(--crit);padding-left:16px}
.finding{margin-bottom:12px;padding:14px 16px;background:var(--bg-0);border:1px solid var(--border-soft);border-radius:8px}
.fh{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.fsev{color:#fff;padding:2px 10px;border-radius:12px;font-size:.7em;font-weight:700;letter-spacing:.04em;text-transform:uppercase}
.finding p{margin:0;color:var(--text-dim);font-size:.88rem;line-height:1.55}
.wbox{background:#1c1208;border:1px solid #854d0e;border-radius:8px;padding:12px 16px;margin-bottom:12px;color:#fde68a;font-size:.88rem}
.ovbox{background:var(--bg-0);border-left:3px solid var(--accent);border-radius:0 8px 8px 0;padding:14px 18px;margin-bottom:16px}
.ovbox p{margin:0;color:var(--text);line-height:1.6}
.ac{display:grid;grid-template-columns:1fr 1fr;gap:20px}
@media(max-width:600px){.ac{grid-template-columns:1fr}.topbar{padding:12px 16px}.subnav{padding:0 16px}.wrap{padding:20px 16px 32px}}
.ok{color:var(--ok)}
.mut{color:var(--text-mut);font-style:italic}
.ai-fail{background:#2a0e0e;border:1px solid #7f1d1d;border-left:4px solid var(--crit);border-radius:8px;padding:14px 18px;margin-bottom:16px;color:#fecaca}
.ai-fail strong{color:#fca5a5;display:block;margin-bottom:6px;font-size:.95rem;letter-spacing:.02em;text-transform:uppercase}
.ai-fail p{margin:4px 0;color:#fecaca;font-size:.9rem;line-height:1.5}
.ai-fail ul{margin:6px 0 0;padding-left:20px;color:#fecaca;font-size:.88rem}
.ai-fail li{margin:3px 0;line-height:1.5}
.ai-skip{background:var(--bg-0);border:1px dashed var(--border);border-radius:8px;padding:14px 18px;margin-bottom:16px;color:var(--text-mut);font-size:.9rem;font-style:italic}
.ai-skip code{background:#020617;padding:1px 5px;border-radius:4px;color:var(--text-dim);font-style:normal;font-size:.9em}
.ai-disclaimer{margin-top:14px;padding:10px 14px;background:#1c1208;border-left:3px solid #ca8a04;border-radius:0 6px 6px 0;color:#fde68a;font-size:.82rem;line-height:1.5}
.ai-disclaimer strong{color:#fcd34d}
footer{text-align:center;color:var(--text-mut);font-size:.78rem;padding:28px 24px 36px;border-top:1px solid var(--border-soft);margin-top:16px}
</style>
</head>
<body>
`, e(tsDate), scoreColor, scorePercent))

	b.WriteString(fmt.Sprintf(`<div class="topbar">
  <div class="topbar-inner">
    <div class="brand">
      <span class="brand-mark">A</span>
      <h1>Anvil Scanner</h1>
    </div>
    <span class="topbar-meta">%s &nbsp;·&nbsp; %s</span>
  </div>
</div>
<nav class="subnav"><div class="subnav-inner">%s</div></nav>
<div class="wrap">
`, e(ts), e(platform), subnav))

	// Summary section
	b.WriteString(fmt.Sprintf(`  <div id="summary" data-nav-section>
    %s
  </div>
`, scoreboard))

	// Priority findings section
	if priorityHTML != "" {
		b.WriteString(priorityHTML + "\n")
	}

	// System section
	b.WriteString(fmt.Sprintf(`  <div id="system" data-nav-section>
    <section>
      <h2>🔌 Open Ports</h2>
      <div class="pills">%s</div>
      %s
    </section>
    <section>
      <h2>📦 Pending Updates</h2>
      <p style="margin:0;font-size:1.1rem;color:%s"><strong>%d</strong> package(s) awaiting upgrade</p>
    </section>
    <section>
      <h2>🔑 SSH Configuration</h2>
      <table><tr><th style="width:220px;">Directive</th><th>Value</th></tr>
      %s
      </table>
    </section>
%s
    %s
  </div>
`, portPills, ocWarnHTML,
		updColor, d.PendingUpdates,
		sshConfigHTML,
		fail2banHTML,
		extHTML))

	// OpenClaw section
	if showOCSection {
		ocContent := ""
		if hasOCChecks {
			ocContent += renderOCChecks(d.OCChecks)
		}
		if hasOCVulns {
			ocContent += renderOCVulns(d.OCVulnResult)
		}
		b.WriteString(fmt.Sprintf("  <div id=\"openclaw\" data-nav-section>\n%s\n  </div>\n", ocContent))
	}

	// Threat Intel section
	if hasThreat {
		b.WriteString(fmt.Sprintf("  <div id=\"threats\" data-nav-section>\n%s\n  </div>\n",
			renderThreatIntel(d.ThreatResult)))
	}

	// AI section
	b.WriteString(fmt.Sprintf(`  <div id="ai" data-nav-section>
    <section>
      <h2>🤖 AI Risk Analysis</h2>
      %s
    </section>
  </div>
`, aiHTML))

	b.WriteString(`</div>
<script>
(function(){
  var links = document.querySelectorAll('.subnav a');
  var byId = {};
  links.forEach(function(a){ byId[a.getAttribute('href').slice(1)] = a; });
  function setActive(id){
    links.forEach(function(a){ a.classList.remove('active'); });
    if (byId[id]) byId[id].classList.add('active');
  }
  var sections = document.querySelectorAll('[data-nav-section]');
  if (!sections.length || !('IntersectionObserver' in window)) return;
  var currentId = sections[0].id;
  setActive(currentId);
  var io = new IntersectionObserver(function(entries){
    entries.forEach(function(entry){
      if (entry.isIntersecting) currentId = entry.target.id;
    });
    setActive(currentId);
  }, { rootMargin: '-120px 0px -60% 0px', threshold: 0 });
  sections.forEach(function(s){ io.observe(s); });
  links.forEach(function(a){
    a.addEventListener('click', function(){
      setActive(a.getAttribute('href').slice(1));
    });
  });
})();
</script>
`)

	b.WriteString(fmt.Sprintf(`<footer>
    Generated by Anvil Scanner &nbsp;·&nbsp; %s<br><br>
    <span style="font-size:.72rem;color:#475569;max-width:800px;display:inline-block;line-height:1.5;">
      <strong>Disclaimer:</strong> Anvil Scanner is provided as-is, without warranty of any kind. Security checks are best-effort and do not
      guarantee your system is secure or protected against all threats. AI-generated analysis may be inaccurate — always verify recommendations
      with a qualified security professional before acting. Applying hardening actions may disrupt services or lock you out of your system.
      The authors accept <strong>no liability</strong> for any damage, data loss, service disruption, or security breach arising from use of this tool.
      This is not a substitute for professional security audits or penetration testing. <strong>Use at your own risk.</strong>
    </span>
  </footer>
</body>
</html>`, e(ts)))

	return b.String()
}

func renderPriorityCard(critCount, highCount int) string {
	total := critCount + highCount
	sub := `font-size:.55em;color:#94a3b8;font-weight:600;letter-spacing:.05em;margin-left:.15em;`
	if total == 0 {
		return `<div class="sc"><div class="sv" style="color:#4ade80;">0</div><div class="sl">Priority Findings</div></div>`
	}
	rows := []string{}
	if critCount > 0 {
		rows = append(rows, fmt.Sprintf(
			`<span style="color:#dc2626;">%d</span><span style="%s">CRITICAL</span>`,
			critCount, sub,
		))
	}
	if highCount > 0 {
		rows = append(rows, fmt.Sprintf(
			`<span style="color:#f97316;">%d</span><span style="%s">HIGH</span>`,
			highCount, sub,
		))
	}
	return fmt.Sprintf(
		`<div class="sc"><div class="sv" style="line-height:1.25;">%s</div><div class="sl">Priority Findings</div></div>`,
		strings.Join(rows, "<br>"),
	)
}

