package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ── Color palette — matches vdb-org-manager / task-dashboard ──

var (
	colorCyan   = lipgloss.Color("#00e5ff")
	colorPurple = lipgloss.Color("#7c4dff")
	colorGreen  = lipgloss.Color("#00e676")
	colorRed    = lipgloss.Color("#ff1744")
	colorAmber  = lipgloss.Color("#ffc107")
	colorYellow = lipgloss.Color("#ffee58")
	colorDim    = lipgloss.Color("#607d8b")
	colorSubtle = lipgloss.Color("#b0bec5")
)

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(colorCyan)
	dimStyle      = lipgloss.NewStyle().Foreground(colorDim)
	errorStyle    = lipgloss.NewStyle().Foreground(colorRed)
	successStyle  = lipgloss.NewStyle().Foreground(colorGreen)
	labelStyle    = lipgloss.NewStyle().Foreground(colorPurple).Bold(true).Width(10)
	valueStyle    = lipgloss.NewStyle().Foreground(colorSubtle)
	cyanStyle     = lipgloss.NewStyle().Foreground(colorCyan)
	amberStyle    = lipgloss.NewStyle().Foreground(colorAmber)
	yellowStyle   = lipgloss.NewStyle().Foreground(colorYellow)
	selectedStyle = lipgloss.NewStyle().Foreground(colorCyan).Bold(true)
	normalStyle   = lipgloss.NewStyle().Foreground(colorSubtle)
	focusedStyle  = lipgloss.NewStyle().Foreground(colorAmber).Bold(true)
)

const leftColWidth = 32
const sepWidth = 3 // " │ "

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// ── Main view ─────────────────────────────────────────────────

func renderMainView(m model) string {
	rightWidth := m.width - leftColWidth - sepWidth
	if rightWidth < 20 {
		rightWidth = 20
	}

	// Auth line
	var authLine string
	if m.authMethod == "" {
		authLine = amberStyle.Render("  No CLI credentials found — results may be limited")
	} else {
		authLine = dimStyle.Render("  auth: ") +
			cyanStyle.Render(m.authMethod) +
			dimStyle.Render("  org: ") +
			valueStyle.Render(m.authOrgID)
	}
	authLine += renderHealthStatus(m) + renderResponseMeta(m)

	// Header with CLI version
	titleStr := titleStyle.Render("VDB Vulnerability Explorer")
	cliInfo := ""
	if m.cliVersion != "" {
		cliInfo = dimStyle.Render("  CLI: ") + cyanStyle.Render(m.cliVersion) +
			dimStyle.Render(" ("+m.cliSource+")")
	} else if m.cliSource == "not found" {
		cliInfo = dimStyle.Render("  CLI: ") + amberStyle.Render("not found")
	}

	header := titleStr + cliInfo + "\n" +
		authLine + "\n" +
		dimStyle.Render(strings.Repeat("─", m.width))

	// Content rows available between the 3-line header and the 24-line panel.
	// Reserve 3 rows for input line + status line + separator inside the left pane.
	contentRows := m.height - 3 - cliLogPanelHeight
	maxItems := contentRows - 3
	if maxItems < 3 {
		maxItems = 3
	}

	leftPane := renderLeftPane(m, leftColWidth, maxItems)
	rightPane := renderRightPane(m, rightWidth)

	sep := dimStyle.Render(" │ ")
	combined := lipgloss.JoinHorizontal(lipgloss.Top, leftPane, sep, rightPane)

	return header + "\n" + combined
}

// ── Left pane ─────────────────────────────────────────────────

func renderLeftPane(m model, width int, maxItems int) string {
	var sb strings.Builder

	// Search input row
	cursor := cyanStyle.Render("█")
	inputLabel := dimStyle.Render("Search: ")
	var inputContent string
	if m.focus == focusInput {
		inputContent = focusedStyle.Render(m.searchInput) + cursor
	} else {
		inputContent = valueStyle.Render(m.searchInput) + " "
	}
	histBadge := ""
	if m.historyIdx >= 0 {
		histBadge = " " + dimStyle.Render(fmt.Sprintf("[%d/%d]", m.historyIdx+1, len(m.searchHistory)))
	}
	sb.WriteString(inputLabel + inputContent + histBadge + "\n")

	// Search status: countdown → spinner → results/error; nothing when idle.
	var statusLine string
	switch {
	case m.searching:
		frame := spinnerFrames[m.spinnerFrame%len(spinnerFrames)]
		statusLine = cyanStyle.Render(frame + " Searching…")
	case m.debounceMs > 0:
		statusLine = amberStyle.Render(fmt.Sprintf("⏱ %.1fs", float64(m.debounceMs)/1000.0))
	case m.searchErr != "":
		statusLine = errorStyle.Render("Error")
	case len(m.results) > 0:
		statusLine = cyanStyle.Render(fmt.Sprintf("RESULTS (%d of %d)", len(m.results), m.searchTotal))
	case searchable(m.searchInput):
		statusLine = dimStyle.Render("No results")
	}
	if statusLine != "" {
		sb.WriteString(statusLine + "\n")
	}
	sb.WriteString(dimStyle.Render(strings.Repeat("─", width)) + "\n")

	if m.searchErr != "" {
		sb.WriteString(errorStyle.Width(width).Render(m.searchErr) + "\n")
	} else {
		shown := 0
		for i, id := range m.results {
			if shown >= maxItems {
				remaining := len(m.results) - i
				sb.WriteString(dimStyle.Render(fmt.Sprintf("  +%d more", remaining)) + "\n")
				break
			}
			if i == m.resultCursor && m.focus == focusList {
				sb.WriteString(cyanStyle.Render("▶ ") + selectedStyle.Render(id) + "\n")
			} else if id == m.selectedID {
				sb.WriteString("  " + cyanStyle.Render(id) + "\n")
			} else {
				sb.WriteString("  " + normalStyle.Render(id) + "\n")
			}
			shown++
		}
	}

	return sb.String()
}

// ── Right pane ────────────────────────────────────────────────

func renderRightPane(m model, width int) string {
	if m.selectedID == "" {
		return "\n\n  " + dimStyle.Render("Select a vulnerability from the list to view details")
	}

	if m.loadingDetail {
		return "\n\n  " + dimStyle.Render("Loading "+m.selectedID+"…")
	}

	if m.detailErr != "" {
		return "\n\n  " + errorStyle.Render("Error: "+m.detailErr)
	}

	// Collect all panel lines
	var allLines []string
	allLines = append(allLines, renderTitleLine(m.selectedID)...)
	allLines = append(allLines, renderMetadataPanel(m, width)...)
	allLines = append(allLines, renderDescriptionPanel(m, width)...)
	allLines = append(allLines, renderCvssPanel(m, width)...)
	allLines = append(allLines, renderEpssKevPanel(m, width)...)
	allLines = append(allLines, renderProblemTypesPanel(m, width)...)
	allLines = append(allLines, renderAffectedPanel(m, width)...)
	allLines = append(allLines, renderReferencesPanel(m, width)...)
	allLines = append(allLines, renderExploitPanel(m, width)...)
	allLines = append(allLines, renderFixPanel(m, width)...)
	allLines = append(allLines, renderTimelinePanel(m, width)...)
	allLines = append(allLines, renderCreditsPanel(m, width)...)

	// Pagination: show panelLines lines; grow with "m".
	limit := m.panelLines
	if limit <= 0 {
		limit = m.pageSize()
	}

	if len(allLines) <= limit {
		return strings.Join(allLines, "\n")
	}

	remaining := len(allLines) - limit
	return strings.Join(allLines[:limit], "\n") + "\n" +
		amberStyle.Render(fmt.Sprintf("  ─── [m/PgDn] more · [l/PgUp] less ─── %d more lines", remaining))
}

func renderTitleLine(id string) []string {
	return []string{
		titleStyle.Render(id),
		"",
	}
}

// ── Panel renderers ───────────────────────────────────────────

func renderMetadataPanel(m model, _ int) []string {
	if m.vulnData == nil {
		return nil
	}
	meta := m.vulnData.CveMetadata
	cna := m.vulnData.Containers.CNA

	var rows []string
	rows = append(rows, panelHeader("METADATA"))
	rows = append(rows, labelVal("ID", meta.CveId))
	rows = append(rows, labelVal("State", meta.State))

	assignerName := meta.AssignerShortName
	if cna != nil && cna.ProviderMetadata != nil && cna.ProviderMetadata.ShortName != "" {
		assignerName = cna.ProviderMetadata.ShortName
	}
	if assignerName != "" {
		rows = append(rows, labelVal("CNA", assignerName))
	}

	if pub := shortDate(meta.DatePublished); pub != "" {
		rows = append(rows, labelVal("Published", pub))
	}
	if upd := shortDate(meta.DateUpdated); upd != "" {
		rows = append(rows, labelVal("Updated", upd))
	}
	rows = append(rows, "")
	return rows
}

func renderDescriptionPanel(m model, width int) []string {
	if m.vulnData == nil || m.vulnData.Containers.CNA == nil {
		return nil
	}
	desc := firstEnglish(m.vulnData.Containers.CNA.Descriptions)
	if desc == "" {
		return nil
	}

	var rows []string
	rows = append(rows, panelHeader("DESCRIPTION"))
	rows = append(rows, wrapText(desc, width-2)...)
	rows = append(rows, "")
	return rows
}

func renderCvssPanel(m model, _ int) []string {
	if m.vulnData == nil {
		return nil
	}

	// Collect metrics from CNA and all ADP containers
	var allMetrics []Metric
	if m.vulnData.Containers.CNA != nil {
		allMetrics = append(allMetrics, m.vulnData.Containers.CNA.Metrics...)
	}
	for _, adp := range m.vulnData.Containers.ADP {
		allMetrics = append(allMetrics, adp.Metrics...)
	}
	if len(allMetrics) == 0 {
		return nil
	}

	type cvssRow struct {
		label string
		score *CvssScore
	}

	seen := map[string]bool{}
	var entries []cvssRow
	for _, metric := range allMetrics {
		if metric.CvssV4_0 != nil && !seen["v4.0"] {
			seen["v4.0"] = true
			entries = append(entries, cvssRow{"V4.0", metric.CvssV4_0})
		}
		if metric.CvssV3_1 != nil && !seen["v3.1"] {
			seen["v3.1"] = true
			entries = append(entries, cvssRow{"V3.1", metric.CvssV3_1})
		}
		if metric.CvssV3_0 != nil && !seen["v3.0"] {
			seen["v3.0"] = true
			entries = append(entries, cvssRow{"V3.0", metric.CvssV3_0})
		}
		if metric.CvssV2_0 != nil && !seen["v2.0"] {
			seen["v2.0"] = true
			entries = append(entries, cvssRow{"V2.0", metric.CvssV2_0})
		}
	}
	if len(entries) == 0 {
		return nil
	}

	var rows []string
	rows = append(rows, panelHeader("CVSS METRICS"))
	for _, e := range entries {
		sev := e.score.BaseSeverity
		scoreStr := fmt.Sprintf("%.1f", e.score.BaseScore)
		sevColored := severityStyle(sev).Render(fmt.Sprintf("%-5s %s", scoreStr, strings.ToUpper(sev)))
		rows = append(rows, fmt.Sprintf("  %s  %s",
			cyanStyle.Render(e.label),
			sevColored,
		))
		if e.score.VectorString != "" {
			rows = append(rows, "        "+dimStyle.Render(e.score.VectorString))
		}
	}
	rows = append(rows, "")
	return rows
}

func renderEpssKevPanel(m model, _ int) []string {
	if m.vulnData == nil {
		return nil
	}

	var epssScore *float64
	var epssPerc *float64
	var kevStatus *bool
	var kevDueDate string

	for _, adp := range m.vulnData.Containers.ADP {
		if adp.XEpssScore != nil && epssScore == nil {
			epssScore = adp.XEpssScore
		}
		if adp.XEpssPercentile != nil && epssPerc == nil {
			epssPerc = adp.XEpssPercentile
		}
		if adp.XKevStatus != nil && kevStatus == nil {
			kevStatus = adp.XKevStatus
			kevDueDate = adp.XKevDueDate
		}
	}

	if epssScore == nil && kevStatus == nil {
		return nil
	}

	var rows []string
	rows = append(rows, panelHeader("EPSS / KEV"))

	if epssScore != nil {
		percStr := ""
		if epssPerc != nil {
			percStr = fmt.Sprintf("  (%dth percentile)", int(*epssPerc*100))
		}
		rows = append(rows, fmt.Sprintf("  %s  %.4f%s",
			labelStyle.Render("EPSS"),
			*epssScore,
			dimStyle.Render(percStr),
		))
	}

	if kevStatus != nil {
		if *kevStatus {
			due := ""
			if kevDueDate != "" {
				due = " — Due " + shortDate(kevDueDate)
			}
			rows = append(rows, fmt.Sprintf("  %s  %s%s",
				labelStyle.Render("KEV"),
				successStyle.Render("YES"),
				amberStyle.Render(due),
			))
		} else {
			rows = append(rows, fmt.Sprintf("  %s  %s",
				labelStyle.Render("KEV"),
				dimStyle.Render("No"),
			))
		}
	}

	if m.fixData != nil && m.fixData.KevRequiredAction != nil && *m.fixData.KevRequiredAction != "" {
		rows = append(rows, fmt.Sprintf("  %s  %s",
			labelStyle.Render("Action"),
			valueStyle.Render(*m.fixData.KevRequiredAction),
		))
	}

	rows = append(rows, "")
	return rows
}

func renderProblemTypesPanel(m model, _ int) []string {
	if m.vulnData == nil || m.vulnData.Containers.CNA == nil {
		return nil
	}
	pts := m.vulnData.Containers.CNA.ProblemTypes
	if len(pts) == 0 {
		return nil
	}

	var rows []string
	rows = append(rows, panelHeader("PROBLEM TYPES"))
	for _, pt := range pts {
		for _, d := range pt.Descriptions {
			if d.CweId != "" {
				rows = append(rows, fmt.Sprintf("  %s  %s",
					cyanStyle.Render(d.CweId),
					valueStyle.Render(d.Description),
				))
			} else if d.Description != "" {
				rows = append(rows, "  "+valueStyle.Render(d.Description))
			}
		}
	}
	rows = append(rows, "")
	return rows
}

func renderAffectedPanel(m model, _ int) []string {
	if m.vulnData == nil || m.vulnData.Containers.CNA == nil {
		return nil
	}
	affected := m.vulnData.Containers.CNA.Affected
	if len(affected) == 0 {
		return nil
	}

	var rows []string
	rows = append(rows, panelHeader("AFFECTED PRODUCTS"))
	for _, p := range affected {
		name := p.Vendor
		if p.Product != "" {
			if name != "" {
				name += " / " + p.Product
			} else {
				name = p.Product
			}
		}
		if p.PackageName != "" {
			name += " (" + p.PackageName + ")"
		}
		rows = append(rows, "  "+cyanStyle.Render(name))

		for _, v := range p.Versions {
			var vStr string
			switch {
			case v.LessThan != "":
				vStr = fmt.Sprintf("%s < %s", v.Version, v.LessThan)
			case v.LessThanOrEqual != "":
				vStr = fmt.Sprintf("%s ≤ %s", v.Version, v.LessThanOrEqual)
			default:
				vStr = v.Version
			}
			statusSt := dimStyle
			if v.Status == "affected" {
				statusSt = errorStyle
			} else if v.Status == "unaffected" {
				statusSt = successStyle
			}
			rows = append(rows, fmt.Sprintf("    %s %s",
				statusSt.Render(v.Status),
				dimStyle.Render(vStr),
			))
		}
	}
	rows = append(rows, "")
	return rows
}

func renderReferencesPanel(m model, width int) []string {
	if m.vulnData == nil || m.vulnData.Containers.CNA == nil {
		return nil
	}
	refs := m.vulnData.Containers.CNA.References
	if len(refs) == 0 {
		return nil
	}

	var rows []string
	rows = append(rows, panelHeader("REFERENCES"))
	for _, r := range refs {
		tagStr := ""
		if len(r.Tags) > 0 {
			tagStr = " " + formatRefTags(r.Tags)
		}
		url := r.URL
		maxURLLen := width - 6
		if maxURLLen > 0 && len(url) > maxURLLen {
			url = url[:maxURLLen-1] + "…"
		}
		rows = append(rows, fmt.Sprintf("  %s%s", dimStyle.Render(url), tagStr))
	}
	rows = append(rows, "")
	return rows
}

func exploitSourceStyle(source string) lipgloss.Style {
	switch strings.ToLower(source) {
	case "metasploit":
		return errorStyle
	case "nuclei", "vulncheck", "vulncheck_xdb":
		return cyanStyle
	case "exploitdb", "exploit_db", "vulnerabilitylab":
		return amberStyle
	case "crowdsec":
		return lipgloss.NewStyle().Foreground(colorPurple)
	default:
		return dimStyle
	}
}

func renderExploitPanel(m model, width int) []string {
	if m.exploitData == nil || m.exploitData.Count == 0 {
		return nil
	}
	s := m.exploitData.Summary

	var rows []string
	rows = append(rows, panelHeader("EXPLOIT INTELLIGENCE"))

	// Summary: total + per-source breakdown on one line
	type srcCount struct {
		label string
		val   int
	}
	all := []srcCount{
		{"Nuclei", s.Nuclei}, {"Metasploit", s.Metasploit},
		{"ExploitDB", s.ExploitDb}, {"CrowdSec", s.CrowdSec},
		{"GitHub", s.Github}, {"PoC", s.Poc},
		{"VulnCheckXDB", s.VulnCheckXDB}, {"VulnCheck", s.VulnCheckReportedExploitation},
		{"VulnLab", s.VulnerabilityLab}, {"Other", s.Other},
	}
	var active []string
	for _, sc := range all {
		if sc.val > 0 {
			active = append(active, fmt.Sprintf("%s:%d", sc.label, sc.val))
		}
	}
	rows = append(rows, fmt.Sprintf("  %s  %s",
		errorStyle.Render(fmt.Sprintf("%d exploit(s)", m.exploitData.Count)),
		dimStyle.Render(strings.Join(active, "  ")),
	))

	// Individual entries
	urlMax := width - 6
	if urlMax < 20 {
		urlMax = 20
	}
	for i, e := range m.exploitData.Exploits {
		rows = append(rows, "")
		src := strings.ToUpper(e.Source)
		if src == "" {
			src = "UNKNOWN"
		}
		dateStr := ""
		if e.DateAdded != "" {
			dateStr = "  " + dimStyle.Render(shortDate(e.DateAdded))
		}
		rows = append(rows, fmt.Sprintf("  %s%s",
			exploitSourceStyle(e.Source).Bold(true).Render(fmt.Sprintf("[%d] %s", i+1, src)),
			dateStr,
		))
		if e.URL != "" {
			rows = append(rows, "      "+dimStyle.Render(truncateURL(e.URL, urlMax)))
		}
		if e.Description != "" {
			for _, l := range wrapText(e.Description, width-6) {
				rows = append(rows, "    "+l)
			}
		}
	}

	rows = append(rows, "")
	return rows
}

func renderFixPanel(m model, width int) []string {
	if m.fixData == nil {
		return nil
	}

	var rows []string
	rows = append(rows, panelHeader("FIX INTELLIGENCE"))

	// Availability + summary counts
	if m.fixData.FixAvailability != "" {
		availSt := dimStyle
		avail := strings.ToLower(m.fixData.FixAvailability)
		if strings.Contains(avail, "available") && !strings.Contains(avail, "unavailable") {
			availSt = successStyle
		} else if strings.Contains(avail, "unavailable") || strings.Contains(avail, "none") {
			availSt = errorStyle
		}
		sum := m.fixData.Summary
		var sumParts []string
		if sum.PatchCount > 0 {
			sumParts = append(sumParts, fmt.Sprintf("%d patch(es)", sum.PatchCount))
		}
		if sum.WorkaroundCount > 0 {
			sumParts = append(sumParts, fmt.Sprintf("%d workaround(s)", sum.WorkaroundCount))
		}
		sumStr := ""
		if len(sumParts) > 0 {
			sumStr = "  " + dimStyle.Render("("+strings.Join(sumParts, " · ")+")")
		}
		rows = append(rows, fmt.Sprintf("  %s  %s%s",
			labelStyle.Render("Fix"),
			availSt.Render(m.fixData.FixAvailability),
			sumStr,
		))
	}

	// Timeline
	tl := m.fixData.Timeline
	if tl.DatePublished != "" {
		rows = append(rows, fmt.Sprintf("  %s  %s",
			labelStyle.Render("Published"),
			dimStyle.Render(shortDate(tl.DatePublished)),
		))
	}
	if tl.FirstPatchDate != nil && *tl.FirstPatchDate != "" {
		ttpStr := ""
		if tl.TimeToPatchDays != nil {
			ttpStr = fmt.Sprintf("  %s", dimStyle.Render(fmt.Sprintf("(%d days to patch)", *tl.TimeToPatchDays)))
		}
		rows = append(rows, fmt.Sprintf("  %s  %s%s",
			labelStyle.Render("1st patch"),
			dimStyle.Render(shortDate(*tl.FirstPatchDate)),
			ttpStr,
		))
	}
	if tl.LifecycleStage != "" {
		rows = append(rows, fmt.Sprintf("  %s  %s",
			labelStyle.Render("Stage"),
			valueStyle.Render(tl.LifecycleStage),
		))
	}

	// KEV required action (shown early — high priority)
	if m.fixData.KevRequiredAction != nil && *m.fixData.KevRequiredAction != "" {
		rows = append(rows, "")
		rows = append(rows, "  "+amberStyle.Bold(true).Render("KEV Required Action"))
		for _, l := range wrapText(*m.fixData.KevRequiredAction, width-4) {
			rows = append(rows, l)
		}
	}

	// Patch URLs
	urlMax := width - 6
	if urlMax < 20 {
		urlMax = 20
	}
	if len(m.fixData.Fixes.Patches) > 0 {
		rows = append(rows, "")
		rows = append(rows, "  "+successStyle.Render(fmt.Sprintf("Patches (%d)", len(m.fixData.Fixes.Patches))))
		for _, p := range m.fixData.Fixes.Patches {
			rows = append(rows, "      "+dimStyle.Render(truncateURL(p, urlMax)))
		}
	}

	// Workaround
	if m.fixData.Fixes.Workaround != "" {
		rows = append(rows, "")
		rows = append(rows, "  "+amberStyle.Render("Workaround"))
		for _, l := range wrapText(m.fixData.Fixes.Workaround, width-4) {
			rows = append(rows, l)
		}
	}

	// Mitigation
	if m.fixData.Fixes.Mitigation != "" {
		rows = append(rows, "")
		rows = append(rows, "  "+cyanStyle.Render("Mitigation"))
		for _, l := range wrapText(m.fixData.Fixes.Mitigation, width-4) {
			rows = append(rows, l)
		}
	}

	// CWE remediations
	if len(m.fixData.CweRemediations) > 0 {
		rows = append(rows, "")
		rows = append(rows, "  "+dimStyle.Render("CWE Remediations"))
		for _, rem := range m.fixData.CweRemediations {
			for _, l := range wrapText(rem, width-4) {
				rows = append(rows, l)
			}
		}
	}

	rows = append(rows, "")
	return rows
}

func renderTimelinePanel(m model, _ int) []string {
	if m.vulnData == nil || m.vulnData.Containers.CNA == nil {
		return nil
	}
	tl := m.vulnData.Containers.CNA.Timeline
	if len(tl) == 0 {
		return nil
	}

	var rows []string
	rows = append(rows, panelHeader("TIMELINE"))
	for _, item := range tl {
		rows = append(rows, fmt.Sprintf("  %s  %s",
			dimStyle.Render(shortDate(item.Time)),
			valueStyle.Render(item.Value),
		))
	}
	rows = append(rows, "")
	return rows
}

func renderCreditsPanel(m model, _ int) []string {
	if m.vulnData == nil || m.vulnData.Containers.CNA == nil {
		return nil
	}
	credits := m.vulnData.Containers.CNA.Credits
	if len(credits) == 0 {
		return nil
	}

	var rows []string
	rows = append(rows, panelHeader("CREDITS"))
	for _, c := range credits {
		t := ""
		if c.Type != "" {
			t = " (" + c.Type + ")"
		}
		rows = append(rows, "  "+valueStyle.Render(c.Value)+dimStyle.Render(t))
	}
	rows = append(rows, "")
	return rows
}

// ── Helpers ───────────────────────────────────────────────────

func panelHeader(title string) string {
	return cyanStyle.Bold(true).Render("── " + title + " ──")
}

func labelVal(key, val string) string {
	return fmt.Sprintf("  %s  %s", labelStyle.Render(key), valueStyle.Render(val))
}

func firstEnglish(descs []Description) string {
	for _, d := range descs {
		if strings.HasPrefix(strings.ToLower(d.Lang), "en") {
			return d.Value
		}
	}
	if len(descs) > 0 {
		return descs[0].Value
	}
	return ""
}

func shortDate(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

func wrapText(text string, width int) []string {
	if width <= 0 {
		width = 60
	}
	words := strings.Fields(text)
	var lines []string
	line := "  "
	for _, w := range words {
		if len(line)+len(w)+1 > width {
			lines = append(lines, valueStyle.Render(line))
			line = "  " + w
		} else {
			if line == "  " {
				line += w
			} else {
				line += " " + w
			}
		}
	}
	if line != "  " {
		lines = append(lines, valueStyle.Render(line))
	}
	return lines
}

func severityStyle(sev string) lipgloss.Style {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return errorStyle
	case "HIGH":
		return amberStyle
	case "MEDIUM":
		return yellowStyle
	case "LOW":
		return successStyle
	default:
		return dimStyle
	}
}

func renderHealthStatus(m model) string {
	var dot string
	switch m.healthStatus {
	case "ok":
		dot = successStyle.Render("●")
	case "degraded":
		dot = amberStyle.Render("●")
	case "down":
		dot = errorStyle.Render("●")
	default:
		dot = dimStyle.Render("○") // not yet checked
	}

	if m.healthChecking && m.healthStatus == "" {
		return dimStyle.Render("  API ") + dimStyle.Render("○ …")
	}

	latStr := ""
	if m.healthLatency > 0 {
		latStr = " " + dimStyle.Render(formatLatency(m.healthLatency))
	}
	return dimStyle.Render("  API ") + dot + latStr
}

func renderResponseMeta(m model) string {
	meta := m.responseMeta
	if meta.CacheStatus == "" && meta.RateDisplay == "" {
		return ""
	}
	var parts []string
	if meta.CacheStatus != "" {
		st := dimStyle
		switch strings.ToUpper(meta.CacheStatus) {
		case "HIT":
			st = successStyle
		case "MISS":
			st = amberStyle
		}
		parts = append(parts, dimStyle.Render("cache:")+st.Render(meta.CacheStatus))
	}
	if meta.RateDisplay != "" {
		parts = append(parts, dimStyle.Render("rate:")+valueStyle.Render(meta.RateDisplay))
	}
	return "  " + strings.Join(parts, "  ")
}

func truncateURL(url string, max int) string {
	if len(url) <= max {
		return url
	}
	return url[:max-1] + "…"
}

func formatLatency(ms int) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.1fs", float64(ms)/1000.0)
}

func formatRefTags(tags []string) string {
	var parts []string
	for _, tag := range tags {
		switch strings.ToLower(tag) {
		case "patch":
			parts = append(parts, successStyle.Render("["+tag+"]"))
		case "exploit":
			parts = append(parts, errorStyle.Render("["+tag+"]"))
		case "advisory":
			parts = append(parts, cyanStyle.Render("["+tag+"]"))
		case "vendor":
			parts = append(parts, amberStyle.Render("["+tag+"]"))
		default:
			parts = append(parts, dimStyle.Render("["+tag+"]"))
		}
	}
	return strings.Join(parts, " ")
}

// renderCLILogPanel renders the persistent bottom panel showing CLI activity log lines.
// Layout: separator | status line | 20 log lines (bottom-aligned) | margin | hotkey footer.
func renderCLILogPanel(m model) string {
	const showLines = 20
	var b strings.Builder

	b.WriteString(dimStyle.Render(strings.Repeat("─", m.width)) + "\n")

	// ── Status line ──────────────────────────────────────────────
	statusLine := fmt.Sprintf("%s CLI Activity Log  %s",
		successStyle.Render("●"),
		dimStyle.Render(fmt.Sprintf("(%d entries)", len(m.cliLogLines))),
	)
	b.WriteString(statusLine + "\n")

	// ── Log lines — bottom-aligned ───────────────────────────────
	lines := m.cliLogLines
	start := 0
	if len(lines) > showLines {
		start = len(lines) - showLines
	}
	shown := lines[start:]
	maxW := m.width - 2
	if maxW < 1 {
		maxW = 1
	}
	// Fill blank rows above so content anchors to bottom.
	for i := len(shown); i < showLines; i++ {
		b.WriteString("\n")
	}
	for _, l := range shown {
		if len(l) > maxW {
			l = l[:maxW]
		}
		b.WriteString(dimStyle.Render(l) + "\n")
	}

	// ── Small margin + footer with all hotkeys ───────────────────
	b.WriteString("\n") // margin
	eagerLabel := successStyle.Render("eager:on")
	if !m.eagerSearch {
		eagerLabel = dimStyle.Render("eager:off")
	}
	footer := dimStyle.Render("Tab focus  ↑/↓ nav  Enter sel  m more  Esc back  ^E ") +
		eagerLabel +
		dimStyle.Render("  ^O spec  q quit")
	if m.saveSpecStatus != "" {
		footer += "  " + valueStyle.Render(m.saveSpecStatus)
	}
	b.WriteString(footer + "\n")

	return b.String()
}
