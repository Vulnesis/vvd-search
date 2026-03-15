package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// ── Search structs ──────────────────────────────────────────

type SearchResponse struct {
	Identifiers []string `json:"identifiers"`
	Total       int      `json:"total"`
	HasMore     bool     `json:"hasMore"`
}

// ── CVE Record structs ──────────────────────────────────────

type CVERecord struct {
	DataType    string      `json:"dataType"`
	DataVersion string      `json:"dataVersion"`
	CveMetadata CVEMetadata `json:"cveMetadata"`
	Containers  Containers  `json:"containers"`
}

type CVEMetadata struct {
	CveId             string `json:"cveId"`
	State             string `json:"state"`
	AssignerShortName string `json:"assignerShortName"`
	AssignerOrgId     string `json:"assignerOrgId"`
	DatePublished     string `json:"datePublished"`
	DateUpdated       string `json:"dateUpdated"`
	DateReserved      string `json:"dateReserved"`
}

type Containers struct {
	CNA *CNAContainer  `json:"cna"`
	ADP []ADPContainer `json:"adp"`
}

type CNAContainer struct {
	Title            string            `json:"title"`
	DatePublic       string            `json:"datePublic"`
	Descriptions     []Description     `json:"descriptions"`
	Affected         []Product         `json:"affected"`
	References       []Reference       `json:"references"`
	Metrics          []Metric          `json:"metrics"`
	ProblemTypes     []ProblemType     `json:"problemTypes"`
	Timeline         []TimelineItem    `json:"timeline"`
	Credits          []Credit          `json:"credits"`
	ProviderMetadata *ProviderMetadata `json:"providerMetadata"`
}

type ADPContainer struct {
	Title            string            `json:"title"`
	DatePublic       string            `json:"datePublic"`
	Descriptions     []Description     `json:"descriptions"`
	Affected         []Product         `json:"affected"`
	References       []Reference       `json:"references"`
	Metrics          []Metric          `json:"metrics"`
	ProblemTypes     []ProblemType     `json:"problemTypes"`
	Timeline         []TimelineItem    `json:"timeline"`
	Credits          []Credit          `json:"credits"`
	ProviderMetadata *ProviderMetadata `json:"providerMetadata"`
	XEpssScore       *float64          `json:"x_epssScore"`
	XEpssPercentile  *float64          `json:"x_epssPercentile"`
	XKevStatus       *bool             `json:"x_kevStatus"`
	XKevDueDate      string            `json:"x_kevDueDate"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Product struct {
	Vendor        string         `json:"vendor"`
	Product       string         `json:"product"`
	CollectionURL string         `json:"collectionURL"`
	PackageName   string         `json:"packageName"`
	DefaultStatus string         `json:"defaultStatus"`
	Versions      []VersionEntry `json:"versions"`
}

type VersionEntry struct {
	Version         string `json:"version"`
	Status          string `json:"status"`
	VersionType     string `json:"versionType"`
	LessThan        string `json:"lessThan"`
	LessThanOrEqual string `json:"lessThanOrEqual"`
}

type Reference struct {
	URL  string   `json:"url"`
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type Metric struct {
	CvssV4_0 *CvssScore `json:"cvssV4_0"`
	CvssV3_1 *CvssScore `json:"cvssV3_1"`
	CvssV3_0 *CvssScore `json:"cvssV3_0"`
	CvssV2_0 *CvssScore `json:"cvssV2_0"`
}

type CvssScore struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

type ProblemType struct {
	Descriptions []ProblemTypeDesc `json:"descriptions"`
}

type ProblemTypeDesc struct {
	Lang        string `json:"lang"`
	Description string `json:"description"`
	CweId       string `json:"cweId"`
	Type        string `json:"type"`
}

type TimelineItem struct {
	Time  string `json:"time"`
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Credit struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
	Type  string `json:"type"`
}

type ProviderMetadata struct {
	OrgId     string `json:"orgId"`
	ShortName string `json:"shortName"`
}

// ── Exploit structs ─────────────────────────────────────────

type ExploitResponse struct {
	Identifier string         `json:"identifier"`
	Count      int            `json:"count"`
	Exploits   []ExploitEntry `json:"exploits"`
	Summary    ExploitSummary `json:"summary"`
}

type ExploitEntry struct {
	Source      string `json:"source"`
	URL         string `json:"url"`
	Description string `json:"description"`
	DateAdded   string `json:"dateAdded"`
}

type ExploitSummary struct {
	CrowdSec                      int `json:"crowdSec"`
	ExploitDb                     int `json:"exploitDb"`
	Github                        int `json:"github"`
	Metasploit                    int `json:"metasploit"`
	Nuclei                        int `json:"nuclei"`
	Other                         int `json:"other"`
	Poc                           int `json:"poc"`
	VulnCheckReportedExploitation int `json:"vulnCheckReportedExploitation"`
	VulnCheckXDB                  int `json:"vulnCheckXDB"`
	VulnerabilityLab              int `json:"vulnerabilityLab"`
}

// ── Fix structs ─────────────────────────────────────────────

type FixResponse struct {
	Identifier        string      `json:"identifier"`
	FixAvailability   string      `json:"fixAvailability"`
	Fixes             FixDetails  `json:"fixes"`
	Timeline          FixTimeline `json:"timeline"`
	Summary           FixSummary  `json:"summary"`
	CweRemediations   []string    `json:"cweRemediations"`
	KevRequiredAction *string     `json:"kevRequiredAction"`
}

type FixDetails struct {
	Patches    []string `json:"patches"`
	Workaround string   `json:"workaround"`
	Mitigation string   `json:"mitigation"`
}

type FixTimeline struct {
	DatePublished   string  `json:"datePublished"`
	FirstPatchDate  *string `json:"firstPatchDate"`
	LifecycleStage  string  `json:"lifecycle_stage"`
	TimeToPatchDays *int    `json:"timeToPatchDays"`
}

type FixSummary struct {
	PatchCount      int    `json:"patchCount"`
	WorkaroundCount int    `json:"workaroundCount"`
	Availability    string `json:"availability"`
}

// ── VDB Status response ─────────────────────────────────────

// VDBStatusResponse represents the JSON output of `vulnetix vdb status -o json`.
type VDBStatusResponse struct {
	API  *VDBStatusAPI  `json:"api"`
	Auth *VDBStatusAuth `json:"auth"`
}

type VDBStatusAPI struct {
	Status    string `json:"status"`    // "ok", "degraded", "down"
	LatencyMs int    `json:"latencyMs"` // round-trip ms
}

type VDBStatusAuth struct {
	Method string `json:"method"` // "apikey", "env:VVD_ORG", etc.
	OrgID  string `json:"orgId"`
}

// ── Response metadata ───────────────────────────────────────

// ResponseMeta captures API response metadata parsed from CLI stderr output.
type ResponseMeta struct {
	CacheStatus string // "HIT", "MISS", ""
	RateDisplay string // compact rate limit, e.g. "450/500 min", "unlimited"
}

var reMinuteRate = regexp.MustCompile(`([\d,]+)/([\d,]+)\s+requests?\s+remaining\s+this\s+minute`)
var reWeekRate = regexp.MustCompile(`\|\s*([\d,]+)/([\d,]+)\s+this\s+week`)

// parseResponseMeta extracts cache and rate limit info from CLI stderr output.
func parseResponseMeta(stderr []byte) ResponseMeta {
	var meta ResponseMeta
	for _, line := range strings.Split(string(stderr), "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)

		// Cache status: CLI prints "Cache: HIT" / "Cache: MISS";
		// also handle raw CloudFront "X-Cache: Hit from cloudfront" format.
		if strings.HasPrefix(lower, "cache:") || strings.HasPrefix(lower, "x-cache:") {
			val := strings.ToUpper(strings.TrimSpace(trimmed[strings.Index(trimmed, ":")+1:]))
			if strings.Contains(val, "HIT") {
				meta.CacheStatus = "HIT"
			} else if strings.Contains(val, "MISS") {
				meta.CacheStatus = "MISS"
			} else {
				meta.CacheStatus = val
			}
		}

		// Rate limit (CLI prints to stderr: "Rate limit: ...")
		if strings.HasPrefix(lower, "rate limit:") {
			meta.RateDisplay = compactRateLimit(trimmed)
		}
	}
	return meta
}

// compactRateLimit condenses the CLI's verbose rate limit line into a short display string.
func compactRateLimit(line string) string {
	idx := strings.Index(strings.ToLower(line), "rate limit:")
	if idx < 0 {
		return ""
	}
	after := strings.TrimSpace(line[idx+len("rate limit:"):])
	if strings.EqualFold(after, "unlimited") {
		return "unlimited"
	}

	var parts []string
	if m := reMinuteRate.FindStringSubmatch(line); len(m) > 1 {
		parts = append(parts, m[1]+"/"+m[2]+" min")
	}
	if m := reWeekRate.FindStringSubmatch(line); len(m) > 1 {
		parts = append(parts, m[1]+"/"+m[2]+" wk")
	}

	if len(parts) > 0 {
		return strings.Join(parts, " · ")
	}

	// Fallback: truncate the raw value
	if len(after) > 30 {
		after = after[:27] + "…"
	}
	return after
}

// ── Messages ────────────────────────────────────────────────

type debouncedSearchMsg struct {
	query string
	id    int64
}

type countdownTickMsg   struct{ id int64 }
type spinnerTickMsg     struct{}
type healthCheckTickMsg struct{}
type healthResultMsg    struct {
	status     string // "ok", "degraded", "down"
	latencyMs  int
	authMethod string
	authOrgID  string
}

type searchResultMsg struct {
	identifiers []string
	total       int
	err         string
	meta        ResponseMeta
}

type vulnResultMsg struct {
	data *CVERecord
	err  string
	meta ResponseMeta
}

type exploitResultMsg struct {
	data *ExploitResponse
	err  string
	meta ResponseMeta
}

type fixResultMsg struct {
	data *FixResponse
	err  string
	meta ResponseMeta
}

type saveSpecResultMsg struct {
	filename string
	err      string
}

// ── Commands ────────────────────────────────────────────────

func debounceCmd(query string, id int64) tea.Cmd {
	return tea.Tick(2*time.Second, func(_ time.Time) tea.Msg {
		return debouncedSearchMsg{query: query, id: id}
	})
}

// countdownTickCmd fires every 200ms while the debounce is counting down.
func countdownTickCmd(id int64) tea.Cmd {
	return tea.Tick(200*time.Millisecond, func(_ time.Time) tea.Msg {
		return countdownTickMsg{id: id}
	})
}

// spinnerTickCmd fires every 80ms to advance the search spinner.
func spinnerTickCmd() tea.Cmd {
	return tea.Tick(80*time.Millisecond, func(_ time.Time) tea.Msg {
		return spinnerTickMsg{}
	})
}

// scheduleHealthCheckCmd fires a healthCheckTickMsg after 30 seconds.
func scheduleHealthCheckCmd() tea.Cmd {
	return tea.Tick(30*time.Second, func(_ time.Time) tea.Msg {
		return healthCheckTickMsg{}
	})
}

// statusCmd runs `vulnetix vdb status -o json` and reports health + auth info.
func statusCmd(cliPath string) tea.Cmd {
	return func() tea.Msg {
		pushCLILog("vulnetix vdb status -o json")
		start := time.Now()
		out, _, errStr := runCLI(cliPath, []string{"vdb", "status", "-o", "json"})
		latencyMs := int(time.Since(start).Milliseconds())

		if errStr != "" {
			pushCLILog("status: %s (%dms)", errStr, latencyMs)
			return healthResultMsg{status: "down", latencyMs: latencyMs}
		}

		j := jsonFrom(out)
		if j == nil {
			pushCLILog("status: no JSON (%dms)", latencyMs)
			return healthResultMsg{status: "down", latencyMs: latencyMs}
		}

		var resp VDBStatusResponse
		if err := json.Unmarshal(j, &resp); err != nil {
			pushCLILog("status: parse error (%dms)", latencyMs)
			return healthResultMsg{status: "down", latencyMs: latencyMs}
		}

		result := healthResultMsg{latencyMs: latencyMs}
		if resp.API != nil {
			result.status = resp.API.Status
			if resp.API.LatencyMs > 0 {
				result.latencyMs = resp.API.LatencyMs
			}
		} else {
			result.status = "ok" // CLI ran fine, just no API status section
		}
		if resp.Auth != nil {
			result.authMethod = resp.Auth.Method
			result.authOrgID = resp.Auth.OrgID
		}

		pushCLILog("status: %s (%dms)", result.status, result.latencyMs)
		return result
	}
}

// runCLI executes the vulnetix CLI with args and returns stdout, stderr, or an error string.
// For JSON commands the CLI emits progress text before the JSON object on stdout;
// rate limit and status info is printed to stderr.
func runCLI(cliPath string, args []string) (stdout, stderr []byte, errStr string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, cliPath, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	if err != nil {
		// Prefer stderr for the error message; fall back to stdout preamble.
		errText := strings.TrimSpace(errBuf.String())
		if errText == "" {
			errText = strings.TrimSpace(outBuf.String())
		}
		return nil, nil, fmt.Sprintf("CLI error: %s", errText)
	}
	return outBuf.Bytes(), errBuf.Bytes(), ""
}

// jsonFrom strips any preamble text before the first JSON object or array in
// data. Returns the trimmed JSON bytes, or nil if no JSON delimiter is found.
func jsonFrom(data []byte) []byte {
	s := string(data)
	for _, delim := range []string{"{", "["} {
		if idx := strings.Index(s, delim); idx >= 0 {
			return []byte(strings.TrimSpace(s[idx:]))
		}
	}
	return nil
}

func searchCmd(cliPath, query string) tea.Cmd {
	return func() tea.Msg {
		pushCLILog("vulnetix vdb search %s --limit 10", query)
		out, stderrOut, errStr := runCLI(cliPath, []string{"vdb", "search", query, "--limit", "10", "--output", "json"})
		if errStr != "" {
			pushCLILog("search: %s", errStr)
			return searchResultMsg{err: errStr}
		}
		meta := parseResponseMeta(stderrOut)
		ids, total, err := parseSearchOutput(out)
		if err != nil {
			pushCLILog("search: parse error")
			return searchResultMsg{err: fmt.Sprintf("parse error: %s", err.Error()), meta: meta}
		}
		pushCLILog("search: %d results (total: %d)", len(ids), total)
		return searchResultMsg{identifiers: ids, total: total, meta: meta}
	}
}

// parseSearchOutput handles the CLI's mixed output: optional progress lines on
// stdout followed by a JSON object.
func parseSearchOutput(data []byte) (ids []string, total int, err error) {
	// Try JSON first (CLI emits progress text before the JSON object).
	if j := jsonFrom(data); j != nil {
		var resp SearchResponse
		if jsonErr := json.Unmarshal(j, &resp); jsonErr == nil {
			return resp.Identifiers, resp.Total, nil
		}
	}

	// Fallback: scan for identifier lines in the pretty-text output.
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if isVulnIdentifier(trimmed) {
			ids = append(ids, trimmed)
			continue
		}
		if strings.HasPrefix(trimmed, "Found ") {
			fmt.Sscanf(trimmed, "Found %d", &total)
		}
	}
	if total == 0 {
		total = len(ids)
	}
	return ids, total, nil
}

// isVulnIdentifier returns true for strings that look like a vulnerability ID.
func isVulnIdentifier(s string) bool {
	for _, prefix := range []string{"CVE-", "GHSA-", "PYSEC-", "RUSTSEC-", "GO-", "MAL-", "SNYK-"} {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

func vulnCmd(cliPath, id string) tea.Cmd {
	return func() tea.Msg {
		pushCLILog("vulnetix vdb vuln %s", id)
		out, stderrOut, errStr := runCLI(cliPath, []string{"vdb", "vuln", id, "--output", "json"})
		if errStr != "" {
			pushCLILog("vuln: %s", errStr)
			return vulnResultMsg{err: errStr}
		}
		meta := parseResponseMeta(stderrOut)
		j := jsonFrom(out)
		if j == nil {
			pushCLILog("vuln: no JSON in output")
			return vulnResultMsg{err: "no JSON in vuln output", meta: meta}
		}
		var rec CVERecord
		if err := json.NewDecoder(bytes.NewReader(j)).Decode(&rec); err != nil {
			pushCLILog("vuln: parse error")
			return vulnResultMsg{err: fmt.Sprintf("parse error: %s", err.Error()), meta: meta}
		}
		pushCLILog("vuln: loaded %s", id)
		return vulnResultMsg{data: &rec, meta: meta}
	}
}

func exploitCmd(cliPath, id string) tea.Cmd {
	return func() tea.Msg {
		pushCLILog("vulnetix vdb exploits %s", id)
		out, stderrOut, errStr := runCLI(cliPath, []string{"vdb", "exploits", id, "--output", "json"})
		if errStr != "" {
			pushCLILog("exploits: %s", errStr)
			return exploitResultMsg{err: errStr}
		}
		meta := parseResponseMeta(stderrOut)
		j := jsonFrom(out)
		if j == nil {
			return exploitResultMsg{err: "no JSON in exploits output", meta: meta}
		}
		var resp ExploitResponse
		if err := json.NewDecoder(bytes.NewReader(j)).Decode(&resp); err != nil {
			return exploitResultMsg{err: fmt.Sprintf("parse error: %s", err.Error()), meta: meta}
		}
		pushCLILog("exploits: %d for %s", resp.Count, id)
		return exploitResultMsg{data: &resp, meta: meta}
	}
}

// saveSpecCmd fetches the OpenAPI spec using the CLI and saves it locally.
func saveSpecCmd(cliPath string) tea.Cmd {
	return func() tea.Msg {
		pushCLILog("vulnetix vdb spec -o json")
		out, _, errStr := runCLI(cliPath, []string{"vdb", "spec", "-o", "json"})
		if errStr != "" {
			pushCLILog("spec: %s", errStr)
			return saveSpecResultMsg{err: errStr}
		}

		j := jsonFrom(out)
		if j == nil {
			// Try using the full output as-is (might be raw JSON)
			j = out
		}

		filename := "vdb-openapi.json"
		if err := os.WriteFile(filename, j, 0o644); err != nil {
			pushCLILog("spec: write error: %s", err)
			return saveSpecResultMsg{err: fmt.Sprintf("write: %s", err.Error())}
		}
		pushCLILog("spec: saved %s", filename)
		return saveSpecResultMsg{filename: filename}
	}
}

func fixCmd(cliPath, id string) tea.Cmd {
	return func() tea.Msg {
		pushCLILog("vulnetix vdb fixes %s", id)
		out, stderrOut, errStr := runCLI(cliPath, []string{"vdb", "fixes", id, "--output", "json"})
		if errStr != "" {
			pushCLILog("fixes: %s", errStr)
			return fixResultMsg{err: errStr}
		}
		meta := parseResponseMeta(stderrOut)
		j := jsonFrom(out)
		if j == nil {
			return fixResultMsg{err: "no JSON in fixes output", meta: meta}
		}
		var resp FixResponse
		if err := json.NewDecoder(bytes.NewReader(j)).Decode(&resp); err != nil {
			return fixResultMsg{err: fmt.Sprintf("parse error: %s", err.Error()), meta: meta}
		}
		pushCLILog("fixes: %s for %s", resp.FixAvailability, id)
		return fixResultMsg{data: &resp, meta: meta}
	}
}
