package main

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// Build metadata — populated by ldflags.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

// ── Focus modes ───────────────────────────────────────────────

type focusMode int

const (
	focusInput focusMode = iota
	focusList
)

// ── CLI activity log constants ────────────────────────────────

const cliLogPanelHeight = 24
const cliLogMaxLines = 500

var cliLogChan = make(chan string, 100)

type cliLogLineMsg string

// ── Model ─────────────────────────────────────────────────────

type model struct {
	cliPath    string
	cliVersion string
	cliSource  string // "vendored", "sibling", "PATH", "not found"
	projectDir string
	authMethod string // e.g. "apikey", "env:VVD_ORG", "env:VULNETIX", ""
	authOrgID  string // org UUID or identifier

	searchInput   string
	debounceID    int64
	searching     bool
	searchErr     string
	searchHistory []string // recent successful queries, [0]=most recent, max 20
	historyIdx    int      // -1 = live input; 0..N-1 = browsing history
	historyDraft  string   // searchInput saved when history browsing starts

	results      []string
	resultCursor int
	searchTotal  int

	selectedID    string
	loadingDetail bool
	vulnData      *CVERecord
	exploitData   *ExploitResponse
	fixData       *FixResponse
	detailErr     string
	panelLines    int // lines of detail to show; 0 = first page; grows with "m"

	eagerSearch  bool // when true, debounce fires search automatically; false = Enter only
	debounceMs   int  // countdown remaining in ms (200ms units); 0 = idle
	spinnerFrame int  // current braille spinner frame index

	healthStatus   string // "ok", "degraded", "down", ""
	healthLatency  int    // ms
	healthChecking bool

	saveSpecStatus string       // last save-spec result message
	responseMeta   ResponseMeta // last API response cache/rate-limit metadata

	// CLI activity log panel
	cliLogLines []string

	focus  focusMode
	width  int
	height int
}

// pageSize returns lines per detail page based on terminal height (minus log panel).
func (m model) pageSize() int {
	n := m.height - 5 - cliLogPanelHeight
	if n < 10 {
		n = 10
	}
	return n
}

// ── Init ──────────────────────────────────────────────────────

func (m model) Init() tea.Cmd {
	return tea.Batch(
		statusCmd(m.cliPath),
		scheduleHealthCheckCmd(),
		cmdWaitCLILog(),
	)
}

// ── Update ────────────────────────────────────────────────────

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case countdownTickMsg:
		if msg.id != m.debounceID || m.debounceMs <= 0 {
			return m, nil // stale or already cancelled
		}
		m.debounceMs -= 200
		if m.debounceMs > 0 {
			return m, countdownTickCmd(msg.id)
		}
		return m, nil

	case spinnerTickMsg:
		if !m.searching {
			return m, nil // search finished; stop ticking
		}
		m.spinnerFrame = (m.spinnerFrame + 1) % len(spinnerFrames)
		return m, spinnerTickCmd()

	case healthCheckTickMsg:
		m.healthChecking = true
		return m, tea.Batch(statusCmd(m.cliPath), scheduleHealthCheckCmd())

	case healthResultMsg:
		m.healthChecking = false
		m.healthStatus = msg.status
		m.healthLatency = msg.latencyMs
		if msg.authMethod != "" {
			m.authMethod = msg.authMethod
		}
		if msg.authOrgID != "" {
			m.authOrgID = msg.authOrgID
		}
		return m, nil

	case debouncedSearchMsg:
		if msg.id != m.debounceID {
			return m, nil // stale debounce
		}
		if !searchable(m.searchInput) {
			return m, nil // nothing after hyphen yet
		}
		m.debounceMs = 0
		m.searching = true
		m.searchErr = ""
		return m, tea.Batch(searchCmd(m.cliPath, m.searchInput), spinnerTickCmd())

	case searchResultMsg:
		m.searching = false
		m.responseMeta = msg.meta
		if msg.err != "" {
			m.searchErr = msg.err
			m.results = nil
			m.searchTotal = 0
		} else {
			m.results = msg.identifiers
			m.searchTotal = msg.total
			m.resultCursor = 0
			if len(m.results) > 0 {
				m.searchHistory = pushHistory(m.searchHistory, m.searchInput, 20)
				m.historyIdx = -1
				if len(m.results) == 1 {
					// Auto-select the only match.
					id := m.results[0]
					m.selectedID = id
					m.vulnData = nil
					m.exploitData = nil
					m.fixData = nil
					m.detailErr = ""
					m.panelLines = 0
					m.loadingDetail = true
					m.focus = focusList
					return m, tea.Batch(
						vulnCmd(m.cliPath, id),
						exploitCmd(m.cliPath, id),
						fixCmd(m.cliPath, id),
					)
				}
				if m.focus == focusInput {
					m.focus = focusList
				}
			}
		}
		return m, nil

	case vulnResultMsg:
		if msg.meta.CacheStatus != "" || msg.meta.RateDisplay != "" {
			m.responseMeta = msg.meta
		}
		if msg.err != "" {
			m.detailErr = msg.err
		} else {
			m.vulnData = msg.data
		}
		m.loadingDetail = m.exploitData == nil && m.fixData == nil
		return m, nil

	case exploitResultMsg:
		if msg.meta.CacheStatus != "" || msg.meta.RateDisplay != "" {
			m.responseMeta = msg.meta
		}
		if msg.err == "" {
			m.exploitData = msg.data
		}
		m.loadingDetail = m.vulnData == nil && m.fixData == nil
		return m, nil

	case fixResultMsg:
		if msg.meta.CacheStatus != "" || msg.meta.RateDisplay != "" {
			m.responseMeta = msg.meta
		}
		if msg.err == "" {
			m.fixData = msg.data
		}
		m.loadingDetail = m.vulnData == nil && m.exploitData == nil
		return m, nil

	case saveSpecResultMsg:
		if msg.err != "" {
			m.saveSpecStatus = "Error: " + msg.err
		} else {
			m.saveSpecStatus = "Saved: " + msg.filename
		}
		return m, nil

	case cliLogLineMsg:
		m.cliLogLines = append(m.cliLogLines, string(msg))
		if len(m.cliLogLines) > cliLogMaxLines {
			m.cliLogLines = m.cliLogLines[len(m.cliLogLines)-cliLogMaxLines:]
		}
		return m, cmdWaitCLILog()

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Global bindings
	switch key {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "ctrl+e":
		m.eagerSearch = !m.eagerSearch
		return m, nil
	case "ctrl+o":
		m.saveSpecStatus = "Saving spec…"
		return m, saveSpecCmd(m.cliPath)
	case "tab", "shift+tab":
		m.focus = (m.focus + 1) % 2
		return m, nil
	}

	switch m.focus {
	case focusInput:
		return m.handleInputKey(msg)
	case focusList:
		return m.handleListKey(msg)
	}
	return m, nil
}

func (m model) handleInputKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	switch key {
	case "up":
		// Cycle backwards through history (older entries).
		if len(m.searchHistory) == 0 {
			return m, nil
		}
		if m.historyIdx == -1 {
			m.historyDraft = m.searchInput
			m.historyIdx = 0
		} else if m.historyIdx < len(m.searchHistory)-1 {
			m.historyIdx++
		}
		m.searchInput = m.searchHistory[m.historyIdx]
		return m, nil

	case "down":
		if m.historyIdx >= 0 {
			// Cycle forwards through history (newer entries).
			m.historyIdx--
			if m.historyIdx < 0 {
				m.searchInput = m.historyDraft
			} else {
				m.searchInput = m.searchHistory[m.historyIdx]
			}
			return m, nil
		}
		// Not browsing history: drop into results list if available.
		if len(m.results) > 0 {
			m.focus = focusList
			m.resultCursor = 0
		}
		return m, nil

	case "backspace":
		m.historyIdx = -1
		runes := []rune(m.searchInput)
		if len(runes) > 0 {
			m.searchInput = string(runes[:len(runes)-1])
		}
		if !searchable(m.searchInput) {
			m.results = nil
			m.searchTotal = 0
			m.searchErr = ""
			m.debounceMs = 0
			m.debounceID++ // invalidate any pending debounce/countdown ticks
		}
		return m, nil

	case "esc":
		m.selectedID = ""
		m.vulnData = nil
		m.exploitData = nil
		m.fixData = nil
		m.detailErr = ""
		m.panelLines = 0
		m.historyIdx = -1
		m.focus = focusList
		return m, nil

	case "enter":
		if searchable(m.searchInput) {
			m.debounceMs = 0
			m.debounceID++ // cancel any pending debounce
			m.searching = true
			m.searchErr = ""
			m.historyIdx = -1
			return m, tea.Batch(searchCmd(m.cliPath, m.searchInput), spinnerTickCmd())
		}
		return m, nil

	default:
		if len(msg.Runes) > 0 {
			m.historyIdx = -1
			for _, r := range msg.Runes {
				m.searchInput += string(r)
			}
			if m.eagerSearch && searchable(m.searchInput) {
				m.debounceMs = 2000
				newID := atomic.AddInt64(&m.debounceID, 1)
				m.debounceID = newID
				return m, tea.Batch(debounceCmd(m.searchInput, newID), countdownTickCmd(newID))
			}
		}
	}
	return m, nil
}

func (m model) handleListKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	switch key {
	case "up", "k":
		if m.resultCursor == 0 {
			m.focus = focusInput
			return m, nil
		}
		m.resultCursor--
	case "down", "j":
		if m.resultCursor < len(m.results)-1 {
			m.resultCursor++
		}
	case "enter", " ":
		if m.resultCursor < len(m.results) {
			id := m.results[m.resultCursor]
			m.selectedID = id
			m.vulnData = nil
			m.exploitData = nil
			m.fixData = nil
			m.detailErr = ""
			m.panelLines = 0
			m.loadingDetail = true
			return m, tea.Batch(
				vulnCmd(m.cliPath, id),
				exploitCmd(m.cliPath, id),
				fixCmd(m.cliPath, id),
			)
		}
	case "m", "pgdown":
		if m.selectedID != "" {
			ps := m.pageSize()
			if m.panelLines == 0 {
				m.panelLines = ps * 2
			} else {
				m.panelLines += ps
			}
		}
	case "l", "pgup":
		if m.selectedID != "" {
			ps := m.pageSize()
			if m.panelLines > ps {
				m.panelLines -= ps
			} else {
				m.panelLines = 0
			}
		}
	case "esc":
		if m.selectedID != "" {
			m.selectedID = ""
			m.vulnData = nil
			m.exploitData = nil
			m.fixData = nil
			m.detailErr = ""
			m.panelLines = 0
			return m, nil
		}
		m.focus = focusInput
	}
	return m, nil
}

// ── View ──────────────────────────────────────────────────────

func (m model) View() string {
	return renderMainView(m) + renderCLILogPanel(m)
}

// ── Helpers ───────────────────────────────────────────────────

// pushHistory prepends query to history (deduplicating) and trims to max entries.
// history[0] is always the most recent entry.
func pushHistory(history []string, query string, max int) []string {
	// Remove existing occurrence if present.
	filtered := history[:0]
	for _, h := range history {
		if h != query {
			filtered = append(filtered, h)
		}
	}
	// Prepend.
	result := make([]string, 1, len(filtered)+1)
	result[0] = query
	result = append(result, filtered...)
	if len(result) > max {
		result = result[:max]
	}
	return result
}

// searchable returns true when the input has at least one character after a hyphen,
// meaning there is something substantive to search for (e.g. "CVE-2024", not just "CVE-").
func searchable(s string) bool {
	idx := strings.LastIndex(s, "-")
	return idx >= 0 && idx < len(s)-1
}

// cmdWaitCLILog returns a tea.Cmd that blocks until a CLI log line arrives.
func cmdWaitCLILog() tea.Cmd {
	return func() tea.Msg {
		line := <-cliLogChan
		return cliLogLineMsg(line)
	}
}

// pushCLILog sends a timestamped log line to the CLI activity log panel.
func pushCLILog(format string, args ...any) {
	ts := time.Now().Format("15:04:05")
	line := ts + "  " + fmt.Sprintf(format, args...)
	select {
	case cliLogChan <- line:
	default:
	}
}

// ── Main ──────────────────────────────────────────────────────

func main() {
	// Handle --version flag
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Printf("vvd-search %s (%s, %s)\n", version, commit, buildDate)
		os.Exit(0)
	}

	projectDir, _ := os.Getwd()

	// Interactive CLI installation/update (before BubbleTea claims stdin)
	cli := ensureCLI(projectDir)

	m := model{
		cliPath:        cli.Path,
		cliVersion:     cli.Version,
		cliSource:      cli.Source,
		projectDir:     projectDir,
		eagerSearch:    true,
		historyIdx:     -1,
		healthChecking: true, // show "checking" from startup
		focus:          focusInput,
		width:          120,
		height:         30,
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
