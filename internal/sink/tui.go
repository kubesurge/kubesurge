package sink

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// MsgStats carries updated PcapStats to the Bubble Tea model.
type MsgStats PcapStats

// MsgTick is a periodic timer tick to update duration and rates.
type MsgTick time.Time

// keyMap defines keyboard shortcuts for the TUI dashboard.
type keyMap struct {
	Quit key.Binding
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Quit}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{k.Quit}}
}

var keys = keyMap{
	Quit: key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q", "quit"),
	),
}

// TuiModel represents the Bubble Tea state model.
type TuiModel struct {
	Stats     PcapStats
	StartTime time.Time
	Duration  time.Duration
	StatsChan <-chan PcapStats
	Err       error
	Help      help.Model
	Quitting  bool
}

// NewTuiModel initializes a new TuiModel.
func NewTuiModel(statsChan <-chan PcapStats) TuiModel {
	return TuiModel{
		Stats: PcapStats{
			TopTalkers: make(map[string]int),
		},
		StartTime: time.Now(),
		StatsChan: statsChan,
		Help:      help.New(),
	}
}

// Init starts the Bubble Tea loops.
func (m TuiModel) Init() tea.Cmd {
	return tea.Batch(
		m.recvStats(),
		m.tick(),
	)
}

func (m TuiModel) recvStats() tea.Cmd {
	return func() tea.Msg {
		stats, ok := <-m.StatsChan
		if !ok {
			return nil
		}
		return MsgStats(stats)
	}
}

func (m TuiModel) tick() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return MsgTick(t)
	})
}

// Update handles state changes based on received Bubble Tea messages.
func (m TuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if key.Matches(msg, keys.Quit) {
			m.Quitting = true
			return m, tea.Quit
		}

	case MsgStats:
		m.Stats = PcapStats(msg)
		return m, m.recvStats()

	case MsgTick:
		if !m.Quitting {
			m.Duration = time.Since(m.StartTime)
			return m, m.tick()
		}
	}

	return m, nil
}

// View renders the TUI screen.
func (m TuiModel) View() string {
	if m.Quitting {
		return "\n  👋 Closed KubeSurge TUI dashboard.\n\n"
	}

	// Styles
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00F0FF")).
		Border(lipgloss.RoundedBorder()).
		Padding(0, 1)

	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#ADBAC7"))

	labelStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#768390")).
		Width(18)

	valStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#F2F4F8"))

	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#444c56")).
		Padding(1, 2).
		MarginRight(2)

	var sb strings.Builder

	// Header
	sb.WriteString("\n")
	sb.WriteString(titleStyle.Render("📡 KubeSurge — Live Packet Dashboard"))
	sb.WriteString("\n\n")

	// Info section
	durationStr := fmt.Sprintf("%02d:%02d", int(m.Duration.Minutes()), int(m.Duration.Seconds())%60)
	rate := float64(m.Stats.TotalPackets)
	if m.Duration.Seconds() > 0 {
		rate = float64(m.Stats.TotalPackets) / m.Duration.Seconds()
	}

	info := lipgloss.JoinVertical(
		lipgloss.Left,
		headerStyle.Render("📊 GENERAL STATS"),
		"",
		fmt.Sprintf("%s %s", labelStyle.Render("Duration:"), valStyle.Render(durationStr)),
		fmt.Sprintf("%s %s", labelStyle.Render("Total Packets:"), valStyle.Render(fmt.Sprintf("%d", m.Stats.TotalPackets))),
		fmt.Sprintf("%s %s", labelStyle.Render("Total Bytes:"), valStyle.Render(fmt.Sprintf("%.2f KB", float64(m.Stats.TotalBytes)/1024.0))),
		fmt.Sprintf("%s %s", labelStyle.Render("Packet Rate:"), valStyle.Render(fmt.Sprintf("%.1f pps", rate))),
	)

	// Protocol section
	protocols := lipgloss.JoinVertical(
		lipgloss.Left,
		headerStyle.Render("🔌 PROTOCOLS"),
		"",
		fmt.Sprintf("%s %s", labelStyle.Render("TCP:"), valStyle.Render(fmt.Sprintf("%d", m.Stats.TCPCount))),
		fmt.Sprintf("%s %s", labelStyle.Render("UDP:"), valStyle.Render(fmt.Sprintf("%d", m.Stats.UDPCount))),
		fmt.Sprintf("%s %s", labelStyle.Render("ICMP:"), valStyle.Render(fmt.Sprintf("%d", m.Stats.ICMPCount))),
		fmt.Sprintf("%s %s", labelStyle.Render("DNS:"), valStyle.Render(fmt.Sprintf("%d", m.Stats.DNSCount))),
		fmt.Sprintf("%s %s", labelStyle.Render("HTTP (80):"), valStyle.Render(fmt.Sprintf("%d", m.Stats.HTTPCount))),
	)

	// Combine Left boxes
	boxes := lipgloss.JoinHorizontal(
		lipgloss.Top,
		boxStyle.Render(info),
		boxStyle.Render(protocols),
	)
	sb.WriteString(boxes)
	sb.WriteString("\n\n")

	// Top IP Talkers section
	sb.WriteString(headerStyle.Render("🔥 TOP IP TALKERS (Active Flows)"))
	sb.WriteString("\n\n")

	// Sort talkers by count
	type talker struct {
		pair  string
		count int
	}
	var list []talker
	for k, v := range m.Stats.TopTalkers {
		list = append(list, talker{k, v})
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].count > list[j].count
	})

	if len(list) == 0 {
		sb.WriteString("  Waiting for active flows...\n")
	} else {
		maxRows := 5
		if len(list) < maxRows {
			maxRows = len(list)
		}
		for i := 0; i < maxRows; i++ {
			flowStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#58A6FF"))
			countStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#8B949E"))
			sb.WriteString(fmt.Sprintf("  %d. %s  %s packets\n", i+1, flowStyle.Render(list[i].pair), countStyle.Render(fmt.Sprintf("(%d)", list[i].count))))
		}
	}
	sb.WriteString("\n")

	// Help / Quit bar
	sb.WriteString(m.Help.View(keys))
	sb.WriteString("\n")

	return sb.String()
}
