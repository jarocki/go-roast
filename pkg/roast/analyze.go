package roast

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// CampaignStats contains statistics for a specific campaign
type CampaignStats struct {
	CampaignID   string    `json:"campaign_id"`
	Count        int       `json:"count"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	MachineIDs   []string  `json:"machine_ids"`
	PIDs         []uint16  `json:"pids"`
	CounterMin   uint32    `json:"counter_min"`
	CounterMax   uint32    `json:"counter_max"`
	KSortValues  []string  `json:"ksort_values"`
}

// CampaignAnalysis contains the full analysis of OAST domains
type CampaignAnalysis struct {
	TotalDomains    int                      `json:"total_domains"`
	ValidDomains    int                      `json:"valid_domains"`
	InvalidDomains  int                      `json:"invalid_domains"`
	UniqueCampaigns int                      `json:"unique_campaigns"`
	FirstSeen       time.Time                `json:"first_seen,omitempty"`
	LastSeen        time.Time                `json:"last_seen,omitempty"`
	TimeSpan        string                   `json:"time_span,omitempty"`
	UniqueMachines  int                      `json:"unique_machines"`
	UniquePIDs      int                      `json:"unique_pids"`
	MachineIDs      []string                 `json:"machine_ids"`
	PIDs            []uint16                 `json:"pids"`
	Campaigns       map[string]*CampaignStats `json:"campaigns"`
}

// AnalyzeCampaignFromFile analyzes OAST domains from a file and returns campaign statistics
func AnalyzeCampaignFromFile(path string) (*CampaignAnalysis, error) {
	matches, decoded, err := ExtractAndDecodeFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to extract domains: %w", err)
	}

	return analyzeCampaign(matches, decoded), nil
}

// AnalyzeCampaignFromString analyzes OAST domains from a string and returns campaign statistics
func AnalyzeCampaignFromString(text string) *CampaignAnalysis {
	matches, decoded := ExtractAndDecode(text)
	return analyzeCampaign(matches, decoded)
}

func analyzeCampaign(matches []OASTMatch, decoded []*DecodedOAST) *CampaignAnalysis {
	analysis := &CampaignAnalysis{
		TotalDomains: len(matches),
		Campaigns:    make(map[string]*CampaignStats),
	}

	machineIDSet := make(map[string]bool)
	pidSet := make(map[uint16]bool)

	for _, d := range decoded {
		if !d.Valid {
			analysis.InvalidDomains++
			continue
		}

		analysis.ValidDomains++

		// Track overall time range
		if analysis.FirstSeen.IsZero() || d.Timestamp.Before(analysis.FirstSeen) {
			analysis.FirstSeen = d.Timestamp
		}
		if analysis.LastSeen.IsZero() || d.Timestamp.After(analysis.LastSeen) {
			analysis.LastSeen = d.Timestamp
		}

		// Track unique machines and PIDs
		machineIDSet[d.MachineID] = true
		pidSet[d.PID] = true

		// Get or create campaign stats
		campaignID := d.Campaign
		if campaignID == "" {
			campaignID = "unknown"
		}

		stats, exists := analysis.Campaigns[campaignID]
		if !exists {
			stats = &CampaignStats{
				CampaignID: campaignID,
				FirstSeen:  d.Timestamp,
				LastSeen:   d.Timestamp,
				CounterMin: d.Counter,
				CounterMax: d.Counter,
			}
			analysis.Campaigns[campaignID] = stats
		}

		// Update campaign stats
		stats.Count++

		if d.Timestamp.Before(stats.FirstSeen) {
			stats.FirstSeen = d.Timestamp
		}
		if d.Timestamp.After(stats.LastSeen) {
			stats.LastSeen = d.Timestamp
		}

		// Track unique values per campaign
		if !contains(stats.MachineIDs, d.MachineID) {
			stats.MachineIDs = append(stats.MachineIDs, d.MachineID)
		}
		if !containsUint16(stats.PIDs, d.PID) {
			stats.PIDs = append(stats.PIDs, d.PID)
		}
		if !contains(stats.KSortValues, d.KSort) {
			stats.KSortValues = append(stats.KSortValues, d.KSort)
		}

		if d.Counter < stats.CounterMin {
			stats.CounterMin = d.Counter
		}
		if d.Counter > stats.CounterMax {
			stats.CounterMax = d.Counter
		}
	}

	// Convert sets to sorted slices
	analysis.MachineIDs = make([]string, 0, len(machineIDSet))
	for mid := range machineIDSet {
		analysis.MachineIDs = append(analysis.MachineIDs, mid)
	}
	sort.Strings(analysis.MachineIDs)

	analysis.PIDs = make([]uint16, 0, len(pidSet))
	for pid := range pidSet {
		analysis.PIDs = append(analysis.PIDs, pid)
	}
	sort.Slice(analysis.PIDs, func(i, j int) bool {
		return analysis.PIDs[i] < analysis.PIDs[j]
	})

	analysis.UniqueMachines = len(analysis.MachineIDs)
	analysis.UniquePIDs = len(analysis.PIDs)
	analysis.UniqueCampaigns = len(analysis.Campaigns)

	// Calculate time span
	if !analysis.FirstSeen.IsZero() && !analysis.LastSeen.IsZero() {
		duration := analysis.LastSeen.Sub(analysis.FirstSeen)
		analysis.TimeSpan = formatDuration(duration)
	}

	return analysis
}

// FormatMarkdown returns a nicely formatted markdown report
func (a *CampaignAnalysis) FormatMarkdown() string {
	var sb strings.Builder

	sb.WriteString("# OAST Campaign Analysis\n\n")

	// Overall statistics
	sb.WriteString("## Overall Statistics\n\n")
	sb.WriteString(fmt.Sprintf("- **Total Domains Found:** %d\n", a.TotalDomains))
	sb.WriteString(fmt.Sprintf("- **Valid Domains:** %d\n", a.ValidDomains))
	if a.InvalidDomains > 0 {
		sb.WriteString(fmt.Sprintf("- **Invalid Domains:** %d\n", a.InvalidDomains))
	}
	sb.WriteString(fmt.Sprintf("- **Unique Campaigns:** %d\n", a.UniqueCampaigns))
	sb.WriteString(fmt.Sprintf("- **Unique Machine IDs:** %d\n", a.UniqueMachines))
	sb.WriteString(fmt.Sprintf("- **Unique PIDs:** %d\n", a.UniquePIDs))

	if !a.FirstSeen.IsZero() {
		sb.WriteString(fmt.Sprintf("- **First Seen:** %s\n", a.FirstSeen.Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("- **Last Seen:** %s\n", a.LastSeen.Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("- **Time Span:** %s\n", a.TimeSpan))
	}

	// Machine IDs
	if len(a.MachineIDs) > 0 {
		sb.WriteString("\n## Machine IDs\n\n")
		for _, mid := range a.MachineIDs {
			sb.WriteString(fmt.Sprintf("- `%s`\n", mid))
		}
	}

	// PIDs
	if len(a.PIDs) > 0 {
		sb.WriteString("\n## Process IDs\n\n")
		pidStrs := make([]string, len(a.PIDs))
		for i, pid := range a.PIDs {
			pidStrs[i] = fmt.Sprintf("`%d`", pid)
		}
		sb.WriteString(strings.Join(pidStrs, ", ") + "\n")
	}

	// Campaign details
	if len(a.Campaigns) > 0 {
		sb.WriteString("\n## Campaign Details\n\n")

		// Sort campaigns by count (descending)
		campaigns := make([]*CampaignStats, 0, len(a.Campaigns))
		for _, stats := range a.Campaigns {
			campaigns = append(campaigns, stats)
		}
		sort.Slice(campaigns, func(i, j int) bool {
			return campaigns[i].Count > campaigns[j].Count
		})

		for _, stats := range campaigns {
			sb.WriteString(fmt.Sprintf("### Campaign: `%s`\n\n", stats.CampaignID))
			sb.WriteString(fmt.Sprintf("- **Count:** %d domains\n", stats.Count))
			sb.WriteString(fmt.Sprintf("- **First Seen:** %s\n", stats.FirstSeen.Format(time.RFC3339)))
			sb.WriteString(fmt.Sprintf("- **Last Seen:** %s\n", stats.LastSeen.Format(time.RFC3339)))

			duration := stats.LastSeen.Sub(stats.FirstSeen)
			sb.WriteString(fmt.Sprintf("- **Duration:** %s\n", formatDuration(duration)))

			sb.WriteString(fmt.Sprintf("- **Counter Range:** %d - %d\n", stats.CounterMin, stats.CounterMax))

			if len(stats.MachineIDs) > 0 {
				sb.WriteString(fmt.Sprintf("- **Machine IDs (%d):** ", len(stats.MachineIDs)))
				machineStrs := make([]string, len(stats.MachineIDs))
				for i, mid := range stats.MachineIDs {
					machineStrs[i] = fmt.Sprintf("`%s`", mid)
				}
				sb.WriteString(strings.Join(machineStrs, ", ") + "\n")
			}

			if len(stats.PIDs) > 0 {
				sb.WriteString(fmt.Sprintf("- **PIDs (%d):** ", len(stats.PIDs)))
				pidStrs := make([]string, len(stats.PIDs))
				for i, pid := range stats.PIDs {
					pidStrs[i] = fmt.Sprintf("`%d`", pid)
				}
				sb.WriteString(strings.Join(pidStrs, ", ") + "\n")
			}

			if len(stats.KSortValues) > 0 {
				sort.Strings(stats.KSortValues)
				sb.WriteString(fmt.Sprintf("- **K-Sort Values (%d):** ", len(stats.KSortValues)))
				ksortStrs := make([]string, len(stats.KSortValues))
				for i, ksort := range stats.KSortValues {
					ksortStrs[i] = fmt.Sprintf("`%s`", ksort)
				}
				sb.WriteString(strings.Join(ksortStrs, ", ") + "\n")
			}

			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// Helper functions
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsUint16(slice []uint16, item uint16) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0f seconds", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.1f minutes", d.Minutes())
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1f hours", d.Hours())
	}
	days := d.Hours() / 24
	if days < 7 {
		return fmt.Sprintf("%.1f days", days)
	}
	if days < 30 {
		return fmt.Sprintf("%.1f weeks", days/7)
	}
	return fmt.Sprintf("%.1f months", days/30)
}
