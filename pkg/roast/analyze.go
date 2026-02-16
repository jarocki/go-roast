package roast

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// CampaignStats contains statistics for a specific campaign
type CampaignStats struct {
	CampaignID       string                `json:"campaign_id"`
	Count            int                   `json:"count"`
	FirstSeen        time.Time             `json:"first_seen"`
	LastSeen         time.Time             `json:"last_seen"`
	MachineIDs       []string              `json:"machine_ids"`
	PIDs             []uint16              `json:"pids"`
	CounterMin       uint32                `json:"counter_min"`
	CounterMax       uint32                `json:"counter_max"`
	KSortValues      []string              `json:"ksort_values"`
	ClientTypes      map[ClientType]int    `json:"client_types,omitempty"`
	ServerVersions   map[ServerVersion]int `json:"server_versions,omitempty"`
	NonceTimestampMin   *time.Time        `json:"nonce_timestamp_min,omitempty"`
	NonceTimestampMax   *time.Time        `json:"nonce_timestamp_max,omitempty"`
	NonceCounterMinV101 *uint32           `json:"nonce_counter_min_v101,omitempty"`
	NonceCounterMaxV101 *uint32           `json:"nonce_counter_max_v101,omitempty"`
	SessionAgeMinSecs   *int64            `json:"session_age_min_secs,omitempty"`
	SessionAgeMaxSecs   *int64            `json:"session_age_max_secs,omitempty"`
	TimezoneEstimates   []TimezoneEstimate `json:"timezone_estimates,omitempty"`
}

// CampaignAnalysis contains the full analysis of OAST domains
type CampaignAnalysis struct {
	TotalDomains      int                       `json:"total_domains"`
	ValidDomains      int                       `json:"valid_domains"`
	InvalidDomains    int                       `json:"invalid_domains"`
	UniqueCampaigns   int                       `json:"unique_campaigns"`
	FirstSeen         time.Time                 `json:"first_seen,omitempty"`
	LastSeen          time.Time                 `json:"last_seen,omitempty"`
	TimeSpan          string                    `json:"time_span,omitempty"`
	UniqueMachines    int                       `json:"unique_machines"`
	UniquePIDs        int                       `json:"unique_pids"`
	MachineIDs        []string                  `json:"machine_ids"`
	PIDs              []uint16                  `json:"pids"`
	Campaigns         map[string]*CampaignStats `json:"campaigns"`
	ClientTypes       map[ClientType]int        `json:"client_types,omitempty"`
	ServerVersions    map[ServerVersion]int     `json:"server_versions,omitempty"`
	ExecutiveSummary  string                    `json:"executive_summary,omitempty"`
	CrossRefFindings  []string                  `json:"cross_ref_findings,omitempty"`
	TimezoneEstimates []TimezoneEstimate        `json:"timezone_estimates,omitempty"`
	ConsensusTimezone *TimezoneEstimate         `json:"consensus_timezone,omitempty"`
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

// AnalyzeCampaignWithTimestamps analyzes OAST domains with log timestamps for timezone estimation.
func AnalyzeCampaignWithTimestamps(pairs []TimestampedDomain) *CampaignAnalysis {
	decoded := DecodeBatchWithLogTimes(pairs)

	// Create pseudo-matches for analyzeCampaign (it expects matches but we already have decoded)
	matches := make([]OASTMatch, len(decoded))
	for i, d := range decoded {
		matches[i] = OASTMatch{
			Full:      d.Original,
			Subdomain: d.Original,
		}
	}

	analysis := analyzeCampaign(matches, decoded)

	// Collect timezone estimates
	var allEstimates []TimezoneEstimate
	estimatesByMachine := make(map[string][]TimezoneEstimate)

	for _, d := range decoded {
		if d.TimezoneEstimate != nil {
			allEstimates = append(allEstimates, *d.TimezoneEstimate)
			if d.Valid {
				estimatesByMachine[d.MachineID] = append(estimatesByMachine[d.MachineID], *d.TimezoneEstimate)
			}
		}
	}

	analysis.TimezoneEstimates = allEstimates

	// Compute consensus timezone
	if len(allEstimates) > 0 {
		// Try to find consensus per machine first
		var bestConsensus *TimezoneEstimate
		var bestConfidence string

		for _, estimates := range estimatesByMachine {
			if len(estimates) > 0 {
				consensus := ConsensusTimezone(estimates)
				if consensus != nil {
					if bestConsensus == nil {
						bestConsensus = consensus
						bestConfidence = consensus.Confidence
					} else {
						// Prefer higher confidence or more domains
						if confidenceLevel(consensus.Confidence) > confidenceLevel(bestConfidence) {
							bestConsensus = consensus
							bestConfidence = consensus.Confidence
						}
					}
				}
			}
		}

		// If we have estimates from multiple machines, compute global consensus
		if len(estimatesByMachine) > 1 {
			globalConsensus := ConsensusTimezone(allEstimates)
			if globalConsensus != nil && confidenceLevel(globalConsensus.Confidence) >= confidenceLevel(bestConfidence) {
				bestConsensus = globalConsensus
			}
		}

		analysis.ConsensusTimezone = bestConsensus
	}

	return analysis
}

// confidenceLevel converts confidence string to numeric level for comparison
func confidenceLevel(conf string) int {
	switch conf {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func analyzeCampaign(matches []OASTMatch, decoded []*DecodedOAST) *CampaignAnalysis {
	analysis := &CampaignAnalysis{
		TotalDomains:   len(matches),
		Campaigns:      make(map[string]*CampaignStats),
		ClientTypes:    make(map[ClientType]int),
		ServerVersions: make(map[ServerVersion]int),
	}

	machineIDSet := make(map[string]bool)
	pidSet := make(map[uint16]bool)

	for _, d := range decoded {
		// Aggregate classification even for invalid (web client) domains
		if d.Classification != nil {
			analysis.ClientTypes[d.Classification.ClientType]++
			analysis.ServerVersions[d.Classification.ServerVersion]++
		}

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
				CampaignID:     campaignID,
				FirstSeen:      d.Timestamp,
				LastSeen:       d.Timestamp,
				CounterMin:     d.Counter,
				CounterMax:     d.Counter,
				ClientTypes:    make(map[ClientType]int),
				ServerVersions: make(map[ServerVersion]int),
			}
			analysis.Campaigns[campaignID] = stats
		}

		// Update campaign stats
		stats.Count++

		if d.Classification != nil {
			stats.ClientTypes[d.Classification.ClientType]++
			stats.ServerVersions[d.Classification.ServerVersion]++
		}

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

		// Aggregate nonce analytics from NonceAnalysis
		if d.Classification != nil && d.Classification.NonceAnalysis != nil {
			na := d.Classification.NonceAnalysis
			nts := na.NonceTimestamp
			if stats.NonceTimestampMin == nil || nts.Before(*stats.NonceTimestampMin) {
				stats.NonceTimestampMin = &nts
			}
			if stats.NonceTimestampMax == nil || nts.After(*stats.NonceTimestampMax) {
				stats.NonceTimestampMax = &nts
			}
			nctr := na.NonceCounter
			if stats.NonceCounterMinV101 == nil || nctr < *stats.NonceCounterMinV101 {
				stats.NonceCounterMinV101 = &nctr
			}
			if stats.NonceCounterMaxV101 == nil || nctr > *stats.NonceCounterMaxV101 {
				stats.NonceCounterMaxV101 = &nctr
			}
			age := na.SessionAgeSecs
			if stats.SessionAgeMinSecs == nil || age < *stats.SessionAgeMinSecs {
				stats.SessionAgeMinSecs = &age
			}
			if stats.SessionAgeMaxSecs == nil || age > *stats.SessionAgeMaxSecs {
				stats.SessionAgeMaxSecs = &age
			}
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

	// Cross-reference classifications
	CrossReferenceClassifications(decoded)

	// Generate executive summary
	analysis.ExecutiveSummary = generateExecutiveSummary(analysis)

	return analysis
}

// CrossReferenceClassifications cross-validates v1.0.1 classifications across domains
// sharing the same MachineID. Groups with consistent v1.0.1 timestamps get upgraded
// confidence; groups with mixed versions get a warning.
func CrossReferenceClassifications(decoded []*DecodedOAST) {
	// Group valid domains by MachineID
	groups := make(map[string][]*DecodedOAST)
	for _, d := range decoded {
		if d.Valid && d.MachineID != "" {
			groups[d.MachineID] = append(groups[d.MachineID], d)
		}
	}

	for _, group := range groups {
		if len(group) < 2 {
			continue
		}

		v101Count := 0
		var v101Domains []*DecodedOAST
		for _, d := range group {
			if d.Classification != nil && d.Classification.ServerVersion == VersionV101 && d.Classification.NonceAnalysis != nil && d.Classification.NonceAnalysis.TimestampReliable {
				v101Count++
				v101Domains = append(v101Domains, d)
			}
		}

		if v101Count == len(group) && v101Count >= 2 {
			// Check if timestamps are monotonically increasing
			sorted := make([]*DecodedOAST, len(v101Domains))
			copy(sorted, v101Domains)
			sort.Slice(sorted, func(i, j int) bool {
				return sorted[i].Classification.NonceAnalysis.NonceTimestamp.Before(sorted[j].Classification.NonceAnalysis.NonceTimestamp)
			})

			monotonic := true
			for i := 1; i < len(sorted); i++ {
				if !sorted[i].Classification.NonceAnalysis.NonceTimestamp.After(sorted[i-1].Classification.NonceAnalysis.NonceTimestamp) &&
					sorted[i].Classification.NonceAnalysis.NonceTimestamp != sorted[i-1].Classification.NonceAnalysis.NonceTimestamp {
					monotonic = false
					break
				}
			}

			if monotonic {
				reason := fmt.Sprintf("corroborated by %d sibling domains from same machine", len(group))
				for _, d := range group {
					if d.Classification != nil && d.Classification.Confidence == "medium" {
						d.Classification.Confidence = "high"
						d.Classification.Reasoning = append(d.Classification.Reasoning, reason)
					}
				}
			}
		} else if v101Count > 0 && v101Count < len(group) {
			// Mixed versions from same machine
			reason := "mixed server versions from same machine ID — some classifications may be unreliable"
			for _, d := range group {
				if d.Classification != nil {
					d.Classification.Reasoning = append(d.Classification.Reasoning, reason)
				}
			}
		}
	}
}

// generateExecutiveSummary creates a concise narrative summary of the analysis.
func generateExecutiveSummary(a *CampaignAnalysis) string {
	var parts []string

	parts = append(parts, fmt.Sprintf("Analysis of %d domains across %d campaigns", a.TotalDomains, a.UniqueCampaigns))

	if a.TimeSpan != "" {
		parts[0] += fmt.Sprintf(" spanning %s", a.TimeSpan)
	}
	parts[0] += "."

	parts = append(parts, fmt.Sprintf("Found %d machine IDs and %d PIDs.", a.UniqueMachines, a.UniquePIDs))

	// Classification breakdown
	var classificationParts []string
	for sv, count := range a.ServerVersions {
		classificationParts = append(classificationParts, fmt.Sprintf("%s (%d)", sv, count))
	}
	if len(classificationParts) > 0 {
		sort.Strings(classificationParts)
		parts = append(parts, "Classification: "+strings.Join(classificationParts, ", ")+".")
	}

	return strings.Join(parts, " ")
}

// FormatMarkdown returns a nicely formatted markdown report with executive summary,
// session analytics, cross-reference findings, and per-campaign narratives.
func (a *CampaignAnalysis) FormatMarkdown() string {
	var sb strings.Builder

	sb.WriteString("# OAST Campaign Analysis\n\n")

	// Executive Summary
	if a.ExecutiveSummary != "" {
		sb.WriteString("## Executive Summary\n\n")
		sb.WriteString(a.ExecutiveSummary + "\n")
	}

	// Overall statistics
	sb.WriteString("\n## Overall Statistics\n\n")
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

	// Classification summary with per-campaign breakdown
	if len(a.ClientTypes) > 0 {
		sb.WriteString("\n## Classification\n\n")
		sb.WriteString("**Client Types:** ")
		var ctParts []string
		for ct, count := range a.ClientTypes {
			ctParts = append(ctParts, fmt.Sprintf("%s (%d)", ct, count))
		}
		sort.Strings(ctParts)
		sb.WriteString(strings.Join(ctParts, ", ") + "\n\n")

		sb.WriteString("**Server Versions:** ")
		var svParts []string
		for sv, count := range a.ServerVersions {
			svParts = append(svParts, fmt.Sprintf("%s (%d)", sv, count))
		}
		sort.Strings(svParts)
		sb.WriteString(strings.Join(svParts, ", ") + "\n")

		// Per-campaign classification breakdown
		if len(a.Campaigns) > 1 {
			sb.WriteString("\n**Per-Campaign Breakdown:**\n")
			for cid, stats := range a.Campaigns {
				var parts []string
				for sv, count := range stats.ServerVersions {
					parts = append(parts, fmt.Sprintf("%s=%d", sv, count))
				}
				sort.Strings(parts)
				sb.WriteString(fmt.Sprintf("- `%s`: %s\n", cid, strings.Join(parts, ", ")))
			}
		}
	}

	// Session Analytics — when v1.0.1 nonces present
	hasSessionAnalytics := false
	for _, stats := range a.Campaigns {
		if stats.NonceTimestampMin != nil {
			hasSessionAnalytics = true
			break
		}
	}
	if hasSessionAnalytics {
		sb.WriteString("\n## Session Analytics\n\n")
		sb.WriteString("v1.0.1 nonce-derived session data:\n\n")
		for cid, stats := range a.Campaigns {
			if stats.NonceTimestampMin == nil {
				continue
			}
			sb.WriteString(fmt.Sprintf("**Campaign `%s`:**\n", cid))
			if stats.NonceTimestampMin != nil && stats.NonceTimestampMax != nil {
				sb.WriteString(fmt.Sprintf("- Nonce Timestamp Range: %s to %s\n",
					stats.NonceTimestampMin.Format(time.RFC3339),
					stats.NonceTimestampMax.Format(time.RFC3339)))
			}
			if stats.SessionAgeMinSecs != nil && stats.SessionAgeMaxSecs != nil {
				sb.WriteString(fmt.Sprintf("- Session Age Range: %ds to %ds\n", *stats.SessionAgeMinSecs, *stats.SessionAgeMaxSecs))
			}
			if stats.NonceCounterMinV101 != nil && stats.NonceCounterMaxV101 != nil {
				sb.WriteString(fmt.Sprintf("- Domain Counter Range (v1.0.1): %d to %d\n", *stats.NonceCounterMinV101, *stats.NonceCounterMaxV101))
			}
			// Velocity calculation
			if stats.NonceTimestampMin != nil && stats.NonceTimestampMax != nil {
				nonceDuration := stats.NonceTimestampMax.Sub(*stats.NonceTimestampMin)
				if nonceDuration > 0 && stats.Count > 1 {
					velocity := float64(stats.Count) / nonceDuration.Hours()
					sb.WriteString(fmt.Sprintf("- Domain Generation Velocity: %.1f domains/hour\n", velocity))
				}
			}
			sb.WriteString("\n")
		}
	}

	// Cross-Reference Findings
	if len(a.CrossRefFindings) > 0 {
		sb.WriteString("\n## Cross-Reference Findings\n\n")
		for _, finding := range a.CrossRefFindings {
			sb.WriteString(fmt.Sprintf("- %s\n", finding))
		}
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

			// Nonce timestamp and counter ranges
			if stats.NonceTimestampMin != nil && stats.NonceTimestampMax != nil {
				sb.WriteString(fmt.Sprintf("- **Nonce Timestamp Range:** %s to %s\n",
					stats.NonceTimestampMin.Format(time.RFC3339),
					stats.NonceTimestampMax.Format(time.RFC3339)))
			}
			if stats.NonceCounterMinV101 != nil && stats.NonceCounterMaxV101 != nil {
				sb.WriteString(fmt.Sprintf("- **Nonce Counter Range (v1.0.1):** %d - %d\n",
					*stats.NonceCounterMinV101, *stats.NonceCounterMaxV101))
			}
			if stats.SessionAgeMinSecs != nil && stats.SessionAgeMaxSecs != nil {
				sb.WriteString(fmt.Sprintf("- **Session Age Range:** %ds - %ds\n",
					*stats.SessionAgeMinSecs, *stats.SessionAgeMaxSecs))
			}

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

			// Campaign narrative
			narrative := fmt.Sprintf("Campaign %s was active for %s across %d machines, generating %d domains.",
				stats.CampaignID, formatDuration(duration), len(stats.MachineIDs), stats.Count)
			sb.WriteString(fmt.Sprintf("\n%s\n\n", narrative))
		}
	}

	// Timezone Analysis section
	if a.ConsensusTimezone != nil || len(a.TimezoneEstimates) > 0 {
		sb.WriteString("\n## Timezone Analysis\n\n")

		if a.ConsensusTimezone != nil {
			sb.WriteString(fmt.Sprintf("**Consensus Timezone:** %s (confidence: %s)\n\n",
				a.ConsensusTimezone.UTCDesignation, a.ConsensusTimezone.Confidence))
			sb.WriteString(fmt.Sprintf("- **Offset:** %d seconds (%.1f hours)\n",
				a.ConsensusTimezone.OffsetSeconds, a.ConsensusTimezone.OffsetHours))
			sb.WriteString(fmt.Sprintf("- **Method:** %s\n", a.ConsensusTimezone.Method))
			if len(a.ConsensusTimezone.Reasoning) > 0 {
				sb.WriteString("- **Analysis:**\n")
				for _, reason := range a.ConsensusTimezone.Reasoning {
					sb.WriteString(fmt.Sprintf("  - %s\n", reason))
				}
			}
			sb.WriteString("\n")
		}

		if len(a.TimezoneEstimates) > 1 {
			sb.WriteString("### Individual Estimates\n\n")
			sb.WriteString("| Offset | UTC | Confidence | Method | Count |\n")
			sb.WriteString("|--------|-----|------------|--------|-------|\n")

			// Group estimates by offset
			offsetCounts := make(map[int]int)
			offsetExamples := make(map[int]*TimezoneEstimate)
			for i := range a.TimezoneEstimates {
				est := &a.TimezoneEstimates[i]
				offsetCounts[est.OffsetSeconds]++
				if offsetExamples[est.OffsetSeconds] == nil {
					offsetExamples[est.OffsetSeconds] = est
				}
			}

			// Sort by offset
			var offsets []int
			for offset := range offsetCounts {
				offsets = append(offsets, offset)
			}
			sort.Ints(offsets)

			for _, offset := range offsets {
				est := offsetExamples[offset]
				count := offsetCounts[offset]
				sb.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %d |\n",
					est.OffsetSeconds, est.UTCDesignation, est.Confidence, est.Method, count))
			}
		}
	}

	// Timeline section
	if !a.FirstSeen.IsZero() && a.ValidDomains > 0 {
		sb.WriteString("\n## Timeline\n\n")
		sb.WriteString(fmt.Sprintf("Activity observed from %s to %s (%s).\n",
			a.FirstSeen.Format(time.RFC3339),
			a.LastSeen.Format(time.RFC3339),
			a.TimeSpan))
		sb.WriteString(fmt.Sprintf("%d domains decoded across %d campaigns from %d unique machines.\n",
			a.ValidDomains, a.UniqueCampaigns, a.UniqueMachines))
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
