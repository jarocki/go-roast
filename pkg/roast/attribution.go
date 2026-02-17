// Package roast provides attribution profile synthesis for OAST domain forensics.
// Combines all forensic signals (timezone, temporal, clusters, PIDs, gaps, enrichment)
// into a human-readable narrative and confidence score for attribution.
/**
 * @decision DEC-ATTRIBUTION-001
 * @title Attribution Profile Synthesis
 * @status accepted
 * @rationale Combines all forensic signals (timezone, temporal, clusters, PIDs,
 *            gaps, enrichment) into a human-readable narrative and confidence
 *            score for attribution.
 */
package roast

import (
	"fmt"
	"strings"
)

// AttributionProfile synthesizes all forensic signals for a machine
type AttributionProfile struct {
	MachineID         string            `json:"machine_id"`
	TimezoneEstimate  *TimezoneEstimate `json:"timezone,omitempty"`
	TemporalProfile   *TemporalProfile  `json:"temporal,omitempty"`
	CampaignLinks     []string          `json:"campaign_links"`
	PIDSessions       []PIDSession      `json:"pid_sessions"`
	CounterGaps       []CounterGap      `json:"counter_gaps,omitempty"`
	Enrichment        *EnrichmentData   `json:"enrichment,omitempty"`
	OverallConfidence string            `json:"overall_confidence"` // high/medium/low
	Narrative         string            `json:"narrative"`          // human-readable summary
}

// BuildAttributionProfile synthesizes all signals into a forensic profile.
// Combines cluster data (campaigns, PIDs, time range) with temporal profile and enrichment.
func BuildAttributionProfile(cluster MachineCluster, temporal *TemporalProfile, enrichment *EnrichmentData) *AttributionProfile {
	profile := &AttributionProfile{
		MachineID:        cluster.MachineID,
		TimezoneEstimate: cluster.TimezoneConsensus,
		TemporalProfile:  temporal,
		CampaignLinks:    cluster.Campaigns,
		Enrichment:       enrichment,
	}

	// Extract PID sessions from cluster (simplified - real implementation would come from AnalyzePIDLifecycles)
	for _, pid := range cluster.PIDs {
		session := PIDSession{
			PID:          pid,
			MachineID:    cluster.MachineID,
			DomainCount:  cluster.DomainCount, // Simplified
			FirstSeen:    cluster.FirstSeen,
			LastSeen:     cluster.LastSeen,
			Duration:     cluster.Duration,
			Velocity:     cluster.Velocity,
			CounterRange: cluster.CounterRange,
		}
		profile.PIDSessions = append(profile.PIDSessions, session)
	}

	// Compute overall confidence
	profile.OverallConfidence = computeOverallConfidence(cluster, temporal)

	// Generate narrative
	profile.Narrative = generateNarrative(cluster, temporal, enrichment)

	return profile
}

// computeOverallConfidence determines attribution confidence from available signals
func computeOverallConfidence(cluster MachineCluster, temporal *TemporalProfile) string {
	confidence := "low"

	// Bump to medium if we have timezone estimate
	if cluster.TimezoneConsensus != nil && (cluster.TimezoneConsensus.Confidence == "medium" || cluster.TimezoneConsensus.Confidence == "high") {
		confidence = "medium"
	}

	// Bump to medium if we have 6+ domains
	if cluster.DomainCount >= 6 {
		confidence = "medium"
	}

	// Bump to high if we have strong signals across multiple dimensions
	hasStrongTimezone := cluster.TimezoneConsensus != nil && cluster.TimezoneConsensus.Confidence == "high"
	hasStrongTemporal := temporal != nil && temporal.AutomatedLikelihood == "high"
	hasMultipleCampaigns := len(cluster.Campaigns) > 1
	hasSignificantVolume := cluster.DomainCount >= 6

	if hasStrongTimezone && hasStrongTemporal && hasMultipleCampaigns && hasSignificantVolume {
		confidence = "high"
	}

	return confidence
}

// generateNarrative creates a human-readable forensic summary
func generateNarrative(cluster MachineCluster, temporal *TemporalProfile, enrichment *EnrichmentData) string {
	parts := []string{}

	// Machine and timezone
	machineDesc := fmt.Sprintf("Machine `%s`", cluster.MachineID)
	if cluster.TimezoneConsensus != nil {
		machineDesc += fmt.Sprintf(" operated from %s", cluster.TimezoneConsensus.UTCDesignation)

		// Add active hours if available
		if temporal != nil && len(temporal.ActiveHours) > 0 {
			minHour := temporal.ActiveHours[0]
			maxHour := temporal.ActiveHours[len(temporal.ActiveHours)-1]
			machineDesc += fmt.Sprintf(" between %02d:00-%02d:00 local time", minHour, maxHour)

			// Add active days if available
			if len(temporal.ActiveDays) > 0 {
				machineDesc += fmt.Sprintf(" on %s", strings.Join(temporal.ActiveDays, ", "))
			}
		}
	}
	parts = append(parts, machineDesc)

	// Domain generation activity
	activityDesc := fmt.Sprintf("generated %d domains", cluster.DomainCount)
	if len(cluster.Campaigns) > 0 {
		activityDesc += fmt.Sprintf(" across %d campaign%s", len(cluster.Campaigns), pluralize(len(cluster.Campaigns)))
	}
	activityDesc += fmt.Sprintf(" over %s", cluster.Duration)
	parts = append(parts, activityDesc)

	// PID/process information
	if len(cluster.PIDs) > 0 {
		pidDesc := fmt.Sprintf("using %d process%s (PID%s: %s)",
			len(cluster.PIDs),
			pluralize(len(cluster.PIDs)),
			pluralizeEs(len(cluster.PIDs)),
			formatPIDs(cluster.PIDs))
		parts = append(parts, pidDesc)
	}

	// Temporal pattern description
	if temporal != nil {
		temporalDesc := ""
		if temporal.AutomatedLikelihood == "high" {
			temporalDesc = fmt.Sprintf("Timing suggests automated scanning (mean interval %.1fs, σ=%.1fs)",
				temporal.MeanIntervalSecs, temporal.StdDevIntervalSecs)
		} else if temporal.AutomatedLikelihood == "medium" {
			temporalDesc = fmt.Sprintf("Timing suggests scheduled automation (mean interval %.1fs, %d quiet period%s)",
				temporal.MeanIntervalSecs, temporal.QuietPeriods, pluralize(temporal.QuietPeriods))
		} else {
			temporalDesc = fmt.Sprintf("Timing suggests manual interaction (mean interval %.1fs)",
				temporal.MeanIntervalSecs)
		}
		parts = append(parts, temporalDesc)
	}

	// Enrichment data
	if enrichment != nil {
		enrichDesc := ""
		if len(enrichment.Tags) > 0 {
			enrichDesc = fmt.Sprintf("Tags: %s", strings.Join(enrichment.Tags, ", "))
		}
		if enrichment.SourceIP != "" {
			if enrichDesc != "" {
				enrichDesc += ". "
			}
			enrichDesc += fmt.Sprintf("Source IP: %s", enrichment.SourceIP)
		}
		if enrichDesc != "" {
			parts = append(parts, enrichDesc)
		}
	}

	return strings.Join(parts, ", ") + "."
}

// Helper functions
func pluralize(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

func pluralizeEs(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

func formatPIDs(pids []uint16) string {
	if len(pids) == 0 {
		return ""
	}
	if len(pids) == 1 {
		return fmt.Sprintf("%d", pids[0])
	}

	strs := make([]string, len(pids))
	for i, pid := range pids {
		strs[i] = fmt.Sprintf("%d", pid)
	}
	return strings.Join(strs, ", ")
}
