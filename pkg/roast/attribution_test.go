// Package roast provides tests for attribution profile synthesis.
// Tests cover narrative generation, confidence scoring, and edge cases.
/**
 * @decision DEC-ATTRIBUTION-001
 * @title Attribution Profile Synthesis
 * @status accepted
 * @rationale Combines all forensic signals into human-readable narrative.
 */
package roast

import (
	"strings"
	"testing"
	"time"
)

func TestBuildAttributionProfile_FullContext(t *testing.T) {
	baseTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	cluster := MachineCluster{
		MachineID:   "2e:00:10",
		DomainCount: 847,
		FirstSeen:   baseTime,
		LastSeen:    baseTime.Add(12 * 24 * time.Hour),
		Duration:    "12.0 days",
		Velocity:    2.9,
		PIDs:        []uint16{56447},
		CounterRange: [2]uint32{1, 847},
		Campaigns:    []string{"camp1", "camp2", "camp3"},
		TimezoneConsensus: &TimezoneEstimate{
			OffsetSeconds:  -25200,
			OffsetHours:    -7.0,
			UTCDesignation: "UTC-7",
			Confidence:     "high",
		},
	}

	temporal := &TemporalProfile{
		MachineID:           "2e:00:10",
		MeanIntervalSecs:    3.2,
		StdDevIntervalSecs:  0.8,
		BurstCount:          200,
		QuietPeriods:        5,
		AutomatedLikelihood: "high",
		ActiveHours:         []int{9, 10, 11, 12, 13, 14, 15, 16, 17},
		ActiveDays:          []string{"Mon", "Tue", "Wed", "Thu", "Fri"},
		Reasoning:           []string{"Mean interval: 3.2s (σ=0.8s)"},
	}

	enrichment := &EnrichmentData{
		SourceIP: "1.2.3.4",
		Tags:     []string{"nuclei-scanner"},
		GreyNoiseCtx: map[string]any{
			"classification": "malicious",
		},
	}

	profile := BuildAttributionProfile(cluster, temporal, enrichment)

	if profile.MachineID != "2e:00:10" {
		t.Errorf("MachineID = %q, want 2e:00:10", profile.MachineID)
	}

	if profile.OverallConfidence != "high" {
		t.Errorf("OverallConfidence = %q, want high", profile.OverallConfidence)
	}

	// Check narrative contains key elements
	narrative := profile.Narrative
	if !strings.Contains(narrative, "2e:00:10") {
		t.Error("Narrative should contain machine ID")
	}
	if !strings.Contains(narrative, "UTC-7") {
		t.Error("Narrative should contain timezone")
	}
	if !strings.Contains(narrative, "847 domains") {
		t.Error("Narrative should contain domain count")
	}
	if !strings.Contains(narrative, "3 campaigns") {
		t.Error("Narrative should contain campaign count")
	}
	if !strings.Contains(narrative, "PID") || !strings.Contains(narrative, "56447") {
		t.Error("Narrative should contain PID information")
	}
	if !strings.Contains(narrative, "automated") || !strings.Contains(narrative, "3.2s") {
		t.Error("Narrative should describe temporal pattern")
	}
}

func TestBuildAttributionProfile_MinimalContext(t *testing.T) {
	cluster := MachineCluster{
		MachineID:    "aa:bb:cc",
		DomainCount:  3,
		FirstSeen:    time.Now(),
		LastSeen:     time.Now().Add(5 * time.Minute),
		Duration:     "5.0 minutes",
		PIDs:         []uint16{1234},
		CounterRange: [2]uint32{1, 3},
		Campaigns:    []string{"test"},
	}

	temporal := &TemporalProfile{
		MachineID:           "aa:bb:cc",
		MeanIntervalSecs:    150,
		StdDevIntervalSecs:  20,
		AutomatedLikelihood: "low",
	}

	profile := BuildAttributionProfile(cluster, temporal, nil)

	if profile.OverallConfidence != "low" {
		t.Errorf("OverallConfidence = %q, want low for minimal data", profile.OverallConfidence)
	}

	if profile.Narrative == "" {
		t.Error("Narrative should be generated even with minimal data")
	}

	if !strings.Contains(profile.Narrative, "aa:bb:cc") {
		t.Error("Narrative should contain machine ID")
	}
}

func TestBuildAttributionProfile_ConfidenceScoring(t *testing.T) {
	baseCluster := MachineCluster{
		MachineID:    "aa:bb:cc",
		DomainCount:  2,
		FirstSeen:    time.Now(),
		LastSeen:     time.Now().Add(1 * time.Hour),
		PIDs:         []uint16{1234},
		CounterRange: [2]uint32{1, 2},
		Campaigns:    []string{"test"},
	}

	baseTemporal := &TemporalProfile{
		MachineID:           "aa:bb:cc",
		AutomatedLikelihood: "low",
	}

	// Test 1: Low confidence (minimal data)
	profile := BuildAttributionProfile(baseCluster, baseTemporal, nil)
	if profile.OverallConfidence != "low" {
		t.Errorf("Minimal data: OverallConfidence = %q, want low", profile.OverallConfidence)
	}

	// Test 2: Medium confidence (6+ domains)
	cluster := baseCluster
	cluster.DomainCount = 10
	profile = BuildAttributionProfile(cluster, baseTemporal, nil)
	if profile.OverallConfidence != "medium" {
		t.Errorf("10 domains: OverallConfidence = %q, want medium", profile.OverallConfidence)
	}

	// Test 3: Medium confidence with timezone
	cluster = baseCluster
	cluster.TimezoneConsensus = &TimezoneEstimate{
		Confidence: "medium",
	}
	profile = BuildAttributionProfile(cluster, baseTemporal, nil)
	if profile.OverallConfidence != "medium" {
		t.Errorf("With timezone: OverallConfidence = %q, want medium", profile.OverallConfidence)
	}

	// Test 4: High confidence (timezone + temporal + multiple campaigns + 6+ domains)
	cluster = baseCluster
	cluster.DomainCount = 10
	cluster.Campaigns = []string{"camp1", "camp2"}
	cluster.TimezoneConsensus = &TimezoneEstimate{
		Confidence: "high",
	}
	temporal := &TemporalProfile{
		MachineID:           "aa:bb:cc",
		AutomatedLikelihood: "high",
	}
	profile = BuildAttributionProfile(cluster, temporal, nil)
	if profile.OverallConfidence != "high" {
		t.Errorf("Full context: OverallConfidence = %q, want high", profile.OverallConfidence)
	}
}

func TestBuildAttributionProfile_EmptyCluster(t *testing.T) {
	cluster := MachineCluster{
		MachineID: "test",
	}

	profile := BuildAttributionProfile(cluster, nil, nil)

	if profile.MachineID != "test" {
		t.Errorf("MachineID = %q, want test", profile.MachineID)
	}

	if profile.OverallConfidence != "low" {
		t.Error("Empty cluster should have low confidence")
	}
}
