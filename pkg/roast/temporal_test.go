// Package roast provides tests for temporal pattern analysis.
// Tests cover automated detection, manual pattern detection, burst counting,
// quiet period detection, active hours/days computation, and edge cases.
/**
 * @decision DEC-TEMPORAL-001
 * @title Temporal Pattern Analysis
 * @status accepted
 * @rationale Inter-domain timing reveals automated vs manual behavior.
 */
package roast

import (
	"testing"
	"time"
)

func TestAnalyzeTemporalPatterns_Automated(t *testing.T) {
	// Domains with regular 3s intervals → high automated likelihood
	baseTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	domains := []*DecodedOAST{
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime},
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime.Add(3 * time.Second)},
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime.Add(6 * time.Second)},
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime.Add(9 * time.Second)},
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime.Add(12 * time.Second)},
	}

	profile := AnalyzeTemporalPatterns(domains, nil)

	if profile.MachineID != "aa:bb:cc" {
		t.Errorf("MachineID = %q, want aa:bb:cc", profile.MachineID)
	}

	if profile.MeanIntervalSecs < 2.5 || profile.MeanIntervalSecs > 3.5 {
		t.Errorf("MeanIntervalSecs = %.2f, want ~3.0", profile.MeanIntervalSecs)
	}

	if profile.StdDevIntervalSecs > 0.5 {
		t.Errorf("StdDevIntervalSecs = %.2f, want < 0.5 for regular intervals", profile.StdDevIntervalSecs)
	}

	if profile.AutomatedLikelihood != "high" {
		t.Errorf("AutomatedLikelihood = %q, want high", profile.AutomatedLikelihood)
	}
}

func TestAnalyzeTemporalPatterns_Manual(t *testing.T) {
	// Domains with irregular intervals over hours → low automated likelihood
	baseTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	domains := []*DecodedOAST{
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime},
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime.Add(5 * time.Minute)},
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime.Add(2 * time.Hour)},
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime.Add(2*time.Hour + 30*time.Minute)},
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime.Add(5 * time.Hour)},
	}

	profile := AnalyzeTemporalPatterns(domains, nil)

	if profile.AutomatedLikelihood != "low" {
		t.Errorf("AutomatedLikelihood = %q, want low for manual pattern", profile.AutomatedLikelihood)
	}

	if profile.QuietPeriods < 2 {
		t.Errorf("QuietPeriods = %d, want at least 2 for large gaps", profile.QuietPeriods)
	}
}

func TestAnalyzeTemporalPatterns_BurstCounting(t *testing.T) {
	baseTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	domains := []*DecodedOAST{
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime},
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime.Add(1 * time.Second)},
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime.Add(2 * time.Second)},
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime.Add(3 * time.Second)},
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime.Add(4 * time.Second)},
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime.Add(2 * time.Hour)}, // 2hr gap
	}

	profile := AnalyzeTemporalPatterns(domains, nil)

	if profile.BurstCount < 4 {
		t.Errorf("BurstCount = %d, want at least 4 for bursts < 5s", profile.BurstCount)
	}

	if profile.QuietPeriods < 1 {
		t.Errorf("QuietPeriods = %d, want at least 1 for 2hr gap", profile.QuietPeriods)
	}
}

func TestAnalyzeTemporalPatterns_ActiveHours(t *testing.T) {
	baseTime := time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC) // 09:00 UTC

	// Timezone is UTC-7, so local time is 02:00
	tz := &TimezoneEstimate{
		OffsetSeconds:  -25200,
		OffsetHours:    -7.0,
		UTCDesignation: "UTC-7",
		Confidence:     "high",
	}

	domains := []*DecodedOAST{
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime},                    // 02:00 local
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime.Add(1 * time.Hour)}, // 03:00 local
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime.Add(2 * time.Hour)}, // 04:00 local
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime.Add(8 * time.Hour)}, // 10:00 local
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime.Add(9 * time.Hour)}, // 11:00 local
	}

	profile := AnalyzeTemporalPatterns(domains, tz)

	if len(profile.ActiveHours) == 0 {
		t.Error("ActiveHours should be populated when timezone provided")
	}

	// Should have hours: 2, 3, 4, 10, 11
	expectedHours := map[int]bool{2: true, 3: true, 4: true, 10: true, 11: true}
	for _, hour := range profile.ActiveHours {
		if !expectedHours[hour] {
			t.Errorf("Unexpected active hour: %d", hour)
		}
	}
}

func TestAnalyzeTemporalPatterns_ActiveDays(t *testing.T) {
	// 2024-01-01 is Monday
	monday := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	tuesday := time.Date(2024, 1, 2, 12, 0, 0, 0, time.UTC)
	wednesday := time.Date(2024, 1, 3, 12, 0, 0, 0, time.UTC)
	friday := time.Date(2024, 1, 5, 12, 0, 0, 0, time.UTC)

	domains := []*DecodedOAST{
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: monday},
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: tuesday},
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: wednesday},
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: friday},
	}

	tz := &TimezoneEstimate{OffsetSeconds: 0, UTCDesignation: "UTC"}

	profile := AnalyzeTemporalPatterns(domains, tz)

	if len(profile.ActiveDays) == 0 {
		t.Error("ActiveDays should be populated when timezone provided")
	}

	expectedDays := map[string]bool{"Mon": true, "Tue": true, "Wed": true, "Fri": true}
	for _, day := range profile.ActiveDays {
		if !expectedDays[day] {
			t.Errorf("Unexpected active day: %s", day)
		}
	}

	// Should NOT have Thursday
	for _, day := range profile.ActiveDays {
		if day == "Thu" {
			t.Error("Thursday should not be active")
		}
	}
}

func TestAnalyzeTemporalPatterns_Empty(t *testing.T) {
	profile := AnalyzeTemporalPatterns([]*DecodedOAST{}, nil)

	if profile.MachineID != "" {
		t.Error("Empty input should produce empty MachineID")
	}

	if profile.BurstCount != 0 {
		t.Error("Empty input should have 0 bursts")
	}
}

func TestAnalyzeTemporalPatterns_SingleDomain(t *testing.T) {
	domains := []*DecodedOAST{
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: time.Now()},
	}

	profile := AnalyzeTemporalPatterns(domains, nil)

	if profile.MachineID != "aa:bb:cc" {
		t.Errorf("MachineID = %q, want aa:bb:cc", profile.MachineID)
	}

	if profile.MeanIntervalSecs != 0 {
		t.Error("Single domain should have 0 mean interval")
	}

	if profile.BurstCount != 0 {
		t.Error("Single domain should have 0 bursts")
	}
}

func TestAnalyzeTemporalPatterns_MediumAutomation(t *testing.T) {
	// Regular intervals but periodic quiet periods → medium automation
	baseTime := time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC)
	domains := []*DecodedOAST{
		// Burst 1: 09:00
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime},
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime.Add(30 * time.Second)},
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime.Add(60 * time.Second)},
		// Quiet period
		// Burst 2: 11:00
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime.Add(2 * time.Hour)},
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime.Add(2*time.Hour + 30*time.Second)},
		{Valid: true, MachineID: "aa:bb:cc", Timestamp: baseTime.Add(2*time.Hour + 60*time.Second)},
	}

	profile := AnalyzeTemporalPatterns(domains, nil)

	if profile.AutomatedLikelihood != "medium" {
		t.Errorf("AutomatedLikelihood = %q, want medium for scheduled pattern", profile.AutomatedLikelihood)
	}

	if profile.QuietPeriods < 1 {
		t.Error("Should detect quiet period between bursts")
	}
}
