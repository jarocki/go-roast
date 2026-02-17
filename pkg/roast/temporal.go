// Package roast provides temporal pattern analysis for OAST domain forensics.
// Analyzes inter-domain timing to distinguish automated scanning (regular intervals)
// from manual testing (irregular intervals). Computes active hours and days when
// timezone estimates are available.
/**
 * @decision DEC-TEMPORAL-001
 * @title Temporal Pattern Analysis
 * @status accepted
 * @rationale Inter-domain timing reveals automated vs manual behavior. Regular
 *            intervals with low stddev indicate scripted scanning; irregular
 *            intervals spanning hours suggest manual testing; periodic bursts
 *            with quiet periods suggest scheduled jobs.
 */
package roast

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// TemporalProfile characterizes the timing patterns of domain generation
type TemporalProfile struct {
	MachineID           string   `json:"machine_id"`
	MeanIntervalSecs    float64  `json:"mean_interval_secs"`
	StdDevIntervalSecs  float64  `json:"stddev_interval_secs"`
	BurstCount          int      `json:"burst_count"`           // clusters < 5s apart
	QuietPeriods        int      `json:"quiet_periods"`         // gaps > 1hr
	AutomatedLikelihood string   `json:"automated_likelihood"`  // high/medium/low
	ActiveHours         []int    `json:"active_hours,omitempty"` // 0-23, local time
	ActiveDays          []string `json:"active_days,omitempty"`  // Mon-Sun
	Reasoning           []string `json:"reasoning"`
}

// AnalyzeTemporalPatterns computes timing profile from decoded domains.
// If timezone estimate is provided, computes active hours and days in local time.
func AnalyzeTemporalPatterns(decoded []*DecodedOAST, tz *TimezoneEstimate) *TemporalProfile {
	profile := &TemporalProfile{
		Reasoning: []string{},
	}

	// Filter to valid domains
	valid := make([]*DecodedOAST, 0, len(decoded))
	for _, d := range decoded {
		if d.Valid {
			valid = append(valid, d)
		}
	}

	if len(valid) == 0 {
		return profile
	}

	// Get machine ID from first valid domain
	profile.MachineID = valid[0].MachineID

	// Sort by timestamp
	sort.Slice(valid, func(i, j int) bool {
		return valid[i].Timestamp.Before(valid[j].Timestamp)
	})

	// Single domain edge case
	if len(valid) == 1 {
		profile.Reasoning = append(profile.Reasoning, "Single domain - no timing pattern")
		return profile
	}

	// Compute inter-domain intervals
	intervals := make([]float64, 0, len(valid)-1)
	for i := 0; i < len(valid)-1; i++ {
		interval := valid[i+1].Timestamp.Sub(valid[i].Timestamp).Seconds()
		intervals = append(intervals, interval)
	}

	// Calculate mean
	var sum float64
	for _, interval := range intervals {
		sum += interval
	}
	profile.MeanIntervalSecs = sum / float64(len(intervals))

	// Calculate standard deviation
	var varianceSum float64
	for _, interval := range intervals {
		diff := interval - profile.MeanIntervalSecs
		varianceSum += diff * diff
	}
	variance := varianceSum / float64(len(intervals))
	profile.StdDevIntervalSecs = math.Sqrt(variance)

	// Count bursts (intervals < 5s)
	for _, interval := range intervals {
		if interval < 5.0 {
			profile.BurstCount++
		}
	}

	// Count quiet periods (intervals > 1hr)
	for _, interval := range intervals {
		if interval > 3600.0 {
			profile.QuietPeriods++
		}
	}

	// Determine automated likelihood
	profile.AutomatedLikelihood = determineAutomatedLikelihood(
		profile.MeanIntervalSecs,
		profile.StdDevIntervalSecs,
		profile.QuietPeriods,
		len(intervals),
	)

	// Add reasoning
	profile.Reasoning = append(profile.Reasoning,
		fmt.Sprintf("Mean interval: %.1fs (σ=%.1fs)", profile.MeanIntervalSecs, profile.StdDevIntervalSecs))
	profile.Reasoning = append(profile.Reasoning,
		fmt.Sprintf("Bursts: %d, Quiet periods: %d", profile.BurstCount, profile.QuietPeriods))

	// Compute active hours and days if timezone provided
	if tz != nil {
		computeActiveHoursAndDays(valid, tz, profile)
	}

	return profile
}

// determineAutomatedLikelihood applies heuristics to classify automation level
func determineAutomatedLikelihood(mean, stddev float64, quietPeriods, intervalCount int) string {
	// High automation: regular intervals with low variance, short mean
	if stddev < 2.0 && mean < 10.0 {
		return "high"
	}

	// Low automation: very long mean intervals (manual testing)
	if mean > 1800.0 { // mean > 30 minutes
		return "low"
	}

	// Medium automation: scheduled jobs with bursts separated by quiet periods
	// Key: has quiet periods BUT mean is reasonable (under 30 min) AND stddev is not extreme
	// This distinguishes scheduled jobs from manual testing
	if quietPeriods > 0 && mean <= 1800.0 && intervalCount >= 4 {
		// Further refinement: if stddev is very high relative to mean, it's manual not scheduled
		if stddev > mean*2.0 {
			return "low"
		}
		return "medium"
	}

	// Default: irregular but not clearly manual
	if stddev > mean*0.8 { // high variance relative to mean
		return "low"
	}

	return "medium"
}

// computeActiveHoursAndDays populates ActiveHours and ActiveDays in local time
func computeActiveHoursAndDays(domains []*DecodedOAST, tz *TimezoneEstimate, profile *TemporalProfile) {
	hourSet := make(map[int]bool)
	daySet := make(map[string]bool)

	offsetDuration := time.Duration(tz.OffsetSeconds) * time.Second

	for _, d := range domains {
		// Convert UTC timestamp to local time
		localTime := d.Timestamp.Add(offsetDuration)
		hour := localTime.Hour()
		day := localTime.Weekday().String()[:3] // Mon, Tue, etc.

		hourSet[hour] = true
		daySet[day] = true
	}

	// Convert sets to sorted slices
	profile.ActiveHours = make([]int, 0, len(hourSet))
	for hour := range hourSet {
		profile.ActiveHours = append(profile.ActiveHours, hour)
	}
	sort.Ints(profile.ActiveHours)

	profile.ActiveDays = make([]string, 0, len(daySet))
	for day := range daySet {
		profile.ActiveDays = append(profile.ActiveDays, day)
	}

	// Sort days by weekday order (Mon-Sun)
	dayOrder := map[string]int{
		"Mon": 1, "Tue": 2, "Wed": 3, "Thu": 4,
		"Fri": 5, "Sat": 6, "Sun": 7,
	}
	sort.Slice(profile.ActiveDays, func(i, j int) bool {
		return dayOrder[profile.ActiveDays[i]] < dayOrder[profile.ActiveDays[j]]
	})

	// Add work-hours pattern detection
	if len(profile.ActiveHours) > 0 {
		minHour := profile.ActiveHours[0]
		maxHour := profile.ActiveHours[len(profile.ActiveHours)-1]
		span := maxHour - minHour

		if span <= 8 && minHour >= 7 && maxHour <= 18 {
			profile.Reasoning = append(profile.Reasoning,
				fmt.Sprintf("Activity concentrated in %d-hour window (%02d:00-%02d:00 local) - suggests work hours",
					span, minHour, maxHour))
		}
	}

	// Add weekday-only pattern detection
	weekdaysOnly := true
	for _, day := range profile.ActiveDays {
		if day == "Sat" || day == "Sun" {
			weekdaysOnly = false
			break
		}
	}
	if weekdaysOnly && len(profile.ActiveDays) >= 3 {
		profile.Reasoning = append(profile.Reasoning, "Weekday-only activity pattern detected")
	}
}
