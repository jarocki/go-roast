// Package roast provides timezone estimation from XID/nonce timestamps vs log timestamps.
// XID timestamps encode client local time; DNS logs provide UTC timestamps.
// The delta reveals timezone offset as a passive attribution signal.
/**
 * @decision DEC-TIMEZONE-001
 * @title Timezone Offset Estimation from Timestamp Deltas
 * @status accepted
 * @rationale XID timestamps encode client local time, DNS logs are UTC.
 *            The delta reveals timezone offset as a passive attribution signal.
 */
package roast

import (
	"fmt"
	"math"
	"time"
)

// Standard UTC offsets in seconds (handles half-hour and 45-minute zones)
var standardOffsets = []int{
	-43200, // UTC-12
	-39600, // UTC-11
	-36000, // UTC-10
	-34200, // UTC-9:30
	-32400, // UTC-9
	-28800, // UTC-8
	-25200, // UTC-7
	-21600, // UTC-6
	-18000, // UTC-5
	-14400, // UTC-4
	-12600, // UTC-3:30
	-10800, // UTC-3
	-7200,  // UTC-2
	-3600,  // UTC-1
	0,      // UTC
	3600,   // UTC+1
	7200,   // UTC+2
	10800,  // UTC+3
	12600,  // UTC+3:30
	14400,  // UTC+4
	16200,  // UTC+4:30
	18000,  // UTC+5
	19800,  // UTC+5:30
	20700,  // UTC+5:45 (Nepal)
	21600,  // UTC+6
	23400,  // UTC+6:30
	25200,  // UTC+7
	28800,  // UTC+8
	31500,  // UTC+8:45 (Australia)
	32400,  // UTC+9
	34200,  // UTC+9:30
	36000,  // UTC+10
	37800,  // UTC+10:30
	39600,  // UTC+11
	41400,  // UTC+11:30
	43200,  // UTC+12
	45900,  // UTC+12:45 (Chatham)
	46800,  // UTC+13
	50400,  // UTC+14
}

// EstimateTimezone computes timezone offset from XID timestamp vs log timestamp.
// xidTimestamp is treated as local time, logTimestamp is UTC.
func EstimateTimezone(xidTimestamp, logTimestamp time.Time) *TimezoneEstimate {
	return estimateTimezoneInternal(xidTimestamp, logTimestamp, "xid_vs_log")
}

// EstimateTimezoneFromNonce computes timezone offset from nonce timestamp vs log timestamp.
// Used for v1.0.1 nonce-based timestamps.
func EstimateTimezoneFromNonce(nonceTimestamp, logTimestamp time.Time) *TimezoneEstimate {
	return estimateTimezoneInternal(nonceTimestamp, logTimestamp, "nonce_vs_log")
}

func estimateTimezoneInternal(clientTimestamp, logTimestamp time.Time, method string) *TimezoneEstimate {
	// Delta = UTC log time - client local time
	// If client is UTC-7, their clock shows 14:00 when UTC is 21:00
	// delta = 21:00 - 14:00 = 7 hours = 25200 seconds
	// offset = -delta = -25200 (UTC-7)
	rawDelta := int(logTimestamp.Unix() - clientTimestamp.Unix())
	rawOffset := -rawDelta

	// Quantize to nearest standard offset
	quantizedOffset := QuantizeOffset(rawOffset)
	offsetHours := float64(quantizedOffset) / 3600.0
	utcDesignation := formatUTCDesignation(quantizedOffset)

	reasoning := []string{
		fmt.Sprintf("Raw delta: %d seconds", rawDelta),
		fmt.Sprintf("Quantized to: %s", utcDesignation),
	}

	// Determine confidence
	confidence := "low" // Default for single domain
	deviation := abs(rawOffset - quantizedOffset)

	if deviation > 1800 { // More than 30 minutes from any standard offset
		confidence = "low"
		reasoning = append(reasoning, fmt.Sprintf("Large deviation from standard offset: %d seconds", deviation))
		reasoning = append(reasoning, "Possible clock skew or non-standard timezone")
	} else if deviation > 900 { // 15-30 minutes deviation
		confidence = "low"
		reasoning = append(reasoning, fmt.Sprintf("Moderate clock skew: %d seconds", deviation))
	} else {
		reasoning = append(reasoning, "Single domain estimate - confidence limited by clock skew possibility")
	}

	// Check for DST ambiguity on common offsets
	if quantizedOffset == -25200 {
		reasoning = append(reasoning, "Could be UTC-7 (MST/PDT) - check DST calendar")
	} else if quantizedOffset == -18000 {
		reasoning = append(reasoning, "Could be UTC-5 (EST/CDT) - check DST calendar")
	}

	return &TimezoneEstimate{
		OffsetSeconds:  quantizedOffset,
		OffsetHours:    offsetHours,
		UTCDesignation: utcDesignation,
		Confidence:     confidence,
		Method:         method,
		Reasoning:      reasoning,
	}
}

// ConsensusTimezone computes statistical consensus from multiple timezone estimates.
// Returns the mode (most common offset) with confidence based on agreement and variance.
func ConsensusTimezone(estimates []TimezoneEstimate) *TimezoneEstimate {
	if len(estimates) == 0 {
		return nil
	}

	if len(estimates) == 1 {
		return &estimates[0]
	}

	// Group by quantized offset
	offsetGroups := make(map[int][]TimezoneEstimate)
	for _, est := range estimates {
		offsetGroups[est.OffsetSeconds] = append(offsetGroups[est.OffsetSeconds], est)
	}

	// Find mode (most common offset)
	var modeOffset int
	var modeCount int
	for offset, group := range offsetGroups {
		if len(group) > modeCount {
			modeCount = len(group)
			modeOffset = offset
		}
	}

	modeGroup := offsetGroups[modeOffset]
	offsetHours := float64(modeOffset) / 3600.0
	utcDesignation := formatUTCDesignation(modeOffset)

	// Determine confidence
	confidence := "low"
	reasoning := []string{
		fmt.Sprintf("Consensus from %d domains", len(modeGroup)),
		fmt.Sprintf("Mode offset: %s (%d/%d domains)", utcDesignation, modeCount, len(estimates)),
	}

	if modeCount == len(estimates) {
		// Perfect agreement
		if len(estimates) >= 6 {
			confidence = "high"
			reasoning = append(reasoning, "All domains agree on offset (high confidence)")
		} else if len(estimates) >= 2 {
			confidence = "medium"
			reasoning = append(reasoning, "All domains agree on offset (medium confidence)")
		}
	} else {
		// Partial agreement
		agreementPct := float64(modeCount) / float64(len(estimates)) * 100
		reasoning = append(reasoning, fmt.Sprintf("Agreement: %.1f%%", agreementPct))
		if agreementPct >= 80 && modeCount >= 5 {
			confidence = "medium"
		} else {
			reasoning = append(reasoning, "Low agreement across domains - possible mixed sources")
		}
	}

	// Check if both XID and nonce methods agree
	xidCount := 0
	nonceCount := 0
	for _, est := range modeGroup {
		if est.Method == "xid_vs_log" {
			xidCount++
		} else if est.Method == "nonce_vs_log" {
			nonceCount++
		}
	}

	if xidCount > 0 && nonceCount > 0 {
		reasoning = append(reasoning, fmt.Sprintf("Both XID and nonce timestamps agree (%d XID, %d nonce)", xidCount, nonceCount))
		// Bump confidence one level
		if confidence == "low" {
			confidence = "medium"
		} else if confidence == "medium" {
			confidence = "high"
		}
	}

	// Detect anomalies
	if len(offsetGroups) > 3 {
		reasoning = append(reasoning, fmt.Sprintf("Warning: %d different offsets detected - possible mixed sources or time drift", len(offsetGroups)))
	}

	return &TimezoneEstimate{
		OffsetSeconds:  modeOffset,
		OffsetHours:    offsetHours,
		UTCDesignation: utcDesignation,
		Confidence:     confidence,
		Method:         "consensus",
		Reasoning:      reasoning,
	}
}

// QuantizeOffset snaps raw offset to nearest standard UTC offset.
// Returns raw offset if more than 15 minutes from any standard offset.
func QuantizeOffset(rawSeconds int) int {
	minDiff := math.MaxInt32
	closestOffset := rawSeconds

	for _, stdOffset := range standardOffsets {
		diff := abs(rawSeconds - stdOffset)
		if diff < minDiff {
			minDiff = diff
			closestOffset = stdOffset
		}
	}

	// If raw is more than 15 minutes from any standard, return raw
	if minDiff > 900 {
		return rawSeconds
	}

	return closestOffset
}

// formatUTCDesignation formats offset in seconds as UTC designation string.
// Examples: -25200 -> "UTC-7", 19800 -> "UTC+5:30", 20700 -> "UTC+5:45"
func formatUTCDesignation(offsetSeconds int) string {
	if offsetSeconds == 0 {
		return "UTC"
	}

	sign := "+"
	absOffset := offsetSeconds
	if offsetSeconds < 0 {
		sign = "-"
		absOffset = -offsetSeconds
	}

	hours := absOffset / 3600
	minutes := (absOffset % 3600) / 60

	if minutes == 0 {
		return fmt.Sprintf("UTC%s%d", sign, hours)
	}
	return fmt.Sprintf("UTC%s%d:%02d", sign, hours, minutes)
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
