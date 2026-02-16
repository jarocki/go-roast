// Package roast provides timezone estimation tests.
/**
 * @decision DEC-TIMEZONE-001
 * @title Timezone Offset Estimation Test Coverage
 * @status accepted
 * @rationale Comprehensive test vectors for standard offsets, half-hour zones,
 *            45-minute zones, clock skew handling, and consensus algorithms.
 */
package roast

import (
	"testing"
	"time"
)

func TestEstimateTimezone(t *testing.T) {
	tests := []struct {
		name             string
		xidTime          string
		logTime          string
		expectedOffset   int
		expectedUTC      string
		expectedConfidence string
	}{
		{
			name:             "Mountain Time UTC-7",
			xidTime:          "2025-02-14T14:00:00Z",
			logTime:          "2025-02-14T21:00:00Z",
			expectedOffset:   -25200,
			expectedUTC:      "UTC-7",
			expectedConfidence: "low",
		},
		{
			name:             "Eastern Time UTC-5",
			xidTime:          "2025-02-14T14:00:00Z",
			logTime:          "2025-02-14T19:00:00Z",
			expectedOffset:   -18000,
			expectedUTC:      "UTC-5",
			expectedConfidence: "low",
		},
		{
			name:             "India Standard Time UTC+5:30",
			xidTime:          "2025-02-14T14:00:00Z",
			logTime:          "2025-02-14T08:30:00Z",
			expectedOffset:   19800,
			expectedUTC:      "UTC+5:30",
			expectedConfidence: "low",
		},
		{
			name:             "Clock skew 3 minutes - should still snap to UTC-7",
			xidTime:          "2025-02-14T14:00:00Z",
			logTime:          "2025-02-14T21:03:00Z",
			expectedOffset:   -25200,
			expectedUTC:      "UTC-7",
			expectedConfidence: "low",
		},
		{
			name:             "Nepal UTC+5:45",
			xidTime:          "2025-02-14T14:00:00Z",
			logTime:          "2025-02-14T08:15:00Z",
			expectedOffset:   20700,
			expectedUTC:      "UTC+5:45",
			expectedConfidence: "low",
		},
		{
			name:             "Chatham UTC+12:45",
			xidTime:          "2025-02-14T14:00:00Z",
			logTime:          "2025-02-14T01:15:00Z",
			expectedOffset:   45900,
			expectedUTC:      "UTC+12:45",
			expectedConfidence: "low",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			xidTime, _ := time.Parse(time.RFC3339, tt.xidTime)
			logTime, _ := time.Parse(time.RFC3339, tt.logTime)

			result := EstimateTimezone(xidTime, logTime)

			if result.OffsetSeconds != tt.expectedOffset {
				t.Errorf("OffsetSeconds = %d, want %d", result.OffsetSeconds, tt.expectedOffset)
			}
			if result.UTCDesignation != tt.expectedUTC {
				t.Errorf("UTCDesignation = %s, want %s", result.UTCDesignation, tt.expectedUTC)
			}
			if result.Confidence != tt.expectedConfidence {
				t.Errorf("Confidence = %s, want %s", result.Confidence, tt.expectedConfidence)
			}
			if result.Method != "xid_vs_log" {
				t.Errorf("Method = %s, want xid_vs_log", result.Method)
			}

			expectedHours := float64(tt.expectedOffset) / 3600.0
			if result.OffsetHours != expectedHours {
				t.Errorf("OffsetHours = %f, want %f", result.OffsetHours, expectedHours)
			}
		})
	}
}

func TestEstimateTimezoneFromNonce(t *testing.T) {
	nonceTime, _ := time.Parse(time.RFC3339, "2025-02-14T14:00:00Z")
	logTime, _ := time.Parse(time.RFC3339, "2025-02-14T21:00:00Z")

	result := EstimateTimezoneFromNonce(nonceTime, logTime)

	if result.Method != "nonce_vs_log" {
		t.Errorf("Method = %s, want nonce_vs_log", result.Method)
	}
	if result.OffsetSeconds != -25200 {
		t.Errorf("OffsetSeconds = %d, want -25200", result.OffsetSeconds)
	}
}

func TestQuantizeOffset(t *testing.T) {
	tests := []struct {
		name     string
		raw      int
		expected int
	}{
		{"Exact UTC-7", -25200, -25200},
		{"Close to UTC-7 (+2min)", -25200 + 120, -25200},
		{"Close to UTC-7 (-2min)", -25200 - 120, -25200},
		{"Exact UTC+5:30", 19800, 19800},
		{"Close to UTC+5:30", 19800 + 60, 19800},
		{"Exact UTC+5:45", 20700, 20700},
		{"Far from any standard (>15min)", -25200 + 1000, -25200 + 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := QuantizeOffset(tt.raw)
			if result != tt.expected {
				t.Errorf("QuantizeOffset(%d) = %d, want %d", tt.raw, result, tt.expected)
			}
		})
	}
}

func TestFormatUTCDesignation(t *testing.T) {
	tests := []struct {
		offset   int
		expected string
	}{
		{0, "UTC"},
		{-25200, "UTC-7"},
		{-18000, "UTC-5"},
		{19800, "UTC+5:30"},
		{20700, "UTC+5:45"},
		{45900, "UTC+12:45"},
		{3600, "UTC+1"},
		{-3600, "UTC-1"},
		{12600, "UTC+3:30"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatUTCDesignation(tt.offset)
			if result != tt.expected {
				t.Errorf("formatUTCDesignation(%d) = %s, want %s", tt.offset, result, tt.expected)
			}
		})
	}
}

func TestConsensusTimezone(t *testing.T) {
	t.Run("Empty estimates", func(t *testing.T) {
		result := ConsensusTimezone([]TimezoneEstimate{})
		if result != nil {
			t.Errorf("Expected nil for empty estimates")
		}
	})

	t.Run("Single estimate", func(t *testing.T) {
		estimates := []TimezoneEstimate{
			{
				OffsetSeconds:  -25200,
				OffsetHours:    -7.0,
				UTCDesignation: "UTC-7",
				Confidence:     "low",
				Method:         "xid_vs_log",
			},
		}
		result := ConsensusTimezone(estimates)
		if result.OffsetSeconds != -25200 {
			t.Errorf("OffsetSeconds = %d, want -25200", result.OffsetSeconds)
		}
	})

	t.Run("5 domains same offset - medium confidence", func(t *testing.T) {
		estimates := make([]TimezoneEstimate, 5)
		for i := 0; i < 5; i++ {
			estimates[i] = TimezoneEstimate{
				OffsetSeconds:  -25200,
				OffsetHours:    -7.0,
				UTCDesignation: "UTC-7",
				Confidence:     "low",
				Method:         "xid_vs_log",
			}
		}
		result := ConsensusTimezone(estimates)
		if result.Confidence != "medium" {
			t.Errorf("Confidence = %s, want medium", result.Confidence)
		}
		if result.OffsetSeconds != -25200 {
			t.Errorf("OffsetSeconds = %d, want -25200", result.OffsetSeconds)
		}
	})

	t.Run("6 domains same offset - high confidence", func(t *testing.T) {
		estimates := make([]TimezoneEstimate, 6)
		for i := 0; i < 6; i++ {
			estimates[i] = TimezoneEstimate{
				OffsetSeconds:  -25200,
				OffsetHours:    -7.0,
				UTCDesignation: "UTC-7",
				Confidence:     "low",
				Method:         "xid_vs_log",
			}
		}
		result := ConsensusTimezone(estimates)
		if result.Confidence != "high" {
			t.Errorf("Confidence = %s, want high", result.Confidence)
		}
	})

	t.Run("Mixed offsets - low confidence", func(t *testing.T) {
		estimates := []TimezoneEstimate{
			{OffsetSeconds: -25200, Method: "xid_vs_log"},
			{OffsetSeconds: -25200, Method: "xid_vs_log"},
			{OffsetSeconds: -18000, Method: "xid_vs_log"},
			{OffsetSeconds: -18000, Method: "xid_vs_log"},
		}
		result := ConsensusTimezone(estimates)
		// Should pick one of them (whichever comes first in map iteration, typically -25200 or -18000)
		if result.Confidence != "low" {
			t.Errorf("Confidence = %s, want low (mixed offsets)", result.Confidence)
		}
	})

	t.Run("XID and nonce both agree - bump confidence", func(t *testing.T) {
		estimates := []TimezoneEstimate{
			{OffsetSeconds: -25200, Method: "xid_vs_log", Confidence: "low"},
			{OffsetSeconds: -25200, Method: "xid_vs_log", Confidence: "low"},
			{OffsetSeconds: -25200, Method: "nonce_vs_log", Confidence: "low"},
			{OffsetSeconds: -25200, Method: "nonce_vs_log", Confidence: "low"},
		}
		result := ConsensusTimezone(estimates)
		// All 4 agree, so starts at medium, bumped to high due to method agreement
		if result.Confidence != "high" {
			t.Errorf("Confidence = %s, want high (both methods agree)", result.Confidence)
		}
	})
}
