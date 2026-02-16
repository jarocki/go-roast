// Package roast provides counter gap analysis for OAST domain forensics.
/**
 * @decision DEC-GAPS-001
 * @title Counter Gap Analysis
 * @status accepted
 * @rationale Counter gaps reveal missing domains - possible filtering, deletion,
 *            or selective disclosure. Large gaps suggest bulk cleanup or long-running
 *            campaigns with partial captures.
 */
package roast

import (
	"sort"
	"time"
)

// CounterGap represents a gap in the counter sequence
type CounterGap struct {
	MachineID    string    `json:"machine_id"`
	PID          uint16    `json:"pid"`
	StartCounter uint32    `json:"start_counter"`  // Counter before gap
	EndCounter   uint32    `json:"end_counter"`    // Counter after gap
	GapSize      uint32    `json:"gap_size"`       // Number of missing counters
	TimeGap      int64     `json:"time_gap_secs"`  // Time between start and end
	StartTime    time.Time `json:"start_time"`
	EndTime      time.Time `json:"end_time"`
	Suspicious   bool      `json:"suspicious"`     // True if gap > 100
}

// GapAnalysis contains the full gap analysis results
type GapAnalysis struct {
	TotalGaps       int            `json:"total_gaps"`
	MissingDomains  uint32         `json:"missing_domains"`  // Total missing across all gaps
	Gaps            []CounterGap   `json:"gaps"`
	PerMachineGaps  map[string]int `json:"per_machine_gaps"`
}

// AnalyzeCounterGaps detects gaps in counter sequences per machine+PID.
// Counters should be sequential. Gaps indicate missing domains.
// Returns nil if input is empty.
func AnalyzeCounterGaps(decoded []*DecodedOAST) *GapAnalysis {
	if len(decoded) == 0 {
		return nil
	}

	analysis := &GapAnalysis{
		Gaps:           []CounterGap{},
		PerMachineGaps: make(map[string]int),
	}

	// Group by machine+PID
	type sessionKey struct {
		machineID string
		pid       uint16
	}
	sessions := make(map[sessionKey][]*DecodedOAST)

	for _, d := range decoded {
		if !d.Valid {
			continue
		}
		key := sessionKey{d.MachineID, d.PID}
		sessions[key] = append(sessions[key], d)
	}

	// Analyze each session for gaps
	for key, domains := range sessions {
		// Sort by counter
		sort.Slice(domains, func(i, j int) bool {
			return domains[i].Counter < domains[j].Counter
		})

		// Detect gaps
		for i := 0; i < len(domains)-1; i++ {
			current := domains[i]
			next := domains[i+1]

			// Gap exists if counters are not consecutive
			if next.Counter != current.Counter+1 {
				gapSize := next.Counter - current.Counter - 1
				gap := CounterGap{
					MachineID:    key.machineID,
					PID:          key.pid,
					StartCounter: current.Counter,
					EndCounter:   next.Counter,
					GapSize:      gapSize,
					StartTime:    current.Timestamp,
					EndTime:      next.Timestamp,
					TimeGap:      int64(next.Timestamp.Sub(current.Timestamp).Seconds()),
					Suspicious:   gapSize > 100,
				}
				analysis.Gaps = append(analysis.Gaps, gap)
				analysis.PerMachineGaps[key.machineID]++
				analysis.MissingDomains += gapSize
			}
		}
	}

	analysis.TotalGaps = len(analysis.Gaps)
	return analysis
}
