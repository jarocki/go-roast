// Package roast provides counter gap analysis tests.
/**
 * @decision DEC-GAPS-001
 * @title Counter Gap Analysis Test Coverage
 * @status accepted
 * @rationale Tests for counter gap detection: no gaps, single gap, multiple gaps,
 *            gap size calculation, and per-machine gap analysis.
 */
package roast

import (
	"testing"
	"time"
)

func TestAnalyzeCounterGaps(t *testing.T) {
	t.Run("Empty input", func(t *testing.T) {
		analysis := AnalyzeCounterGaps([]*DecodedOAST{})
		if analysis != nil {
			t.Errorf("Expected nil for empty input, got %+v", analysis)
		}
	})

	t.Run("No gaps - consecutive counters", func(t *testing.T) {
		decoded := []*DecodedOAST{
			{
				Valid:     true,
				Counter:   1,
				MachineID: "aa:bb:cc",
				PID:       100,
				Timestamp: time.Unix(1000, 0),
			},
			{
				Valid:     true,
				Counter:   2,
				MachineID: "aa:bb:cc",
				PID:       100,
				Timestamp: time.Unix(1001, 0),
			},
			{
				Valid:     true,
				Counter:   3,
				MachineID: "aa:bb:cc",
				PID:       100,
				Timestamp: time.Unix(1002, 0),
			},
		}

		analysis := AnalyzeCounterGaps(decoded)

		if analysis.TotalGaps != 0 {
			t.Errorf("TotalGaps = %d, want 0 (consecutive)", analysis.TotalGaps)
		}
		if len(analysis.Gaps) != 0 {
			t.Errorf("Expected no gaps, got %d", len(analysis.Gaps))
		}
	})

	t.Run("Single gap", func(t *testing.T) {
		decoded := []*DecodedOAST{
			{
				Valid:     true,
				Counter:   1,
				MachineID: "aa:bb:cc",
				PID:       100,
				Timestamp: time.Unix(1000, 0),
			},
			{
				Valid:     true,
				Counter:   5,
				MachineID: "aa:bb:cc",
				PID:       100,
				Timestamp: time.Unix(1004, 0),
			},
		}

		analysis := AnalyzeCounterGaps(decoded)

		if analysis.TotalGaps != 1 {
			t.Fatalf("TotalGaps = %d, want 1", analysis.TotalGaps)
		}

		gap := analysis.Gaps[0]
		if gap.MachineID != "aa:bb:cc" {
			t.Errorf("MachineID = %s, want aa:bb:cc", gap.MachineID)
		}
		if gap.PID != 100 {
			t.Errorf("PID = %d, want 100", gap.PID)
		}
		if gap.StartCounter != 1 {
			t.Errorf("StartCounter = %d, want 1", gap.StartCounter)
		}
		if gap.EndCounter != 5 {
			t.Errorf("EndCounter = %d, want 5", gap.EndCounter)
		}
		if gap.GapSize != 3 {
			t.Errorf("GapSize = %d, want 3 (2, 3, 4)", gap.GapSize)
		}
	})

	t.Run("Multiple gaps same machine", func(t *testing.T) {
		decoded := []*DecodedOAST{
			{
				Valid:     true,
				Counter:   1,
				MachineID: "aa:bb:cc",
				PID:       100,
				Timestamp: time.Unix(1000, 0),
			},
			{
				Valid:     true,
				Counter:   3,
				MachineID: "aa:bb:cc",
				PID:       100,
				Timestamp: time.Unix(1002, 0),
			},
			{
				Valid:     true,
				Counter:   5,
				MachineID: "aa:bb:cc",
				PID:       100,
				Timestamp: time.Unix(1004, 0),
			},
		}

		analysis := AnalyzeCounterGaps(decoded)

		if analysis.TotalGaps != 2 {
			t.Fatalf("TotalGaps = %d, want 2", analysis.TotalGaps)
		}

		// First gap: 1 -> 3 (missing 2)
		if analysis.Gaps[0].StartCounter != 1 || analysis.Gaps[0].EndCounter != 3 {
			t.Errorf("Gap 0: [%d, %d], want [1, 3]", analysis.Gaps[0].StartCounter, analysis.Gaps[0].EndCounter)
		}
		if analysis.Gaps[0].GapSize != 1 {
			t.Errorf("Gap 0 GapSize = %d, want 1", analysis.Gaps[0].GapSize)
		}

		// Second gap: 3 -> 5 (missing 4)
		if analysis.Gaps[1].StartCounter != 3 || analysis.Gaps[1].EndCounter != 5 {
			t.Errorf("Gap 1: [%d, %d], want [3, 5]", analysis.Gaps[1].StartCounter, analysis.Gaps[1].EndCounter)
		}
		if analysis.Gaps[1].GapSize != 1 {
			t.Errorf("Gap 1 GapSize = %d, want 1", analysis.Gaps[1].GapSize)
		}
	})

	t.Run("Multiple machines separate gaps", func(t *testing.T) {
		decoded := []*DecodedOAST{
			{
				Valid:     true,
				Counter:   1,
				MachineID: "aa:bb:cc",
				PID:       100,
				Timestamp: time.Unix(1000, 0),
			},
			{
				Valid:     true,
				Counter:   5,
				MachineID: "aa:bb:cc",
				PID:       100,
				Timestamp: time.Unix(1004, 0),
			},
			{
				Valid:     true,
				Counter:   10,
				MachineID: "dd:ee:ff",
				PID:       200,
				Timestamp: time.Unix(2000, 0),
			},
			{
				Valid:     true,
				Counter:   15,
				MachineID: "dd:ee:ff",
				PID:       200,
				Timestamp: time.Unix(2005, 0),
			},
		}

		analysis := AnalyzeCounterGaps(decoded)

		if analysis.TotalGaps != 2 {
			t.Fatalf("TotalGaps = %d, want 2", analysis.TotalGaps)
		}

		if len(analysis.PerMachineGaps) != 2 {
			t.Fatalf("PerMachineGaps count = %d, want 2", len(analysis.PerMachineGaps))
		}

		// Check per-machine aggregation
		aaGaps, ok := analysis.PerMachineGaps["aa:bb:cc"]
		if !ok {
			t.Fatal("Missing aa:bb:cc in PerMachineGaps")
		}
		if aaGaps != 1 {
			t.Errorf("aa:bb:cc gaps = %d, want 1", aaGaps)
		}

		ddGaps, ok := analysis.PerMachineGaps["dd:ee:ff"]
		if !ok {
			t.Fatal("Missing dd:ee:ff in PerMachineGaps")
		}
		if ddGaps != 1 {
			t.Errorf("dd:ee:ff gaps = %d, want 1", ddGaps)
		}
	})

	t.Run("Filter invalid domains", func(t *testing.T) {
		decoded := []*DecodedOAST{
			{
				Valid:     false,
				Counter:   1,
				MachineID: "aa:bb:cc",
				PID:       100,
			},
			{
				Valid:     true,
				Counter:   1,
				MachineID: "aa:bb:cc",
				PID:       100,
				Timestamp: time.Unix(1000, 0),
			},
			{
				Valid:     true,
				Counter:   2,
				MachineID: "aa:bb:cc",
				PID:       100,
				Timestamp: time.Unix(1001, 0),
			},
		}

		analysis := AnalyzeCounterGaps(decoded)

		if analysis.TotalGaps != 0 {
			t.Errorf("TotalGaps = %d, want 0 (invalid filtered)", analysis.TotalGaps)
		}
	})

	t.Run("Large gap", func(t *testing.T) {
		decoded := []*DecodedOAST{
			{
				Valid:     true,
				Counter:   1,
				MachineID: "aa:bb:cc",
				PID:       100,
				Timestamp: time.Unix(1000, 0),
			},
			{
				Valid:     true,
				Counter:   200,
				MachineID: "aa:bb:cc",
				PID:       100,
				Timestamp: time.Unix(1199, 0),
			},
		}

		analysis := AnalyzeCounterGaps(decoded)

		if analysis.TotalGaps != 1 {
			t.Fatalf("TotalGaps = %d, want 1", analysis.TotalGaps)
		}

		gap := analysis.Gaps[0]
		if gap.GapSize != 198 {
			t.Errorf("GapSize = %d, want 198 (2-199)", gap.GapSize)
		}
		if gap.StartCounter != 1 || gap.EndCounter != 200 {
			t.Errorf("Gap range = [%d, %d], want [1, 200]", gap.StartCounter, gap.EndCounter)
		}
		if !gap.Suspicious {
			t.Error("Expected gap to be marked suspicious (>100)")
		}
		if analysis.MissingDomains != 198 {
			t.Errorf("MissingDomains = %d, want 198", analysis.MissingDomains)
		}
	})
}
