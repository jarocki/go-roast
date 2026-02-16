// Package roast provides PID lifecycle tracking tests.
/**
 * @decision DEC-LIFECYCLE-001
 * @title PID Lifecycle Tracking Test Coverage
 * @status accepted
 * @rationale Tests for PID session extraction: single PID, multiple PIDs,
 *            counter range tracking, and chronological ordering.
 */
package roast

import (
	"testing"
	"time"
)

func TestAnalyzePIDLifecycles(t *testing.T) {
	t.Run("Empty input", func(t *testing.T) {
		sessions := AnalyzePIDLifecycles([]*DecodedOAST{})
		if len(sessions) != 0 {
			t.Errorf("Expected empty result for empty input, got %d sessions", len(sessions))
		}
	})

	t.Run("Single PID session", func(t *testing.T) {
		decoded := []*DecodedOAST{
			{
				Valid:     true,
				PID:       12345,
				Counter:   1,
				Timestamp: time.Unix(1000, 0),
				MachineID: "aa:bb:cc",
			},
			{
				Valid:     true,
				PID:       12345,
				Counter:   5,
				Timestamp: time.Unix(1100, 0),
				MachineID: "aa:bb:cc",
			},
			{
				Valid:     true,
				PID:       12345,
				Counter:   3,
				Timestamp: time.Unix(1050, 0),
				MachineID: "aa:bb:cc",
			},
		}

		sessions := AnalyzePIDLifecycles(decoded)

		if len(sessions) != 1 {
			t.Fatalf("Expected 1 session, got %d", len(sessions))
		}

		s := sessions[0]
		if s.PID != 12345 {
			t.Errorf("PID = %d, want 12345", s.PID)
		}
		if s.DomainCount != 3 {
			t.Errorf("DomainCount = %d, want 3", s.DomainCount)
		}
		if s.FirstSeen.Unix() != 1000 {
			t.Errorf("FirstSeen = %d, want 1000", s.FirstSeen.Unix())
		}
		if s.LastSeen.Unix() != 1100 {
			t.Errorf("LastSeen = %d, want 1100", s.LastSeen.Unix())
		}
		if s.CounterRange[0] != 1 {
			t.Errorf("CounterRange[0] = %d, want 1", s.CounterRange[0])
		}
		if s.CounterRange[1] != 5 {
			t.Errorf("CounterRange[1] = %d, want 5", s.CounterRange[1])
		}
		if s.DurationSecs != 100 {
			t.Errorf("DurationSecs = %d, want 100", s.DurationSecs)
		}
	})

	t.Run("Multiple PIDs sorted by FirstSeen", func(t *testing.T) {
		decoded := []*DecodedOAST{
			{
				Valid:     true,
				PID:       100,
				Counter:   1,
				Timestamp: time.Unix(2000, 0),
				MachineID: "aa:bb:cc",
			},
			{
				Valid:     true,
				PID:       200,
				Counter:   10,
				Timestamp: time.Unix(1000, 0),
				MachineID: "aa:bb:cc",
			},
			{
				Valid:     true,
				PID:       100,
				Counter:   2,
				Timestamp: time.Unix(2100, 0),
				MachineID: "aa:bb:cc",
			},
		}

		sessions := AnalyzePIDLifecycles(decoded)

		if len(sessions) != 2 {
			t.Fatalf("Expected 2 sessions, got %d", len(sessions))
		}

		// Should be sorted by FirstSeen (PID 200 comes first)
		if sessions[0].PID != 200 {
			t.Errorf("sessions[0].PID = %d, want 200", sessions[0].PID)
		}
		if sessions[1].PID != 100 {
			t.Errorf("sessions[1].PID = %d, want 100", sessions[1].PID)
		}

		// Verify PID 200 stats
		if sessions[0].DomainCount != 1 {
			t.Errorf("PID 200 DomainCount = %d, want 1", sessions[0].DomainCount)
		}
		if sessions[0].CounterRange[0] != 10 || sessions[0].CounterRange[1] != 10 {
			t.Errorf("PID 200 CounterRange = %v, want [10, 10]", sessions[0].CounterRange)
		}

		// Verify PID 100 stats
		if sessions[1].DomainCount != 2 {
			t.Errorf("PID 100 DomainCount = %d, want 2", sessions[1].DomainCount)
		}
		if sessions[1].CounterRange[0] != 1 || sessions[1].CounterRange[1] != 2 {
			t.Errorf("PID 100 CounterRange = %v, want [1, 2]", sessions[1].CounterRange)
		}
	})

	t.Run("Filter invalid domains", func(t *testing.T) {
		decoded := []*DecodedOAST{
			{
				Valid:     false,
				PID:       999,
				Counter:   1,
				Timestamp: time.Unix(1000, 0),
			},
			{
				Valid:     true,
				PID:       100,
				Counter:   1,
				Timestamp: time.Unix(1000, 0),
				MachineID: "aa:bb:cc",
			},
		}

		sessions := AnalyzePIDLifecycles(decoded)

		if len(sessions) != 1 {
			t.Fatalf("Expected 1 session (invalid filtered), got %d", len(sessions))
		}

		if sessions[0].PID != 100 {
			t.Errorf("PID = %d, want 100", sessions[0].PID)
		}
	})

	t.Run("Multiple PIDs same machine", func(t *testing.T) {
		decoded := []*DecodedOAST{
			{
				Valid:     true,
				PID:       100,
				Counter:   1,
				Timestamp: time.Unix(1000, 0),
				MachineID: "aa:bb:cc",
			},
			{
				Valid:     true,
				PID:       200,
				Counter:   1,
				Timestamp: time.Unix(2000, 0),
				MachineID: "aa:bb:cc",
			},
		}

		sessions := AnalyzePIDLifecycles(decoded)

		if len(sessions) != 2 {
			t.Fatalf("Expected 2 sessions, got %d", len(sessions))
		}

		for _, s := range sessions {
			if s.MachineID != "aa:bb:cc" {
				t.Errorf("MachineID = %s, want aa:bb:cc", s.MachineID)
			}
		}
	})
}
