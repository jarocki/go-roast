// Package roast provides machine clustering tests.
/**
 * @decision DEC-CLUSTER-001
 * @title Machine Clustering Test Coverage
 * @status accepted
 * @rationale Tests for machine-based domain clustering: single machine, multiple machines,
 *            domain counting, timeline tracking, and sorting by domain count.
 */
package roast

import (
	"testing"
	"time"
)

func TestClusterByMachine(t *testing.T) {
	t.Run("Empty input", func(t *testing.T) {
		clusters := ClusterByMachine([]*DecodedOAST{})
		if len(clusters) != 0 {
			t.Errorf("Expected empty result for empty input, got %d clusters", len(clusters))
		}
	})

	t.Run("Single machine", func(t *testing.T) {
		decoded := []*DecodedOAST{
			{
				Valid:     true,
				MachineID: "aa:bb:cc",
				Counter:   1,
				PID:       100,
				Timestamp: time.Unix(1000, 0),
			},
			{
				Valid:     true,
				MachineID: "aa:bb:cc",
				Counter:   2,
				PID:       100,
				Timestamp: time.Unix(1100, 0),
			},
			{
				Valid:     true,
				MachineID: "aa:bb:cc",
				Counter:   3,
				PID:       200,
				Timestamp: time.Unix(1050, 0),
			},
		}

		clusters := ClusterByMachine(decoded)

		if len(clusters) != 1 {
			t.Fatalf("Expected 1 cluster, got %d", len(clusters))
		}

		c := clusters[0]
		if c.MachineID != "aa:bb:cc" {
			t.Errorf("MachineID = %s, want aa:bb:cc", c.MachineID)
		}
		if c.DomainCount != 3 {
			t.Errorf("DomainCount = %d, want 3", c.DomainCount)
		}
		if c.FirstSeen.Unix() != 1000 {
			t.Errorf("FirstSeen = %d, want 1000", c.FirstSeen.Unix())
		}
		if c.LastSeen.Unix() != 1100 {
			t.Errorf("LastSeen = %d, want 1100", c.LastSeen.Unix())
		}
		if len(c.PIDs) != 2 {
			t.Errorf("PIDs count = %d, want 2", len(c.PIDs))
		}
		if c.CounterRange[0] != 1 || c.CounterRange[1] != 3 {
			t.Errorf("CounterRange = %v, want [1, 3]", c.CounterRange)
		}
	})

	t.Run("Multiple machines sorted by FirstSeen", func(t *testing.T) {
		decoded := []*DecodedOAST{
			{
				Valid:     true,
				MachineID: "aa:bb:cc",
				Counter:   1,
				PID:       100,
				Timestamp: time.Unix(2000, 0),
			},
			{
				Valid:     true,
				MachineID: "dd:ee:ff",
				Counter:   1,
				PID:       200,
				Timestamp: time.Unix(1000, 0),
			},
			{
				Valid:     true,
				MachineID: "dd:ee:ff",
				Counter:   2,
				PID:       200,
				Timestamp: time.Unix(1001, 0),
			},
			{
				Valid:     true,
				MachineID: "dd:ee:ff",
				Counter:   3,
				PID:       200,
				Timestamp: time.Unix(1002, 0),
			},
		}

		clusters := ClusterByMachine(decoded)

		if len(clusters) != 2 {
			t.Fatalf("Expected 2 clusters, got %d", len(clusters))
		}

		// Should be sorted by FirstSeen chronological (dd:ee:ff first at 1000, aa:bb:cc at 2000)
		if clusters[0].MachineID != "dd:ee:ff" {
			t.Errorf("clusters[0].MachineID = %s, want dd:ee:ff", clusters[0].MachineID)
		}
		if clusters[0].DomainCount != 3 {
			t.Errorf("clusters[0].DomainCount = %d, want 3", clusters[0].DomainCount)
		}

		if clusters[1].MachineID != "aa:bb:cc" {
			t.Errorf("clusters[1].MachineID = %s, want aa:bb:cc", clusters[1].MachineID)
		}
		if clusters[1].DomainCount != 1 {
			t.Errorf("clusters[1].DomainCount = %d, want 1", clusters[1].DomainCount)
		}
	})

	t.Run("Filter invalid domains", func(t *testing.T) {
		decoded := []*DecodedOAST{
			{
				Valid:     false,
				MachineID: "invalid:machine",
				Counter:   1,
				PID:       999,
			},
			{
				Valid:     true,
				MachineID: "aa:bb:cc",
				Counter:   1,
				PID:       100,
				Timestamp: time.Unix(1000, 0),
			},
		}

		clusters := ClusterByMachine(decoded)

		if len(clusters) != 1 {
			t.Fatalf("Expected 1 cluster (invalid filtered), got %d", len(clusters))
		}

		if clusters[0].MachineID != "aa:bb:cc" {
			t.Errorf("MachineID = %s, want aa:bb:cc", clusters[0].MachineID)
		}
	})

	t.Run("Multiple PIDs per machine", func(t *testing.T) {
		decoded := []*DecodedOAST{
			{
				Valid:     true,
				MachineID: "aa:bb:cc",
				Counter:   1,
				PID:       100,
				Timestamp: time.Unix(1000, 0),
			},
			{
				Valid:     true,
				MachineID: "aa:bb:cc",
				Counter:   2,
				PID:       200,
				Timestamp: time.Unix(1001, 0),
			},
			{
				Valid:     true,
				MachineID: "aa:bb:cc",
				Counter:   3,
				PID:       300,
				Timestamp: time.Unix(1002, 0),
			},
		}

		clusters := ClusterByMachine(decoded)

		if len(clusters) != 1 {
			t.Fatalf("Expected 1 cluster, got %d", len(clusters))
		}

		if len(clusters[0].PIDs) != 3 {
			t.Errorf("PIDs count = %d, want 3", len(clusters[0].PIDs))
		}

		// PIDs should be sorted
		expectedPIDs := []uint16{100, 200, 300}
		for i, expected := range expectedPIDs {
			if clusters[0].PIDs[i] != expected {
				t.Errorf("PIDs[%d] = %d, want %d", i, clusters[0].PIDs[i], expected)
			}
		}
	})

	t.Run("Campaign tracking", func(t *testing.T) {
		decoded := []*DecodedOAST{
			{
				Valid:     true,
				MachineID: "aa:bb:cc",
				Counter:   1,
				PID:       100,
				Timestamp: time.Unix(1000, 0),
				Campaign:  "abcde",
			},
			{
				Valid:     true,
				MachineID: "aa:bb:cc",
				Counter:   2,
				PID:       100,
				Timestamp: time.Unix(1001, 0),
				Campaign:  "fghij",
			},
		}

		clusters := ClusterByMachine(decoded)

		if len(clusters) != 1 {
			t.Fatalf("Expected 1 cluster, got %d", len(clusters))
		}

		if len(clusters[0].Campaigns) != 2 {
			t.Errorf("Campaigns count = %d, want 2", len(clusters[0].Campaigns))
		}
	})
}
