// Package roast provides machine-based clustering for OAST domain analysis.
/**
 * @decision DEC-CLUSTER-001
 * @title Machine-Based Domain Clustering
 * @status accepted
 * @rationale Group domains by MachineID to reveal distinct hosts in a campaign.
 *            Multiple machines indicate distributed operations, VM/container sprawl,
 *            or coordinated testing infrastructure.
 */
package roast

import (
	"sort"
	"time"
)

// MachineCluster represents all domains from a single machine
type MachineCluster struct {
	MachineID         string             `json:"machine_id"`
	DomainCount       int                `json:"domain_count"`
	FirstSeen         time.Time          `json:"first_seen"`
	LastSeen          time.Time          `json:"last_seen"`
	Duration          string             `json:"duration"`          // Human-readable duration
	Velocity          float64            `json:"velocity"`          // Domains per hour
	PIDs              []uint16           `json:"pids"`
	CounterRange      [2]uint32          `json:"counter_range"`     // [min, max]
	Campaigns         []string           `json:"campaigns"`
	TimezoneConsensus *TimezoneEstimate  `json:"timezone_consensus,omitempty"`
}

// ClusterByMachine groups decoded domains by MachineID.
// Returns clusters sorted by FirstSeen chronological (earliest first).
func ClusterByMachine(decoded []*DecodedOAST) []MachineCluster {
	// Group by MachineID
	machineGroups := make(map[string][]*DecodedOAST)
	for _, d := range decoded {
		if !d.Valid {
			continue
		}
		machineGroups[d.MachineID] = append(machineGroups[d.MachineID], d)
	}

	// Build clusters
	clusters := make([]MachineCluster, 0, len(machineGroups))
	for machineID, domains := range machineGroups {
		if len(domains) == 0 {
			continue
		}

		cluster := MachineCluster{
			MachineID:   machineID,
			DomainCount: len(domains),
		}

		// Track unique PIDs and campaigns
		pidSet := make(map[uint16]bool)
		campaignSet := make(map[string]bool)

		// Find time and counter ranges
		cluster.FirstSeen = domains[0].Timestamp
		cluster.LastSeen = domains[0].Timestamp
		cluster.CounterRange = [2]uint32{domains[0].Counter, domains[0].Counter}

		for _, d := range domains {
			pidSet[d.PID] = true
			if d.Campaign != "" {
				campaignSet[d.Campaign] = true
			}

			if d.Timestamp.Before(cluster.FirstSeen) {
				cluster.FirstSeen = d.Timestamp
			}
			if d.Timestamp.After(cluster.LastSeen) {
				cluster.LastSeen = d.Timestamp
			}
			if d.Counter < cluster.CounterRange[0] {
				cluster.CounterRange[0] = d.Counter
			}
			if d.Counter > cluster.CounterRange[1] {
				cluster.CounterRange[1] = d.Counter
			}
		}

		// Convert sets to sorted slices
		cluster.PIDs = make([]uint16, 0, len(pidSet))
		for pid := range pidSet {
			cluster.PIDs = append(cluster.PIDs, pid)
		}
		sort.Slice(cluster.PIDs, func(i, j int) bool {
			return cluster.PIDs[i] < cluster.PIDs[j]
		})

		cluster.Campaigns = make([]string, 0, len(campaignSet))
		for campaign := range campaignSet {
			cluster.Campaigns = append(cluster.Campaigns, campaign)
		}
		sort.Strings(cluster.Campaigns)

		// Calculate duration and velocity
		duration := cluster.LastSeen.Sub(cluster.FirstSeen)
		cluster.Duration = formatDuration(duration)
		if duration.Hours() > 0 {
			cluster.Velocity = float64(len(domains)) / duration.Hours()
		}

		// Compute timezone consensus if estimates are present
		var tzEstimates []TimezoneEstimate
		for _, d := range domains {
			if d.TimezoneEstimate != nil {
				tzEstimates = append(tzEstimates, *d.TimezoneEstimate)
			}
		}
		if len(tzEstimates) > 0 {
			cluster.TimezoneConsensus = ConsensusTimezone(tzEstimates)
		}

		clusters = append(clusters, cluster)
	}

	// Sort by FirstSeen chronological (earliest first)
	sort.Slice(clusters, func(i, j int) bool {
		return clusters[i].FirstSeen.Before(clusters[j].FirstSeen)
	})

	return clusters
}
