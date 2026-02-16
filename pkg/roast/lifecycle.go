// Package roast provides PID lifecycle tracking for OAST domain analysis.
/**
 * @decision DEC-LIFECYCLE-001
 * @title PID Lifecycle Tracking
 * @status accepted
 * @rationale Track process (PID) lifespans across domains from the same machine.
 *            Multiple PIDs from one machine indicate tool restarts or parallel processes.
 *            Counter ranges and timestamps reveal process longevity and domain generation rate.
 */
package roast

import (
	"sort"
	"time"
)

// PIDSession represents the lifecycle of a single PID
type PIDSession struct {
	PID          uint16    `json:"pid"`
	MachineID    string    `json:"machine_id"`
	DomainCount  int       `json:"domain_count"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	DurationSecs int64     `json:"duration_secs"`
	Duration     string    `json:"duration"`        // Human-readable duration
	Velocity     float64   `json:"velocity"`        // Domains per hour
	CounterRange [2]uint32 `json:"counter_range"`   // [min, max]
}

// AnalyzePIDLifecycles extracts PID sessions from decoded domains.
// Returns sessions sorted by FirstSeen (chronological order).
func AnalyzePIDLifecycles(decoded []*DecodedOAST) []PIDSession {
	// Group by PID
	pidGroups := make(map[uint16][]*DecodedOAST)
	for _, d := range decoded {
		if !d.Valid {
			continue
		}
		pidGroups[d.PID] = append(pidGroups[d.PID], d)
	}

	// Build sessions
	sessions := make([]PIDSession, 0, len(pidGroups))
	for pid, domains := range pidGroups {
		if len(domains) == 0 {
			continue
		}

		session := PIDSession{
			PID:         pid,
			DomainCount: len(domains),
			MachineID:   domains[0].MachineID,
		}

		// Find time range
		session.FirstSeen = domains[0].Timestamp
		session.LastSeen = domains[0].Timestamp
		session.CounterRange = [2]uint32{domains[0].Counter, domains[0].Counter}

		for _, d := range domains {
			if d.Timestamp.Before(session.FirstSeen) {
				session.FirstSeen = d.Timestamp
			}
			if d.Timestamp.After(session.LastSeen) {
				session.LastSeen = d.Timestamp
			}
			if d.Counter < session.CounterRange[0] {
				session.CounterRange[0] = d.Counter
			}
			if d.Counter > session.CounterRange[1] {
				session.CounterRange[1] = d.Counter
			}
		}

		duration := session.LastSeen.Sub(session.FirstSeen)
		session.DurationSecs = int64(duration.Seconds())
		session.Duration = formatDuration(duration)

		// Calculate velocity (domains per hour)
		if duration.Hours() > 0 {
			session.Velocity = float64(len(domains)) / duration.Hours()
		}

		sessions = append(sessions, session)
	}

	// Sort by FirstSeen (chronological)
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].FirstSeen.Before(sessions[j].FirstSeen)
	})

	return sessions
}
