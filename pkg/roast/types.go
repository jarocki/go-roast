package roast

import "time"

// DecodedOAST contains the decoded metadata from an OAST domain
type DecodedOAST struct {
	Original  string    `json:"original"`            // Original subdomain/FQDN
	Timestamp time.Time `json:"timestamp"`           // Decoded timestamp
	MachineID string    `json:"machine_id"`          // Format: "xx:xx:xx" (3 hex bytes)
	PID       uint16    `json:"pid"`                 // Process ID
	Counter   uint32    `json:"counter"`             // Counter value (24-bit)
	Nonce     string    `json:"nonce,omitempty"`     // The nonce portion (if present)
	KSort     string    `json:"ksort"`               // First 6 chars of preamble (for K-sorting)
	Campaign  string    `json:"campaign"`            // Chars 7-11 of preamble (campaign identifier)
	Valid          bool               `json:"valid"`                        // Whether decoding succeeded
	Error          string             `json:"error,omitempty"`              // Error message if invalid
	Classification *Classification    `json:"classification,omitempty"`     // Client type and version classification
	NonceTimestamp *time.Time         `json:"nonce_timestamp,omitempty"`    // Promoted from NonceAnalysis when reliable
	NonceCounter   *uint32            `json:"nonce_counter,omitempty"`      // Promoted from NonceAnalysis when reliable
	LogTimestamp   *time.Time         `json:"log_timestamp,omitempty"`      // UTC timestamp from DNS/web logs
	TimezoneEstimate *TimezoneEstimate `json:"timezone_estimate,omitempty"` // Timezone offset estimate
}

// OASTMatch represents an extracted OAST domain from text
type OASTMatch struct {
	Full       string `json:"full"`        // Full matched string
	Subdomain  string `json:"subdomain"`   // Just the subdomain portion
	Domain     string `json:"domain"`      // The OAST domain (e.g., "oast.fun")
	StartIndex int    `json:"start_index"` // Position in source text
	EndIndex   int    `json:"end_index"`   // End position in source text
}

// TimezoneEstimate holds the computed timezone offset and confidence
type TimezoneEstimate struct {
	OffsetSeconds  int      `json:"offset_seconds"`   // e.g., -25200 for UTC-7
	OffsetHours    float64  `json:"offset_hours"`     // e.g., -7.0
	UTCDesignation string   `json:"utc_designation"`  // e.g., "UTC-7"
	Confidence     string   `json:"confidence"`       // high/medium/low
	Method         string   `json:"method"`           // "xid_vs_log" or "nonce_vs_log"
	Reasoning      []string `json:"reasoning"`
}

// TimestampedDomain pairs an OAST domain with its log-observed timestamp
type TimestampedDomain struct {
	Domain       string    `json:"domain"`
	LogTimestamp time.Time `json:"log_timestamp"` // UTC from DNS/web logs
}

// Known OAST domain suffixes
var knownOASTDomains = []string{
	"oast.pro",
	"oast.live",
	"oast.site",
	"oast.online",
	"oast.fun",
	"oast.me",
	"interact.sh",
	"interactsh.com",
}

// Base32hex alphabet (RFC 4648)
const base32hexAlphabet = "0123456789abcdefghijklmnopqrstuv"

// z-base-32 alphabet
const zbase32Alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
