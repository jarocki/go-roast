// classify.go implements Interactsh domain classification by client type (CLI vs web)
// and server version (v1.0.1 vs v1.0.2+). Uses character set analysis of the preamble
// and zbase32 decoding of nonces to distinguish origins and extract session analytics.
//
// @decision: Classification uses character-set heuristics rather than attempting full
// protocol fingerprinting. CLI preambles use base32hex [0-9a-v], web preambles use
// letters-only [a-z] (including w,x,y,z which are outside base32hex). v1.0.1 detection
// relies on nonce zbase32-decoding to a valid Unix timestamp (2020-2030 range), since
// v1.0.2+ switched to crypto/rand nonces that produce random timestamps when decoded.
package roast

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// ClientType identifies the Interactsh client that generated the domain.
type ClientType string

const (
	ClientCLI     ClientType = "cli"
	ClientWeb     ClientType = "web"
	ClientUnknown ClientType = "unknown"
)

// ServerVersion identifies the Interactsh server version based on nonce encoding.
type ServerVersion string

const (
	VersionV101    ServerVersion = "v1.0.1"
	VersionV102Plus ServerVersion = "v1.0.2+"
	VersionUnknown ServerVersion = "unknown"
)

// NonceAnalysis contains decoded v1.0.1 nonce fields and derived session analytics.
type NonceAnalysis struct {
	NonceTimestamp    time.Time `json:"nonce_timestamp"`
	NonceCounter      uint32    `json:"nonce_counter"`
	SessionAge        string    `json:"session_age"`
	SessionAgeSecs    int64     `json:"session_age_secs"`
	DomainSequence    uint32    `json:"domain_sequence"`
	TimestampReliable bool      `json:"timestamp_reliable"`
	Commentary        []string  `json:"commentary"`
}

// Classification contains client type, server version, and evidence for a domain.
type Classification struct {
	ClientType    ClientType    `json:"client_type"`
	ServerVersion ServerVersion `json:"server_version"`
	Confidence    string        `json:"confidence"`
	Reasoning     []string      `json:"reasoning"`
	Decodable     bool          `json:"decodable"`
	NonceAnalysis *NonceAnalysis `json:"nonce_analysis,omitempty"`
}

// ClassifyDomain classifies an OAST subdomain by client type and server version.
// cidTimestamp is the decoded XID timestamp (from preamble); pass zero time if unavailable.
func ClassifyDomain(subdomain string, cidTimestamp time.Time) *Classification {
	if len(subdomain) < 20 {
		return &Classification{
			ClientType:    ClientUnknown,
			ServerVersion: VersionUnknown,
			Confidence:    "low",
			Reasoning:     []string{"subdomain too short for classification"},
			Decodable:     false,
		}
	}

	preamble := subdomain[:20]
	var nonce string
	if len(subdomain) > 20 {
		nonce = subdomain[20:]
	}

	clientType, clientReasons, clientConf := classifyClient(preamble)
	version, nonceAnalysis, versionReasons, versionConf := classifyVersion(nonce, cidTimestamp)

	// Combine confidence: take the lower of the two
	confidence := combineConfidence(clientConf, versionConf)

	reasoning := append(clientReasons, versionReasons...)

	return &Classification{
		ClientType:    clientType,
		ServerVersion: version,
		Confidence:    confidence,
		Reasoning:     reasoning,
		Decodable:     clientType == ClientCLI,
		NonceAnalysis: nonceAnalysis,
	}
}

// classifyClient determines CLI vs web client from preamble character set.
func classifyClient(preamble string) (ClientType, []string, string) {
	preamble = strings.ToLower(preamble)
	var reasons []string

	hasDigit := false
	hasHighAlpha := false // w, x, y, z — outside base32hex

	for i := 0; i < len(preamble); i++ {
		c := preamble[i]
		if c >= '0' && c <= '9' {
			hasDigit = true
		}
		if c >= 'w' && c <= 'z' {
			hasHighAlpha = true
		}
	}

	if hasDigit {
		reasons = append(reasons, "preamble contains digits — CLI client (base32hex)")
		return ClientCLI, reasons, "high"
	}

	if hasHighAlpha {
		reasons = append(reasons, fmt.Sprintf("preamble contains letters outside base32hex [w-z] — web client"))
		return ClientWeb, reasons, "high"
	}

	// All-letter preamble within [a-v] — ambiguous (valid in both charsets)
	reasons = append(reasons, "preamble is all-letter [a-v] — ambiguous (valid base32hex and web)")
	return ClientUnknown, reasons, "low"
}

// classifyVersion determines server version from nonce characteristics.
func classifyVersion(nonce string, cidTimestamp time.Time) (ServerVersion, *NonceAnalysis, []string, string) {
	if nonce == "" {
		return VersionUnknown, nil, []string{"no nonce present"}, "low"
	}

	var reasons []string

	// Check for web nonce markers: characters l, v, 0, 2 are NOT in zbase32 alphabet
	hasWebNonceChars := false
	for i := 0; i < len(nonce); i++ {
		c := nonce[i]
		if c == 'l' || c == 'v' || c == '0' || c == '2' {
			hasWebNonceChars = true
			break
		}
	}

	if hasWebNonceChars {
		reasons = append(reasons, "nonce contains characters outside zbase32 alphabet (l/v/0/2) — web nonce")
		return VersionUnknown, nil, reasons, "high"
	}

	// Try to decode as v1.0.1 nonce (zbase32-encoded 8 bytes)
	ts, counter, err := decodeV101Nonce(nonce)
	if err != nil {
		reasons = append(reasons, fmt.Sprintf("nonce zbase32 decode failed: %v — likely v1.0.2+ random", err))
		return VersionV102Plus, nil, reasons, "medium"
	}

	// Check if timestamp is in plausible range (2020-01-01 to 2030-01-01)
	minTS := uint32(1577836800) // 2020-01-01
	maxTS := uint32(1893456000) // 2030-01-01

	if ts >= minTS && ts <= maxTS {
		reasons = append(reasons, fmt.Sprintf("nonce decodes to valid timestamp %s — v1.0.1", time.Unix(int64(ts), 0).UTC().Format(time.RFC3339)))
		reasons = append(reasons, fmt.Sprintf("nonce counter=%d (domain sequence in process)", counter))

		now := time.Now()

		// Future timestamp detection: valid range but ahead of current time
		if ts > uint32(now.Unix()) {
			reasons = append(reasons, "nonce timestamp is in the future — possible false positive v1.0.1 classification")
			na := analyzeNonce(time.Unix(int64(ts), 0), counter, cidTimestamp, now)
			return VersionV101, na, reasons, "medium"
		}

		na := analyzeNonce(time.Unix(int64(ts), 0), counter, cidTimestamp, now)

		// Nonce-predates-CID reclassification: if timestamp is unreliable and
		// nonce significantly predates CID, downgrade confidence
		if !na.TimestampReliable && na.SessionAgeSecs < -300 {
			reasons = append(reasons, "nonce timestamp predates CID by significant margin — likely not a real v1.0.1 timestamp")
			return VersionV101, na, reasons, "low"
		}

		return VersionV101, na, reasons, "high"
	}

	// Timestamp out of range — likely random bytes from v1.0.2+
	reasons = append(reasons, fmt.Sprintf("nonce decodes to out-of-range timestamp %d — likely v1.0.2+ random", ts))
	return VersionV102Plus, nil, reasons, "medium"
}

// decodeV101Nonce zbase32-decodes a nonce and extracts the 4-byte timestamp and 4-byte counter.
func decodeV101Nonce(nonce string) (timestamp uint32, counter uint32, err error) {
	bytes, err := zbase32Decode(nonce)
	if err != nil {
		return 0, 0, err
	}
	if len(bytes) < 8 {
		return 0, 0, fmt.Errorf("decoded nonce too short: %d bytes (need 8)", len(bytes))
	}

	timestamp = binary.BigEndian.Uint32(bytes[0:4])
	counter = binary.BigEndian.Uint32(bytes[4:8])
	return timestamp, counter, nil
}

// analyzeNonce generates analytical commentary comparing CID and nonce fields.
// The now parameter is used to detect future timestamps; pass time.Now() from callers.
func analyzeNonce(nonceTimestamp time.Time, nonceCounter uint32, cidTimestamp time.Time, now time.Time) *NonceAnalysis {
	na := &NonceAnalysis{
		NonceTimestamp:    nonceTimestamp,
		NonceCounter:      nonceCounter,
		DomainSequence:    nonceCounter,
		TimestampReliable: true,
	}

	// Future timestamp detection
	if nonceTimestamp.After(now) {
		na.TimestampReliable = false
		na.Commentary = append(na.Commentary,
			"nonce_timestamp is in the future — decoded value may not represent a real timestamp")
	}

	// Session age: NonceTimestamp - CIDTimestamp
	if !cidTimestamp.IsZero() {
		delta := nonceTimestamp.Sub(cidTimestamp)
		na.SessionAgeSecs = int64(delta.Seconds())

		if delta < 0 {
			// Nonce timestamp predates CID — anomalous (nonce should be >= CID)
			absDelta := -delta
			na.SessionAge = "-" + formatDuration(absDelta)
			na.Commentary = append(na.Commentary,
				fmt.Sprintf("nonce_timestamp predates cid_timestamp by %s — timestamps inconsistent (possible clock skew, recycled nonce, or misclassified version)", formatDuration(absDelta)))

			// Predates CID by more than 5 minutes — mark as unreliable
			if na.SessionAgeSecs < -300 {
				na.TimestampReliable = false
			}
		} else {
			na.SessionAge = formatDuration(delta)

			// Commentary on session age
			switch {
			case delta < 2*time.Second:
				na.Commentary = append(na.Commentary,
					fmt.Sprintf("session_age=%s: domain generated at client startup (likely automated/scripted)", na.SessionAge))
				na.Commentary = append(na.Commentary,
					"nonce_timestamp matches cid_timestamp: single-use client (generated one domain at init)")
			case delta < time.Hour:
				na.Commentary = append(na.Commentary,
					fmt.Sprintf("session_age=%s: short client session", na.SessionAge))
			default:
				na.Commentary = append(na.Commentary,
					fmt.Sprintf("session_age=%s: long-running client session", na.SessionAge))
			}
		}
	}

	// Commentary on counter
	switch {
	case nonceCounter == 0:
		na.Commentary = append(na.Commentary,
			"nonce_counter=0: first domain generated (counter pre-increment yields 1 normally; 0 suggests test or edge case)")
	case nonceCounter == 1:
		na.Commentary = append(na.Commentary,
			"nonce_counter=1: first domain generated in this process (atomic.AddUint32 pre-increment)")
	case nonceCounter <= 10:
		na.Commentary = append(na.Commentary,
			fmt.Sprintf("nonce_counter=%d: low-volume domain generation (%d URLs in session)", nonceCounter, nonceCounter))
	case nonceCounter <= 100:
		na.Commentary = append(na.Commentary,
			fmt.Sprintf("nonce_counter=%d: moderate domain generation", nonceCounter))
	default:
		na.Commentary = append(na.Commentary,
			fmt.Sprintf("nonce_counter=%d: high-volume domain generation (%d URLs in session)", nonceCounter, nonceCounter))
	}

	return na
}

// combineConfidence returns the lower of two confidence levels.
func combineConfidence(a, b string) string {
	order := map[string]int{"high": 3, "medium": 2, "low": 1}
	av, bv := order[a], order[b]
	if av <= bv {
		return a
	}
	return b
}
