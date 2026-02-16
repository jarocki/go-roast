package roast

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Decode decodes a single OAST subdomain (the part before the OAST domain)
// Input can be just the subdomain or a full FQDN
func Decode(input string) (*DecodedOAST, error) {
	if input == "" {
		result := &DecodedOAST{
			Original: input,
			Valid:    false,
			Error:    "empty input",
		}
		return result, fmt.Errorf("empty input")
	}

	// Extract just the subdomain if a full FQDN was provided
	subdomain := input
	if idx := strings.Index(input, "."); idx > 0 {
		subdomain = input[:idx]
	}

	subdomain = strings.ToLower(subdomain)

	result := &DecodedOAST{
		Original: input,
		Valid:    false,
	}

	// Validate minimum length (20 chars for preamble)
	if len(subdomain) < 20 {
		result.Error = fmt.Sprintf("subdomain too short: %d chars (minimum 20)", len(subdomain))
		return result, fmt.Errorf(result.Error)
	}

	// Extract preamble (first 20 chars)
	preamble := subdomain[:20]

	// Validate preamble contains only base32hex characters
	if !IsValidPreamble(preamble) {
		// Check if this is a web client domain (all lowercase alpha)
		if isAllLowerAlpha(preamble) {
			if len(subdomain) > 20 {
				result.Nonce = subdomain[20:]
			}
			result.Error = "web client domain: preamble is not base32hex-decodable"
			result.Classification = ClassifyDomain(subdomain, time.Time{})
			return result, fmt.Errorf(result.Error)
		}
		result.Error = "preamble contains invalid base32hex characters"
		return result, fmt.Errorf(result.Error)
	}

	// Extract nonce if present
	if len(subdomain) > 20 {
		result.Nonce = subdomain[20:]
	}

	// Decode preamble
	bytes, err := decodePreamble(preamble)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Extract fields from the 12-byte array
	// Bytes 0-3: timestamp (big-endian uint32)
	timestamp := binary.BigEndian.Uint32(bytes[0:4])
	result.Timestamp = time.Unix(int64(timestamp), 0)

	// Bytes 4-6: machine ID (3 bytes)
	result.MachineID = fmt.Sprintf("%02x:%02x:%02x", bytes[4], bytes[5], bytes[6])

	// Bytes 7-8: PID (big-endian uint16)
	result.PID = binary.BigEndian.Uint16(bytes[7:9])

	// Bytes 9-11: counter (24-bit big-endian value)
	result.Counter = uint32(bytes[9])<<16 | uint32(bytes[10])<<8 | uint32(bytes[11])

	// Extract K-sort and campaign identifiers
	result.KSort = preamble[:6]
	result.Campaign = preamble[6:11]

	result.Valid = true

	// Classify after successful CLI decode, using decoded CID timestamp for nonce analysis
	result.Classification = ClassifyDomain(subdomain, result.Timestamp)

	// Promote reliable nonce fields to top-level for easier consumption
	if result.Classification != nil && result.Classification.NonceAnalysis != nil && result.Classification.NonceAnalysis.TimestampReliable {
		ts := result.Classification.NonceAnalysis.NonceTimestamp
		result.NonceTimestamp = &ts
		ctr := result.Classification.NonceAnalysis.NonceCounter
		result.NonceCounter = &ctr
	}

	return result, nil
}

// DecodeWithLogTime decodes a single OAST domain with log timestamp for timezone estimation.
// logTime should be the UTC timestamp from DNS/web logs when this domain was observed.
func DecodeWithLogTime(input string, logTime time.Time) (*DecodedOAST, error) {
	result, err := Decode(input)
	if err != nil {
		return result, err
	}

	result.LogTimestamp = &logTime

	// Only estimate timezone for valid domains
	if result.Valid {
		// Estimate from XID timestamp
		result.TimezoneEstimate = EstimateTimezone(result.Timestamp, logTime)

		// If v1.0.1 with reliable nonce timestamp, cross-check with nonce
		if result.NonceTimestamp != nil {
			nonceEst := EstimateTimezoneFromNonce(*result.NonceTimestamp, logTime)
			// If both agree, bump confidence
			if result.TimezoneEstimate != nil && nonceEst != nil &&
				result.TimezoneEstimate.OffsetSeconds == nonceEst.OffsetSeconds {
				if result.TimezoneEstimate.Confidence == "low" {
					result.TimezoneEstimate.Confidence = "medium"
				} else if result.TimezoneEstimate.Confidence == "medium" {
					result.TimezoneEstimate.Confidence = "high"
				}
				result.TimezoneEstimate.Reasoning = append(result.TimezoneEstimate.Reasoning,
					"XID and nonce timestamps agree on offset")
			}
		}
	}

	return result, err
}

// DecodeBatchWithLogTimes decodes multiple OAST domains with log timestamps.
func DecodeBatchWithLogTimes(pairs []TimestampedDomain) []*DecodedOAST {
	results := make([]*DecodedOAST, 0, len(pairs))
	for _, p := range pairs {
		d, _ := DecodeWithLogTime(p.Domain, p.LogTimestamp)
		if d != nil {
			results = append(results, d)
		}
	}
	CrossReferenceClassifications(results)
	return results
}

// DecodeBatch decodes multiple OAST domains and cross-references classifications.
func DecodeBatch(inputs []string) []*DecodedOAST {
	results := make([]*DecodedOAST, len(inputs))
	for i, input := range inputs {
		result, _ := Decode(input)
		results[i] = result
	}
	CrossReferenceClassifications(results)
	return results
}

// decodePreamble converts a 20-character base32hex string to 12 bytes
// 20 chars × 5 bits = 100 bits, but we only use 96 bits (12 bytes)
func decodePreamble(preamble string) ([12]byte, error) {
	var bytes [12]byte
	var bitBuffer uint64
	var bitCount int
	byteIndex := 0

	for i := 0; i < len(preamble); i++ {
		val, ok := base32hexValue(preamble[i])
		if !ok {
			return bytes, fmt.Errorf("invalid base32hex character: %c", preamble[i])
		}

		// Add 5 bits to buffer
		bitBuffer = (bitBuffer << 5) | uint64(val)
		bitCount += 5

		// Extract complete bytes
		for bitCount >= 8 && byteIndex < 12 {
			bitCount -= 8
			bytes[byteIndex] = byte((bitBuffer >> bitCount) & 0xFF)
			byteIndex++
		}
	}

	return bytes, nil
}

// base32hexValue converts a base32hex character to its 5-bit value
func base32hexValue(c byte) (int, bool) {
	if c >= '0' && c <= '9' {
		return int(c - '0'), true
	}
	if c >= 'a' && c <= 'v' {
		return int(c - 'a' + 10), true
	}
	if c >= 'A' && c <= 'V' {
		return int(c - 'A' + 10), true
	}
	return 0, false
}
