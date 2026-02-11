// zbase32.go decodes z-base-32 encoded strings into raw bytes.
// Needed to extract timestamps and counters from v1.0.1 Interactsh nonces,
// which encode 8 bytes (4-byte timestamp + 4-byte atomic counter) via zbase32.
// Uses the zbase32Alphabet defined in types.go: "ybndrfg8ejkmcpqxot1uwisza345h769"
//
// @decision: Implement zbase32 decoder from scratch rather than importing a library.
// The algorithm is trivial (5-bit-to-byte accumulator), the alphabet is already in types.go,
// and adding a dependency for ~40 lines of code is not justified.
package roast

import "fmt"

// zbase32Value returns the 5-bit value for a z-base-32 character.
func zbase32Value(c byte) (int, bool) {
	for i := 0; i < len(zbase32Alphabet); i++ {
		if zbase32Alphabet[i] == c {
			return i, true
		}
	}
	return 0, false
}

// zbase32Decode decodes a z-base-32 encoded string into bytes.
// Each character encodes 5 bits. Output length is floor(len(s)*5/8).
func zbase32Decode(s string) ([]byte, error) {
	if len(s) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	totalBits := len(s) * 5
	outLen := totalBits / 8

	result := make([]byte, outLen)
	var bitBuffer uint64
	var bitCount int
	byteIndex := 0

	for i := 0; i < len(s); i++ {
		val, ok := zbase32Value(s[i])
		if !ok {
			return nil, fmt.Errorf("invalid zbase32 character at position %d: %c", i, s[i])
		}

		bitBuffer = (bitBuffer << 5) | uint64(val)
		bitCount += 5

		for bitCount >= 8 && byteIndex < outLen {
			bitCount -= 8
			result[byteIndex] = byte((bitBuffer >> bitCount) & 0xFF)
			byteIndex++
		}
	}

	return result, nil
}
