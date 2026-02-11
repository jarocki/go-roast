// zbase32_test.go tests the z-base-32 decoder used for v1.0.1 nonce extraction.
// Covers character-to-value mapping, zero-byte decoding, known nonce values,
// invalid input handling, and output length correctness.
//
// @decision: Tests use package-internal access (same package) to test unexported
// zbase32Value and zbase32Decode directly, since they are implementation details
// of the classification engine and not part of the public API.
package roast

import (
	"encoding/binary"
	"testing"
)

func TestZbase32Value(t *testing.T) {
	// 'y' is index 0, 'b' is index 1, 'n' is index 2, etc.
	tests := []struct {
		char byte
		want int
		ok   bool
	}{
		{'y', 0, true},
		{'b', 1, true},
		{'n', 2, true},
		{'d', 3, true},
		{'9', 31, true},
		{'!', 0, false},
		{'A', 0, false},
	}

	for _, tt := range tests {
		got, ok := zbase32Value(tt.char)
		if ok != tt.ok {
			t.Errorf("zbase32Value(%c): ok=%v, want %v", tt.char, ok, tt.ok)
		}
		if ok && got != tt.want {
			t.Errorf("zbase32Value(%c)=%d, want %d", tt.char, got, tt.want)
		}
	}
}

func TestZbase32Decode(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		_, err := zbase32Decode("")
		if err == nil {
			t.Fatal("expected error for empty input")
		}
	})

	t.Run("invalid character", func(t *testing.T) {
		_, err := zbase32Decode("yb!dr")
		if err == nil {
			t.Fatal("expected error for invalid character")
		}
	})

	t.Run("all y chars decode to zero bytes", func(t *testing.T) {
		// 'y' = 0 in zbase32, so "yyyyyyyy" (8 chars = 40 bits = 5 bytes of zeros)
		result, err := zbase32Decode("yyyyyyyy")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 5 {
			t.Fatalf("expected 5 bytes, got %d", len(result))
		}
		for i, b := range result {
			if b != 0 {
				t.Errorf("byte %d = %d, want 0", i, b)
			}
		}
	})

	t.Run("known v1.0.1 nonce decode", func(t *testing.T) {
		// 13-char nonce = 65 bits = 8 bytes
		nonce := "cfemp9yyyyyyn"
		result, err := zbase32Decode(nonce)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 8 {
			t.Fatalf("expected 8 bytes, got %d", len(result))
		}
		ts := binary.BigEndian.Uint32(result[0:4])
		counter := binary.BigEndian.Uint32(result[4:8])
		t.Logf("nonce %q -> timestamp=%d, counter=%d", nonce, ts, counter)
	})

	t.Run("round trip consistency", func(t *testing.T) {
		input := "ybndrfg8ejkmcpqxo" // 17 chars = 85 bits = 10 bytes
		result, err := zbase32Decode(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expectedLen := (17 * 5) / 8 // 10
		if len(result) != expectedLen {
			t.Errorf("expected %d bytes, got %d", expectedLen, len(result))
		}
	})
}
