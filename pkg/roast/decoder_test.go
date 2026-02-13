package roast

import (
	"testing"
	"time"
)

func TestDecode(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantValid   bool
		wantError   bool
		checkFields func(*testing.T, *DecodedOAST)
	}{
		{
			name:      "valid OAST subdomain only",
			input:     "c58bduhe008dovpvhvugcfemp9yyyyyyn",
			wantValid: true,
			wantError: false,
			checkFields: func(t *testing.T, d *DecodedOAST) {
				if d.Timestamp.IsZero() {
					t.Error("timestamp should not be zero")
				}
				if d.MachineID == "" {
					t.Error("machine ID should not be empty")
				}
				if d.KSort != "c58bdu" {
					t.Errorf("KSort = %q, want %q", d.KSort, "c58bdu")
				}
				if d.Campaign != "he008" {
					t.Errorf("Campaign = %q, want %q", d.Campaign, "he008")
				}
				if d.Nonce != "cfemp9yyyyyyn" {
					t.Errorf("Nonce = %q, want %q", d.Nonce, "cfemp9yyyyyyn")
				}
				// Promoted nonce fields should be populated for reliable v1.0.1 nonces
				if d.NonceTimestamp == nil {
					t.Error("NonceTimestamp should be populated for v1.0.1 domain")
				} else if d.NonceTimestamp.Year() != 2021 {
					t.Errorf("NonceTimestamp year=%d, want 2021", d.NonceTimestamp.Year())
				}
				if d.NonceCounter == nil {
					t.Error("NonceCounter should be populated for v1.0.1 domain")
				} else if *d.NonceCounter != 1 {
					t.Errorf("NonceCounter=%d, want 1", *d.NonceCounter)
				}
			},
		},
		{
			name:      "valid OAST full FQDN",
			input:     "c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro",
			wantValid: true,
			wantError: false,
			checkFields: func(t *testing.T, d *DecodedOAST) {
				if d.KSort != "c58bdu" {
					t.Errorf("KSort = %q, want %q", d.KSort, "c58bdu")
				}
			},
		},
		{
			name:      "valid minimal (just preamble)",
			input:     "c58bduhe008dovpvhvug",
			wantValid: true,
			wantError: false,
			checkFields: func(t *testing.T, d *DecodedOAST) {
				if d.Nonce != "" {
					t.Errorf("Nonce should be empty, got %q", d.Nonce)
				}
			},
		},
		{
			name:      "uppercase should work",
			input:     "C58BDUHE008DOVPVHVUGCFEMP9YYYYYYN",
			wantValid: true,
			wantError: false,
		},
		{
			name:      "too short",
			input:     "c58bduhe008",
			wantValid: false,
			wantError: true,
		},
		{
			name:      "empty input",
			input:     "",
			wantValid: false,
			wantError: true,
		},
		{
			name:      "invalid base32hex chars (w-z) in preamble",
			input:     "c58bduhe008dovpvhvwx",
			wantValid: false,
			wantError: true,
		},
		{
			name:      "known timestamp domain",
			input:     "c58bduhe008dovpvhvug",
			wantValid: true,
			wantError: false,
			checkFields: func(t *testing.T, d *DecodedOAST) {
				// Decode "c58bdu" which is first 6 chars
				// This should give us a timestamp around 2023-2024
				year := d.Timestamp.Year()
				if year < 2020 || year > 2030 {
					t.Errorf("Timestamp year %d seems unreasonable", year)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decode(tt.input)

			if (err != nil) != tt.wantError {
				t.Errorf("Decode() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if got == nil {
				t.Fatal("Decode() returned nil")
			}

			if got.Valid != tt.wantValid {
				t.Errorf("Decode() Valid = %v, want %v (error: %s)", got.Valid, tt.wantValid, got.Error)
			}

			if got.Original != tt.input {
				t.Errorf("Decode() Original = %q, want %q", got.Original, tt.input)
			}

			if tt.checkFields != nil && got.Valid {
				tt.checkFields(t, got)
			}
		})
	}
}

func TestDecodeBatch(t *testing.T) {
	inputs := []string{
		"c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro",
		"c58bduhe008dovpvhvug",
		"invalid",
		"",
		"c58bduhe008dovpvhvugcfemp9yyyyyyn",
	}

	results := DecodeBatch(inputs)

	if len(results) != len(inputs) {
		t.Errorf("DecodeBatch() returned %d results, want %d", len(results), len(inputs))
	}

	// Check that all entries have a result (even invalid ones)
	for i, r := range results {
		if r == nil {
			t.Errorf("result[%d] is nil", i)
		}
	}

	validCount := 0
	for _, r := range results {
		if r != nil && r.Valid {
			validCount++
		}
	}

	expectedValid := 3
	if validCount != expectedValid {
		t.Errorf("DecodeBatch() found %d valid results, want %d", validCount, expectedValid)
	}
}

func TestBase32hexValue(t *testing.T) {
	tests := []struct {
		input   byte
		want    int
		wantOk  bool
	}{
		{'0', 0, true},
		{'9', 9, true},
		{'a', 10, true},
		{'f', 15, true},
		{'v', 31, true},
		{'A', 10, true},
		{'V', 31, true},
		{'w', 0, false},
		{'z', 0, false},
		{'!', 0, false},
		{' ', 0, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			got, ok := base32hexValue(tt.input)
			if ok != tt.wantOk {
				t.Errorf("base32hexValue(%c) ok = %v, want %v", tt.input, ok, tt.wantOk)
			}
			if ok && got != tt.want {
				t.Errorf("base32hexValue(%c) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestDecodePreamble(t *testing.T) {
	tests := []struct {
		name      string
		preamble  string
		wantError bool
		checkTime func(*testing.T, [12]byte)
	}{
		{
			name:      "valid preamble",
			preamble:  "c58bduhe008dovpvhvug",
			wantError: false,
			checkTime: func(t *testing.T, b [12]byte) {
				// First 4 bytes should decode to a reasonable Unix timestamp
				ts := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
				timestamp := time.Unix(int64(ts), 0)
				if timestamp.Year() < 2020 || timestamp.Year() > 2030 {
					t.Errorf("decoded timestamp %v seems unreasonable", timestamp)
				}
			},
		},
		{
			name:      "all zeros",
			preamble:  "00000000000000000000",
			wantError: false,
		},
		{
			name:      "all max values",
			preamble:  "vvvvvvvvvvvvvvvvvvvv",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodePreamble(tt.preamble)
			if (err != nil) != tt.wantError {
				t.Errorf("decodePreamble() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if !tt.wantError && tt.checkTime != nil {
				tt.checkTime(t, got)
			}
		})
	}
}

func BenchmarkDecode(b *testing.B) {
	input := "c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decode(input)
	}
}

func BenchmarkDecodeBatch(b *testing.B) {
	inputs := []string{
		"c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro",
		"c58bduhe008dovpvhvug",
		"c58bduhe008dovpvhvugcfemp9yyyyyyn",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DecodeBatch(inputs)
	}
}
