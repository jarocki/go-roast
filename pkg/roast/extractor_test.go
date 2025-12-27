package roast

import (
	"strings"
	"testing"
)

func TestExtractFromString(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantCount int
		checkFunc func(*testing.T, []OASTMatch)
	}{
		{
			name:      "single OAST domain",
			input:     "Found domain: c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro",
			wantCount: 1,
			checkFunc: func(t *testing.T, matches []OASTMatch) {
				if matches[0].Subdomain != "c58bduhe008dovpvhvugcfemp9yyyyyyn" {
					t.Errorf("subdomain = %q, want %q", matches[0].Subdomain, "c58bduhe008dovpvhvugcfemp9yyyyyyn")
				}
				if matches[0].Domain != "oast.pro" {
					t.Errorf("domain = %q, want %q", matches[0].Domain, "oast.pro")
				}
			},
		},
		{
			name:      "multiple OAST domains",
			input:     "c58bduhe008dovpvhvug.oast.live and c59bduhe008dovpvhvug.oast.fun",
			wantCount: 2,
		},
		{
			name:      "mixed known domains",
			input:     "c58bduhe008dovpvhvug.oast.pro c59bduhe009dovpvhvug.interact.sh c5abduhe00akovpvhvug.interactsh.com",
			wantCount: 3,
		},
		{
			name:      "no OAST domains",
			input:     "This is just regular text with example.com",
			wantCount: 0,
		},
		{
			name:      "subdomain too short",
			input:     "short.oast.pro",
			wantCount: 0,
		},
		{
			name:      "case insensitive",
			input:     "C58BDUHE008DOVPVHVUG.OAST.PRO",
			wantCount: 1,
			checkFunc: func(t *testing.T, matches []OASTMatch) {
				if matches[0].Domain != "oast.pro" {
					t.Errorf("domain = %q, want lowercase", matches[0].Domain)
				}
			},
		},
		{
			name:      "in URL context",
			input:     "https://c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro/callback",
			wantCount: 1,
		},
		{
			name:      "in log line",
			input:     "[2024-01-15 10:30:45] DNS query for c58bduhe008dovpvhvug.oast.live from 192.168.1.1",
			wantCount: 1,
		},
		{
			name:      "multiple on same line",
			input:     "Saw c58bduhe008dovpvhvug.oast.pro and c59bduhe009dovpvhvug.oast.live",
			wantCount: 2,
			checkFunc: func(t *testing.T, matches []OASTMatch) {
				if matches[0].StartIndex >= matches[1].StartIndex {
					t.Error("matches should be in order of appearance")
				}
			},
		},
		{
			name:      "with underscores and dashes",
			input:     "c58bduhe008dovpvhvug_test-123.oast.pro",
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractFromString(tt.input)
			if len(got) != tt.wantCount {
				t.Errorf("ExtractFromString() found %d matches, want %d", len(got), tt.wantCount)
				return
			}

			if tt.checkFunc != nil {
				tt.checkFunc(t, got)
			}
		})
	}
}

func TestExtractFromReader(t *testing.T) {
	input := `Line 1: c58bduhe008dovpvhvug.oast.pro
Line 2: regular text
Line 3: c59bduhe009dovpvhvug.oast.live
Line 4: another c5abduhe00akovpvhvug.interact.sh here`

	reader := strings.NewReader(input)
	matches, err := ExtractFromReader(reader)

	if err != nil {
		t.Fatalf("ExtractFromReader() error = %v", err)
	}

	if len(matches) != 3 {
		t.Errorf("ExtractFromReader() found %d matches, want 3", len(matches))
	}

	// Check indices are cumulative across lines
	for i := 1; i < len(matches); i++ {
		if matches[i].StartIndex <= matches[i-1].StartIndex {
			t.Error("match indices should be cumulative across lines")
		}
	}
}

func TestExtractAndDecode(t *testing.T) {
	input := "Found: c58bduhe008dovpvhvug.oast.pro and c59bduhe009dovpvhvug.oast.live"

	matches, decoded := ExtractAndDecode(input)

	if len(matches) != 2 {
		t.Errorf("found %d matches, want 2", len(matches))
	}

	if len(decoded) != 2 {
		t.Errorf("decoded %d domains, want 2", len(decoded))
	}

	if decoded[0] == nil || !decoded[0].Valid {
		t.Error("first domain should be valid")
	}

	if decoded[1] == nil || !decoded[1].Valid {
		t.Error("second domain should be valid")
	}
}

func TestOASTPattern(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "valid oast.pro",
			input:   "c58bduhe008dovpvhvug.oast.pro",
			wantHit: true,
		},
		{
			name:    "valid oast.live",
			input:   "c58bduhe008dovpvhvug.oast.live",
			wantHit: true,
		},
		{
			name:    "valid oast.site",
			input:   "c58bduhe008dovpvhvug.oast.site",
			wantHit: true,
		},
		{
			name:    "valid oast.online",
			input:   "c58bduhe008dovpvhvug.oast.online",
			wantHit: true,
		},
		{
			name:    "valid oast.fun",
			input:   "c58bduhe008dovpvhvug.oast.fun",
			wantHit: true,
		},
		{
			name:    "valid oast.me",
			input:   "c58bduhe008dovpvhvug.oast.me",
			wantHit: true,
		},
		{
			name:    "valid interact.sh",
			input:   "c58bduhe008dovpvhvug.interact.sh",
			wantHit: true,
		},
		{
			name:    "valid interactsh.com",
			input:   "c58bduhe008dovpvhvug.interactsh.com",
			wantHit: true,
		},
		{
			name:    "unknown domain",
			input:   "c58bduhe008dovpvhvug.example.com",
			wantHit: false,
		},
		{
			name:    "subdomain too short",
			input:   "short.oast.pro",
			wantHit: false,
		},
		{
			name:    "invalid chars in subdomain",
			input:   "c58bduhe008dovpvhvugwxyz.oast.pro",
			wantHit: true, // Pattern matches, but decoding will fail
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := oastPattern.FindStringSubmatch(tt.input)
			gotHit := len(matches) > 0

			if gotHit != tt.wantHit {
				t.Errorf("pattern match = %v, want %v", gotHit, tt.wantHit)
			}
		})
	}
}

func BenchmarkExtractFromString(b *testing.B) {
	input := strings.Repeat("Some text with c58bduhe008dovpvhvug.oast.pro in it. ", 100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractFromString(input)
	}
}

func BenchmarkExtractAndDecode(b *testing.B) {
	input := "Found: c58bduhe008dovpvhvug.oast.pro and c59bduhe009dovpvhvug.oast.live"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ExtractAndDecode(input)
	}
}
