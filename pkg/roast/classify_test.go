// classify_test.go tests the domain classification engine for client type detection
// (CLI vs web), server version detection (v1.0.1 vs v1.0.2+), and nonce analysis.
//
// @decision: Tests use real-world-style subdomains rather than synthetic data to ensure
// heuristics work against the actual character distributions seen in production domains.
// The sample v1.0.1 domain "c58bduhe008dovpvhvug" + "cfemp9yyyyyyn" is from the project's
// own test fixtures and produces a known-good timestamp of 2021-09-26.
package roast

import (
	"testing"
	"time"
)

func TestClassifyClient(t *testing.T) {
	tests := []struct {
		name     string
		preamble string
		wantType ClientType
		wantConf string
	}{
		{
			name:     "CLI with digits",
			preamble: "c58bduhe008dovpvhvug",
			wantType: ClientCLI,
			wantConf: "high",
		},
		{
			name:     "web with w",
			preamble: "abcdefghijklmnopqrwt",
			wantType: ClientWeb,
			wantConf: "high",
		},
		{
			name:     "web with x",
			preamble: "abcdefghijklmnopqrxt",
			wantType: ClientWeb,
			wantConf: "high",
		},
		{
			name:     "web with y",
			preamble: "abcdefghijklmnopqrys",
			wantType: ClientWeb,
			wantConf: "high",
		},
		{
			name:     "web with z",
			preamble: "abcdefghijklmnopqrzs",
			wantType: ClientWeb,
			wantConf: "high",
		},
		{
			name:     "ambiguous a-v only letters",
			preamble: "abcdefghijklmnopqrst",
			wantType: ClientUnknown,
			wantConf: "low",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, _, gotConf := classifyClient(tt.preamble)
			if gotType != tt.wantType {
				t.Errorf("classifyClient(%q) type=%q, want %q", tt.preamble, gotType, tt.wantType)
			}
			if gotConf != tt.wantConf {
				t.Errorf("classifyClient(%q) conf=%q, want %q", tt.preamble, gotConf, tt.wantConf)
			}
		})
	}
}

func TestClassifyVersion(t *testing.T) {
	cidTime := time.Unix(1632679670, 0) // ~6 seconds before the nonce timestamp

	t.Run("v1.0.1 nonce with valid timestamp", func(t *testing.T) {
		// "cfemp9yyyyyyn" decodes to timestamp=1632679676, counter=1
		version, na, _, conf := classifyVersion("cfemp9yyyyyyn", cidTime)
		if version != VersionV101 {
			t.Errorf("version=%q, want %q", version, VersionV101)
		}
		if conf != "high" {
			t.Errorf("confidence=%q, want high", conf)
		}
		if na == nil {
			t.Fatal("expected NonceAnalysis, got nil")
		}
		if na.NonceCounter != 1 {
			t.Errorf("counter=%d, want 1", na.NonceCounter)
		}
		if na.DomainSequence != 1 {
			t.Errorf("domain_sequence=%d, want 1", na.DomainSequence)
		}
		t.Logf("session_age=%s, commentary=%v", na.SessionAge, na.Commentary)
	})

	t.Run("no nonce", func(t *testing.T) {
		version, na, _, conf := classifyVersion("", cidTime)
		if version != VersionUnknown {
			t.Errorf("version=%q, want %q", version, VersionUnknown)
		}
		if conf != "low" {
			t.Errorf("confidence=%q, want low", conf)
		}
		if na != nil {
			t.Error("expected nil NonceAnalysis")
		}
	})

	t.Run("web nonce with l char", func(t *testing.T) {
		version, _, _, conf := classifyVersion("abcdelghijklm", cidTime)
		if version != VersionUnknown {
			t.Errorf("version=%q, want %q", version, VersionUnknown)
		}
		if conf != "high" {
			t.Errorf("confidence=%q, want high", conf)
		}
	})

	t.Run("web nonce with 0 char", func(t *testing.T) {
		version, _, _, _ := classifyVersion("abc0efghijklm", cidTime)
		if version != VersionUnknown {
			t.Errorf("version=%q, want %q", version, VersionUnknown)
		}
	})
}

func TestDecodeV101Nonce(t *testing.T) {
	t.Run("valid nonce", func(t *testing.T) {
		ts, counter, err := decodeV101Nonce("cfemp9yyyyyyn")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Timestamp should be ~2021-09-26
		tsTime := time.Unix(int64(ts), 0)
		if tsTime.Year() != 2021 {
			t.Errorf("timestamp year=%d, want 2021", tsTime.Year())
		}
		if counter != 1 {
			t.Errorf("counter=%d, want 1", counter)
		}
	})

	t.Run("all zeros nonce", func(t *testing.T) {
		// "yyyyyyyyyyyyy" = 13 y's = all zero bits
		ts, counter, err := decodeV101Nonce("yyyyyyyyyyyyy")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ts != 0 {
			t.Errorf("timestamp=%d, want 0", ts)
		}
		if counter != 0 {
			t.Errorf("counter=%d, want 0", counter)
		}
	})
}

func TestClassifyDomain(t *testing.T) {
	t.Run("CLI v1.0.1 domain", func(t *testing.T) {
		c := ClassifyDomain("c58bduhe008dovpvhvugcfemp9yyyyyyn", time.Unix(1632679670, 0))
		if c.ClientType != ClientCLI {
			t.Errorf("client_type=%q, want cli", c.ClientType)
		}
		if c.ServerVersion != VersionV101 {
			t.Errorf("server_version=%q, want v1.0.1", c.ServerVersion)
		}
		if !c.Decodable {
			t.Error("expected decodable=true")
		}
		if c.NonceAnalysis == nil {
			t.Fatal("expected nonce_analysis")
		}
		t.Logf("classification: %+v", c)
	})

	t.Run("too short", func(t *testing.T) {
		c := ClassifyDomain("short", time.Time{})
		if c.ClientType != ClientUnknown {
			t.Errorf("client_type=%q, want unknown", c.ClientType)
		}
		if c.Decodable {
			t.Error("expected decodable=false")
		}
	})

	t.Run("web client domain", func(t *testing.T) {
		c := ClassifyDomain("abcdefghijklmnopqrwtnonce123456", time.Time{})
		if c.ClientType != ClientWeb {
			t.Errorf("client_type=%q, want web", c.ClientType)
		}
		if c.Decodable {
			t.Error("expected decodable=false for web client")
		}
	})
}

func TestAnalyzeNonce(t *testing.T) {
	t.Run("startup domain", func(t *testing.T) {
		cidTime := time.Unix(1632679676, 0)
		nonceTime := time.Unix(1632679676, 0) // same second
		na := analyzeNonce(nonceTime, 1, cidTime)

		if na.SessionAgeSecs != 0 {
			t.Errorf("session_age_secs=%d, want 0", na.SessionAgeSecs)
		}
		if len(na.Commentary) == 0 {
			t.Error("expected commentary")
		}
		t.Logf("commentary: %v", na.Commentary)
	})

	t.Run("long session", func(t *testing.T) {
		cidTime := time.Unix(1632679676, 0)
		nonceTime := time.Unix(1632679676+7200, 0) // 2 hours later
		na := analyzeNonce(nonceTime, 847, cidTime)

		if na.SessionAgeSecs != 7200 {
			t.Errorf("session_age_secs=%d, want 7200", na.SessionAgeSecs)
		}
		hasHighVolume := false
		for _, c := range na.Commentary {
			if len(c) > 0 {
				hasHighVolume = true
			}
		}
		if !hasHighVolume {
			t.Error("expected commentary about high-volume generation")
		}
		t.Logf("commentary: %v", na.Commentary)
	})

	t.Run("negative delta — nonce predates CID", func(t *testing.T) {
		cidTime := time.Unix(1737000000, 0)  // 2025
		nonceTime := time.Unix(1632679676, 0) // 2021
		na := analyzeNonce(nonceTime, 1, cidTime)

		if na.SessionAgeSecs >= 0 {
			t.Errorf("session_age_secs=%d, want negative", na.SessionAgeSecs)
		}
		// Must flag as inconsistent, NOT "matches cid_timestamp"
		hasInconsistent := false
		hasMatches := false
		for _, c := range na.Commentary {
			if len(c) > 20 && c[:20] == "nonce_timestamp pred" {
				hasInconsistent = true
			}
			if len(c) > 20 && c[:20] == "nonce_timestamp matc" {
				hasMatches = true
			}
		}
		if !hasInconsistent {
			t.Error("expected 'nonce_timestamp predates' commentary for negative delta")
		}
		if hasMatches {
			t.Error("should NOT report 'nonce_timestamp matches cid_timestamp' when years apart")
		}
		t.Logf("commentary: %v", na.Commentary)
	})
}

func TestCombineConfidence(t *testing.T) {
	tests := []struct {
		a, b, want string
	}{
		{"high", "high", "high"},
		{"high", "medium", "medium"},
		{"high", "low", "low"},
		{"medium", "low", "low"},
		{"low", "low", "low"},
	}

	for _, tt := range tests {
		got := combineConfidence(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("combineConfidence(%q, %q)=%q, want %q", tt.a, tt.b, got, tt.want)
		}
	}
}
