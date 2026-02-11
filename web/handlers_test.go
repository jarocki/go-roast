// handlers_test.go tests the web API handlers using httptest.
// Covers decode, classify, extract, and analyze endpoints with valid input,
// empty input, and malformed JSON.
//
// @decision: Use httptest.NewRequest + httptest.NewRecorder rather than spinning
// up a real server. This keeps tests fast and deterministic.
package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"codeberg.org/hrbrmstr/go-roast/pkg/roast"
)

func TestHandleDecode(t *testing.T) {
	t.Run("valid CLI domain", func(t *testing.T) {
		body := `{"input":"c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro"}`
		req := httptest.NewRequest("POST", "/api/decode", strings.NewReader(body))
		w := httptest.NewRecorder()

		handleDecode(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status=%d, want 200", w.Code)
		}

		var results []*roast.DecodedOAST
		if err := json.Unmarshal(w.Body.Bytes(), &results); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		if !results[0].Valid {
			t.Error("expected valid=true")
		}
		if results[0].Classification == nil {
			t.Error("expected classification to be present")
		}
		if results[0].Classification.ClientType != roast.ClientCLI {
			t.Errorf("client_type=%q, want cli", results[0].Classification.ClientType)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		body := `{"input":""}`
		req := httptest.NewRequest("POST", "/api/decode", strings.NewReader(body))
		w := httptest.NewRecorder()

		handleDecode(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("status=%d, want 400", w.Code)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/decode", strings.NewReader("not json"))
		w := httptest.NewRecorder()

		handleDecode(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("status=%d, want 400", w.Code)
		}
	})
}

func TestHandleClassify(t *testing.T) {
	body := `{"input":"c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro"}`
	req := httptest.NewRequest("POST", "/api/classify", strings.NewReader(body))
	w := httptest.NewRecorder()

	handleClassify(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", w.Code)
	}

	var results []struct {
		Domain         string              `json:"domain"`
		Classification *roast.Classification `json:"classification"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &results); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Classification.ClientType != roast.ClientCLI {
		t.Errorf("client_type=%q, want cli", results[0].Classification.ClientType)
	}
}

func TestHandleExtract(t *testing.T) {
	body := `{"input":"Found domain c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro in logs"}`
	req := httptest.NewRequest("POST", "/api/extract", strings.NewReader(body))
	w := httptest.NewRecorder()

	handleExtract(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", w.Code)
	}

	var result map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if _, ok := result["matches"]; !ok {
		t.Error("expected 'matches' in response")
	}
	if _, ok := result["decoded"]; !ok {
		t.Error("expected 'decoded' in response")
	}
}

func TestHandleAnalyze(t *testing.T) {
	body := `{"input":"c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro"}`
	req := httptest.NewRequest("POST", "/api/analyze", strings.NewReader(body))
	w := httptest.NewRecorder()

	handleAnalyze(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", w.Code)
	}

	var analysis roast.CampaignAnalysis
	if err := json.Unmarshal(w.Body.Bytes(), &analysis); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if analysis.TotalDomains != 1 {
		t.Errorf("total_domains=%d, want 1", analysis.TotalDomains)
	}
}
