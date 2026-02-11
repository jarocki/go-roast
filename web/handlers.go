// handlers.go implements the API endpoint handlers for the web UI.
// Each handler accepts POST with JSON body, delegates to pkg/roast, and returns JSON.
//
// @decision: Handlers accept both {"input":"single string"} and {"input":"multi\nline"}
// formats. This simplifies the client — textarea content is sent as-is, and the handler
// splits on newlines for batch operations. Classification is always included in decode
// results since it's now part of DecodedOAST.
package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"codeberg.org/hrbrmstr/go-roast/pkg/roast"
)

type apiRequest struct {
	Input string `json:"input"`
}

type apiError struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func readRequest(r *http.Request) (*apiRequest, error) {
	var req apiRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, err
	}
	return &req, nil
}

// POST /api/decode — decode one or more OAST domains
func handleDecode(w http.ResponseWriter, r *http.Request) {
	req, err := readRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid JSON: " + err.Error()})
		return
	}

	lines := splitLines(req.Input)
	if len(lines) == 0 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "no input provided"})
		return
	}

	results := roast.DecodeBatch(lines)
	writeJSON(w, http.StatusOK, results)
}

// POST /api/classify — classify domains without full decode
func handleClassify(w http.ResponseWriter, r *http.Request) {
	req, err := readRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid JSON: " + err.Error()})
		return
	}

	lines := splitLines(req.Input)
	if len(lines) == 0 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "no input provided"})
		return
	}

	type classifyResult struct {
		Domain         string               `json:"domain"`
		Classification *roast.Classification `json:"classification"`
	}

	results := make([]classifyResult, len(lines))
	for i, line := range lines {
		subdomain := line
		if idx := strings.Index(line, "."); idx > 0 {
			subdomain = line[:idx]
		}
		subdomain = strings.ToLower(subdomain)

		// Try decode for CID timestamp
		var cidTimestamp time.Time
		decoded, _ := roast.Decode(line)
		if decoded != nil && decoded.Valid {
			cidTimestamp = decoded.Timestamp
		}

		results[i] = classifyResult{
			Domain:         line,
			Classification: roast.ClassifyDomain(subdomain, cidTimestamp),
		}
	}

	writeJSON(w, http.StatusOK, results)
}

// POST /api/extract — extract OAST domains from text
func handleExtract(w http.ResponseWriter, r *http.Request) {
	req, err := readRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid JSON: " + err.Error()})
		return
	}

	if req.Input == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "no input provided"})
		return
	}

	matches, decoded := roast.ExtractAndDecode(req.Input)

	result := map[string]interface{}{
		"matches": matches,
		"decoded": decoded,
	}
	writeJSON(w, http.StatusOK, result)
}

// POST /api/analyze — campaign analysis
func handleAnalyze(w http.ResponseWriter, r *http.Request) {
	req, err := readRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid JSON: " + err.Error()})
		return
	}

	if req.Input == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "no input provided"})
		return
	}

	analysis := roast.AnalyzeCampaignFromString(req.Input)
	writeJSON(w, http.StatusOK, analysis)
}

func splitLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
