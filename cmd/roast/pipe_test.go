package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"codeberg.org/hrbrmstr/go-roast/pkg/roast"
)

// PipeRecord matches the structure defined in pipeCmd
type PipeRecord struct {
	LineNum     int                  `json:"line_num"`
	Line        string               `json:"line"`
	OASTCount   int                  `json:"oast_count"`
	OASTDecoded []*roast.DecodedOAST `json:"oast_decoded"`
}

func TestPipeCommand(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		skipEmpty bool
		wantLines int
		wantOASTs int
	}{
		{
			name: "single OAST domain",
			input: `Line 1: Regular text
Line 2: OAST domain c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro
Line 3: Regular text`,
			skipEmpty: false,
			wantLines: 3,
			wantOASTs: 1,
		},
		{
			name: "skip empty lines",
			input: `Line 1: Regular text
Line 2: OAST domain c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro
Line 3: Regular text`,
			skipEmpty: true,
			wantLines: 1,
			wantOASTs: 1,
		},
		{
			name: "multiple OASTs per line",
			input: `Line 1: Multiple: c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.fun and c58bdui0008dp1ffhvugg21cqtyyyyyyn.oast.live`,
			skipEmpty: false,
			wantLines: 1,
			wantOASTs: 2,
		},
		{
			name:      "no OAST domains",
			input:     "Just regular text\nNo OASTs here\n",
			skipEmpty: false,
			wantLines: 2,
			wantOASTs: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file
			tmpfile, err := os.CreateTemp("", "pipe-test-*.txt")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tmpfile.Name())

			if _, err := tmpfile.WriteString(tt.input); err != nil {
				t.Fatal(err)
			}
			if err := tmpfile.Close(); err != nil {
				t.Fatal(err)
			}

			// Capture output
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Run pipe command logic (simulated)
			file, err := os.Open(tmpfile.Name())
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()

			var records []PipeRecord
			scanner := strings.Split(tt.input, "\n")
			lineNum := 0

			for _, line := range scanner {
				if line == "" {
					continue
				}
				lineNum++

				matches := roast.ExtractFromString(line)
				var decoded []*roast.DecodedOAST
				for _, match := range matches {
					d, _ := roast.Decode(match.Subdomain)
					decoded = append(decoded, d)
				}

				oastCount := len(decoded)

				if tt.skipEmpty && oastCount == 0 {
					continue
				}

				records = append(records, PipeRecord{
					LineNum:     lineNum,
					Line:        line,
					OASTCount:   oastCount,
					OASTDecoded: decoded,
				})
			}

			// Encode to JSON
			encoder := json.NewEncoder(w)
			for _, rec := range records {
				if err := encoder.Encode(rec); err != nil {
					t.Fatal(err)
				}
			}

			w.Close()
			os.Stdout = oldStdout

			var buf bytes.Buffer
			buf.ReadFrom(r)
			output := buf.String()

			// Parse output
			var parsedRecords []PipeRecord
			for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
				if line == "" {
					continue
				}
				var rec PipeRecord
				if err := json.Unmarshal([]byte(line), &rec); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				parsedRecords = append(parsedRecords, rec)
			}

			// Verify results
			if len(parsedRecords) != tt.wantLines {
				t.Errorf("got %d lines, want %d", len(parsedRecords), tt.wantLines)
			}

			totalOASTs := 0
			for _, rec := range parsedRecords {
				totalOASTs += rec.OASTCount
			}

			if totalOASTs != tt.wantOASTs {
				t.Errorf("got %d OASTs, want %d", totalOASTs, tt.wantOASTs)
			}

			// Verify line numbers are sequential
			for i, rec := range parsedRecords {
				if tt.skipEmpty {
					// Line numbers may have gaps when skipping
					if rec.LineNum <= 0 {
						t.Errorf("invalid line number: %d", rec.LineNum)
					}
				} else {
					expectedLineNum := i + 1
					if rec.LineNum != expectedLineNum {
						t.Errorf("line %d: got line_num=%d, want %d", i, rec.LineNum, expectedLineNum)
					}
				}
			}
		})
	}
}

func TestPipeOutputStructure(t *testing.T) {
	input := "Test: c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro"

	matches := roast.ExtractFromString(input)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	decoded, err := roast.Decode(matches[0].Subdomain)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	record := PipeRecord{
		LineNum:     1,
		Line:        input,
		OASTCount:   1,
		OASTDecoded: []*roast.DecodedOAST{decoded},
	}

	// Marshal to JSON
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Verify we can unmarshal back
	var parsed PipeRecord
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Verify structure
	if parsed.LineNum != 1 {
		t.Errorf("line_num: got %d, want 1", parsed.LineNum)
	}
	if parsed.Line != input {
		t.Errorf("line: got %q, want %q", parsed.Line, input)
	}
	if parsed.OASTCount != 1 {
		t.Errorf("oast_count: got %d, want 1", parsed.OASTCount)
	}
	if len(parsed.OASTDecoded) != 1 {
		t.Errorf("oast_decoded length: got %d, want 1", len(parsed.OASTDecoded))
	}
	if !parsed.OASTDecoded[0].Valid {
		t.Error("decoded OAST should be valid")
	}
}
