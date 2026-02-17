// Package roast provides tests for enrichment data model.
// Tests cover MergeEnrichment with various combinations and nil handling.
/**
 * @decision DEC-ENRICH-001
 * @title Enrichment Data Model
 * @status accepted
 * @rationale Schema for external enrichment attached to DecodedOAST.
 */
package roast

import (
	"reflect"
	"testing"
)

func TestMergeEnrichment_BothPopulated(t *testing.T) {
	base := &EnrichmentData{
		SourceIP: "1.2.3.4",
		GreyNoiseCtx: map[string]any{
			"classification": "malicious",
			"name":           "scanner",
		},
		Tags: []string{"nuclei", "scanner"},
	}

	overlay := &EnrichmentData{
		SourceIP:       "1.2.3.4",
		JA4Fingerprint: "t13d1516h2_8daaf6152771_e5627efa2ab1",
		GreyNoiseCtx: map[string]any{
			"last_seen": "2024-01-15",
		},
		Tags: []string{"scanner", "automated"},
	}

	result := MergeEnrichment(base, overlay)

	if result.SourceIP != "1.2.3.4" {
		t.Errorf("SourceIP = %q, want 1.2.3.4", result.SourceIP)
	}

	if result.JA4Fingerprint != "t13d1516h2_8daaf6152771_e5627efa2ab1" {
		t.Errorf("JA4Fingerprint = %q, want overlay value", result.JA4Fingerprint)
	}

	// GreyNoise should be merged
	if result.GreyNoiseCtx["classification"] != "malicious" {
		t.Error("GreyNoiseCtx should include base classification")
	}
	if result.GreyNoiseCtx["last_seen"] != "2024-01-15" {
		t.Error("GreyNoiseCtx should include overlay last_seen")
	}

	// Tags should be deduplicated
	expectedTags := []string{"nuclei", "scanner", "automated"}
	if !reflect.DeepEqual(result.Tags, expectedTags) {
		t.Errorf("Tags = %v, want %v", result.Tags, expectedTags)
	}
}

func TestMergeEnrichment_NilBase(t *testing.T) {
	overlay := &EnrichmentData{
		SourceIP: "5.6.7.8",
		Tags:     []string{"test"},
	}

	result := MergeEnrichment(nil, overlay)

	if result.SourceIP != "5.6.7.8" {
		t.Errorf("SourceIP = %q, want 5.6.7.8", result.SourceIP)
	}

	if !reflect.DeepEqual(result.Tags, []string{"test"}) {
		t.Errorf("Tags = %v, want [test]", result.Tags)
	}
}

func TestMergeEnrichment_NilOverlay(t *testing.T) {
	base := &EnrichmentData{
		SourceIP: "9.10.11.12",
		Tags:     []string{"base"},
	}

	result := MergeEnrichment(base, nil)

	if result.SourceIP != "9.10.11.12" {
		t.Errorf("SourceIP = %q, want 9.10.11.12", result.SourceIP)
	}

	if !reflect.DeepEqual(result.Tags, []string{"base"}) {
		t.Errorf("Tags = %v, want [base]", result.Tags)
	}
}

func TestMergeEnrichment_BothNil(t *testing.T) {
	result := MergeEnrichment(nil, nil)

	if result != nil {
		t.Errorf("MergeEnrichment(nil, nil) = %v, want nil", result)
	}
}

func TestMergeEnrichment_TagDeduplication(t *testing.T) {
	base := &EnrichmentData{
		Tags: []string{"tag1", "tag2", "tag3"},
	}

	overlay := &EnrichmentData{
		Tags: []string{"tag2", "tag4", "tag1"},
	}

	result := MergeEnrichment(base, overlay)

	// Should have unique tags, preserving order from base then overlay
	expectedTags := []string{"tag1", "tag2", "tag3", "tag4"}
	if !reflect.DeepEqual(result.Tags, expectedTags) {
		t.Errorf("Tags = %v, want %v (deduplicated)", result.Tags, expectedTags)
	}
}

func TestMergeEnrichment_KEVMatches(t *testing.T) {
	base := &EnrichmentData{
		KEVMatches: []string{"CVE-2023-1234", "CVE-2023-5678"},
	}

	overlay := &EnrichmentData{
		KEVMatches: []string{"CVE-2023-5678", "CVE-2024-9999"},
	}

	result := MergeEnrichment(base, overlay)

	expectedKEV := []string{"CVE-2023-1234", "CVE-2023-5678", "CVE-2024-9999"}
	if !reflect.DeepEqual(result.KEVMatches, expectedKEV) {
		t.Errorf("KEVMatches = %v, want %v (deduplicated)", result.KEVMatches, expectedKEV)
	}
}
