// Package roast provides enrichment data model for OAST domain attribution.
// Defines the schema for external enrichment (GreyNoise, JA4, KEV) that can be
// attached to DecodedOAST. This is the data model only - actual API calls happen
// via MCP tool composition.
/**
 * @decision DEC-ENRICH-001
 * @title Enrichment Data Model
 * @status accepted
 * @rationale Schema for external enrichment (GreyNoise, JA4, KEV) attached to
 *            DecodedOAST. This is the data model only; actual API calls happen
 *            via MCP tool composition.
 */
package roast

// EnrichmentData holds external enrichment information for attribution
type EnrichmentData struct {
	SourceIP       string         `json:"source_ip,omitempty"`
	GreyNoiseCtx   map[string]any `json:"greynoise,omitempty"`
	JA4Fingerprint string         `json:"ja4_fingerprint,omitempty"`
	KEVMatches     []string       `json:"kev_matches,omitempty"`
	Tags           []string       `json:"tags,omitempty"`
}

// MergeEnrichment combines two enrichment data objects.
// Overlay takes precedence for scalar fields. Slices are deduplicated.
// Map fields are merged (overlay keys override base keys).
// Returns nil if both inputs are nil.
func MergeEnrichment(base, overlay *EnrichmentData) *EnrichmentData {
	if base == nil && overlay == nil {
		return nil
	}

	if base == nil {
		return copyEnrichment(overlay)
	}

	if overlay == nil {
		return copyEnrichment(base)
	}

	result := &EnrichmentData{}

	// Scalar fields: overlay wins if present
	if overlay.SourceIP != "" {
		result.SourceIP = overlay.SourceIP
	} else {
		result.SourceIP = base.SourceIP
	}

	if overlay.JA4Fingerprint != "" {
		result.JA4Fingerprint = overlay.JA4Fingerprint
	} else {
		result.JA4Fingerprint = base.JA4Fingerprint
	}

	// Map merge: combine keys, overlay wins on conflicts
	if len(base.GreyNoiseCtx) > 0 || len(overlay.GreyNoiseCtx) > 0 {
		result.GreyNoiseCtx = make(map[string]any)
		for k, v := range base.GreyNoiseCtx {
			result.GreyNoiseCtx[k] = v
		}
		for k, v := range overlay.GreyNoiseCtx {
			result.GreyNoiseCtx[k] = v
		}
	}

	// Slice merge with deduplication
	result.KEVMatches = deduplicateStrings(base.KEVMatches, overlay.KEVMatches)
	result.Tags = deduplicateStrings(base.Tags, overlay.Tags)

	return result
}

// copyEnrichment creates a deep copy of enrichment data
func copyEnrichment(src *EnrichmentData) *EnrichmentData {
	if src == nil {
		return nil
	}

	dst := &EnrichmentData{
		SourceIP:       src.SourceIP,
		JA4Fingerprint: src.JA4Fingerprint,
	}

	if len(src.GreyNoiseCtx) > 0 {
		dst.GreyNoiseCtx = make(map[string]any, len(src.GreyNoiseCtx))
		for k, v := range src.GreyNoiseCtx {
			dst.GreyNoiseCtx[k] = v
		}
	}

	if len(src.KEVMatches) > 0 {
		dst.KEVMatches = make([]string, len(src.KEVMatches))
		copy(dst.KEVMatches, src.KEVMatches)
	}

	if len(src.Tags) > 0 {
		dst.Tags = make([]string, len(src.Tags))
		copy(dst.Tags, src.Tags)
	}

	return dst
}

// deduplicateStrings merges two string slices, preserving order and removing duplicates
func deduplicateStrings(a, b []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(a)+len(b))

	for _, s := range a {
		if !seen[s] {
			result = append(result, s)
			seen[s] = true
		}
	}

	for _, s := range b {
		if !seen[s] {
			result = append(result, s)
			seen[s] = true
		}
	}

	return result
}
