package roast

import "strings"

// IsValidOASTSubdomain checks if a string looks like a valid OAST subdomain
func IsValidOASTSubdomain(s string) bool {
	if s == "" {
		return false
	}

	// Extract subdomain if full FQDN provided
	subdomain := s
	if idx := strings.Index(s, "."); idx > 0 {
		subdomain = s[:idx]
	}

	// Must be at least 20 characters (preamble length)
	if len(subdomain) < 20 {
		return false
	}

	// Check first 20 characters are valid base32hex
	preamble := subdomain[:20]
	return IsValidPreamble(preamble)
}

// IsValidPreamble validates that a 20-char string is valid base32hex
func IsValidPreamble(s string) bool {
	if len(s) != 20 {
		return false
	}

	s = strings.ToLower(s)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'v')) {
			return false
		}
	}
	return true
}

// KnownOASTDomains returns the list of known OAST domain suffixes
func KnownOASTDomains() []string {
	result := make([]string, len(knownOASTDomains))
	copy(result, knownOASTDomains)
	return result
}

// IsValidOASTSubdomainExtended checks if a string looks like a valid OAST subdomain,
// recognizing both CLI (base32hex) and web (all-alpha) client formats.
// Returns validity and the detected client type.
func IsValidOASTSubdomainExtended(s string) (bool, ClientType) {
	if s == "" {
		return false, ClientUnknown
	}

	subdomain := s
	if idx := strings.Index(s, "."); idx > 0 {
		subdomain = s[:idx]
	}

	if len(subdomain) < 20 {
		return false, ClientUnknown
	}

	preamble := strings.ToLower(subdomain[:20])

	// Check CLI: valid base32hex [0-9a-v]
	if IsValidPreamble(preamble) {
		return true, ClientCLI
	}

	// Check web: all lowercase alpha [a-z]
	if isAllLowerAlpha(preamble) {
		return true, ClientWeb
	}

	return false, ClientUnknown
}

// isAllLowerAlpha returns true if s contains only lowercase ASCII letters.
func isAllLowerAlpha(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 'a' || s[i] > 'z' {
			return false
		}
	}
	return len(s) > 0
}

// IsKnownOASTDomain checks if the given domain is a known OAST domain
func IsKnownOASTDomain(domain string) bool {
	domain = strings.ToLower(domain)
	for _, known := range knownOASTDomains {
		if domain == known {
			return true
		}
	}
	return false
}
