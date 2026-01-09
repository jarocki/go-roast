package mcp

import (
	"strings"
	"sync"

	"codeberg.org/hrbrmstr/go-roast/pkg/roast"
)

// DomainValidator provides validation against external domain lists
type DomainValidator struct {
	mu                    sync.RWMutex
	interactshDomains     map[string]bool
	burpCollaboratorDomains map[string]bool
	fetcher               *HTTPFetcher
	lastUpdated           map[string]string // cache key -> last update time
}

// NewDomainValidator creates a new domain validator
func NewDomainValidator() *DomainValidator {
	return &DomainValidator{
		interactshDomains:       make(map[string]bool),
		burpCollaboratorDomains: make(map[string]bool),
		fetcher:                 GetGlobalFetcher(),
		lastUpdated:             make(map[string]string),
	}
}

// ValidationResult contains the result of domain validation
type ValidationResult struct {
	Domain              string `json:"domain"`
	IsValid             bool   `json:"is_valid"`
	IsOAST              bool   `json:"is_oast"`
	IsBuiltIn           bool   `json:"is_builtin"`
	IsInteractsh        bool   `json:"is_interactsh"`
	IsBurpCollaborator  bool   `json:"is_burp_collaborator"`
	IsCustomInstance    bool   `json:"is_custom_instance"`
	Attribution         string `json:"attribution,omitempty"`
	DomainType          string `json:"domain_type"`
	Confidence          string `json:"confidence"`
	Notes               string `json:"notes,omitempty"`
}

// LoadExternalDomains loads domain lists from external sources
func (v *DomainValidator) LoadExternalDomains() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Load Interactsh domains
	if result, err := v.fetcher.FetchInteractshDomains(); err == nil {
		v.interactshDomains = make(map[string]bool)
		for _, domain := range result.Domains {
			v.interactshDomains[strings.ToLower(domain)] = true
		}
		v.lastUpdated[CacheKeyInteractshDomains] = result.FetchTime.Format("2006-01-02 15:04:05 UTC")
	}

	// Load Burp Collaborator domains
	if result, err := v.fetcher.FetchBurpCollaboratorDomains(); err == nil {
		v.burpCollaboratorDomains = make(map[string]bool)
		for _, domain := range result.Domains {
			v.burpCollaboratorDomains[strings.ToLower(domain)] = true
		}
		v.lastUpdated[CacheKeyBurpCollaborator] = result.FetchTime.Format("2006-01-02 15:04:05 UTC")
	}

	return nil
}

// ValidateDomain validates a domain against all available lists
func (v *DomainValidator) ValidateDomain(domain string) *ValidationResult {
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Remove leading dot if present
	if strings.HasPrefix(domain, ".") {
		domain = domain[1:]
	}

	result := &ValidationResult{
		Domain:    domain,
		IsValid:   v.isValidDomainFormat(domain),
		DomainType: "unknown",
		Confidence: "low",
	}

	if !result.IsValid {
		result.Notes = "Invalid domain format"
		return result
	}

	// Check against built-in OAST domains
	builtinDomains := roast.KnownOASTDomains()
	for _, builtinDomain := range builtinDomains {
		if domain == strings.ToLower(builtinDomain) || strings.HasSuffix(domain, "."+strings.ToLower(builtinDomain)) {
			result.IsBuiltIn = true
			result.IsOAST = true
			result.IsInteractsh = true
			result.DomainType = "official_interactsh"
			result.Confidence = "high"
			result.Attribution = "Official Interactsh domain"
			break
		}
	}

	// Check against external Interactsh domains
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.interactshDomains[domain] || v.isDomainInList(domain, v.interactshDomains) {
		result.IsInteractsh = true
		result.IsOAST = true

		if !result.IsBuiltIn {
			result.IsCustomInstance = true
			result.DomainType = "custom_interactsh"
			result.Confidence = "high"
			result.Attribution = v.getAttribution(domain)
		}
	}

	// Check against Burp Collaborator domains
	if v.burpCollaboratorDomains[domain] || v.isDomainInList(domain, v.burpCollaboratorDomains) {
		result.IsBurpCollaborator = true
		result.IsOAST = true
		result.DomainType = "burp_collaborator"
		result.Confidence = "high"
		if result.Attribution == "" {
			result.Attribution = v.getBurpAttribution(domain)
		}
		result.Notes = "Burp Collaborator domains use different format than Interactsh and cannot be decoded"
	}

	// Set final domain type if still unknown
	if result.DomainType == "unknown" && result.IsOAST {
		result.DomainType = "oast_generic"
		result.Confidence = "medium"
	}

	return result
}

// ValidateBatch validates multiple domains
func (v *DomainValidator) ValidateBatch(domains []string) []*ValidationResult {
	results := make([]*ValidationResult, len(domains))
	for i, domain := range domains {
		results[i] = v.ValidateDomain(domain)
	}
	return results
}

// isDomainInList checks if a domain or its parent domain is in the list
func (v *DomainValidator) isDomainInList(domain string, domainList map[string]bool) bool {
	// Direct match
	if domainList[domain] {
		return true
	}

	// Check if it's a subdomain of any domain in the list
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parentDomain := strings.Join(parts[i:], ".")
		if domainList[parentDomain] {
			return true
		}
	}

	return false
}

// getAttribution attempts to determine the attribution of a domain
func (v *DomainValidator) getAttribution(domain string) string {
	domain = strings.ToLower(domain)

	// Security companies
	if strings.Contains(domain, "netspi") {
		return "NetSPI (Security Company)"
	}
	if strings.Contains(domain, "rapid7") {
		return "Rapid7 (Security Company)"
	}
	if strings.Contains(domain, "outpost24") {
		return "Outpost24 (Security Company)"
	}
	if strings.Contains(domain, "yeswehack") {
		return "YesWeHack (Bug Bounty Platform)"
	}
	if strings.Contains(domain, "hackerone") || strings.Contains(domain, "h1.") {
		return "HackerOne (Bug Bounty Platform)"
	}
	if strings.Contains(domain, "bugcrowd") {
		return "Bugcrowd (Bug Bounty Platform)"
	}

	// Research/Academic
	if strings.Contains(domain, "cert.") {
		return "CERT (Computer Emergency Response Team)"
	}
	if strings.Contains(domain, ".edu") {
		return "Academic Institution"
	}
	if strings.Contains(domain, ".gov") {
		return "Government Entity"
	}

	// Generic patterns
	if strings.Contains(domain, "pentest") {
		return "Penetration Testing Company"
	}
	if strings.Contains(domain, "security") || strings.Contains(domain, "sec") {
		return "Security Organization"
	}
	if strings.Contains(domain, "research") || strings.Contains(domain, "lab") {
		return "Security Research"
	}

	// Country-specific patterns
	if strings.HasSuffix(domain, ".fi") {
		return "Finnish Entity"
	}
	if strings.HasSuffix(domain, ".de") {
		return "German Entity"
	}
	if strings.HasSuffix(domain, ".nl") {
		return "Dutch Entity"
	}
	if strings.HasSuffix(domain, ".fr") {
		return "French Entity"
	}

	return "Custom Interactsh Instance"
}

// getBurpAttribution attempts to determine attribution for Burp Collaborator domains
func (v *DomainValidator) getBurpAttribution(domain string) string {
	domain = strings.ToLower(domain)

	// Similar patterns as Interactsh but for Burp
	if strings.Contains(domain, "pentest") {
		return "Penetration Testing (Burp Collaborator)"
	}
	if strings.Contains(domain, "security") || strings.Contains(domain, "sec") {
		return "Security Testing (Burp Collaborator)"
	}
	if strings.Contains(domain, "audit") {
		return "Security Audit (Burp Collaborator)"
	}

	return "Burp Collaborator Server"
}

// isValidDomainFormat performs basic domain format validation
func (v *DomainValidator) isValidDomainFormat(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}

	if strings.Contains(domain, "..") {
		return false
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}

	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		if strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
	}

	return true
}

// GetStats returns statistics about loaded domain lists
func (v *DomainValidator) GetStats() map[string]interface{} {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return map[string]interface{}{
		"interactsh_domains_count":       len(v.interactshDomains),
		"burp_collaborator_domains_count": len(v.burpCollaboratorDomains),
		"last_updated":                   v.lastUpdated,
		"builtin_domains_count":          len(roast.KnownOASTDomains()),
	}
}

// RefreshDomains forces a refresh of domain lists
func (v *DomainValidator) RefreshDomains() error {
	// Clear cache to force refresh
	cache := GetGlobalCache()
	cache.Delete(CacheKeyInteractshDomains)
	cache.Delete(CacheKeyBurpCollaborator)

	return v.LoadExternalDomains()
}

// Global validator instance
var globalValidator = NewDomainValidator()

// GetGlobalValidator returns the global domain validator instance
func GetGlobalValidator() *DomainValidator {
	return globalValidator
}
