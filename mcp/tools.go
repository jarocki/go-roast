package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"codeberg.org/hrbrmstr/go-roast/pkg/roast"
	"github.com/mark3labs/mcp-go/mcp"
)

func decodeOASTTool() mcp.Tool {
	return mcp.NewTool("decode_oast",
		mcp.WithDescription("Decode one or more OAST domains to extract metadata (timestamp, machine ID, PID, counter)"),
		mcp.WithString("domains",
			mcp.Required(),
			mcp.Description("OAST domain(s) to decode (can be subdomain only or full FQDN)"),
		),
	)
}

func handleDecodeOAST(args map[string]interface{}) (*mcp.CallToolResult, error) {
	domainsRaw, ok := args["domains"]
	if !ok {
		return mcp.NewToolResultError("domains parameter required"), nil
	}

	var inputs []string

	// Handle both single string and array of strings
	switch v := domainsRaw.(type) {
	case string:
		inputs = []string{v}
	case []interface{}:
		inputs = make([]string, len(v))
		for i, d := range v {
			s, ok := d.(string)
			if !ok {
				return mcp.NewToolResultError("all domains must be strings"), nil
			}
			inputs[i] = s
		}
	default:
		return mcp.NewToolResultError("domains must be a string or array of strings"), nil
	}

	results := roast.DecodeBatch(inputs)

	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to encode results: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

func classifyOASTTool() mcp.Tool {
	return mcp.NewTool("classify_oast",
		mcp.WithDescription("Classify an OAST domain by client type (CLI/web) and server version (v1.0.1/v1.0.2+) without full decode"),
		mcp.WithString("domain",
			mcp.Required(),
			mcp.Description("OAST domain to classify (subdomain or full FQDN)"),
		),
	)
}

func handleClassifyOAST(args map[string]interface{}) (*mcp.CallToolResult, error) {
	domain, ok := args["domain"].(string)
	if !ok {
		return mcp.NewToolResultError("domain must be a string"), nil
	}

	// Extract subdomain
	subdomain := domain
	if idx := strings.Index(domain, "."); idx > 0 {
		subdomain = domain[:idx]
	}
	subdomain = strings.ToLower(subdomain)

	// Try decode to get CID timestamp for nonce analysis
	decoded, _ := roast.Decode(domain)
	var cidTimestamp time.Time
	if decoded != nil && decoded.Valid {
		cidTimestamp = decoded.Timestamp
	}

	classification := roast.ClassifyDomain(subdomain, cidTimestamp)

	result := map[string]interface{}{
		"domain":         domain,
		"classification": classification,
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to encode results: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

func extractOASTTool() mcp.Tool {
	return mcp.NewTool("extract_oast",
		mcp.WithDescription("Extract OAST domains from text"),
		mcp.WithString("text",
			mcp.Required(),
			mcp.Description("Text to search for OAST domains"),
		),
		mcp.WithBoolean("decode",
			mcp.Description("Also decode extracted domains (default: false)"),
		),
	)
}

func handleExtractOAST(args map[string]interface{}) (*mcp.CallToolResult, error) {
	text, ok := args["text"].(string)
	if !ok {
		return mcp.NewToolResultError("text must be a string"), nil
	}

	decode, _ := args["decode"].(bool)

	if decode {
		matches, decoded := roast.ExtractAndDecode(text)

		result := map[string]interface{}{
			"matches": matches,
			"decoded": decoded,
		}

		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to encode results: %v", err)), nil
		}

		return mcp.NewToolResultText(string(data)), nil
	}

	matches := roast.ExtractFromString(text)

	data, err := json.MarshalIndent(matches, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to encode results: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

func extractOASTFileTool() mcp.Tool {
	return mcp.NewTool("extract_oast_file",
		mcp.WithDescription("Extract OAST domains from a file"),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Path to file to extract OAST domains from"),
		),
		mcp.WithBoolean("decode",
			mcp.Description("Also decode extracted domains (default: false)"),
		),
	)
}

func handleExtractOASTFile(args map[string]interface{}) (*mcp.CallToolResult, error) {
	path, ok := args["path"].(string)
	if !ok {
		return mcp.NewToolResultError("path must be a string"), nil
	}

	decode, _ := args["decode"].(bool)

	if decode {
		matches, decoded, err := roast.ExtractAndDecodeFromFile(path)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to extract from file: %v", err)), nil
		}

		result := map[string]interface{}{
			"matches": matches,
			"decoded": decoded,
		}

		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to encode results: %v", err)), nil
		}

		return mcp.NewToolResultText(string(data)), nil
	}

	matches, err := roast.ExtractFromFile(path)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to extract from file: %v", err)), nil
	}

	data, err := json.MarshalIndent(matches, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to encode results: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

func validateOASTTool() mcp.Tool {
	return mcp.NewTool("validate_oast",
		mcp.WithDescription("Check if a string is a valid OAST domain"),
		mcp.WithString("domain",
			mcp.Required(),
			mcp.Description("Domain to validate"),
		),
	)
}

func handleValidateOAST(args map[string]interface{}) (*mcp.CallToolResult, error) {
	domain, ok := args["domain"].(string)
	if !ok {
		return mcp.NewToolResultError("domain must be a string"), nil
	}

	isValid := roast.IsValidOASTSubdomain(domain)

	result := map[string]interface{}{
		"domain": domain,
		"valid":  isValid,
	}

	if isValid {
		result["message"] = "Valid OAST subdomain"
	} else {
		result["message"] = "Invalid OAST subdomain (must be at least 20 chars with base32hex preamble)"
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to encode results: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

func campaignAnalysisTool() mcp.Tool {
	return mcp.NewTool("oast_campaign_analysis",
		mcp.WithDescription("Analyze OAST domains from a file and generate a campaign analysis summary in markdown format"),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Path to file containing OAST domains"),
		),
		mcp.WithBoolean("include_json",
			mcp.Description("Also include JSON data (default: false)"),
		),
	)
}

func handleCampaignAnalysis(args map[string]interface{}) (*mcp.CallToolResult, error) {
	path, ok := args["path"].(string)
	if !ok {
		return mcp.NewToolResultError("path must be a string"), nil
	}

	includeJSON, _ := args["include_json"].(bool)

	analysis, err := roast.AnalyzeCampaignFromFile(path)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to analyze campaigns: %v", err)), nil
	}

	// Generate markdown report
	markdown := analysis.FormatMarkdown()

	// If JSON requested, append it
	if includeJSON {
		data, err := json.MarshalIndent(analysis, "", "  ")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to encode analysis: %v", err)), nil
		}
		markdown += "\n\n## Raw JSON Data\n\n```json\n" + string(data) + "\n```\n"
	}

	return mcp.NewToolResultText(markdown), nil
}

// Enhanced tools with live fetching and caching

func fetchInteractshDomainsLiveTool() mcp.Tool {
	return mcp.NewTool("fetch_interactsh_domains_live",
		mcp.WithDescription("Fetch the latest Interactsh domains list with live HTTP requests, caching, and update detection"),
		mcp.WithBoolean("force_refresh",
			mcp.Description("Force refresh from source, bypassing cache (default: false)"),
		),
	)
}

func handleFetchInteractshDomainsLive(args map[string]interface{}) (*mcp.CallToolResult, error) {
	forceRefresh, _ := args["force_refresh"].(bool)

	fetcher := GetGlobalFetcher()

	// Force refresh by clearing cache if requested
	if forceRefresh {
		GetGlobalCache().Delete(CacheKeyInteractshDomains)
	}

	result, err := fetcher.FetchInteractshDomains()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to fetch domains: %v", err)), nil
	}

	// Add metadata about the fetch
	response := map[string]interface{}{
		"source":        "darses/cti repository",
		"url":           result.URL,
		"fetch_time":    result.FetchTime.Format("2006-01-02 15:04:05 UTC"),
		"from_cache":    result.FromCache,
		"was_updated":   result.WasUpdated,
		"domain_count":  result.Size,
		"content_hash":  result.ContentHash[:16] + "...", // Truncate for display
		"status_code":   result.StatusCode,
		"domains":       result.Domains,
	}

	if result.LastModified != "" {
		response["last_modified"] = result.LastModified
	}
	if result.ETag != "" {
		response["etag"] = result.ETag
	}
	if result.Error != "" {
		response["error"] = result.Error
	}

	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to encode results: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

func fetchBurpCollaboratorDomainsLiveTool() mcp.Tool {
	return mcp.NewTool("fetch_burp_collaborator_domains_live",
		mcp.WithDescription("Fetch the latest Burp Collaborator domains list with live HTTP requests, caching, and update detection"),
		mcp.WithBoolean("force_refresh",
			mcp.Description("Force refresh from source, bypassing cache (default: false)"),
		),
	)
}

func handleFetchBurpCollaboratorDomainsLive(args map[string]interface{}) (*mcp.CallToolResult, error) {
	forceRefresh, _ := args["force_refresh"].(bool)

	fetcher := GetGlobalFetcher()

	// Force refresh by clearing cache if requested
	if forceRefresh {
		GetGlobalCache().Delete(CacheKeyBurpCollaborator)
	}

	result, err := fetcher.FetchBurpCollaboratorDomains()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to fetch domains: %v", err)), nil
	}

	// Add metadata about the fetch
	response := map[string]interface{}{
		"source":        "darses/cti repository",
		"url":           result.URL,
		"fetch_time":    result.FetchTime.Format("2006-01-02 15:04:05 UTC"),
		"from_cache":    result.FromCache,
		"was_updated":   result.WasUpdated,
		"domain_count":  result.Size,
		"content_hash":  result.ContentHash[:16] + "...", // Truncate for display
		"status_code":   result.StatusCode,
		"domains":       result.Domains,
		"note":          "Burp Collaborator domains use different format than Interactsh and cannot be decoded",
	}

	if result.LastModified != "" {
		response["last_modified"] = result.LastModified
	}
	if result.ETag != "" {
		response["etag"] = result.ETag
	}
	if result.Error != "" {
		response["error"] = result.Error
	}

	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to encode results: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

func checkDomainUpdatesTool() mcp.Tool {
	return mcp.NewTool("check_domain_updates",
		mcp.WithDescription("Check for updates to external OAST domain lists using efficient HEAD requests"),
	)
}

func handleCheckDomainUpdates(args map[string]interface{}) (*mcp.CallToolResult, error) {
	fetcher := GetGlobalFetcher()

	updates, err := fetcher.CheckForUpdates()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to check for updates: %v", err)), nil
	}

	// Process results
	response := map[string]interface{}{
		"check_time": fmt.Sprintf("%s", time.Now().Format("2006-01-02 15:04:05 UTC")),
		"lists":      make(map[string]interface{}),
	}

	for listName, result := range updates {
		listInfo := map[string]interface{}{
			"url":           result.URL,
			"status_code":   result.StatusCode,
			"update_available": result.WasUpdated,
		}

		if result.LastModified != "" {
			listInfo["last_modified"] = result.LastModified
		}
		if result.ETag != "" {
			listInfo["etag"] = result.ETag
		}
		if result.Error != "" {
			listInfo["error"] = result.Error
		}

		response["lists"].(map[string]interface{})[listName] = listInfo
	}

	// Add cache stats
	response["cache_stats"] = fetcher.GetCacheStats()

	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to encode results: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

func validateDomainAdvancedTool() mcp.Tool {
	return mcp.NewTool("validate_domain_advanced",
		mcp.WithDescription("Advanced domain validation against external OAST lists with attribution and threat intelligence"),
		mcp.WithString("domain",
			mcp.Required(),
			mcp.Description("Domain to validate"),
		),
		mcp.WithBoolean("load_external",
			mcp.Description("Load external domain lists if not already loaded (default: true)"),
		),
	)
}

func handleValidateDomainAdvanced(args map[string]interface{}) (*mcp.CallToolResult, error) {
	domain, ok := args["domain"].(string)
	if !ok {
		return mcp.NewToolResultError("domain must be a string"), nil
	}

	loadExternal, exists := args["load_external"].(bool)
	if !exists {
		loadExternal = true
	}

	validator := GetGlobalValidator()

	// Load external domains if requested and not already loaded
	if loadExternal {
		if err := validator.LoadExternalDomains(); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to load external domains: %v", err)), nil
		}
	}

	result := validator.ValidateDomain(domain)

	// Add validator stats
	response := map[string]interface{}{
		"validation_result": result,
		"validator_stats":   validator.GetStats(),
	}

	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to encode results: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

func validateDomainBatchAdvancedTool() mcp.Tool {
	return mcp.NewTool("validate_domain_batch_advanced",
		mcp.WithDescription("Advanced batch domain validation against external OAST lists with attribution"),
		mcp.WithString("domains",
			mcp.Required(),
			mcp.Description("Domains to validate (JSON array of strings or newline-separated text)"),
		),
		mcp.WithBoolean("load_external",
			mcp.Description("Load external domain lists if not already loaded (default: true)"),
		),
	)
}

func handleValidateDomainBatchAdvanced(args map[string]interface{}) (*mcp.CallToolResult, error) {
	domainsRaw, ok := args["domains"]
	if !ok {
		return mcp.NewToolResultError("domains parameter required"), nil
	}

	loadExternal, exists := args["load_external"].(bool)
	if !exists {
		loadExternal = true
	}

	var domains []string

	// Handle both JSON array and newline-separated text
	switch v := domainsRaw.(type) {
	case string:
		// Try to parse as JSON array first
		if err := json.Unmarshal([]byte(v), &domains); err != nil {
			// Fall back to newline-separated
			lines := strings.Split(v, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					domains = append(domains, line)
				}
			}
		}
	case []interface{}:
		domains = make([]string, len(v))
		for i, d := range v {
			s, ok := d.(string)
			if !ok {
				return mcp.NewToolResultError("all domains must be strings"), nil
			}
			domains[i] = s
		}
	default:
		return mcp.NewToolResultError("domains must be a string or array of strings"), nil
	}

	validator := GetGlobalValidator()

	// Load external domains if requested
	if loadExternal {
		if err := validator.LoadExternalDomains(); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to load external domains: %v", err)), nil
		}
	}

	results := validator.ValidateBatch(domains)

	// Generate summary statistics
	summary := map[string]int{
		"total":               len(results),
		"valid":              0,
		"oast":               0,
		"builtin":            0,
		"interactsh":         0,
		"burp_collaborator":  0,
		"custom_instances":   0,
	}

	for _, result := range results {
		if result.IsValid {
			summary["valid"]++
		}
		if result.IsOAST {
			summary["oast"]++
		}
		if result.IsBuiltIn {
			summary["builtin"]++
		}
		if result.IsInteractsh {
			summary["interactsh"]++
		}
		if result.IsBurpCollaborator {
			summary["burp_collaborator"]++
		}
		if result.IsCustomInstance {
			summary["custom_instances"]++
		}
	}

	response := map[string]interface{}{
		"summary":           summary,
		"validation_results": results,
		"validator_stats":   validator.GetStats(),
	}

	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to encode results: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

func cacheStatsTool() mcp.Tool {
	return mcp.NewTool("oast_cache_stats",
		mcp.WithDescription("Get statistics about the OAST domain cache including TTL, entries, and cleanup status"),
	)
}

func handleCacheStats(args map[string]interface{}) (*mcp.CallToolResult, error) {
	cache := GetGlobalCache()
	fetcher := GetGlobalFetcher()
	validator := GetGlobalValidator()

	response := map[string]interface{}{
		"cache_stats":     cache.Stats(),
		"stale_entries":   cache.GetStaleEntries(),
		"all_entries":     make(map[string]interface{}),
		"validator_stats": validator.GetStats(),
		"fetcher_stats":   fetcher.GetCacheStats(),
	}

	// Get detailed info about all cache entries
	allEntries := cache.GetAll()
	for key, entry := range allEntries {
		response["all_entries"].(map[string]interface{})[key] = map[string]interface{}{
			"url":            entry.URL,
			"last_fetched":   entry.LastFetched.Format("2006-01-02 15:04:05 UTC"),
			"expires_at":     entry.ExpiresAt.Format("2006-01-02 15:04:05 UTC"),
			"ttl":            entry.TTL.String(),
			"domain_count":   len(entry.Data),
			"content_hash":   entry.ContentHash[:16] + "...",
			"is_stale":       entry.IsStale(),
			"last_modified":  entry.LastModified,
			"etag":           entry.ETag,
		}
	}

	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to encode results: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

// Legacy tools (kept for backward compatibility)

func fetchInteractshDomainsTool() mcp.Tool {
	return mcp.NewTool("fetch_interactsh_domains",
		mcp.WithDescription("Fetch the latest list of Interactsh domains from darses/cti repository (legacy - use fetch_interactsh_domains_live for enhanced features)"),
	)
}

func handleFetchInteractshDomains(args map[string]interface{}) (*mcp.CallToolResult, error) {
	result := map[string]interface{}{
		"source": "darses/cti repository",
		"url": "https://raw.githubusercontent.com/darses/cti/refs/heads/main/interactsh-domains.txt",
		"description": "Actively maintained list of Interactsh server domains discovered via Shodan",
		"queries_used": []string{
			"product:\"Interactsh SMTP Server\" port:25",
			"http.html:\"<h1> Interactsh Server </h1>\"",
		},
		"last_update": "2026-01-07",
		"note": "This is a legacy tool. Use fetch_interactsh_domains_live for live fetching with caching.",
		"count": "400+ domains",
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to encode results: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

func fetchBurpCollaboratorDomainsTool() mcp.Tool {
	return mcp.NewTool("fetch_burp_collaborator_domains",
		mcp.WithDescription("Fetch the latest list of Burp Collaborator domains from darses/cti repository (legacy - use fetch_burp_collaborator_domains_live for enhanced features)"),
	)
}

func handleFetchBurpCollaboratorDomains(args map[string]interface{}) (*mcp.CallToolResult, error) {
	result := map[string]interface{}{
		"source": "darses/cti repository",
		"url": "https://raw.githubusercontent.com/darses/cti/refs/heads/main/burpsuite-domains.txt",
		"description": "List of Burp Collaborator Server domains found in SMTP services",
		"queries_used": []string{
			"port:25 \"Burp Collaborator Server ready\"",
		},
		"note": "This is a legacy tool. Use fetch_burp_collaborator_domains_live for live fetching with caching. Burp Collaborator domains use different format than Interactsh and cannot be decoded with roast.",
		"burp_vs_interactsh": "These are Burp Suite's Collaborator domains, not Interactsh domains. They use a different format and cannot be decoded with roast.",
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to encode results: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

func oastIntelTool() mcp.Tool {
	return mcp.NewTool("oast_threat_intel",
		mcp.WithDescription("Get threat intelligence context about OAST domains and infrastructure"),
	)
}

func handleOASTIntel(args map[string]interface{}) (*mcp.CallToolResult, error) {
	content := `# OAST Threat Intelligence Context

## Active Domain Intelligence Sources

### darses/cti Repository
- **Repository:** https://github.com/darses/cti
- **Maintainer:** [darses](https://github.com/darses)
- **Last Update:** 2026-01-07
- **Description:** "Free CTI, so it can't be bad"

### Interactsh Domains (400+ domains)
**Source:** https://raw.githubusercontent.com/darses/cti/refs/heads/main/interactsh-domains.txt

**Discovery Methods:**
- Shodan query: ` + "`product:\"Interactsh SMTP Server\" port:25`" + `
- Shodan query: ` + "`http.html:\"<h1> Interactsh Server </h1>\"`" + `

**Examples from the list:**
- .oast.pro (official)
- .oast.live (official)
- .interact.sh (official)
- .burp.mbti.red (custom instance)
- .interactsh.dev.netspi.net (NetSPI instance)
- .oast.l00t.fi (security researcher)
- .interact.pentestglobal.com (pentest company)

### Burp Collaborator Domains
**Source:** https://raw.githubusercontent.com/darses/cti/refs/heads/main/burpsuite-domains.txt

**Discovery Methods:**
- Shodan query: ` + "`port:25 \"Burp Collaborator Server ready\"`" + `

**Note:** Burp Collaborator domains use a different format than Interactsh and cannot be decoded using roast. However, they're valuable for threat intelligence correlation.

## Threat Intelligence Applications

### 1. Infrastructure Correlation
- Track scanning campaigns across multiple OAST instances
- Identify custom/private OAST deployments
- Correlate with known security companies and researchers

### 2. Campaign Attribution
- Many domains indicate organizational ownership:
  - .interactsh.dev.netspi.net → NetSPI scanning
  - .oast.l00t.fi → Finnish security researcher
  - .interact.pentestglobal.com → PentestGlobal activities

### 3. Threat Landscape Monitoring
- Monitor for new OAST infrastructure deployment
- Track evolution of scanning infrastructure
- Identify potential malicious vs legitimate usage

### 4. Defense Applications
- Whitelist known legitimate OAST domains
- Monitor for callbacks to unknown OAST infrastructure
- Correlate with vulnerability disclosure timelines

## Integration Recommendations

1. **Fetch lists programmatically** from darses/cti repository
2. **Update domain lists regularly** (recommend daily/weekly)
3. **Correlate with internal logs** to identify scanning sources
4. **Track new domains** for emerging threat actors
5. **Maintain attribution database** linking domains to organizations

## Attribution Examples from the Lists

### Security Companies
- NetSPI: .interactsh.dev.netspi.net, .netspi.sh
- Rapid7: .collab.rapid7test.com
- Outpost24: .swati.outpost24.com

### Bug Bounty Platforms
- YesWeHack: .interactsh.prod.yeswehack.cloud
- HackerOne: .h1.ci

### Security Researchers
- Various .oast.[researcher-domain] patterns
- Custom subdomains indicating individual researchers

This intelligence helps differentiate between legitimate security testing and potentially malicious scanning activities.

## Enhanced Tools Available

Use these enhanced MCP tools for live data and advanced analysis:
- **fetch_interactsh_domains_live** - Live HTTP fetching with caching
- **fetch_burp_collaborator_domains_live** - Live Burp Collaborator list fetching
- **check_domain_updates** - Check for updates using efficient HEAD requests
- **validate_domain_advanced** - Advanced validation with attribution
- **validate_domain_batch_advanced** - Batch validation with statistics
- **oast_cache_stats** - Cache and performance statistics`

	return mcp.NewToolResultText(content), nil
}
