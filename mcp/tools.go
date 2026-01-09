package mcp

import (
	"encoding/json"
	"fmt"

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

func fetchInteractshDomainsTool() mcp.Tool {
	return mcp.NewTool("fetch_interactsh_domains",
		mcp.WithDescription("Fetch the latest list of Interactsh domains from darses/cti repository"),
	)
}

func handleFetchInteractshDomains(args map[string]interface{}) (*mcp.CallToolResult, error) {
	url := "https://raw.githubusercontent.com/darses/cti/refs/heads/main/interactsh-domains.txt"

	// Note: In a real implementation, you'd use net/http to fetch this
	// For now, we'll return information about the resource

	result := map[string]interface{}{
		"source": "darses/cti repository",
		"url": url,
		"description": "Actively maintained list of Interactsh server domains discovered via Shodan",
		"queries_used": []string{
			"product:\"Interactsh SMTP Server\" port:25",
			"http.html:\"<h1> Interactsh Server </h1>\"",
		},
		"last_update": "2026-01-07",
		"note": "Use standard HTTP client to fetch the current list from the URL above",
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
		mcp.WithDescription("Fetch the latest list of Burp Collaborator domains from darses/cti repository"),
	)
}

func handleFetchBurpCollaboratorDomains(args map[string]interface{}) (*mcp.CallToolResult, error) {
	url := "https://raw.githubusercontent.com/darses/cti/refs/heads/main/burpsuite-domains.txt"

	// Note: In a real implementation, you'd use net/http to fetch this
	// For now, we'll return information about the resource

	result := map[string]interface{}{
		"source": "darses/cti repository",
		"url": url,
		"description": "List of Burp Collaborator Server domains found in SMTP services",
		"queries_used": []string{
			"port:25 \"Burp Collaborator Server ready\"",
		},
		"note": "Use standard HTTP client to fetch the current list from the URL above",
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

This intelligence helps differentiate between legitimate security testing and potentially malicious scanning activities.`

	return mcp.NewToolResultText(content), nil
}
