package mcp

import (
	"fmt"
	"time"

	"codeberg.org/hrbrmstr/go-roast/pkg/roast"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Serve starts the MCP stdio server
func Serve() error {
	s := server.NewMCPServer(
		"roast",
		"1.0.0",
		server.WithResourceCapabilities(false, false),
		server.WithPromptCapabilities(true),
	)

	// Register prompt
	s.AddPrompt(
		mcp.NewPrompt("oast-expert",
			mcp.WithPromptDescription("Comprehensive OAST domain knowledge and analysis guidance")),
		getOASTExpertPrompt,
	)

	// Register resources (kept for backward compatibility)
	s.AddResource(
		mcp.NewResource("oast://info", "Overview of OAST domains",
			mcp.WithResourceDescription("OAST domain overview and structure"),
			mcp.WithMIMEType("text/plain")),
		getInfoResource,
	)

	s.AddResource(
		mcp.NewResource("oast://format", "OAST domain format specification",
			mcp.WithResourceDescription("Detailed format specification"),
			mcp.WithMIMEType("text/plain")),
		getFormatResource,
	)

	s.AddResource(
		mcp.NewResource("oast://domains", "Known OAST domain suffixes",
			mcp.WithResourceDescription("List of known OAST domains"),
			mcp.WithMIMEType("text/plain")),
		getDomainsResource,
	)

	s.AddResource(
		mcp.NewResource("oast://intel", "External OAST domain intelligence",
			mcp.WithResourceDescription("Information about actively maintained OAST domain lists"),
			mcp.WithMIMEType("text/plain")),
		getIntelResource,
	)

	// Register tools
	s.AddTool(decodeOASTTool(), handleDecodeOAST)
	s.AddTool(classifyOASTTool(), handleClassifyOAST)
	s.AddTool(extractOASTTool(), handleExtractOAST)
	s.AddTool(extractOASTFileTool(), handleExtractOASTFile)
	s.AddTool(validateOASTTool(), handleValidateOAST)
	s.AddTool(campaignAnalysisTool(), handleCampaignAnalysis)

	// Legacy tools (kept for backward compatibility)
	s.AddTool(fetchInteractshDomainsTool(), handleFetchInteractshDomains)
	s.AddTool(fetchBurpCollaboratorDomainsTool(), handleFetchBurpCollaboratorDomains)
	s.AddTool(oastIntelTool(), handleOASTIntel)

	// Enhanced tools with live fetching, caching, and validation
	s.AddTool(fetchInteractshDomainsLiveTool(), handleFetchInteractshDomainsLive)
	s.AddTool(fetchBurpCollaboratorDomainsLiveTool(), handleFetchBurpCollaboratorDomainsLive)
	s.AddTool(checkDomainUpdatesTool(), handleCheckDomainUpdates)
	s.AddTool(validateDomainAdvancedTool(), handleValidateDomainAdvanced)
	s.AddTool(validateDomainBatchAdvancedTool(), handleValidateDomainBatchAdvanced)
	s.AddTool(cacheStatsTool(), handleCacheStats)

	// Start cache cleanup background task
	StartCacheCleanup(15 * time.Minute)

	return server.ServeStdio(s)
}

func getOASTExpertPrompt(arguments map[string]string) (*mcp.GetPromptResult, error) {
	return &mcp.GetPromptResult{
		Description: "Comprehensive OAST domain knowledge and analysis guidance",
		Messages: []mcp.PromptMessage{
			{
				Role: "user",
				Content: mcp.TextContent{
					Type: "text",
					Text: GetInitializationPrompt(),
				},
			},
		},
	}, nil
}

func getInfoResource(request mcp.ReadResourceRequest) ([]interface{}, error) {
	content := `# OAST Domains Overview

OAST (Out-of-band Application Security Testing) is a technique that uses unique DNS
subdomains to detect blind vulnerabilities. Interactsh is the most popular OAST
platform, used by Nuclei and other security scanners.

## Domain Structure

An Interactsh FQDN looks like:
c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro
|------ preamble ------||- nonce -|

**Preamble (20 characters):** Base32hex-encoded 12-byte XID containing:
- Bytes 0-3: Unix timestamp (seconds since epoch, big-endian)
- Bytes 4-6: Machine ID (first 3 bytes of hashed platform UUID)
- Bytes 7-8: Process ID (big-endian)
- Bytes 9-11: Counter (big-endian, starts at random value)

**Nonce (13 characters by default):** z-base-32 encoded random value

## Use Cases

- Threat intelligence correlation
- Campaign tracking
- Security research
- Vulnerability assessment correlation
`

	return []interface{}{
		mcp.TextContent{
			Type: "text",
			Text: content,
		},
	}, nil
}

func getFormatResource(request mcp.ReadResourceRequest) ([]interface{}, error) {
	content := `# OAST Domain Format Specification

## Preamble Encoding

The first 20 characters use **base32hex** (RFC 4648):
Alphabet: 0123456789abcdefghijklmnopqrstuv

Encoding: 20 chars × 5 bits = 100 bits → 12 bytes (96 bits used)

## Field Layout (12 bytes)

| Bytes | Field      | Type                | Description                    |
|-------|------------|---------------------|--------------------------------|
| 0-3   | Timestamp  | uint32 (big-endian) | Unix timestamp (seconds)       |
| 4-6   | Machine ID | 3 bytes             | Hashed platform UUID           |
| 7-8   | PID        | uint16 (big-endian) | Process ID                     |
| 9-11  | Counter    | 24-bit (big-endian) | Incremental counter            |

## Derived Fields

- **K-Sort:** First 6 characters of preamble (timestamp sortable)
- **Campaign:** Characters 7-11 of preamble (campaign identifier)
- **Nonce:** Characters 21+ (z-base-32 encoded random data)

## Nonce Encoding

Uses **z-base-32** alphabet: ybndrfg8ejkmcpqxot1uwisza345h769

Note: Domains with strings of 'y' in the nonce indicate Interactsh CLI v1.0.1
or earlier (used timestamp+counter scheme instead of random values).
`

	return []interface{}{
		mcp.TextContent{
			Type: "text",
			Text: content,
		},
	}, nil
}

func getIntelResource(request mcp.ReadResourceRequest) ([]interface{}, error) {
	content := `# External OAST Domain Intelligence

## darses/cti Repository
- **Repository:** https://github.com/darses/cti
- **Maintainer:** darses
- **Description:** "Free CTI, so it can't be bad"
- **Last Update:** 2026-01-07

## Interactsh Domains (400+ domains)
**URL:** https://raw.githubusercontent.com/darses/cti/refs/heads/main/interactsh-domains.txt

**Discovery Methods:**
- Shodan: product:"Interactsh SMTP Server" port:25
- Shodan: http.html:"<h1> Interactsh Server </h1>"

**Examples:**
- .oast.pro (official)
- .interact.sh (official)
- .interactsh.dev.netspi.net (NetSPI)
- .oast.l00t.fi (researcher)

## Burp Collaborator Domains
**URL:** https://raw.githubusercontent.com/darses/cti/refs/heads/main/burpsuite-domains.txt

**Discovery Method:**
- Shodan: port:25 "Burp Collaborator Server ready"

**Note:** Burp Collaborator uses different format than Interactsh

## Usage
Use MCP tools:
- fetch_interactsh_domains
- fetch_burp_collaborator_domains
- oast_threat_intel
`

	return []interface{}{
		mcp.TextContent{
			Type: "text",
			Text: content,
		},
	}, nil
}

func getDomainsResource(request mcp.ReadResourceRequest) ([]interface{}, error) {
	domains := roast.KnownOASTDomains()
	content := "# Known OAST Domain Suffixes\n\n"
	for _, domain := range domains {
		content += fmt.Sprintf("- %s\n", domain)
	}

	return []interface{}{
		mcp.TextContent{
			Type: "text",
			Text: content,
		},
	}, nil
}
