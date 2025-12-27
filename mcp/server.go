package mcp

import (
	"fmt"

	"github.com/hrbrmstr/go-roast/pkg/roast"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Serve starts the MCP stdio server
func Serve() error {
	s := server.NewMCPServer(
		"roast",
		"1.0.0",
		server.WithResourceCapabilities(false, false),
	)

	// Register resources
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

	// Register tools
	s.AddTool(decodeOASTTool(), handleDecodeOAST)
	s.AddTool(extractOASTTool(), handleExtractOAST)
	s.AddTool(extractOASTFileTool(), handleExtractOASTFile)
	s.AddTool(validateOASTTool(), handleValidateOAST)

	return server.ServeStdio(s)
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
