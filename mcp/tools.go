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
