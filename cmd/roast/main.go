package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"codeberg.org/hrbrmstr/go-roast/mcp"
	"codeberg.org/hrbrmstr/go-roast/pkg/roast"
	"github.com/spf13/cobra"
)

var (
	version    = "dev"
	outputFlag string
	quietFlag  bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:     "roast",
		Short:   "Decode Interactsh OAST domain metadata",
		Long:    `A Go library, CLI tool, and stdio MCP server for processing Interactsh OAST (Out-of-band Application Security Testing) domains.`,
		Version: version,
	}

	rootCmd.PersistentFlags().StringVarP(&outputFlag, "output", "o", "json", "Output format: json, csv, table")
	rootCmd.PersistentFlags().BoolVarP(&quietFlag, "quiet", "q", false, "Suppress non-essential output")

	rootCmd.AddCommand(decodeCmd())
	rootCmd.AddCommand(extractCmd())
	rootCmd.AddCommand(analyzeCmd())
	rootCmd.AddCommand(pipeCmd())
	rootCmd.AddCommand(mcpCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func decodeCmd() *cobra.Command {
	var fileFlag string

	cmd := &cobra.Command{
		Use:   "decode",
		Short: "Decode OAST domains",
		Long:  "Decode one or more OAST domains from a file (one per line) or stdin.",
		RunE: func(cmd *cobra.Command, args []string) error {
			var inputs []string

			if fileFlag != "" {
				file, err := os.Open(fileFlag)
				if err != nil {
					return fmt.Errorf("failed to open file: %w", err)
				}
				defer file.Close()

				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line != "" {
						inputs = append(inputs, line)
					}
				}
				if err := scanner.Err(); err != nil {
					return fmt.Errorf("failed to read file: %w", err)
				}
			} else {
				scanner := bufio.NewScanner(os.Stdin)
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line != "" {
						inputs = append(inputs, line)
					}
				}
				if err := scanner.Err(); err != nil {
					return fmt.Errorf("failed to read stdin: %w", err)
				}
			}

			if len(inputs) == 0 {
				return fmt.Errorf("no input provided")
			}

			results := roast.DecodeBatch(inputs)

			return outputResults(results, outputFlag)
		},
	}

	cmd.Flags().StringVarP(&fileFlag, "file", "f", "", "File containing OAST domains (one per line)")

	return cmd
}

func extractCmd() *cobra.Command {
	var fileFlag string
	var decodeFlag bool

	cmd := &cobra.Command{
		Use:   "extract",
		Short: "Extract OAST domains from text",
		Long:  "Extract OAST domains from text files or stdin.",
		RunE: func(cmd *cobra.Command, args []string) error {
			var matches []roast.OASTMatch
			var decoded []*roast.DecodedOAST
			var err error

			if fileFlag != "" {
				if decodeFlag {
					matches, decoded, err = roast.ExtractAndDecodeFromFile(fileFlag)
				} else {
					matches, err = roast.ExtractFromFile(fileFlag)
				}
			} else {
				if decodeFlag {
					matches, decoded, err = roast.ExtractAndDecodeFromReader(os.Stdin)
				} else {
					matches, err = roast.ExtractFromReader(os.Stdin)
				}
			}

			if err != nil {
				return fmt.Errorf("extraction failed: %w", err)
			}

			if !quietFlag {
				fmt.Fprintf(os.Stderr, "Found %d OAST domain(s)\n", len(matches))
			}

			if decodeFlag {
				return outputResults(decoded, outputFlag)
			}

			return outputMatches(matches, outputFlag)
		},
	}

	cmd.Flags().StringVarP(&fileFlag, "file", "f", "", "File to extract OAST domains from")
	cmd.Flags().BoolVar(&decodeFlag, "decode", false, "Also decode extracted domains")

	return cmd
}

func analyzeCmd() *cobra.Command {
	var fileFlag string
	var includeJSON bool

	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze OAST domains for campaign patterns",
		Long:  "Analyze OAST domains from a file or stdin and generate campaign statistics.",
		RunE: func(cmd *cobra.Command, args []string) error {
			var analysis *roast.CampaignAnalysis
			var err error

			if fileFlag != "" {
				analysis, err = roast.AnalyzeCampaignFromFile(fileFlag)
			} else {
				content, err := readFromStdin()
				if err != nil {
					return fmt.Errorf("failed to read stdin: %w", err)
				}
				analysis = roast.AnalyzeCampaignFromString(content)
			}

			if err != nil {
				return fmt.Errorf("analysis failed: %w", err)
			}

			return outputAnalysis(analysis, outputFlag, includeJSON)
		},
	}

	cmd.Flags().StringVarP(&fileFlag, "file", "f", "", "File to analyze (if not provided, reads from stdin)")
	cmd.Flags().BoolVar(&includeJSON, "include-json", false, "Include raw JSON data in markdown output")

	return cmd
}

func pipeCmd() *cobra.Command {
	var fileFlag string
	var skipEmpty bool

	cmd := &cobra.Command{
		Use:   "pipe",
		Short: "Process input line-by-line for DuckDB integration",
		Long: `Process input line by line, extracting and decoding OAST domains.

Emits NDJSON (newline-delimited JSON) where each line contains:
  - line_num: 1-indexed line number
  - line: original line text
  - oast_count: number of OAST domains found
  - oast_decoded: array of decoded OAST objects

Example DuckDB usage:
  -- Read all lines with decoded OASTs
  SELECT * FROM read_json('/path/to/output.ndjson');

  -- Unnest decoded OASTs for per-domain analysis
  SELECT line_num, unnest(oast_decoded) as oast
  FROM read_json('/path/to/output.ndjson')
  WHERE oast_count > 0;`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// PipeRecord is the output structure for each line
			type PipeRecord struct {
				LineNum     int                   `json:"line_num"`
				Line        string                `json:"line"`
				OASTCount   int                   `json:"oast_count"`
				OASTDecoded []*roast.DecodedOAST  `json:"oast_decoded"`
			}

			var reader *bufio.Scanner
			var file *os.File

			if fileFlag != "" {
				var err error
				file, err = os.Open(fileFlag)
				if err != nil {
					return fmt.Errorf("failed to open file: %w", err)
				}
				defer file.Close()
				reader = bufio.NewScanner(file)
			} else {
				reader = bufio.NewScanner(os.Stdin)
			}

			encoder := json.NewEncoder(os.Stdout)
			// No indentation for compact NDJSON
			lineNum := 0
			processedCount := 0
			matchedCount := 0

			for reader.Scan() {
				lineNum++
				line := reader.Text()

				// Extract OAST domains from the line
				matches := roast.ExtractFromString(line)

				// Decode each extracted domain
				var decoded []*roast.DecodedOAST
				for _, match := range matches {
					d, err := roast.Decode(match.Subdomain)
					if err != nil {
						// Include invalid decodes with error set
						decoded = append(decoded, &roast.DecodedOAST{
							Original: match.Subdomain,
							Valid:    false,
							Error:    err.Error(),
						})
					} else {
						decoded = append(decoded, d)
					}
				}

				oastCount := len(decoded)

				// Skip lines with no OASTs if requested
				if skipEmpty && oastCount == 0 {
					continue
				}

				processedCount++
				if oastCount > 0 {
					matchedCount++
				}

				record := PipeRecord{
					LineNum:     lineNum,
					Line:        line,
					OASTCount:   oastCount,
					OASTDecoded: decoded,
				}

				if err := encoder.Encode(record); err != nil {
					return fmt.Errorf("failed to encode JSON: %w", err)
				}
			}

			if err := reader.Err(); err != nil {
				return fmt.Errorf("failed to read input: %w", err)
			}

			if !quietFlag {
				fmt.Fprintf(os.Stderr, "Processed %d lines, %d with OAST domains\n", processedCount, matchedCount)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&fileFlag, "file", "f", "", "Input file (if omitted, reads stdin)")
	cmd.Flags().BoolVar(&skipEmpty, "skip-empty", false, "Skip lines with no OAST domains")

	return cmd
}

func mcpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Start MCP stdio server",
		Long:  "Start the Model Context Protocol stdio server.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return mcp.Serve()
		},
	}
}

func outputResults(results []*roast.DecodedOAST, format string) error {
	switch strings.ToLower(format) {
	case "json":
		return outputJSON(results)
	case "csv":
		return outputCSV(results)
	case "table":
		return outputTable(results)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

func outputMatches(matches []roast.OASTMatch, format string) error {
	switch strings.ToLower(format) {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(matches)
	case "csv":
		w := csv.NewWriter(os.Stdout)
		defer w.Flush()

		if err := w.Write([]string{"Full", "Subdomain", "Domain", "StartIndex", "EndIndex"}); err != nil {
			return err
		}

		for _, m := range matches {
			if err := w.Write([]string{
				m.Full,
				m.Subdomain,
				m.Domain,
				fmt.Sprintf("%d", m.StartIndex),
				fmt.Sprintf("%d", m.EndIndex),
			}); err != nil {
				return err
			}
		}
		return nil
	case "table":
		fmt.Printf("%-60s %-40s %-20s\n", "Full", "Subdomain", "Domain")
		fmt.Println(strings.Repeat("-", 120))
		for _, m := range matches {
			fmt.Printf("%-60s %-40s %-20s\n", m.Full, m.Subdomain, m.Domain)
		}
		return nil
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

func outputJSON(results []*roast.DecodedOAST) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func outputCSV(results []*roast.DecodedOAST) error {
	w := csv.NewWriter(os.Stdout)
	defer w.Flush()

	if err := w.Write([]string{
		"Original", "Valid", "Timestamp", "MachineID", "PID", "Counter",
		"KSort", "Campaign", "Nonce", "Error",
	}); err != nil {
		return err
	}

	for _, r := range results {
		if err := w.Write([]string{
			r.Original,
			fmt.Sprintf("%t", r.Valid),
			r.Timestamp.Format("2006-01-02 15:04:05"),
			r.MachineID,
			fmt.Sprintf("%d", r.PID),
			fmt.Sprintf("%d", r.Counter),
			r.KSort,
			r.Campaign,
			r.Nonce,
			r.Error,
		}); err != nil {
			return err
		}
	}

	return nil
}

func outputTable(results []*roast.DecodedOAST) error {
	fmt.Printf("%-40s %-6s %-20s %-12s %-7s %-10s %-10s %-10s\n",
		"Original", "Valid", "Timestamp", "MachineID", "PID", "Counter", "KSort", "Campaign")
	fmt.Println(strings.Repeat("-", 140))

	for _, r := range results {
		status := "✓"
		if !r.Valid {
			status = "✗"
		}

		timestamp := r.Timestamp.Format("2006-01-02 15:04:05")
		if !r.Valid {
			timestamp = ""
		}

		fmt.Printf("%-40s %-6s %-20s %-12s %-7d %-10d %-10s %-10s\n",
			truncate(r.Original, 40),
			status,
			timestamp,
			r.MachineID,
			r.PID,
			r.Counter,
			r.KSort,
			r.Campaign,
		)

		if r.Error != "" {
			fmt.Printf("  Error: %s\n", r.Error)
		}
	}

	return nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func readFromStdin() (string, error) {
	var sb strings.Builder
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		sb.WriteString(scanner.Text())
		sb.WriteString("\n")
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func outputAnalysis(analysis *roast.CampaignAnalysis, format string, includeJSON bool) error {
	switch strings.ToLower(format) {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(analysis)
	case "markdown", "md":
		markdown := analysis.FormatMarkdown()
		if includeJSON {
			data, err := json.MarshalIndent(analysis, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to encode JSON: %w", err)
			}
			markdown += "\n## Raw JSON Data\n\n```json\n" + string(data) + "\n```\n"
		}
		fmt.Print(markdown)
		return nil
	default:
		// Default to markdown for campaign analysis
		markdown := analysis.FormatMarkdown()
		if includeJSON {
			data, err := json.MarshalIndent(analysis, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to encode JSON: %w", err)
			}
			markdown += "\n## Raw JSON Data\n\n```json\n" + string(data) + "\n```\n"
		}
		fmt.Print(markdown)
		return nil
	}
}
