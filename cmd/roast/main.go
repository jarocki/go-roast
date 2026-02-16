package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"codeberg.org/hrbrmstr/go-roast/mcp"
	"codeberg.org/hrbrmstr/go-roast/pkg/roast"
	"codeberg.org/hrbrmstr/go-roast/web"
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
	rootCmd.AddCommand(serveCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func decodeCmd() *cobra.Command {
	var fileFlag string
	var logTimeFlag string

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

			var results []*roast.DecodedOAST

			// If log-time is provided, decode with timezone estimation
			if logTimeFlag != "" {
				logTime, err := parseRFC3339(logTimeFlag)
				if err != nil {
					return fmt.Errorf("invalid log-time format (use RFC3339): %w", err)
				}
				// For single input with log time
				if len(inputs) == 1 {
					result, err := roast.DecodeWithLogTime(inputs[0], logTime)
					if err != nil {
						results = []*roast.DecodedOAST{result}
					} else {
						results = []*roast.DecodedOAST{result}
					}
				} else {
					// For multiple inputs, use same log time for all
					for _, input := range inputs {
						result, _ := roast.DecodeWithLogTime(input, logTime)
						results = append(results, result)
					}
				}
			} else {
				results = roast.DecodeBatch(inputs)
			}

			return outputResults(results, outputFlag)
		},
	}

	cmd.Flags().StringVarP(&fileFlag, "file", "f", "", "File containing OAST domains (one per line)")
	cmd.Flags().StringVar(&logTimeFlag, "log-time", "", "UTC log timestamp (RFC3339 format) for timezone estimation")

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
	var timestampsFlag bool

	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze OAST domains for campaign patterns",
		Long:  "Analyze OAST domains from a file or stdin and generate campaign statistics.",
		RunE: func(cmd *cobra.Command, args []string) error {
			var analysis *roast.CampaignAnalysis
			var err error

			// If --timestamps is provided, parse CSV/TSV with log_timestamp,domain format
			if timestampsFlag {
				var pairs []roast.TimestampedDomain

				if fileFlag != "" {
					pairs, err = parseTimestampedFile(fileFlag)
					if err != nil {
						return fmt.Errorf("failed to parse timestamped file: %w", err)
					}
				} else {
					pairs, err = parseTimestampedStdin()
					if err != nil {
						return fmt.Errorf("failed to parse timestamped input: %w", err)
					}
				}

				analysis = roast.AnalyzeCampaignWithTimestamps(pairs)
			} else {
				// Standard analysis without timestamps
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
			}

			return outputAnalysis(analysis, outputFlag, includeJSON)
		},
	}

	cmd.Flags().StringVarP(&fileFlag, "file", "f", "", "File to analyze (if not provided, reads from stdin)")
	cmd.Flags().BoolVar(&includeJSON, "include-json", false, "Include raw JSON data in markdown output")
	cmd.Flags().BoolVar(&timestampsFlag, "timestamps", false, "Parse CSV/TSV input with log_timestamp,domain format")

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

func serveCmd() *cobra.Command {
	var addr string
	var port int

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start web UI server",
		Long:  "Start the web interface for decoding and analyzing OAST domains.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return web.Serve(addr, port)
		},
	}

	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1", "Listen address")
	cmd.Flags().IntVar(&port, "port", 8080, "Listen port")

	return cmd
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
		"KSort", "Campaign", "Nonce", "ClientType", "ServerVersion", "Decodable", "Confidence",
		"NonceTimestamp", "NonceCounter", "Error",
	}); err != nil {
		return err
	}

	for _, r := range results {
		clientType, serverVersion, decodable, confidence := "", "", "", ""
		if r.Classification != nil {
			clientType = string(r.Classification.ClientType)
			serverVersion = string(r.Classification.ServerVersion)
			decodable = fmt.Sprintf("%t", r.Classification.Decodable)
			confidence = r.Classification.Confidence
		}

		nonceTs, nonceCtr := "", ""
		if r.NonceTimestamp != nil {
			nonceTs = r.NonceTimestamp.Format("2006-01-02 15:04:05")
		}
		if r.NonceCounter != nil {
			nonceCtr = fmt.Sprintf("%d", *r.NonceCounter)
		}

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
			clientType,
			serverVersion,
			decodable,
			confidence,
			nonceTs,
			nonceCtr,
			r.Error,
		}); err != nil {
			return err
		}
	}

	return nil
}

func outputTable(results []*roast.DecodedOAST) error {
	fmt.Printf("%-40s %-6s %-20s %-12s %-7s %-10s %-8s %-8s %-8s %-20s %-13s\n",
		"Original", "Valid", "Timestamp", "MachineID", "PID", "Counter", "Client", "Version", "Conf", "Nonce-Timestamp", "Nonce-Counter")
	fmt.Println(strings.Repeat("-", 180))

	for _, r := range results {
		status := "✓"
		if !r.Valid {
			status = "✗"
		}

		timestamp := r.Timestamp.Format("2006-01-02 15:04:05")
		if !r.Valid {
			timestamp = ""
		}

		clientType, version, conf := "", "", ""
		nonceTs, nonceCtr := "", ""
		if r.Classification != nil {
			clientType = string(r.Classification.ClientType)
			version = string(r.Classification.ServerVersion)
			conf = r.Classification.Confidence
		}
		// Prefer top-level promoted fields, fall back to NonceAnalysis
		if r.NonceTimestamp != nil {
			nonceTs = r.NonceTimestamp.Format("2006-01-02 15:04:05")
		} else if r.Classification != nil && r.Classification.NonceAnalysis != nil {
			nonceTs = r.Classification.NonceAnalysis.NonceTimestamp.Format("2006-01-02 15:04:05")
		}
		if r.NonceCounter != nil {
			nonceCtr = fmt.Sprintf("%d", *r.NonceCounter)
		} else if r.Classification != nil && r.Classification.NonceAnalysis != nil {
			nonceCtr = fmt.Sprintf("%d", r.Classification.NonceAnalysis.NonceCounter)
		}

		fmt.Printf("%-40s %-6s %-20s %-12s %-7d %-10d %-8s %-8s %-8s %-20s %-13s\n",
			truncate(r.Original, 40),
			status,
			timestamp,
			r.MachineID,
			r.PID,
			r.Counter,
			clientType,
			version,
			conf,
			nonceTs,
			nonceCtr,
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

// parseTimestampedFile reads a CSV/TSV file with log_timestamp,domain format
func parseTimestampedFile(path string) ([]roast.TimestampedDomain, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return parseTimestampedReader(file)
}

// parseTimestampedStdin reads CSV/TSV from stdin with log_timestamp,domain format
func parseTimestampedStdin() ([]roast.TimestampedDomain, error) {
	return parseTimestampedReader(os.Stdin)
}

// parseTimestampedReader parses CSV/TSV input with log_timestamp,domain format
func parseTimestampedReader(r *os.File) ([]roast.TimestampedDomain, error) {
	var pairs []roast.TimestampedDomain
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Try comma first, then tab
		var fields []string
		if strings.Contains(line, ",") {
			fields = strings.Split(line, ",")
		} else if strings.Contains(line, "\t") {
			fields = strings.Split(line, "\t")
		} else {
			continue // Skip lines without delimiters
		}

		if len(fields) < 2 {
			continue
		}

		timestampStr := strings.TrimSpace(fields[0])
		domain := strings.TrimSpace(fields[1])

		logTime, err := parseRFC3339(timestampStr)
		if err != nil {
			// Skip lines with invalid timestamps
			continue
		}

		pairs = append(pairs, roast.TimestampedDomain{
			Domain:       domain,
			LogTimestamp: logTime,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return pairs, nil
}

// parseRFC3339 parses an RFC3339 timestamp string
func parseRFC3339(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}
