# roast

A Go library, CLI tool, and stdio MCP server for processing Interactsh OAST (Out-of-band Application Security Testing) domains.

## Overview

`roast` decodes metadata embedded in Interactsh OAST domain names. These domains encode a 12-byte XID preamble containing timestamp, machine ID, process ID, and counter values that can be used for threat intelligence correlation and campaign tracking.

## Homage

Built this thanks to John Jarocki's epic LabsCon presentation "["Tracking the cyberspace ghost from OAST to OAST"](https://drive.proton.me/urls/ACAEQN0HB4#wfhmFCMfc4Os)".

## Installation

```bash
go install codeberg.org/hrbrmstr/go-roast/cmd/roast@latest
```

Or build from source:

```bash
git clone https://codeberg.org/hrbrmstr/go-roast
cd go-roast
go build -o roast ./cmd/roast
```

## CLI Usage

### Quick Reference

| Command | Purpose |
|---------|---------|
| `roast decode` | Decode OAST domains (one per line) |
| `roast extract` | Extract OAST domains from text/logs |
| `roast analyze` | Analyze domains for campaign patterns |
| `roast mcp` | Start MCP stdio server |

### Global Flags

- `-o, --output` - Output format: json, csv, table, markdown (default: json)
- `-q, --quiet` - Suppress non-essential output
- `-h, --help` - Show help for any command
- `-v, --version` - Show version information

### Decode OAST domains

Decode one or more OAST domains from a file or stdin.

```bash
# Decode from stdin
echo "c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro" | roast decode

# Decode from file (one domain per line)
roast decode -f domains.txt

# Output as CSV
roast decode -f domains.txt -o csv

# Output as table
roast decode -f domains.txt -o table

# Quiet mode (suppress counts)
roast decode -f domains.txt -q
```

**Flags:**
- `-f, --file` - File containing OAST domains (one per line)

### Extract OAST domains from text

Extract OAST domains from text files or stdin.

```bash
# Extract from file
roast extract -f logfile.txt

# Extract and decode in one step
roast extract -f logfile.txt --decode

# Extract from stdin
cat logs.txt | roast extract --decode -o json

# Extract with CSV output
roast extract -f logfile.txt -o csv

# Extract and decode with table output
roast extract -f logfile.txt --decode -o table
```

**Flags:**
- `-f, --file` - File to extract OAST domains from (if not provided, reads from stdin)
- `--decode` - Also decode extracted domains

### Analyze OAST campaigns

Analyze OAST domains from a file or stdin and generate campaign statistics. Automatically extracts and decodes all domains found.

```bash
# Analyze domains from a file (markdown report)
roast analyze -f domains.txt -o markdown

# Analyze from stdin
cat logs.txt | roast analyze -o markdown

# Output as JSON
roast analyze -f domains.txt -o json

# Include raw JSON data with markdown report
roast analyze -f domains.txt -o markdown --include-json
```

**Flags:**
- `-f, --file` - File to analyze (if not provided, reads from stdin)
- `--include-json` - Include raw JSON data in markdown output

**Campaign analysis provides:**
- Overall statistics (total domains, valid/invalid, unique campaigns/machines/PIDs)
- Time span of activity (first seen, last seen, duration)
- Per-campaign breakdown with counts, timestamps, machine IDs, PIDs, and K-sort values
- Correlation data for threat intelligence
- Counter ranges to identify campaign progression

### Example Output

**Decode output (JSON):**
```json
[
  {
    "original": "c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro",
    "timestamp": "2024-01-15T10:30:45Z",
    "machine_id": "12:34:56",
    "pid": 1234,
    "counter": 5678,
    "nonce": "cfemp9yyyyyyn",
    "ksort": "c58bdu",
    "campaign": "he008",
    "valid": true
  }
]
```

**Campaign analysis output (Markdown):**
```markdown
# OAST Campaign Analysis

## Overall Statistics
- **Total Domains Found:** 15
- **Valid Domains:** 15
- **Unique Campaigns:** 3
- **Unique Machine IDs:** 2
- **Unique PIDs:** 1
- **First Seen:** 2024-01-15T10:30:45Z
- **Last Seen:** 2024-01-17T14:22:33Z
- **Time Span:** 2.2 days

## Campaign Details

### Campaign: `he008`
- **Count:** 8 domains
- **Duration:** 4.5 hours
- **Counter Range:** 5678 - 5801
- **Machine IDs (1):** `12:34:56`
- **PIDs (1):** `1234`
```

## MCP Server

Start the Model Context Protocol stdio server:

```bash
roast mcp
```

📖 **For detailed Claude Desktop configuration, see [CLAUDE_DESKTOP.md](CLAUDE_DESKTOP.md)**

### Prompts

- `oast-expert` - Comprehensive OAST domain knowledge base and analysis guidance (load with `/oast-expert` in Claude Desktop)

### Resources

- `oast://info` - Overview of OAST domains and their structure
- `oast://format` - Detailed format specification including encoding details
- `oast://domains` - List of known OAST domain suffixes
- `oast://intel` - External OAST domain intelligence from actively maintained threat intelligence sources

### Tools

#### Core Analysis Tools
- `decode_oast` - Decode one or more OAST domains
- `extract_oast` - Extract OAST domains from text
- `extract_oast_file` - Extract OAST domains from a file
- `validate_oast` - Check if a string is a valid OAST domain
- `oast_campaign_analysis` - Analyze OAST domains from a file and generate a campaign analysis summary in markdown format

#### Threat Intelligence Tools
- `fetch_interactsh_domains` - Fetch the latest list of Interactsh domains from darses/cti repository
- `fetch_burp_collaborator_domains` - Fetch the latest list of Burp Collaborator domains from darses/cti repository  
- `oast_threat_intel` - Get comprehensive threat intelligence context about OAST domains and infrastructure

### MCP Configuration

#### Basic Configuration

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "roast": {
      "command": "/path/to/roast",
      "args": ["mcp"]
    }
  }
}
```

Replace `/path/to/roast` with the full path to your roast binary.

#### Using the OAST Expert Prompt

Claude Desktop supports MCP prompts. To automatically provide OAST domain expertise context:

1. After adding the MCP server configuration above, restart Claude Desktop
2. Start a conversation and type `/oast-expert` to load the comprehensive OAST knowledge base
3. Claude will have access to detailed information about:
   - OAST domain structure and encoding
   - Decoding algorithms and field layouts
   - Campaign analysis techniques
   - Machine ID derivation
   - Version detection patterns
   - Analysis best practices

The prompt provides context for intelligent analysis of OAST domains without needing to read resources manually.

**What's included in the prompt:**
- Complete OAST domain structure documentation
- Base32hex and z-base-32 encoding specifications
- Field layout with byte-level details
- Machine ID derivation for all platforms
- K-sort and campaign identifier explanations
- Version detection techniques (v1.0.1 detection via 'y' patterns)
- Threat intelligence correlation strategies
- Campaign tracking methodologies
- Analysis tips and best practices
- All known OAST domain suffixes

This rich context allows Claude to provide expert-level analysis and guidance when working with OAST domains.

## Library Usage

### Core Types

```go
// DecodedOAST contains the decoded metadata from an OAST domain
type DecodedOAST struct {
    Original  string    // Original subdomain/FQDN
    Timestamp time.Time // Decoded timestamp
    MachineID string    // Format: "xx:xx:xx" (3 hex bytes)
    PID       uint16    // Process ID
    Counter   uint32    // Counter value (24-bit)
    Nonce     string    // The nonce portion (if present)
    KSort     string    // First 6 chars of preamble (for K-sorting)
    Campaign  string    // Chars 7-11 of preamble (campaign identifier)
    Valid     bool      // Whether decoding succeeded
    Error     string    // Error message if invalid
}

// OASTMatch represents an extracted OAST domain from text
type OASTMatch struct {
    Full       string // Full matched string
    Subdomain  string // Just the subdomain portion
    Domain     string // The OAST domain (e.g., "oast.fun")
    StartIndex int    // Position in source text
    EndIndex   int    // End position in source text
}

// CampaignAnalysis contains the full analysis of OAST domains
type CampaignAnalysis struct {
    TotalDomains    int
    ValidDomains    int
    InvalidDomains  int
    UniqueCampaigns int
    FirstSeen       time.Time
    LastSeen        time.Time
    TimeSpan        string
    UniqueMachines  int
    UniquePIDs      int
    MachineIDs      []string
    PIDs            []uint16
    Campaigns       map[string]*CampaignStats
}
```

### Decoding Functions

```go
import "codeberg.org/hrbrmstr/go-roast/pkg/roast"

// Decode a single domain
decoded, err := roast.Decode("c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Timestamp: %s\n", decoded.Timestamp)
fmt.Printf("Machine ID: %s\n", decoded.MachineID)
fmt.Printf("PID: %d\n", decoded.PID)
fmt.Printf("Counter: %d\n", decoded.Counter)
fmt.Printf("Campaign: %s\n", decoded.Campaign)

// Decode multiple domains at once
domains := []string{"domain1.oast.pro", "domain2.oast.fun"}
results := roast.DecodeBatch(domains)
for _, result := range results {
    if result.Valid {
        fmt.Printf("%s: %s\n", result.Campaign, result.Timestamp)
    }
}
```

### Extraction Functions

```go
// Extract domains from a string
matches := roast.ExtractFromString("Found: c58bduhe008dovpvhvug.oast.pro")
for _, match := range matches {
    fmt.Printf("Found: %s at position %d\n", match.Full, match.StartIndex)
}

// Extract from a reader (e.g., file, HTTP response)
file, _ := os.Open("logs.txt")
matches, err := roast.ExtractFromReader(file)

// Extract from a file
matches, err := roast.ExtractFromFile("logs.txt")

// Extract and decode in one step
text := "Logs contain c58bduhe008dovpvhvug.oast.pro"
matches, decoded := roast.ExtractAndDecode(text)

// Extract and decode from a reader
matches, decoded, err := roast.ExtractAndDecodeFromReader(file)

// Extract and decode from a file
matches, decoded, err := roast.ExtractAndDecodeFromFile("logs.txt")
```

### Campaign Analysis Functions

```go
// Analyze domains from a file
analysis, err := roast.AnalyzeCampaignFromFile("domains.txt")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Total domains: %d\n", analysis.TotalDomains)
fmt.Printf("Unique campaigns: %d\n", analysis.UniqueCampaigns)
fmt.Printf("Time span: %s\n", analysis.TimeSpan)

// Generate markdown report
markdown := analysis.FormatMarkdown()
fmt.Println(markdown)

// Analyze domains from a string
text := "log with c58bduhe008dovpvhvug.oast.pro domains"
analysis := roast.AnalyzeCampaignFromString(text)
```

### Validation Functions

```go
// Check if a string is a valid OAST subdomain
if roast.IsValidOASTSubdomain("c58bduhe008dovpvhvugcfemp9yyyyyyn") {
    fmt.Println("Valid subdomain")
}

// Validate that a 20-char string is valid base32hex
if roast.IsValidPreamble("c58bduhe008dovpvhvug") {
    fmt.Println("Valid preamble")
}

// Get list of known OAST domain suffixes
domains := roast.KnownOASTDomains()
// Returns: ["oast.pro", "oast.live", "oast.site", ...]

// Check if a domain is a known OAST domain
if roast.IsKnownOASTDomain("oast.pro") {
    fmt.Println("Known OAST domain")
}
```

## OAST Domain Format

An Interactsh FQDN looks like:
```
c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro
|------ preamble ------||- nonce -|
```

### Preamble (20 characters)

Base32hex-encoded 12-byte XID containing:
- **Bytes 0-3:** Unix timestamp (seconds since epoch, big-endian)
- **Bytes 4-6:** Machine ID (first 3 bytes of hashed platform UUID)
- **Bytes 7-8:** Process ID (big-endian)
- **Bytes 9-11:** Counter (big-endian, starts at random value)

### Nonce (13+ characters)

z-base-32 encoded random value (used for session uniqueness)

### Known OAST Domains

**Built-in domains:**
- oast.pro
- oast.live
- oast.site
- oast.online
- oast.fun
- oast.me
- interact.sh
- interactsh.com

**Extended Domain Lists**

For comprehensive OAST domain coverage, `roast` recognizes domains from actively maintained threat intelligence lists:

- **Interactsh domains:** [darses/cti interactsh-domains.txt](https://github.com/darses/cti/blob/main/interactsh-domains.txt) - 400+ Interactsh server domains discovered via Shodan
- **Burp Collaborator domains:** [darses/cti burpsuite-domains.txt](https://github.com/darses/cti/blob/main/burpsuite-domains.txt) - Burp Collaborator Server domains found in SMTP services

These lists are maintained by [darses](https://github.com/darses) and updated regularly through automated Shodan queries. The Interactsh domains are discovered using:
- `product:"Interactsh SMTP Server" port:25`
- `http.html:"<h1> Interactsh Server </h1>"`

Burp Collaborator domains are found using:
- `port:25 "Burp Collaborator Server ready"`

**Note:** `roast` will attempt to decode any domain matching the Interactsh preamble format, regardless of the domain suffix. These lists help identify legitimate OAST infrastructure for threat intelligence correlation.

## Use Cases

- **Threat Intelligence:** Correlate OAST callbacks across different security events
- **Campaign Tracking:** Identify related scanning activities by machine ID and campaign identifier
- **Forensics:** Extract timestamps and source information from OAST domains found in logs
- **Security Research:** Analyze Interactsh usage patterns and scanning behaviors

## Testing

```bash
# Run all tests
go test ./...

# Run with verbose output
go test -v ./pkg/roast/...

# Run with coverage
go test -cover ./...
```

## References

- [Interactsh GitHub](https://github.com/projectdiscovery/interactsh)
- [XID GitHub (K-sortable ID)](https://github.com/rs/xid)
- [Base32hex (RFC 4648)](https://datatracker.ietf.org/doc/html/rfc4648#section-7)
- [z-base-32](https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt)
- [MCP Specification](https://spec.modelcontextprotocol.io/)
- [darses/cti](https://github.com/darses/cti) - Actively maintained lists of OAST domain infrastructure

## License

MIT
