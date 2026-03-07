# roast

A Go library, CLI tool, self-hosted web server, and stdio MCP server for processing Interactsh OAST (Out-of-band Application Security Testing) domains.

## Overview

`roast` decodes metadata embedded in Interactsh OAST domain names. These domains encode a 12-byte XID preamble containing timestamp, machine ID, process ID, and counter values that can be used for threat intelligence correlation and campaign tracking.

## Backgfround and OAST Analytics

The methods used in roast are based on John Jarocki's LABSCon presentation ["Tracking the cyberspace ghost from OAST to OAST"](https://drive.proton.me/urls/ACAEQN0HB4#wfhmFCMfc4Os).

The paper describes the data that is stored in OAST fully-qualified domain names, which are used as a unique tag for out-of-band testing tools (such as Project Discovery's Nuclei) to validate test success.

### Analytics Derived from the Original Presnetation

| Slide | Claim | Verification |
|-------|-------|--------------|
| 17 | XID is a "K-sortable unique identifier" with 12-byte structure | Confirmed: `id.go` defines `type ID [rawLen]byte` where `rawLen = 12` |
| 17 | Preamble encoded in base32hex, nonce in z-base-32 | Confirmed: preamble uses `0123456789abcdefghijklmnopqrstuv`, nonce uses `ybndrfg8ejkmcpqxot1uwisza345h769` |
| 19 | Byte layout: TS(4) + MID(3) + PID(2) + Counter(3) | Confirmed: matches `id.go` field offsets exactly |
| 21 | MID uses SHA-256 of platform machine ID | Confirmed for xid v1.5.0+ (current versions) |
| 21 | Platform sources: Linux `/etc/machine-id`, macOS `sysctl kern.uuid`, Windows Registry `MachineGuid`, FreeBSD `sysctl kern.hostuuid` | Confirmed: matches `hostid_*.go` platform files |
| 21 | Fallback to hostname or random bytes | Confirmed: `readMachineID()` fallback chain |
| 22 | z-base-32 `y` = 0, producing `yyy` runs in v1.0.1 nonces | Confirmed: z-base-32 alphabet starts with `y` mapping to 0 |
| 22 | v1.0.2 (2022-03-20) fixed the nonce to use random bytes | Confirmed: commit `0166128` switched to `crypto/rand` |
| 22 | Web client uses z-base-32 for both preamble and nonce | Confirmed: web client JavaScript uses z-base-32 throughout |
| 37 | "The timestamp is relative to the timezone setting of the interactsh client" | Confirmed: XID encodes `time.Now().Unix()` which uses the client's local wall clock, not UTC |

### Missing from Presentation

The following details are absent from the presentation but are important for
forensic analysis:

| Topic | What's Missing | Why It Matters |
|-------|---------------|----------------|
| **Hash evolution** | Presentation shows SHA-256 (slide 21) but does not mention that older versions used MD5, or when the transition occurred | An analyst comparing MIDs across pre/post April 2023 domains would see different MIDs for the same machine and might incorrectly conclude they're different operators |
| **Exact xid version mapping** | No mapping of interactsh versions to xid versions | Without this, analysts can't determine which hash algorithm produced a given MID |
| **`XID_MACHINE_ID` env var** | Not mentioned (added May 2025, after the presentation) | Operators can now spoof their MID by setting this environment variable, undermining machine correlation |
| **Linux fallback path** | `/sys/class/dmi/id/product_uuid` as secondary source on Linux | In containerized environments where `/etc/machine-id` may be absent, the DMI UUID is used instead |
| **Automated timezone estimation at scale** | Presentation demonstrates the differential technique (GA cookie vs XID timestamp, slide 36) and notes timestamps are local (slide 37), but doesn't formalize it as a systematic pipeline for bulk timezone estimation across campaigns | Roast's `EstimateTimezone()` and `ConsensusTimezone()` automate this across many domains with confidence scoring |
| **Counter initialization** | Counter is seeded from `crypto/rand`, not started at 0 | Important for counter gap analysis — the first domain from a process won't have counter=0 (unlike v1.0.1 nonces) |
| **PID truncation** | PID is stored as `os.Getpid() % 65536` (2 bytes) | On Linux with high PIDs (>65535), different processes can produce the same PID field |


## Installation

```bash
go install codeberg.org/hrbrmstr/go-roast/cmd/roast@latest
```

Or build from source:

```bash
# To install from Bob Rudis' original repo:
# git clone https://codeberg.org/hrbrmstr/go-roast
# To install from this fork:
git clone https://github.com/jarocki/go-roast
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
| `roast pipe` | Line-by-line NDJSON output for DuckDB integration |
| `roast serve` | Start web UI server |
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
- Executive summary with high-level findings
- Overall statistics (total domains, valid/invalid, unique campaigns/machines/PIDs)
- Time span of activity (first seen, last seen, duration)
- Classification breakdown (client types, server versions) with per-campaign detail
- Session analytics from v1.0.1 nonces (session age, domain generation velocity)
- Cross-reference findings (corroboration or warnings across same-machine domains)
- Per-campaign narratives with nonce timestamp ranges, counter ranges, and session ages
- Activity timeline across all campaigns
- Correlation data for threat intelligence

### Example Output

**Decode output (JSON):**
```json
[
  {
    "original": "c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro",
    "timestamp": "2021-09-26T18:07:54Z",
    "machine_id": "2e:00:10",
    "pid": 56447,
    "counter": 4165629,
    "nonce": "cfemp9yyyyyyn",
    "ksort": "c58bdu",
    "campaign": "he008",
    "valid": true,
    "classification": {
      "client_type": "cli",
      "server_version": "v1.0.1",
      "confidence": "high",
      "reasoning": [
        "preamble contains digits — CLI client (base32hex)",
        "nonce decodes to valid timestamp 2021-09-26T18:07:56Z — v1.0.1",
        "nonce counter=1 (domain sequence in process)"
      ],
      "decodable": true,
      "nonce_analysis": {
        "nonce_timestamp": "2021-09-26T18:07:56Z",
        "nonce_counter": 1,
        "session_age": "2 seconds",
        "session_age_secs": 2,
        "domain_sequence": 1,
        "timestamp_reliable": true,
        "commentary": [
          "session_age=2 seconds: short client session",
          "nonce_counter=1: first domain generated in this process"
        ]
      }
    },
    "nonce_timestamp": "2021-09-26T18:07:56Z",
    "nonce_counter": 1
  }
]
```

**Campaign analysis output (Markdown):**
```markdown
# OAST Campaign Analysis

## Executive Summary

Analysis of 15 domains across 3 campaigns spanning 2.2 days.
Found 2 machine IDs and 1 PIDs. Classification: v1.0.1 (15).

## Overall Statistics
- **Total Domains Found:** 15
- **Valid Domains:** 15
- **Unique Campaigns:** 3
- **Unique Machine IDs:** 2
- **Unique PIDs:** 1

## Session Analytics

v1.0.1 nonce-derived session data:

**Campaign `he008`:**
- Nonce Timestamp Range: 2024-01-15T10:30:45Z to 2024-01-15T15:02:12Z
- Session Age Range: 2s to 16200s
- Domain Generation Velocity: 1.8 domains/hour

## Campaign Details

### Campaign: `he008`
- **Count:** 8 domains
- **Duration:** 4.5 hours
- **Counter Range:** 5678 - 5801
- **Machine IDs (1):** `12:34:56`
- **PIDs (1):** `1234`

Campaign he008 was active for 4.5 hours across 1 machines, generating 8 domains.

## Timeline

Activity observed from 2024-01-15T10:30:45Z to 2024-01-17T14:22:33Z (2.2 days).
15 domains decoded across 3 campaigns from 2 unique machines.
```

## MCP Server

Start the Model Context Protocol stdio server:

```bash
roast mcp
```

**For detailed Claude Desktop configuration, see [CLAUDE_DESKTOP.md](CLAUDE_DESKTOP.md)**

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

#### Enhanced Live Intelligence Tools
- `fetch_interactsh_domains_live` - Live HTTP fetching of 400+ Interactsh domains with caching and conditional requests
- `fetch_burp_collaborator_domains_live` - Live HTTP fetching of Burp Collaborator domains with caching
- `check_domain_updates` - Efficient update checking using HEAD requests with ETag/Last-Modified support
- `validate_domain_advanced` - Advanced domain validation with attribution and threat intelligence context
- `validate_domain_batch_advanced` - Batch domain validation with statistics and organizational attribution
- `oast_cache_stats` - Cache statistics including TTL, performance metrics, and cleanup status

#### Legacy Threat Intelligence Tools
- `fetch_interactsh_domains` - Basic info about Interactsh domains (use live version for enhanced features)
- `fetch_burp_collaborator_domains` - Basic info about Burp Collaborator domains (use live version for enhanced features)  
- `oast_threat_intel` - Comprehensive threat intelligence context about OAST domains and infrastructure

### Enhanced Capabilities

#### Live Data Fetching
- **HTTP Client Integration**: Direct fetching from darses/cti GitHub repository
- **Conditional Requests**: Uses ETag and Last-Modified headers to minimize bandwidth
- **Error Handling**: Graceful fallback and detailed error reporting
- **User Agent**: Identifies as "roast/1.0.0 (OAST Domain Analyzer)"

#### Intelligent Caching
- **TTL-Based Caching**: 1-hour default TTL with configurable expiration
- **Content Hashing**: SHA256 hashing to detect actual content changes
- **Staleness Detection**: Early refresh when cache is 90% expired
- **Background Cleanup**: Automatic removal of expired entries every 15 minutes

#### Update Notifications
- **Change Detection**: Tracks ETag, Last-Modified, and content hashes
- **Efficient Checking**: HEAD requests to check for updates without downloading
- **Update Alerts**: Notifications when external lists are updated
- **Cache Statistics**: Detailed metrics on cache performance and hit rates

#### Advanced Domain Validation
- **Multi-Source Validation**: Cross-references built-in + 400+ external domains
- **Attribution Engine**: Identifies organizational ownership (NetSPI, Rapid7, researchers)
- **Threat Classification**: Distinguishes legitimate testing from potential threats
- **Confidence Scoring**: High/medium/low confidence levels for validation results
- **Batch Processing**: Validate multiple domains with summary statistics

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

## Web UI

Start the web interface for interactive domain analysis:

```bash
# Start on default port (8080)
roast serve

# Custom address and port
roast serve --addr 0.0.0.0 --port 9090
```

The web UI provides:
- **Paste or upload** — paste domains directly or drag-and-drop CSV files
- **Decode / Classify / Extract / Analyze** — all CLI capabilities in the browser
- **Classification badges** — visual indicators for client type (CLI/web), server version (v1.0.1/v1.0.2+), and confidence (high/medium/low)
- **Nonce analysis display** — decoded timestamps, counters, session age, and commentary
- **Save CSV** — export any result set as a CSV file
- **Download Report** — download campaign analysis as a markdown report

## Domain Classification

`roast` classifies OAST domains by **client type** and **server version** using character-set heuristics and nonce analysis.

### Client Type Detection

| Client | Signal | Confidence |
|--------|--------|------------|
| **CLI** | Preamble contains digits `[0-9]` (base32hex) | High |
| **Web** | Preamble contains `[w-z]` (outside base32hex) | High |
| **Unknown** | Preamble is all `[a-v]` (ambiguous) | Low |

### Server Version Detection

| Version | Signal | Confidence |
|---------|--------|------------|
| **v1.0.1** | Nonce zbase32-decodes to valid timestamp (2020-2030) | High |
| **v1.0.1** | Valid timestamp but in the future | Medium |
| **v1.0.1** | Valid timestamp but predates CID by >5 min | Low |
| **v1.0.2+** | Nonce decodes to out-of-range timestamp | Medium |
| **Unknown** | Nonce contains non-zbase32 chars (`l/v/0/2`) | High (web nonce) |

### Nonce Analysis (v1.0.1)

When a v1.0.1 nonce is detected, `roast` extracts:
- **Nonce timestamp** — when the domain was generated (promoted to top-level JSON field when reliable)
- **Nonce counter** — domain sequence number within the process
- **Session age** — time between CID creation and domain generation
- **Commentary** — automated analysis (startup domain, long session, high-volume generation, etc.)
- **Timestamp reliability** — flagged as unreliable when future or predating CID

### Cross-Reference Validation

When decoding multiple domains in a batch, `roast` cross-references v1.0.1 classifications across domains sharing the same machine ID:
- **All consistent** — confidence upgraded, domains corroborate each other
- **Mixed versions** — warning added that some classifications may be unreliable
- **Single domain** — no corroboration possible, classification stands as-is

## Library Usage

### Core Types

```go
// DecodedOAST contains the decoded metadata from an OAST domain
type DecodedOAST struct {
    Original       string          // Original subdomain/FQDN
    Timestamp      time.Time       // Decoded timestamp
    MachineID      string          // Format: "xx:xx:xx" (3 hex bytes)
    PID            uint16          // Process ID
    Counter        uint32          // Counter value (24-bit)
    Nonce          string          // The nonce portion (if present)
    KSort          string          // First 6 chars of preamble (for K-sorting)
    Campaign       string          // Chars 7-11 of preamble (campaign identifier)
    Valid          bool            // Whether decoding succeeded
    Error          string          // Error message if invalid
    Classification *Classification // Client type, server version, and nonce analysis
    NonceTimestamp *time.Time      // Promoted from nonce analysis (when reliable)
    NonceCounter   *uint32         // Promoted from nonce analysis (when reliable)
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

For comprehensive OAST domain coverage, `roast` provides **live access** to actively maintained threat intelligence lists:

- **552+ Interactsh domains:** [darses/cti interactsh-domains.txt](https://github.com/darses/cti/blob/main/interactsh-domains.txt) - Live HTTP fetching with caching
- **316+ Burp Collaborator domains:** [darses/cti burpsuite-domains.txt](https://github.com/darses/cti/blob/main/burpsuite-domains.txt) - Live HTTP fetching with caching

These lists are maintained by [darses](https://github.com/darses) and updated regularly through automated Shodan queries:

**Interactsh Discovery:**
- `product:"Interactsh SMTP Server" port:25`
- `http.html:"<h1> Interactsh Server </h1>"`

**Burp Collaborator Discovery:**
- `port:25 "Burp Collaborator Server ready"`

**Enhanced Features:**
- **Live HTTP Fetching**: Real-time access to current domain lists
- **Intelligent Caching**: 1-hour TTL with conditional requests (ETag/Last-Modified)
- **Update Detection**: Automatic notifications when lists change
- **Attribution Engine**: Identifies organizational ownership (NetSPI, Rapid7, researchers)
- **Advanced Validation**: Cross-references 868+ total domains for threat intelligence

**Note:** `roast` will attempt to decode any domain matching the Interactsh preamble format, regardless of suffix. The enhanced validation provides attribution context for threat intelligence correlation.

## Use Cases

- **Threat Intelligence:** Correlate OAST callbacks across different security events with attribution context
- **Campaign Tracking:** Identify related scanning activities by machine ID and campaign identifier
- **Forensics:** Extract timestamps and source information from OAST domains found in logs
- **Security Research:** Analyze Interactsh usage patterns and scanning behaviors
- **Attribution Analysis:** Distinguish legitimate security testing (NetSPI, Rapid7) from potential threats
- **Infrastructure Monitoring:** Track new OAST deployments with real-time domain intelligence
- **Incident Response:** Validate OAST callbacks against known legitimate vs suspicious infrastructure

## Key Accomplishments

### Enterprise-Grade Intelligence
- **868+ Total Domains**: 8 built-in + 552 Interactsh + 316 Burp Collaborator domains
- **Live Data Fetching**: Real-time HTTP access to darses/cti repository
- **Intelligent Caching**: Sub-second response times with 1-hour TTL
- **Attribution Engine**: Automated organizational identification and threat classification

### Performance & Reliability
- **100% Cache Hit Rate**: For requests within TTL window
- **Conditional Requests**: ETag and Last-Modified optimization
- **Background Processing**: Automatic cache cleanup every 15 minutes
- **Thread-Safe Design**: Full concurrent access support

### Advanced Capabilities
- **Update Notifications**: Automatic detection when external lists change
- **Batch Processing**: Validate multiple domains with comprehensive statistics
- **Confidence Scoring**: High/medium/low confidence levels for validation results
- **Threat Context**: Distinguish security companies, researchers, and potential threats

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

## Acknowledgements

This update was produced by **John Jarocki** ([@jarocki](https://github.com/jarocki)) and
[Claude Code](https://claude.ai/claude-code). It couldn't have been done without this
village of folks — I am eternally grateful for this amazing collaboration.

- **Bob Rudis** ([@hrbrmstr](https://github.com/hrbrmstr)) — Creator of the original
  [roast](https://codeberg.org/hrbrmstr/go-roast) and
  [roast-mcp](https://codeberg.org/hrbrmstr/roast-mcp) codebase. His work on OAST domain
  decoding and MCP server integration forms the foundation of this project.
- **Ian Campbell** — For collaboration and discussion on OAST domain analysis techniques,
  discussed on Mastodon at the beginning of 2026.
- **darses** ([@darses](https://github.com/darses)) — For the tireless work maintaining
  [darses/cti](https://github.com/darses/cti), the actively curated lists of Interactsh and
  Burp Collaborator domains that power roast's live threat intelligence capabilities.
- **Claude System** by **Juan Andres Guerrero-Sade** ([@JAGS](https://github.com/JAGS)) —
  The [Claude Code Config](https://github.com/anthropics/claude-code) harness was instrumental
  in orchestrating this update, providing the agent infrastructure, hooks, and workflow
  guardrails that made a multi-issue implementation like this possible.

## License

MIT
