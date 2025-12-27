# roast

A Go library, CLI tool, and stdio MCP server for processing Interactsh OAST (Out-of-band Application Security Testing) domains.

## Overview

`roast` decodes metadata embedded in Interactsh OAST domain names. These domains encode a 12-byte XID preamble containing timestamp, machine ID, process ID, and counter values that can be used for threat intelligence correlation and campaign tracking.

## Installation

```bash
go install github.com/hrbrmstr/go-roast/cmd/roast@latest
```

Or build from source:

```bash
git clone https://github.com/hrbrmstr/go-roast
cd go-roast
go build -o roast ./cmd/roast
```

## CLI Usage

### Decode OAST domains

```bash
# Decode from stdin
echo "c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro" | roast decode

# Decode from file (one domain per line)
roast decode -f domains.txt

# Output as CSV
roast decode -f domains.txt -o csv

# Output as table
roast decode -f domains.txt -o table
```

### Extract OAST domains from text

```bash
# Extract from file
roast extract -f logfile.txt

# Extract and decode in one step
roast extract -f logfile.txt --decode

# Extract from stdin
cat logs.txt | roast extract --decode -o json
```

### Example Output

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

## MCP Server

Start the Model Context Protocol stdio server:

```bash
roast mcp
```

### Resources

- `oast://info` - Overview of OAST domains and their structure
- `oast://format` - Detailed format specification including encoding details
- `oast://domains` - List of known OAST domain suffixes

### Tools

- `decode_oast` - Decode one or more OAST domains
- `extract_oast` - Extract OAST domains from text
- `extract_oast_file` - Extract OAST domains from a file
- `validate_oast` - Check if a string is a valid OAST domain

### MCP Configuration

Add to your Claude Desktop config:

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

## Library Usage

```go
import "github.com/hrbrmstr/go-roast/pkg/roast"

// Decode a single domain
decoded, err := roast.Decode("c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Timestamp: %s\n", decoded.Timestamp)
fmt.Printf("Machine ID: %s\n", decoded.MachineID)
fmt.Printf("PID: %d\n", decoded.PID)
fmt.Printf("Counter: %d\n", decoded.Counter)

// Extract domains from text
matches := roast.ExtractFromString("Found: c58bduhe008dovpvhvug.oast.pro")
for _, match := range matches {
    fmt.Printf("Found: %s at position %d\n", match.Full, match.StartIndex)
}

// Extract and decode
text := "Logs contain c58bduhe008dovpvhvug.oast.pro"
matches, decoded := roast.ExtractAndDecode(text)
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

- oast.pro
- oast.live
- oast.site
- oast.online
- oast.fun
- oast.me
- interact.sh
- interactsh.com

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

## License

MIT
