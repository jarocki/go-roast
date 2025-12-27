# Claude Desktop MCP Server Configuration

This guide explains how to configure the `roast` MCP server with Claude Desktop to enable intelligent OAST domain analysis.

## Prerequisites

1. Build the roast binary:
   ```bash
   go build -o roast ./cmd/roast
   ```

2. Note the full path to the binary:
   ```bash
   pwd
   # Example: /Users/username/projects/go-roast
   ```

## Configuration

### Step 1: Locate Claude Desktop Config

Open the Claude Desktop configuration file:

**macOS:**
```
~/Library/Application Support/Claude/claude_desktop_config.json
```

**Windows:**
```
%APPDATA%\Claude\claude_desktop_config.json
```

**Linux:**
```
~/.config/Claude/claude_desktop_config.json
```

### Step 2: Add MCP Server Configuration

Add the roast server to your configuration:

```json
{
  "mcpServers": {
    "roast": {
      "command": "/full/path/to/roast",
      "args": ["mcp"]
    }
  }
}
```

**Example (macOS):**
```json
{
  "mcpServers": {
    "roast": {
      "command": "/Users/hrbrmstr/projects/go-roast/roast",
      "args": ["mcp"]
    }
  }
}
```

### Step 3: Restart Claude Desktop

Completely quit and restart Claude Desktop for the configuration to take effect.

## Using the MCP Server

### Loading the OAST Expert Prompt

In any conversation, type:
```
/oast-expert
```

This loads comprehensive OAST domain knowledge including:
- Domain structure and encoding specifications
- Decoding algorithms with byte-level details
- Campaign analysis techniques
- Machine ID derivation across platforms
- Version detection patterns
- Threat intelligence correlation strategies
- Analysis best practices

### Available Tools

Once the server is configured, you have access to these tools:

1. **decode_oast** - Decode OAST domains to extract metadata
   ```
   Can you decode c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro?
   ```

2. **extract_oast** - Find OAST domains in text
   ```
   Extract all OAST domains from this log file: /path/to/logs.txt
   ```

3. **extract_oast_file** - Extract domains from a file
   ```
   Find OAST domains in /var/log/dns.log
   ```

4. **validate_oast** - Check if a domain is valid
   ```
   Is this a valid OAST domain: abc123xyz.oast.pro?
   ```

5. **oast_campaign_analysis** - Analyze campaigns
   ```
   Analyze the OAST domains in domains.txt and show me campaign patterns
   ```

## Example Usage

### Basic Domain Analysis

```
User: /oast-expert

User: I found this domain in my logs: c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro
What can you tell me about it?

Claude: [Uses decode_oast tool and provides expert analysis based on the
loaded knowledge base, including timestamp, machine ID, campaign correlation,
version detection, and threat intelligence context]
```

### Campaign Investigation

```
User: /oast-expert

User: I have a file with multiple OAST domains from a security incident.
Can you analyze them for campaign patterns?
File: /tmp/incident_domains.txt

Claude: [Uses oast_campaign_analysis tool to generate comprehensive report
with correlations, timelines, machine tracking, and threat intelligence]
```

### Log Analysis

```
User: /oast-expert

User: Search through this Apache access log and find any OAST callbacks:
/var/log/apache2/access.log

Claude: [Uses extract_oast_file to find domains, then provides context
about what they mean and potential security implications]
```

## Prompt Content Preview

The `oast-expert` prompt provides ~5,200 characters of expert context including:

### Domain Structure
- Complete breakdown of the 20-character preamble
- Base32hex encoding specification (alphabet: 0-9, a-v)
- z-base-32 nonce encoding (alphabet: ybndrfg8ejkmcpqxot1uwisza345h769)
- 12-byte XID field layout with big-endian byte ordering

### Decoding Details
- Timestamp extraction (bytes 0-3, unix epoch)
- Machine ID format (bytes 4-6, platform UUID hash)
- Process ID (bytes 7-8)
- Counter values (bytes 9-11, 24-bit)
- K-sort identifier (chars 1-6, timestamp-sortable)
- Campaign ID (chars 7-11, for grouping)

### Platform-Specific Details
- Linux: `/etc/machine-id` or `/sys/class/dmi/id/product_uuid`
- Windows: `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`
- macOS: `sysctl kern.uuid`
- FreeBSD: `sysctl kern.hostuuid`

### Analysis Techniques
- Campaign correlation by shared campaign IDs
- Machine tracking via 3-byte machine identifiers
- Temporal analysis using K-sort values
- Counter progression monitoring for velocity
- Version detection via 'y' pattern in nonces

### Known Domains
Complete list of OAST domain suffixes:
- oast.pro, oast.live, oast.site
- oast.online, oast.fun, oast.me
- interact.sh, interactsh.com

## Troubleshooting

### Server Not Appearing

1. Check the config file is valid JSON
2. Verify the path to the roast binary is correct
3. Ensure the binary is executable: `chmod +x /path/to/roast`
4. Check Claude Desktop logs (Help → View Logs)

### Tools Not Working

1. Restart Claude Desktop completely
2. Test the MCP server manually:
   ```bash
   /path/to/roast mcp
   # Should start without errors and wait for input
   ```
3. Check for Go dependencies: `go mod tidy`

### Prompt Not Loading

1. Type exactly `/oast-expert` (with the slash)
2. Wait for the prompt to load (may take a moment)
3. Check that prompt capabilities are enabled in the server

## Advanced Configuration

### Running from $PATH

If roast is in your PATH:

```json
{
  "mcpServers": {
    "roast": {
      "command": "roast",
      "args": ["mcp"]
    }
  }
}
```

### Adding Environment Variables

```json
{
  "mcpServers": {
    "roast": {
      "command": "/path/to/roast",
      "args": ["mcp"],
      "env": {
        "CUSTOM_VAR": "value"
      }
    }
  }
}
```

## Support

For issues or questions:
- Repository: https://codeberg.org/hrbrmstr/go-roast
- Issues: https://codeberg.org/hrbrmstr/go-roast/issues

## References

- [MCP Specification](https://spec.modelcontextprotocol.io/)
- [Claude Desktop Documentation](https://claude.ai/docs)
- [Interactsh Project](https://github.com/projectdiscovery/interactsh)
