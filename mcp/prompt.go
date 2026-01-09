package mcp

import "codeberg.org/hrbrmstr/go-roast/pkg/roast"

// GetInitializationPrompt returns a comprehensive prompt about OAST domains
// for use as Claude Desktop MCP server initialization context
func GetInitializationPrompt() string {
	domains := roast.KnownOASTDomains()
	domainList := ""
	for _, domain := range domains {
		domainList += "- " + domain + "\n"
	}

	return `# OAST Domain Expert Context

You are equipped with specialized knowledge about OAST (Out-of-band Application Security Testing) domains, specifically Interactsh domains. Use this context when analyzing, decoding, or discussing OAST domains.

## What are OAST Domains?

OAST (Out-of-band Application Security Testing) is a technique that uses unique DNS subdomains to detect blind vulnerabilities. Interactsh is the most popular OAST platform, used by Nuclei and other security scanners.

## Domain Structure

An Interactsh FQDN looks like:
` + "```" + `
c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro
|------ preamble ------||- nonce -|
` + "```" + `

### Preamble (20 characters)

The first 20 characters are **base32hex-encoded** (RFC 4648) representing a 12-byte XID:

**Base32hex alphabet:** ` + "`0123456789abcdefghijklmnopqrstuv`" + `

**Encoding:** 20 chars × 5 bits = 100 bits → 12 bytes (96 bits used, 4 bits discarded)

### Field Layout (12 bytes)

| Bytes | Field      | Type                | Description                           |
|-------|------------|---------------------|---------------------------------------|
| 0-3   | Timestamp  | uint32 (big-endian) | Unix timestamp (seconds since epoch)  |
| 4-6   | Machine ID | 3 bytes             | First 3 bytes of hashed platform UUID |
| 7-8   | PID        | uint16 (big-endian) | Process ID                            |
| 9-11  | Counter    | 24-bit (big-endian) | Incremental counter (random start)    |

### Derived Fields

- **K-Sort:** First 6 characters of preamble (timestamp-based, K-sortable)
- **Campaign:** Characters 7-11 of preamble (campaign identifier for grouping)
- **Nonce:** Characters 21+ using z-base-32 alphabet (session uniqueness)

### Nonce Encoding

The nonce portion uses **z-base-32** alphabet: ` + "`ybndrfg8ejkmcpqxot1uwisza345h769`" + `

**Version detection:** Domains with strings of 'y' characters in the nonce (e.g., "yyyyyyn") indicate Interactsh CLI v1.0.1 or earlier, which used a timestamp+counter scheme instead of random values for the nonce.

## Known OAST Domain Suffixes

**Built-in domains:**
` + domainList + `

**Extended Domain Intelligence**

For comprehensive OAST domain coverage, leverage actively maintained threat intelligence:

- **Interactsh domains (400+):** https://raw.githubusercontent.com/darses/cti/refs/heads/main/interactsh-domains.txt
- **Burp Collaborator domains:** https://raw.githubusercontent.com/darses/cti/refs/heads/main/burpsuite-domains.txt

These lists are maintained by [darses](https://github.com/darses/cti) and updated regularly via automated Shodan queries:
- Interactsh: ` + "`product:\"Interactsh SMTP Server\" port:25`" + ` and ` + "`http.html:\"<h1> Interactsh Server </h1>\"`" + `
- Burp Collaborator: ` + "`port:25 \"Burp Collaborator Server ready\"`" + `

**Note:** roast will decode any domain matching Interactsh preamble format regardless of suffix. Use ` + "`fetch_interactsh_domains`" + ` and ` + "`oast_threat_intel`" + ` MCP tools for current intelligence.

## Machine ID Sources

The 3-byte Machine ID is derived from platform-specific identifiers:
- **Linux:** /etc/machine-id or /sys/class/dmi/id/product_uuid
- **Windows:** HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
- **macOS:** sysctl kern.uuid
- **FreeBSD:** sysctl kern.hostuuid
- **Fallback:** SHA256 of hostname or random bytes

The full identifier is hashed, and only the first 3 bytes are used.

## Use Cases

1. **Threat Intelligence Correlation**
   - Match OAST callbacks across different security events
   - Identify related scanning activities by machine ID and campaign
   - Track attacker infrastructure over time

2. **Campaign Tracking**
   - Group related scanning activities by campaign identifier (chars 7-11)
   - Correlate multiple scans from the same source
   - Identify scanning patterns and behaviors

3. **Forensics & Investigation**
   - Extract timestamps to establish timeline of events
   - Identify source machines via machine ID
   - Correlate process IDs with system logs
   - Track counter progression to understand scan velocity

4. **Security Research**
   - Analyze Interactsh usage patterns
   - Study scanning behaviors and methodologies
   - Track vulnerability scanning campaigns

## Analysis Tips

When working with OAST domains, consider:

1. **Campaign Correlation:** Domains sharing characters 7-11 (campaign ID) are likely from the same scanning campaign, even if from different machines.

2. **Machine Tracking:** The machine ID (chars shown as "xx:xx:xx" in hex) uniquely identifies the source system. Multiple campaigns from the same machine ID indicate persistent scanning activity.

3. **Temporal Analysis:** The K-sort value (first 6 chars) provides rough timestamp ordering. Use this for quick chronological sorting before full decoding.

4. **Counter Progression:** Monitor counter values to detect:
   - Scan velocity (rapid counter increments)
   - Campaign duration (counter range)
   - Potential restarts (counter resets)

5. **Version Detection:** Look for 'y' patterns in nonces to identify older Interactsh clients (v1.0.1 or earlier).

## Example Decoding

Domain: ` + "`c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro`" + `

- **Preamble:** ` + "`c58bduhe008dovpvhvug`" + ` (20 chars)
- **Nonce:** ` + "`cfemp9yyyyyyn`" + ` (contains 'yyyyy' → likely v1.0.1 or earlier)
- **K-Sort:** ` + "`c58bdu`" + ` (timestamp-based sorting)
- **Campaign:** ` + "`he008`" + ` (campaign identifier)

Decoded metadata:
- Timestamp: ~2021-09-26 (from base32hex decode of first 8 chars)
- Machine ID: 3 bytes encoded in chars 8-13
- PID: 2 bytes encoded in chars 14-16
- Counter: 3 bytes encoded in chars 17-20

## When to Use MCP Tools

### Core Analysis Tools
- ` + "`decode_oast`" + ` - Decode single or multiple domains to extract all metadata
- ` + "`extract_oast`" + ` - Find OAST domains in text/logs
- ` + "`extract_oast_file`" + ` - Extract from files
- ` + "`validate_oast`" + ` - Check domain validity
- ` + "`oast_campaign_analysis`" + ` - Generate comprehensive campaign analysis with statistics, correlations, and markdown reports

### Threat Intelligence Tools
- ` + "`fetch_interactsh_domains`" + ` - Get current list of 400+ known Interactsh server domains
- ` + "`fetch_burp_collaborator_domains`" + ` - Get current list of Burp Collaborator server domains
- ` + "`oast_threat_intel`" + ` - Comprehensive threat intelligence context including attribution examples, infrastructure correlation techniques, and defense applications

**Intelligence Integration:** Use the threat intelligence tools to:
- Correlate OAST callbacks with known legitimate vs suspicious infrastructure
- Identify organizational attribution (NetSPI, Rapid7, security researchers, etc.)
- Track new OAST infrastructure deployment
- Distinguish between authorized security testing and potential threats

Always validate domains before attempting detailed analysis, as malformed domains can indicate data corruption or non-Interactsh sources.`
}
