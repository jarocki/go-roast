package roast

import (
	"bufio"
	"io"
	"os"
	"regexp"
	"strings"
)

// Pattern to match OAST domains in text
// Matches: subdomain (20+ base32hex chars + optional nonce) . known-domain
var oastPattern = regexp.MustCompile(
	`(?i)([a-v0-9]{20,}[a-z0-9_-]*)\.(oast\.(?:pro|live|site|online|fun|me)|interact\.sh|interactsh\.com)`,
)

// ExtractFromString finds all OAST domains in a string
func ExtractFromString(text string) []OASTMatch {
	matches := oastPattern.FindAllStringSubmatchIndex(text, -1)
	results := make([]OASTMatch, 0, len(matches))

	for _, match := range matches {
		if len(match) < 6 {
			continue
		}

		fullStart := match[0]
		fullEnd := match[1]
		subdomainStart := match[2]
		subdomainEnd := match[3]
		domainStart := match[4]
		domainEnd := match[5]

		results = append(results, OASTMatch{
			Full:       text[fullStart:fullEnd],
			Subdomain:  text[subdomainStart:subdomainEnd],
			Domain:     strings.ToLower(text[domainStart:domainEnd]),
			StartIndex: fullStart,
			EndIndex:   fullEnd,
		})
	}

	return results
}

// ExtractFromReader finds all OAST domains from an io.Reader
func ExtractFromReader(r io.Reader) ([]OASTMatch, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024) // 1MB max line size

	var results []OASTMatch
	offset := 0

	for scanner.Scan() {
		line := scanner.Text()
		matches := ExtractFromString(line)

		// Adjust indices to account for position in full stream
		for i := range matches {
			matches[i].StartIndex += offset
			matches[i].EndIndex += offset
		}

		results = append(results, matches...)
		offset += len(line) + 1 // +1 for newline
	}

	if err := scanner.Err(); err != nil {
		return results, err
	}

	return results, nil
}

// ExtractFromFile finds all OAST domains in a file
func ExtractFromFile(path string) ([]OASTMatch, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return ExtractFromReader(file)
}

// ExtractAndDecode extracts OAST domains from text and decodes them
func ExtractAndDecode(text string) ([]OASTMatch, []*DecodedOAST) {
	matches := ExtractFromString(text)
	decoded := make([]*DecodedOAST, len(matches))

	for i, match := range matches {
		decoded[i], _ = Decode(match.Full)
	}

	return matches, decoded
}

// ExtractAndDecodeFromReader extracts and decodes OAST domains from an io.Reader
func ExtractAndDecodeFromReader(r io.Reader) ([]OASTMatch, []*DecodedOAST, error) {
	matches, err := ExtractFromReader(r)
	if err != nil {
		return nil, nil, err
	}

	decoded := make([]*DecodedOAST, len(matches))
	for i, match := range matches {
		decoded[i], _ = Decode(match.Full)
	}

	return matches, decoded, nil
}

// ExtractAndDecodeFromFile extracts and decodes OAST domains from a file
func ExtractAndDecodeFromFile(path string) ([]OASTMatch, []*DecodedOAST, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	return ExtractAndDecodeFromReader(file)
}
