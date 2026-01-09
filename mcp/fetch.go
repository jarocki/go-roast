package mcp

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// FetchResult represents the result of fetching a domain list
type FetchResult struct {
	Domains      []string `json:"domains"`
	URL          string   `json:"url"`
	StatusCode   int      `json:"status_code"`
	LastModified string   `json:"last_modified,omitempty"`
	ETag         string   `json:"etag,omitempty"`
	ContentHash  string   `json:"content_hash"`
	FetchTime    time.Time `json:"fetch_time"`
	Size         int      `json:"size"`
	FromCache    bool     `json:"from_cache"`
	WasUpdated   bool     `json:"was_updated"`
	Error        string   `json:"error,omitempty"`
}

// HTTPFetcher handles HTTP requests with caching and conditional requests
type HTTPFetcher struct {
	client *http.Client
	cache  *DomainCache
}

// NewHTTPFetcher creates a new HTTP fetcher with timeout
func NewHTTPFetcher(timeout time.Duration) *HTTPFetcher {
	return &HTTPFetcher{
		client: &http.Client{
			Timeout: timeout,
		},
		cache: GetGlobalCache(),
	}
}

// FetchDomainList fetches a domain list from URL with caching and conditional requests
func (f *HTTPFetcher) FetchDomainList(url, cacheKey string) (*FetchResult, error) {
	// Check cache first
	if entry, exists := f.cache.Get(cacheKey); exists && !entry.IsExpired() {
		return &FetchResult{
			Domains:      entry.Data,
			URL:          entry.URL,
			ContentHash:  entry.ContentHash,
			FetchTime:    entry.LastFetched,
			Size:         len(entry.Data),
			FromCache:    true,
			LastModified: entry.LastModified,
			ETag:         entry.ETag,
		}, nil
	}

	// Prepare request with conditional headers
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add conditional request headers if we have cached data
	if entry, exists := f.cache.entries[cacheKey]; exists {
		if entry.ETag != "" {
			req.Header.Set("If-None-Match", entry.ETag)
		}
		if entry.LastModified != "" {
			req.Header.Set("If-Modified-Since", entry.LastModified)
		}
	}

	// Set user agent
	req.Header.Set("User-Agent", "roast/1.0.0 (OAST Domain Analyzer)")

	// Make the request
	resp, err := f.client.Do(req)
	if err != nil {
		return &FetchResult{
			URL:       url,
			FetchTime: time.Now(),
			Error:     fmt.Sprintf("HTTP request failed: %v", err),
		}, err
	}
	defer resp.Body.Close()

	result := &FetchResult{
		URL:          url,
		StatusCode:   resp.StatusCode,
		LastModified: resp.Header.Get("Last-Modified"),
		ETag:         resp.Header.Get("ETag"),
		FetchTime:    time.Now(),
	}

	// Handle 304 Not Modified
	if resp.StatusCode == http.StatusNotModified {
		if entry, exists := f.cache.Get(cacheKey); exists {
			result.Domains = entry.Data
			result.ContentHash = entry.ContentHash
			result.Size = len(entry.Data)
			result.FromCache = true
			result.WasUpdated = false
			return result, nil
		}
	}

	// Handle non-200 status codes
	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, resp.Status)
		return result, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Read and process the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to read response: %v", err)
		return result, err
	}

	// Parse domains from response
	domains, err := f.parseDomainList(string(body))
	if err != nil {
		result.Error = fmt.Sprintf("Failed to parse domain list: %v", err)
		return result, err
	}

	// Calculate content hash
	hasher := sha256.New()
	hasher.Write(body)
	contentHash := fmt.Sprintf("%x", hasher.Sum(nil))

	// Check if content actually changed
	wasUpdated := f.cache.HasContentChanged(cacheKey, contentHash)

	result.Domains = domains
	result.ContentHash = contentHash
	result.Size = len(domains)
	result.WasUpdated = wasUpdated

	// Update cache
	f.cache.Set(cacheKey, domains, url, result.LastModified, result.ETag, contentHash, 0)

	return result, nil
}

// parseDomainList parses a domain list from text content
func (f *HTTPFetcher) parseDomainList(content string) ([]string, error) {
	var domains []string
	scanner := bufio.NewScanner(strings.NewReader(content))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle domains that start with dot
		if strings.HasPrefix(line, ".") {
			line = line[1:]
		}

		// Basic domain validation
		if f.isValidDomainName(line) {
			domains = append(domains, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading content: %w", err)
	}

	return domains, nil
}

// isValidDomainName performs basic domain name validation
func (f *HTTPFetcher) isValidDomainName(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	// Check for valid characters and basic structure
	if strings.Contains(domain, "..") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}

	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		// Basic character check (simplified)
		for _, r := range part {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				 (r >= '0' && r <= '9') || r == '-') {
				return false
			}
		}
	}

	return true
}

// FetchInteractshDomains fetches the Interactsh domains list
func (f *HTTPFetcher) FetchInteractshDomains() (*FetchResult, error) {
	url := "https://raw.githubusercontent.com/darses/cti/refs/heads/main/interactsh-domains.txt"
	return f.FetchDomainList(url, CacheKeyInteractshDomains)
}

// FetchBurpCollaboratorDomains fetches the Burp Collaborator domains list
func (f *HTTPFetcher) FetchBurpCollaboratorDomains() (*FetchResult, error) {
	url := "https://raw.githubusercontent.com/darses/cti/refs/heads/main/burpsuite-domains.txt"
	return f.FetchDomainList(url, CacheKeyBurpCollaborator)
}

// CheckForUpdates checks if any cached domain lists have updates available
func (f *HTTPFetcher) CheckForUpdates() (map[string]*FetchResult, error) {
	results := make(map[string]*FetchResult)

	// Check Interactsh domains
	if result, err := f.checkSingleUpdate(
		"https://raw.githubusercontent.com/darses/cti/refs/heads/main/interactsh-domains.txt",
		CacheKeyInteractshDomains,
	); err == nil {
		results["interactsh"] = result
	}

	// Check Burp Collaborator domains
	if result, err := f.checkSingleUpdate(
		"https://raw.githubusercontent.com/darses/cti/refs/heads/main/burpsuite-domains.txt",
		CacheKeyBurpCollaborator,
	); err == nil {
		results["burp_collaborator"] = result
	}

	return results, nil
}

// checkSingleUpdate performs a HEAD request to check for updates
func (f *HTTPFetcher) checkSingleUpdate(url, cacheKey string) (*FetchResult, error) {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "roast/1.0.0 (OAST Domain Analyzer)")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	result := &FetchResult{
		URL:          url,
		StatusCode:   resp.StatusCode,
		LastModified: resp.Header.Get("Last-Modified"),
		ETag:         resp.Header.Get("ETag"),
		FetchTime:    time.Now(),
	}

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, resp.Status)
		return result, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Check if update is available
	result.WasUpdated = f.cache.HasUpdated(cacheKey, result.LastModified, result.ETag)

	return result, nil
}

// GetCacheStats returns statistics about the cache
func (f *HTTPFetcher) GetCacheStats() map[string]interface{} {
	return f.cache.Stats()
}

// Global fetcher instance
var globalFetcher = NewHTTPFetcher(30 * time.Second)

// GetGlobalFetcher returns the global HTTP fetcher instance
func GetGlobalFetcher() *HTTPFetcher {
	return globalFetcher
}
