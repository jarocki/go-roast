package mcp

import (
	"sync"
	"time"
)

// CacheEntry represents a cached item with TTL and metadata
type CacheEntry struct {
	Data         []string  `json:"data"`
	LastFetched  time.Time `json:"last_fetched"`
	LastModified string    `json:"last_modified,omitempty"` // HTTP Last-Modified header
	ETag         string    `json:"etag,omitempty"`          // HTTP ETag header
	ContentHash  string    `json:"content_hash"`            // SHA256 hash of content
	URL          string    `json:"url"`
	TTL          time.Duration `json:"ttl"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// IsExpired checks if the cache entry has expired
func (e *CacheEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// IsStale checks if the cache entry is nearing expiration (within 10% of TTL)
func (e *CacheEntry) IsStale() bool {
	staleThreshold := e.ExpiresAt.Add(-time.Duration(float64(e.TTL) * 0.1))
	return time.Now().After(staleThreshold)
}

// DomainCache manages cached domain lists with TTL
type DomainCache struct {
	mu      sync.RWMutex
	entries map[string]*CacheEntry
	defaultTTL time.Duration
}

// NewDomainCache creates a new domain cache with default TTL
func NewDomainCache(defaultTTL time.Duration) *DomainCache {
	return &DomainCache{
		entries:    make(map[string]*CacheEntry),
		defaultTTL: defaultTTL,
	}
}

// Get retrieves a cache entry by key
func (c *DomainCache) Get(key string) (*CacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return nil, false
	}

	if entry.IsExpired() {
		// Don't delete here, let cleanup handle it
		return nil, false
	}

	return entry, true
}

// Set stores a cache entry with the specified TTL
func (c *DomainCache) Set(key string, data []string, url string, lastModified, etag, contentHash string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ttl == 0 {
		ttl = c.defaultTTL
	}

	c.entries[key] = &CacheEntry{
		Data:         data,
		LastFetched:  time.Now(),
		LastModified: lastModified,
		ETag:         etag,
		ContentHash:  contentHash,
		URL:          url,
		TTL:          ttl,
		ExpiresAt:    time.Now().Add(ttl),
	}
}

// GetAll returns all non-expired cache entries
func (c *DomainCache) GetAll() map[string]*CacheEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]*CacheEntry)
	now := time.Now()

	for key, entry := range c.entries {
		if !now.After(entry.ExpiresAt) {
			result[key] = entry
		}
	}

	return result
}

// HasUpdated checks if a cache entry needs updating based on HTTP headers
func (c *DomainCache) HasUpdated(key, lastModified, etag string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return true // No cache entry, consider it updated
	}

	// Check ETag first (more reliable)
	if etag != "" && entry.ETag != "" {
		return entry.ETag != etag
	}

	// Fall back to Last-Modified
	if lastModified != "" && entry.LastModified != "" {
		return entry.LastModified != lastModified
	}

	// If we can't compare, assume it might be updated
	return true
}

// HasContentChanged checks if the content hash has changed
func (c *DomainCache) HasContentChanged(key, contentHash string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return true
	}

	return entry.ContentHash != contentHash
}

// Delete removes a cache entry
func (c *DomainCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, key)
}

// Cleanup removes expired entries
func (c *DomainCache) Cleanup() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0

	for key, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, key)
			removed++
		}
	}

	return removed
}

// Stats returns cache statistics
func (c *DomainCache) Stats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()
	valid := 0
	expired := 0
	stale := 0

	for _, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			expired++
		} else if entry.IsStale() {
			stale++
			valid++
		} else {
			valid++
		}
	}

	return map[string]interface{}{
		"total_entries":   len(c.entries),
		"valid_entries":   valid,
		"expired_entries": expired,
		"stale_entries":   stale,
		"default_ttl":     c.defaultTTL.String(),
	}
}

// GetStaleEntries returns entries that are nearing expiration
func (c *DomainCache) GetStaleEntries() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var stale []string
	for key, entry := range c.entries {
		if !entry.IsExpired() && entry.IsStale() {
			stale = append(stale, key)
		}
	}

	return stale
}

// Global cache instance with 1 hour default TTL
var globalDomainCache = NewDomainCache(1 * time.Hour)

// GetGlobalCache returns the global domain cache instance
func GetGlobalCache() *DomainCache {
	return globalDomainCache
}

// Cache keys for different domain lists
const (
	CacheKeyInteractshDomains = "interactsh_domains"
	CacheKeyBurpCollaborator  = "burp_collaborator"
)

// StartCacheCleanup starts a background goroutine to clean up expired entries
func StartCacheCleanup(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			globalDomainCache.Cleanup()
		}
	}()
}
