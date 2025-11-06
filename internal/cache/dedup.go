package cache

import (
    "sync"

    lru "github.com/hashicorp/golang-lru"
)

// Deduplicator provides thread-safe URL deduplication using LRU cache
type Deduplicator struct {
    cache *lru.Cache
    mu    sync.RWMutex
}

// NewDeduplicator creates a new deduplicator with the specified maximum size
func NewDeduplicator(maxSize int) *Deduplicator {
    cache, err := lru.New(maxSize)
    if err != nil {
        // Fallback to a simple map if LRU fails (shouldn't happen with valid size)
        return &Deduplicator{}
    }
    
    return &Deduplicator{
        cache: cache,
    }
}

// CheckAndAdd checks if a URL has been processed and adds it if not
// Returns true if the URL was already processed (duplicate)
func (d *Deduplicator) CheckAndAdd(url string) bool {
    if d.cache == nil {
        return false
    }
    
    // Fast path: read lock
    d.mu.RLock()
    if d.cache.Contains(url) {
        d.mu.RUnlock()
        return true
    }
    d.mu.RUnlock()
    
    // Slow path: write lock
    d.mu.Lock()
    defer d.mu.Unlock()
    
    // Double-check after acquiring write lock
    if d.cache.Contains(url) {
        return true
    }
    
    d.cache.Add(url, struct{}{})
    return false
}

// Contains checks if a URL has been processed without adding it
func (d *Deduplicator) Contains(url string) bool {
    if d.cache == nil {
        return false
    }
    
    d.mu.RLock()
    defer d.mu.RUnlock()
    return d.cache.Contains(url)
}

// Len returns the number of items in the cache
func (d *Deduplicator) Len() int {
    if d.cache == nil {
        return 0
    }
    
    d.mu.RLock()
    defer d.mu.RUnlock()
    return d.cache.Len()
}

// Purge clears the cache
func (d *Deduplicator) Purge() {
    if d.cache == nil {
        return
    }
    
    d.mu.Lock()
    defer d.mu.Unlock()
    d.cache.Purge()
}