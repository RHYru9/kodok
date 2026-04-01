package cache

import (
    "fmt"
    "sync"

    lru "github.com/hashicorp/golang-lru"
)

// Deduplicator provides thread-safe URL deduplication using LRU cache
type Deduplicator struct {
    cache *lru.Cache
    mu    sync.RWMutex
}

// NewDeduplicator creates a new deduplicator with the specified maximum size.
// Panics if maxSize is invalid (lru.New only fails with size <= 0, which is
// prevented by config validation requiring size >= 100).
func NewDeduplicator(maxSize int) *Deduplicator {
    cache, err := lru.New(maxSize)
    if err != nil {
        panic(fmt.Sprintf("failed to create LRU cache with size %d: %v", maxSize, err))
    }

    return &Deduplicator{
        cache: cache,
    }
}

// CheckAndAdd checks if a URL has been processed and adds it if not.
// Returns true if the URL was already processed (duplicate).
func (d *Deduplicator) CheckAndAdd(url string) bool {
    // Fast path: read lock
    d.mu.RLock()
    if d.cache.Contains(url) {
        d.mu.RUnlock()
        return true
    }
    d.mu.RUnlock()

    // Slow path: write lock with double-check
    d.mu.Lock()
    defer d.mu.Unlock()

    if d.cache.Contains(url) {
        return true
    }

    d.cache.Add(url, struct{}{})
    return false
}

// Contains checks if a URL has been processed without adding it.
func (d *Deduplicator) Contains(url string) bool {
    d.mu.RLock()
    defer d.mu.RUnlock()
    return d.cache.Contains(url)
}

// Len returns the number of items in the cache.
func (d *Deduplicator) Len() int {
    d.mu.RLock()
    defer d.mu.RUnlock()
    return d.cache.Len()
}

// Purge clears the cache.
func (d *Deduplicator) Purge() {
    d.mu.Lock()
    defer d.mu.Unlock()
    d.cache.Purge()
}