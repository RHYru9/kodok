package fetch

import (
    "context"
    "fmt"
    "io"
    "net/http"
    "strings"
    "time"
)

// Fetcher handles HTTP requests with retry logic
type Fetcher struct {
    client        *http.Client
    filter        *ContentFilter
    retryAttempts int
    userAgent     string
}

// NewFetcher creates a new fetcher
func NewFetcher(timeout time.Duration, retryAttempts int) *Fetcher {
    return &Fetcher{
        client: &http.Client{
            Timeout: timeout,
            Transport: &http.Transport{
                MaxIdleConns:        100,
                MaxIdleConnsPerHost: 10,
                IdleConnTimeout:     90 * time.Second,
            },
        },
        filter:        NewContentFilter(),
        retryAttempts: retryAttempts,
        userAgent:     "KODOK-Scanner/1.0",
    }
}

// FetchResult represents the result of a fetch operation
type FetchResult struct {
    Content    string
    StatusCode int
    Headers    http.Header
}

// FetchWithRetry fetches a URL with retry logic
func (f *Fetcher) FetchWithRetry(url string, customHeaders map[string]string) (string, int, error) {
    var lastErr error
    
    for attempt := 0; attempt <= f.retryAttempts; attempt++ {
        if attempt > 0 {
            // Exponential backoff: 1s, 2s, 4s, etc.
            backoff := time.Duration(1<<uint(attempt-1)) * time.Second
            time.Sleep(backoff)
        }
        
        content, statusCode, err := f.fetch(url, customHeaders)
        if err == nil {
            return content, statusCode, nil
        }
        
        lastErr = err
        
        // Don't retry on permanent errors
        if f.isPermanentError(err) {
            break
        }
    }
    
    return "", 0, fmt.Errorf("after %d attempts: %w", f.retryAttempts, lastErr)
}

// fetch performs a single HTTP request
func (f *Fetcher) fetch(url string, customHeaders map[string]string) (string, int, error) {
    ctx, cancel := context.WithTimeout(context.Background(), f.client.Timeout)
    defer cancel()
    
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return "", 0, fmt.Errorf("creating request: %w", err)
    }
    
    // Set headers
    req.Header.Set("User-Agent", f.userAgent)
    req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    req.Header.Set("Accept-Language", "en-US,en;q=0.5")
    req.Header.Set("Accept-Encoding", "gzip")
    req.Header.Set("Connection", "close")
    
    // Add custom headers
    for key, value := range customHeaders {
        req.Header.Set(key, value)
    }
    
    resp, err := f.client.Do(req)
    if err != nil {
        return "", 0, fmt.Errorf("HTTP request: %w", err)
    }
    defer resp.Body.Close()
    
    // Check status code
    if resp.StatusCode < 200 || resp.StatusCode >= 400 {
        return "", resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
    }
    
    // Read and filter content
    content, err := f.filter.ReadAndFilter(resp.Body, resp.Header)
    if err != nil {
        return "", resp.StatusCode, fmt.Errorf("reading content: %w", err)
    }
    
    // Check content size
    if len(content) > 50*1024*1024 { // 50MB limit
        return "", resp.StatusCode, fmt.Errorf("content too large: %d bytes", len(content))
    }
    
    return content, resp.StatusCode, nil
}

// isPermanentError checks if an error is permanent (should not retry)
func (f *Fetcher) isPermanentError(err error) bool {
    if err == nil {
        return false
    }
    
    errorStr := err.Error()
    
    // Permanent errors
    permanentPatterns := []string{
        "404", "410", // Not Found, Gone
        "401", "403", // Unauthorized, Forbidden
        "405", // Method Not Allowed
        "501", // Not Implemented
        "unsupported protocol scheme",
        "no such host",
        "certificate",
    }
    
    for _, pattern := range permanentPatterns {
        if strings.Contains(errorStr, pattern) {
            return true
        }
    }
    
    return false
}

// SetUserAgent sets a custom User-Agent string
func (f *Fetcher) SetUserAgent(ua string) {
    f.userAgent = ua
}