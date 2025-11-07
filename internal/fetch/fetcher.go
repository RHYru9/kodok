package fetch

import (
    "context"
    "fmt"
    "net"
    "net/http"
    "net/url"
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
func (f *Fetcher) FetchWithRetry(urlStr string, customHeaders map[string]string) (string, int, error) {
    // SSRF Protection: Validate URL before fetching
    if err := f.validateURL(urlStr); err != nil {
        return "", 0, fmt.Errorf("SSRF protection: %w", err)
    }
    
    var lastErr error
    
    for attempt := 0; attempt <= f.retryAttempts; attempt++ {
        if attempt > 0 {
            // Exponential backoff: 1s, 2s, 4s, etc.
            backoff := time.Duration(1<<uint(attempt-1)) * time.Second
            time.Sleep(backoff)
        }
        
        content, statusCode, err := f.fetch(urlStr, customHeaders)
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
func (f *Fetcher) fetch(urlStr string, customHeaders map[string]string) (string, int, error) {
    ctx, cancel := context.WithTimeout(context.Background(), f.client.Timeout)
    defer cancel()
    
    req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
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

// NEW: validateURL validates URL against SSRF attacks
func (f *Fetcher) validateURL(urlStr string) error {
    // Parse URL
    parsedURL, err := url.Parse(urlStr)
    if err != nil {
        return fmt.Errorf("invalid URL: %w", err)
    }
    
    // Check scheme
    if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
        return fmt.Errorf("unsupported scheme: %s (only http/https allowed)", parsedURL.Scheme)
    }
    
    // Extract host (without port)
    host := parsedURL.Hostname()
    if host == "" {
        return fmt.Errorf("empty host")
    }
    
    // Check if host is safe
    if !isSafeHost(host) {
        return fmt.Errorf("blocked host: %s (internal/private address)", host)
    }
    
    return nil
}

// NEW: isSafeHost checks if a host is safe to connect to (SSRF protection)
func isSafeHost(host string) bool {
    // Normalize host
    host = strings.ToLower(strings.TrimSpace(host))
    
    // Block dangerous domains/IPs
    dangerousDomains := []string{
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "169.254.169.254",           // AWS metadata
        "metadata.google.internal",  // GCP metadata
        "metadata.azure.com",        // Azure metadata
        "kubernetes.default.svc",    // Kubernetes API
        "rancher-metadata",          // Rancher metadata
    }
    
    for _, dangerous := range dangerousDomains {
        if host == dangerous {
            return false
        }
    }
    
    // Check for IP address
    if ip := net.ParseIP(host); ip != nil {
        // Block loopback addresses (127.0.0.0/8, ::1)
        if ip.IsLoopback() {
            return false
        }
        
        // Block private addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
        if ip.IsPrivate() {
            return false
        }
        
        // Block link-local addresses (169.254.0.0/16, fe80::/10)
        if ip.IsLinkLocalUnicast() {
            return false
        }
        
        // Block multicast addresses
        if ip.IsMulticast() {
            return false
        }
        
        // Block unspecified addresses (0.0.0.0, ::)
        if ip.IsUnspecified() {
            return false
        }
        
        // ENHANCED: Block additional dangerous IP ranges
        // Block 0.0.0.0/8 (current network)
        if ip.To4() != nil && ip.To4()[0] == 0 {
            return false
        }
        
        // Block 100.64.0.0/10 (Carrier-grade NAT)
        if ip.To4() != nil && ip.To4()[0] == 100 && (ip.To4()[1]&0xC0) == 64 {
            return false
        }
        
        // Block 192.0.0.0/24 (IETF Protocol Assignments)
        if ip.To4() != nil && ip.To4()[0] == 192 && ip.To4()[1] == 0 && ip.To4()[2] == 0 {
            return false
        }
        
        // Block 192.0.2.0/24 (TEST-NET-1)
        if ip.To4() != nil && ip.To4()[0] == 192 && ip.To4()[1] == 0 && ip.To4()[2] == 2 {
            return false
        }
        
        // Block 198.18.0.0/15 (Benchmarking)
        if ip.To4() != nil && ip.To4()[0] == 198 && (ip.To4()[1] == 18 || ip.To4()[1] == 19) {
            return false
        }
        
        // Block 198.51.100.0/24 (TEST-NET-2)
        if ip.To4() != nil && ip.To4()[0] == 198 && ip.To4()[1] == 51 && ip.To4()[2] == 100 {
            return false
        }
        
        // Block 203.0.113.0/24 (TEST-NET-3)
        if ip.To4() != nil && ip.To4()[0] == 203 && ip.To4()[1] == 0 && ip.To4()[2] == 113 {
            return false
        }
        
        // Block 240.0.0.0/4 (Reserved)
        if ip.To4() != nil && (ip.To4()[0]&0xF0) == 240 {
            return false
        }
    }
    
    // ENHANCED: Block suspicious domain patterns
    suspiciousPatterns := []string{
        ".local",
        ".internal",
        ".localhost",
        ".localdomain",
        ".lan",
        ".home",
        ".corp",
        ".intranet",
    }
    
    for _, pattern := range suspiciousPatterns {
        if strings.HasSuffix(host, pattern) {
            return false
        }
    }
    
    return true
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
        "SSRF protection", // Don't retry SSRF-blocked URLs
        "blocked host",    //NEW
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