package core

import (
    "context"
    "fmt"
    "net/url"
    "strings"
    "sync"
    "sync/atomic"
    "time"

    "github.com/fatih/color"
    "github.com/rhyru9/kodok/internal/cache"
    "github.com/rhyru9/kodok/internal/fetch"
    "github.com/rhyru9/kodok/internal/output"
    "github.com/rhyru9/kodok/internal/parse"
    "github.com/rhyru9/kodok/internal/scan"
    "github.com/rhyru9/kodok/pkg/types"
)

// Processor orchestrates the scanning process
type Processor struct {
    config     *types.Config
    workerPool *WorkerPool
    dedup      *cache.Deduplicator
    fetcher    *fetch.Fetcher
    parser     *parse.Extractor
    scanner    *scan.SecretScanner
    output     *output.Writer
    validator  *parse.Validator
    
    // Result collection
    resultsChan chan types.ScanResult
    results     []types.ScanResult
    resultsMu   sync.Mutex
    summary     *types.Summary
    
    // Task tracking - FIX: Track ALL tasks including recursive
    allTasks sync.WaitGroup
    
    // Progress tracking
    processedCount int32 // Use atomic
    totalURLs      int
    startTime      time.Time
    
    // Context for cancellation
    ctx    context.Context
    cancel context.CancelFunc
}

// NewProcessor creates a new processor
func NewProcessor(
    config *types.Config,
    workerPool *WorkerPool,
    dedup *cache.Deduplicator,
    fetcher *fetch.Fetcher,
    parser *parse.Extractor,
    scanner *scan.SecretScanner,
    output *output.Writer,
) *Processor {
    
    validator := parse.NewValidator()
    ctx, cancel := context.WithCancel(context.Background())
    
    return &Processor{
        config:      config,
        workerPool:  workerPool,
        dedup:       dedup,
        fetcher:     fetcher,
        parser:      parser,
        scanner:     scanner,
        output:      output,
        validator:   validator,
        resultsChan: make(chan types.ScanResult, 10000), // Increase buffer
        results:     make([]types.ScanResult, 0),
        summary: &types.Summary{
            StartTime: time.Now(),
        },
        ctx:    ctx,
        cancel: cancel,
    }
}

// ProcessURLs processes a list of URLs
func (p *Processor) ProcessURLs(urls []string) error {
    p.startTime = time.Now()
    p.totalURLs = len(urls)
    p.summary.TotalURLs = p.totalURLs
    
    color.Cyan("🐸 KODOK - JavaScript Security Scanner")
    color.Cyan("════════════════════════════════════════════")
    color.Cyan("[!] Starting scan of %d URLs", p.totalURLs)
    color.Cyan("[+] Workers: %d | Depth: %d | Cache: %d", 
        p.config.MaxWorkers, p.config.MaxDepth, p.config.CacheSize)
    if len(p.config.AllowedDomains) > 0 {
        color.Cyan("[+] Allowed Domains: %s", strings.Join(p.config.AllowedDomains, ", "))
    }
    color.Cyan("════════════════════════════════════════════\n")
    
    // Start result collector
    collectorDone := make(chan struct{})
    go p.collectResults(collectorDone)
    
    // Start progress reporter if verbose
    var progressDone chan struct{}
    if p.config.Verbose {
        progressDone = make(chan struct{})
        go p.reportProgress(progressDone)
    }
    
    // Submit URLs to worker pool
    submitted := 0
    for _, u := range urls {
        u := u // Capture for closure
        
        // FIX: Track this task
        p.allTasks.Add(1)
        
        if !p.workerPool.Submit(func() {
            defer p.allTasks.Done()
            result := p.processSingleURL(u, 0, "")
            
            // Send result safely
            select {
            case p.resultsChan <- result:
            case <-p.ctx.Done():
                return
            }
        }) {
            p.allTasks.Done() // Don't forget to decrement if submit fails
            color.Red("[x] Failed to submit URL to worker pool: %s", u)
            continue
        }
        submitted++
    }
    
    color.Green("[+] Submitted %d URLs to worker pool", submitted)
    
    // FIX: Wait for ALL tasks (including recursive) then close channel
    go func() {
        p.allTasks.Wait()
        close(p.resultsChan)
    }()
    
    // Wait for collector to finish
    <-collectorDone
    
    // Stop progress reporter
    if progressDone != nil {
        close(progressDone)
    }
    
    // Calculate summary
    p.calculateSummary()
    
    // Write results
    if err := p.output.WriteResults(p.results, p.summary); err != nil {
        return fmt.Errorf("failed to write results: %w", err)
    }
    
    return nil
}

// collectResults collects results from workers
func (p *Processor) collectResults(done chan struct{}) {
    defer close(done)
    
    for result := range p.resultsChan {
        p.resultsMu.Lock()
        p.results = append(p.results, result)
        p.resultsMu.Unlock()
        
        atomic.AddInt32(&p.processedCount, 1)
        
        // Print individual result if verbose or has findings
        if p.config.Verbose || result.PathCount > 0 || result.SecretCount > 0 {
            p.printResult(result)
        }
    }
}

// processSingleURL processes a single URL - ENHANCED for better path extraction
func (p *Processor) processSingleURL(urlStr string, depth int, parent string) types.ScanResult {
    start := time.Now()
    result := types.ScanResult{
        URL:       urlStr,
        Depth:     depth,
        ParentURL: parent,
        ScanTime:  start,
        IsJSFile:  p.isJSFile(urlStr),
    }
    
    // Check context cancellation
    select {
    case <-p.ctx.Done():
        result.Error = "scan cancelled"
        result.Duration = time.Since(start)
        return result
    default:
    }
    
    // Pre-checks
    if p.dedup.CheckAndAdd(urlStr) {
        result.Error = "duplicate URL (already processed)"
        result.Duration = time.Since(start)
        return result
    }
    
    if depth > p.config.MaxDepth {
        result.Error = fmt.Sprintf("max depth exceeded (%d)", p.config.MaxDepth)
        result.Duration = time.Since(start)
        return result
    }
    
    // Validate URL
    if !p.validator.IsValid(urlStr) {
        result.Error = "invalid URL format"
        result.Duration = time.Since(start)
        return result
    }
    
    // Fetch content
    content, statusCode, err := p.fetcher.FetchWithRetry(urlStr, p.config.CustomHeaders)
    if err != nil {
        result.Error = fmt.Sprintf("fetch failed: %s", err)
        result.StatusCode = statusCode
        result.Duration = time.Since(start)
        return result
    }
    
    result.StatusCode = statusCode
    
    // ENHANCED: Parse paths with multiple extraction methods
    paths := p.parser.Extract(content)
    
    // Additional extraction for concatenated paths and other patterns
    additionalPaths := p.validator.ExtractURLsFromConcat(content)
    paths = append(paths, additionalPaths...)
    
    paths = p.filterAndValidatePaths(paths, urlStr)
    result.Paths = paths
    result.PathCount = len(paths)
    
    // Scan for secrets
    secrets := p.scanner.Scan(content)
    result.Secrets = secrets
    result.SecretCount = len(secrets)
    
    // Deep scan if enabled - FIX: Use allTasks WaitGroup
    if p.config.DeepScan && depth < p.config.MaxDepth {
        jsFiles := p.extractJSFiles(paths, urlStr)
        for _, jsFile := range jsFiles {
            jsFile := jsFile
            
            // FIX: Track recursive task
            p.allTasks.Add(1)
            
            if !p.workerPool.Submit(func() {
                defer p.allTasks.Done()
                
                childResult := p.processSingleURL(jsFile, depth+1, urlStr)
                
                // Send result safely
                select {
                case p.resultsChan <- childResult:
                case <-p.ctx.Done():
                    return
                }
            }) {
                p.allTasks.Done() // Don't forget to decrement if submit fails
            }
        }
    }
    
    result.Duration = time.Since(start)
    return result
}

// filterAndValidatePaths filters and validates extracted paths - ENHANCED
func (p *Processor) filterAndValidatePaths(paths []string, baseURL string) []string {
    filtered := make([]string, 0, len(paths))
    seen := make(map[string]bool)
    
    for _, path := range paths {
        // Clean and validate using enhanced validator
        cleanPath := p.validator.Clean(path)
        if !p.validator.IsValidPath(cleanPath) {
            continue
        }
        
        // Make absolute if relative
        absolutePath := p.makeAbsolute(cleanPath, baseURL)
        if absolutePath == "" || !p.validator.IsValid(absolutePath) {
            continue
        }
        
        // Apply domain filtering if configured
        if len(p.config.AllowedDomains) > 0 {
            if !p.isAllowedDomain(absolutePath, baseURL) {
                continue
            }
        }
        
        // Deduplicate
        if !seen[absolutePath] {
            seen[absolutePath] = true
            filtered = append(filtered, absolutePath)
        }
    }
    
    return filtered
}

// extractJSFiles extracts JavaScript file URLs from paths
func (p *Processor) extractJSFiles(paths []string, baseURL string) []string {
    jsFiles := make([]string, 0)
    
    for _, path := range paths {
        if p.isJSFile(path) && !p.dedup.Contains(path) {
            // Already absolute from filterAndValidatePaths
            if p.validator.IsValid(path) {
                jsFiles = append(jsFiles, path)
            }
        }
    }
    
    return jsFiles
}

// isJSFile checks if a URL points to a JavaScript file - ENHANCED
func (p *Processor) isJSFile(urlStr string) bool {
    lower := strings.ToLower(urlStr)
    
    // Direct JS file extensions
    if strings.HasSuffix(lower, ".js") ||
       strings.Contains(lower, ".js?") ||
       strings.Contains(lower, ".js#") ||
       strings.Contains(lower, ".js&") {
        return true
    }
    
    // JS directories and common patterns
    if strings.Contains(lower, "/js/") ||
       strings.Contains(lower, "/javascript/") ||
       strings.Contains(lower, "/script/") ||
       strings.Contains(lower, ".js.") {
        return true
    }
    
    // Check content type patterns in URL
    if strings.Contains(lower, "type=javascript") ||
       strings.Contains(lower, "script=true") ||
       strings.Contains(lower, "format=js") {
        return true
    }
    
    return false
}

// isAllowedDomain checks if a URL is in allowed domains with wildcard support - ENHANCED
func (p *Processor) isAllowedDomain(urlStr, baseURL string) bool {
    if len(p.config.AllowedDomains) == 0 {
        return true
    }
    
    // Parse URL to get host
    parsedURL, err := url.Parse(urlStr)
    if err != nil {
        // If can't parse, assume it's relative path (allowed)
        return true
    }
    
    if parsedURL.Host == "" {
        // Relative path, allowed
        return true
    }
    
    host := p.validator.NormalizeDomain(parsedURL.Host)
    
    // Check against allowed domains with wildcard support
    for _, domainPattern := range p.config.AllowedDomains {
        domainPattern = p.validator.NormalizeDomain(domainPattern)
        
        if p.matchesDomainPattern(host, domainPattern) {
            return true
        }
    }
    
    return false
}

// matchesDomainPattern checks if host matches domain pattern with wildcard support - ENHANCED
func (p *Processor) matchesDomainPattern(host, pattern string) bool {
    // Exact match
    if host == pattern {
        return true
    }
    
    // Wildcard pattern: *.example.com
    if strings.HasPrefix(pattern, "*.") {
        suffix := pattern[2:] // Remove "*."
        
        // ENHANCED: Wildcard also matches base domain
        // *.example.com will match both "example.com" AND "api.example.com"
        if host == suffix {
            return true
        }
        
        // Ensure the host ends with the suffix
        if strings.HasSuffix(host, suffix) {
            // Check domain boundary to prevent false positives
            // e.g., host = "api.example.com", suffix = "example.com"
            // We need exactly one dot before the suffix or it's the full host
            if len(host) == len(suffix) {
                return true // Exact match (already handled above, but keep for safety)
            }
            
            // Check if the character before suffix is a dot
            if host[len(host)-len(suffix)-1] == '.' {
                // CRITICAL: Additional safety check
                // Ensure we're not matching "evilexample.com" when pattern is "*.example.com"
                
                // OPTION 1: Single-level subdomain only (strict)
                // Uncomment this if you want *.example.ac.id to ONLY match "sub.example.ac.id"
                // but NOT "a.b.example.ac.id"
                /*
                remaining := host[:len(host)-len(suffix)-1]
                if !strings.Contains(remaining, ".") {
                    return true
                }
                */
                
                // OPTION 2: Multi-level subdomain allowed (permissive)
                // This allows *.example.ac.id to match both:
                // - "sub.example.ac.id" 
                // - "a.b.example.ac.id" 
                // But still blocks "fakeexample.ac.id" 
                return true
            }
        }
        return false
    }
    
    // ENHANCED: Subdomain matching without wildcard
    // But be careful: we don't want "evilexample.com" to match "example.com"
    // Check if pattern appears as a full domain part
    if strings.Contains(host, pattern) {
        parts := strings.Split(host, ".")
        for i := 0; i < len(parts); i++ {
            if strings.Join(parts[i:], ".") == pattern {
                return true
            }
        }
    }
    
    return false
}

// makeAbsolute converts relative paths to absolute URLs - IMPROVED
func (p *Processor) makeAbsolute(path, baseURL string) string {
    // Already absolute
    if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
        return path
    }
    
    // Protocol-relative
    if strings.HasPrefix(path, "//") {
        // Use the same protocol as baseURL
        if strings.HasPrefix(baseURL, "https://") {
            return "https:" + path
        }
        return "http:" + path
    }
    
    // Parse base URL
    base, err := url.Parse(baseURL)
    if err != nil {
        return ""
    }
    
    // Parse relative path
    ref, err := url.Parse(path)
    if err != nil {
        return ""
    }
    
    // Resolve reference
    resolved := base.ResolveReference(ref)
    return resolved.String()
}

// printResult prints an individual scan result
func (p *Processor) printResult(result types.ScanResult) {
    depthPrefix := strings.Repeat("  ", result.Depth)
    
    if result.Error != "" {
        color.Red("%s[x] %s (depth: %d) - %s", depthPrefix, result.URL, result.Depth, result.Error)
        return
    }
    
    color.Cyan("%s[?] %s (depth: %d, time: %v, status: %d)", 
        depthPrefix, result.URL, result.Depth, result.Duration.Round(time.Millisecond), result.StatusCode)
    
    if result.PathCount > 0 {
        color.Blue("%s[!] Paths Found: %d", depthPrefix, result.PathCount)
        if p.config.Verbose {
            for i, path := range result.Paths {
                if i >= 10 { // Limit output
                    color.White("%s  ... and %d more", depthPrefix, result.PathCount-10)
                    break
                }
                marker := "  →"
                if p.isJSFile(path) {
                    marker = "  → [JS]"
                }
                color.White("%s%s %s", depthPrefix, marker, path)
            }
        }
    }
    
    if result.SecretCount > 0 {
        color.Red("%s[+] Secrets Found: %d", depthPrefix, result.SecretCount)
        for _, secret := range result.Secrets {
            color.Red("%s  ⚠ %s: %s", depthPrefix, secret.Type, secret.Value)
            if secret.Context != "" && p.config.Verbose {
                color.Yellow("%s    Context: %s", depthPrefix, secret.Context)
            }
        }
    }
    
    if result.PathCount == 0 && result.SecretCount == 0 {
        color.Yellow("%s  No paths or secrets found", depthPrefix)
    }
    
    fmt.Printf("%s────────────────────────────────────────\n", depthPrefix)
}

// reportProgress reports scanning progress
func (p *Processor) reportProgress(done chan struct{}) {
    ticker := time.NewTicker(2 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            processed := atomic.LoadInt32(&p.processedCount)
            total := p.totalURLs
            elapsed := time.Since(p.startTime)
            
            if total > 0 {
                percent := float64(processed) / float64(total) * 100
                color.Yellow("Progress: %d/%d (%.1f%%) | Elapsed: %v | Queue: %d", 
                    processed, total, percent, elapsed.Round(time.Second), p.workerPool.QueuedTasks())
            }
        case <-done:
            return
        }
    }
}

// calculateSummary calculates the final summary
func (p *Processor) calculateSummary() {
    p.summary.EndTime = time.Now()
    p.summary.TotalTime = p.summary.EndTime.Sub(p.summary.StartTime)
    
    successCount := 0
    failedCount := 0
    totalPaths := 0
    totalSecrets := 0
    
    for _, result := range p.results {
        if result.Error == "" {
            successCount++
            totalPaths += result.PathCount
            totalSecrets += result.SecretCount
        } else {
            failedCount++
        }
    }
    
    p.summary.SuccessCount = successCount
    p.summary.FailedCount = failedCount
    p.summary.TotalPaths = totalPaths
    p.summary.TotalSecrets = totalSecrets
    p.summary.Results = p.results
}

// PrintSummary prints the final summary
func (p *Processor) PrintSummary() {
    color.Cyan("\n════════════════════════════════════════════")
    color.Cyan("[+] Final Summary")
    color.Cyan("════════════════════════════════════════════")
    color.Green("  [+]Success: %d", p.summary.SuccessCount)
    color.Red("  [x] Failed: %d", p.summary.FailedCount)
    color.Blue("  📦 Total Paths: %d", p.summary.TotalPaths)
    color.Red("  [!] Total Secrets: %d", p.summary.TotalSecrets)
    color.Yellow("  ⏱  Total Time: %v", p.summary.TotalTime.Round(time.Millisecond))
    color.Cyan("════════════════════════════════════════════")
    
    jsonFile, txtFile := p.output.GetFilenames()
    color.Green("\nResults saved to:")
    color.Green("  - JSON: %s", jsonFile)
    color.Green("  - TXT:  %s", txtFile)
}

// Cancel cancels the scanning process
func (p *Processor) Cancel() {
    p.cancel()
}