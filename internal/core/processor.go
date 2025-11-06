package core

import (
    "bufio"
    "context"
    "fmt"
    "os"
    "strings"
    "sync"
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
    
    // Progress tracking
    progressMu     sync.Mutex
    processedCount int
    totalURLs      int
    startTime      time.Time
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
    
    return &Processor{
        config:     config,
        workerPool: workerPool,
        dedup:      dedup,
        fetcher:    fetcher,
        parser:     parser,
        scanner:    scanner,
        output:     output,
        validator:  validator,
        resultsChan: make(chan types.ScanResult, 1000),
        results:     make([]types.ScanResult, 0),
        summary: &types.Summary{
            StartTime: time.Now(),
        },
    }
}

// ProcessURLs processes a list of URLs
func (p *Processor) ProcessURLs(urls []string) error {
    p.startTime = time.Now()
    p.totalURLs = len(urls)
    p.summary.TotalURLs = p.totalURLs
    
    color.Cyan("🐸 KODOK - JavaScript Security Scanner")
    color.Cyan("════════════════════════════════════════════")
    color.Cyan("📊 Starting scan of %d URLs", p.totalURLs)
    color.Cyan("👷 Workers: %d | Depth: %d | Cache: %d", 
        p.config.MaxWorkers, p.config.MaxDepth, p.config.CacheSize)
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
    for _, url := range urls {
        url := url // Capture for closure
        
        if !p.workerPool.Submit(func() {
            p.processSingleURL(url, 0, "")
        }) {
            color.Red("❌ Failed to submit URL to worker pool: %s", url)
            continue
        }
        submitted++
    }
    
    color.Green("✅ Submitted %d URLs to worker pool", submitted)
    
    // Wait for completion
    p.workerPool.Wait()
    close(p.resultsChan)
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
        
        p.progressMu.Lock()
        p.processedCount++
        p.progressMu.Unlock()
        
        // Print individual result if verbose or has findings
        if p.config.Verbose || result.PathCount > 0 || result.SecretCount > 0 {
            p.printResult(result)
        }
    }
}

// processSingleURL processes a single URL
func (p *Processor) processSingleURL(url string, depth int, parent string) types.ScanResult {
    start := time.Now()
    result := types.ScanResult{
        URL:       url,
        Depth:     depth,
        ParentURL: parent,
        ScanTime:  start,
        IsJSFile:  p.isJSFile(url),
    }
    
    // Pre-checks
    if p.dedup.CheckAndAdd(url) {
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
    if !p.validator.IsValid(url) {
        result.Error = "invalid URL format"
        result.Duration = time.Since(start)
        return result
    }
    
    // Fetch content
    content, statusCode, err := p.fetcher.FetchWithRetry(url, p.config.CustomHeaders)
    if err != nil {
        result.Error = fmt.Sprintf("fetch failed: %s", err)
        result.Duration = time.Since(start)
        return result
    }
    
    result.StatusCode = statusCode
    
    // Parse paths
    paths := p.parser.Extract(content)
    paths = p.filterAndValidatePaths(paths, url)
    result.Paths = paths
    result.PathCount = len(paths)
    
    // Scan for secrets
    secrets := p.scanner.Scan(content)
    result.Secrets = secrets
    result.SecretCount = len(secrets)
    
    // Deep scan if enabled
    if p.config.DeepScan && depth < p.config.MaxDepth {
        jsFiles := p.extractJSFiles(paths, url)
        for _, jsFile := range jsFiles {
            jsFile := jsFile
            p.workerPool.Submit(func() {
                childResult := p.processSingleURL(jsFile, depth+1, url)
                p.resultsChan <- childResult
            })
        }
    }
    
    result.Duration = time.Since(start)
    return result
}

// filterAndValidatePaths filters and validates extracted paths
func (p *Processor) filterAndValidatePaths(paths []string, baseURL string) []string {
    filtered := make([]string, 0, len(paths))
    seen := make(map[string]bool)
    
    for _, path := range paths {
        // Clean and validate
        cleanPath := p.validator.Clean(path)
        if !p.validator.IsValid(cleanPath) {
            continue
        }
        
        // Apply domain filtering if configured
        if len(p.config.AllowedDomains) > 0 {
            if !p.isAllowedDomain(cleanPath, baseURL) {
                continue
            }
        }
        
        // Deduplicate
        if !seen[cleanPath] {
            seen[cleanPath] = true
            filtered = append(filtered, cleanPath)
        }
    }
    
    return filtered
}

// extractJSFiles extracts JavaScript file URLs from paths
func (p *Processor) extractJSFiles(paths []string, baseURL string) []string {
    jsFiles := make([]string, 0)
    
    for _, path := range paths {
        if p.isJSFile(path) && !p.dedup.Contains(path) {
            // Convert relative paths to absolute
            absolutePath := p.makeAbsolute(path, baseURL)
            if p.validator.IsValid(absolutePath) {
                jsFiles = append(jsFiles, absolutePath)
            }
        }
    }
    
    return jsFiles
}

// isJSFile checks if a URL points to a JavaScript file
func (p *Processor) isJSFile(url string) bool {
    return strings.HasSuffix(strings.ToLower(url), ".js") ||
           strings.Contains(strings.ToLower(url), ".js?") ||
           strings.Contains(strings.ToLower(url), "/js/")
}

// isAllowedDomain checks if a URL is in allowed domains
func (p *Processor) isAllowedDomain(url, baseURL string) bool {
    if len(p.config.AllowedDomains) == 0 {
        return true
    }
    
    for _, domain := range p.config.AllowedDomains {
        if strings.Contains(url, domain) {
            return true
        }
    }
    
    // Allow relative paths
    return !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://")
}

// makeAbsolute converts relative paths to absolute URLs
func (p *Processor) makeAbsolute(path, baseURL string) string {
    if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
        return path
    }
    
    if strings.HasPrefix(path, "//") {
        return "https:" + path
    }
    
    if strings.HasPrefix(path, "/") {
        // Extract base domain from baseURL
        if strings.HasPrefix(baseURL, "http") {
            parts := strings.SplitN(baseURL, "/", 4)
            if len(parts) >= 3 {
                return parts[0] + "//" + parts[2] + path
            }
        }
    }
    
    // For relative paths, try to resolve against baseURL directory
    if strings.HasPrefix(baseURL, "http") && !strings.HasPrefix(path, "/") {
        lastSlash := strings.LastIndex(baseURL, "/")
        if lastSlash > 8 { // After https://
            baseDir := baseURL[:lastSlash+1]
            return baseDir + path
        }
    }
    
    return path
}

// printResult prints an individual scan result
func (p *Processor) printResult(result types.ScanResult) {
    depthPrefix := strings.Repeat("  ", result.Depth)
    
    if result.Error != "" {
        color.Red("%s❌ %s (depth: %d) - %s", depthPrefix, result.URL, result.Depth, result.Error)
        return
    }
    
    color.Cyan("%s🔍 %s (depth: %d, time: %v)", depthPrefix, result.URL, result.Depth, result.Duration.Round(time.Millisecond))
    
    if result.PathCount > 0 {
        color.Blue("%s📂 Paths Found: %d", depthPrefix, result.PathCount)
        for _, path := range result.Paths {
            marker := "  →"
            if p.isJSFile(path) {
                marker = "  → [JS]"
            }
            color.White("%s%s %s", depthPrefix, marker, path)
        }
    }
    
    if result.SecretCount > 0 {
        color.Red("%s🔑 Secrets Found: %d", depthPrefix, result.SecretCount)
        for _, secret := range result.Secrets {
            color.Red("%s  ⚠ %s: %s", depthPrefix, secret.Type, secret.Value)
            if secret.Context != "" {
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
            p.progressMu.Lock()
            processed := p.processedCount
            total := p.totalURLs
            elapsed := time.Since(p.startTime)
            p.progressMu.Unlock()
            
            if total > 0 {
                percent := float64(processed) / float64(total) * 100
                color.Yellow("📊 Progress: %d/%d (%.1f%%) | Elapsed: %v", 
                    processed, total, percent, elapsed.Round(time.Second))
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
    color.Cyan("🎯 Final Summary")
    color.Cyan("════════════════════════════════════════════")
    color.Green("  ✅ Success: %d", p.summary.SuccessCount)
    color.Red("  ❌ Failed: %d", p.summary.FailedCount)
    color.Blue("  📦 Total Paths: %d", p.summary.TotalPaths)
    color.Red("  🔐 Total Secrets: %d", p.summary.TotalSecrets)
    color.Yellow("  ⏱  Total Time: %v", p.summary.TotalTime.Round(time.Millisecond))
    color.Cyan("════════════════════════════════════════════")
    
    // Print output file locations
    color.Green("Results saved to: %s.json and %s.txt", p.config.OutputFile, p.config.OutputFile)
}

// GetResults returns the scan results
func (p *Processor) GetResults() []types.ScanResult {
    p.resultsMu.Lock()
    defer p.resultsMu.Unlock()
    return p.results
}

// GetSummary returns the scan summary
func (p *Processor) GetSummary() *types.Summary {
    return p.summary
}

// readURLsFromFile reads URLs from a file
func ReadURLsFromFile(filename string) ([]string, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, fmt.Errorf("failed to open file: %w", err)
    }
    defer file.Close()
    
    var urls []string
    scanner := bufio.NewScanner(file)
    
    for scanner.Scan() {
        url := strings.TrimSpace(scanner.Text())
        if url != "" && !strings.HasPrefix(url, "#") {
            urls = append(urls, url)
        }
    }
    
    if err := scanner.Err(); err != nil {
        return nil, fmt.Errorf("error reading file: %w", err)
    }
    
    return urls, nil
}

// GetURLsFromInput gets URLs from various input sources
func GetURLsFromInput(config *types.Config) ([]string, error) {
    var urls []string
    
    // Check if we're reading from stdin
    stat, _ := os.Stdin.Stat()
    if (stat.Mode() & os.ModeCharDevice) == 0 {
        // Reading from stdin
        scanner := bufio.NewScanner(os.Stdin)
        for scanner.Scan() {
            url := strings.TrimSpace(scanner.Text())
            if url != "" {
                urls = append(urls, url)
            }
        }
        if err := scanner.Err(); err != nil {
            return nil, fmt.Errorf("error reading from stdin: %w", err)
        }
        color.Green("📥 Read %d URLs from stdin", len(urls))
    } else {
        // Check for file input
        if config.OutputFile != "" {
            fileURLs, err := ReadURLsFromFile(config.OutputFile)
            if err == nil {
                urls = append(urls, fileURLs...)
            }
        }
        
        // If no URLs found, show usage
        if len(urls) == 0 {
            return nil, fmt.Errorf("no URLs provided. Use -u for single URL or -f for file, or pipe URLs to stdin")
        }
    }
    
    // Deduplicate input URLs
    seen := make(map[string]bool)
    uniqueURLs := make([]string, 0, len(urls))
    
    for _, url := range urls {
        if !seen[url] {
            seen[url] = true
            uniqueURLs = append(uniqueURLs, url)
        }
    }
    
    color.Green("📝 Processing %d unique URLs", len(uniqueURLs))
    return uniqueURLs, nil
}