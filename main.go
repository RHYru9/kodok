package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rhyru9/kodok/internal/fetcher"
	"github.com/rhyru9/kodok/internal/parser"
	"github.com/rhyru9/kodok/internal/scanner"
	"github.com/rhyru9/kodok/internal/utils"
	"github.com/fatih/color"
)

type headersFlag []string

func (h *headersFlag) String() string {
	return strings.Join(*h, ", ")
}

func (h *headersFlag) Set(value string) error {
	*h = append(*h, value)
	return nil
}

var (
	urlFile       = flag.String("fj", "", "File daftar URL JS")
	singleURL     = flag.String("u", "", "URL tunggal untuk diproses")
	allowedDomain = flag.String("ad", "", "Domain yang diperbolehkan dalam output (pisahkan dengan koma)")
	outputFile    = flag.String("o", "", "Nama file output (tanpa extension, akan menghasilkan .json dan .txt)")
	deepScan      = flag.Bool("deep", false, "Enable deep scanning of discovered JS files")
	maxDepth      = flag.Int("depth", 3, "Maximum depth for recursive JS scanning")
	headers       headersFlag
	showHelp      = flag.Bool("h", false, "Show help")
)

var (
	validPathRegex = regexp.MustCompile(`^(https?://|/)[^\s]+`)
	jsFileRegex    = regexp.MustCompile(`\.js(\?.*)?$`)
	processedURLs  = make(map[string]bool)
	urlMutex       sync.RWMutex
)

// ScanResult holds the results for a single URL scan
type ScanResult struct {
	URL         string    `json:"url"`
	Paths       []string  `json:"paths"`
	Secrets     []string  `json:"secrets"`
	PathCount   int       `json:"path_count"`
	SecretCount int       `json:"secret_count"`
	Error       string    `json:"error,omitempty"`
	ScanTime    time.Time `json:"scan_time"`
	Duration    string    `json:"duration"`
	Depth       int       `json:"depth"`
	IsJSFile    bool      `json:"is_js_file"`
	ParentURL   string    `json:"parent_url,omitempty"`
}

// OverallSummary contains the complete scan results
type OverallSummary struct {
	TotalURLs       int          `json:"total_urls"`
	SuccessfulScans int          `json:"successful_scans"`
	FailedScans     int          `json:"failed_scans"`
	TotalPaths      int          `json:"total_paths"`
	TotalSecrets    int          `json:"total_secrets"`
	DeepScanEnabled bool         `json:"deep_scan_enabled"`
	MaxDepth        int          `json:"max_depth"`
	ScanDate        time.Time    `json:"scan_date"`
	Results         []ScanResult `json:"results"`
}

func main() {
	flag.Var(&headers, "H", "Custom header (dapat digunakan berkali-kali)")
	
	// Show banner first, before parsing flags
	utils.PrintBanner()
	
	flag.Parse()
	
	// Show usage if help flag is used or no arguments provided
	if *showHelp || (flag.NArg() == 0 && *singleURL == "" && *urlFile == "") {
		showUsage()
		return
	}

	allowedDomains := parseAllowedDomains(*allowedDomain)
	customHeaders := parseHeaders(headers)
	urls := getURLs()

	if len(urls) == 0 {
		fmt.Println("Tidak ada URL yang diberikan. Gunakan -fj untuk file atau -u untuk URL tunggal.")
		showUsage()
		return
	}

	// Display scan configuration
	blue := color.New(color.FgBlue).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	
	fmt.Printf("%s %s\n", blue("[i] Deep Scan:"), cyan(fmt.Sprintf("%t", *deepScan)))
	if *deepScan {
		fmt.Printf("%s %s\n", blue("[i] Max Depth:"), cyan(fmt.Sprintf("%d", *maxDepth)))
	}

	// Display header information
	if len(customHeaders) > 0 {
		fmt.Printf("%s %s\n", blue("[i] Using"), cyan(fmt.Sprintf("%d custom headers", len(customHeaders))))
		for key, value := range customHeaders {
			maskedValue := maskSensitiveHeader(key, value)
			fmt.Printf("│   %s: %s\n", key, maskedValue)
		}
		fmt.Println()
	}

	// Setup output files if specified
	var jsonOutputFile, txtOutputFile *os.File
	if *outputFile != "" {
		jsonFilename := *outputFile + ".json"
		txtFilename := *outputFile + ".txt"
		
		var err error
		jsonOutputFile, err = os.Create(jsonFilename)
		if err != nil {
			fmt.Printf("Gagal membuat file JSON output: %s\n", err)
			return
		}
		defer jsonOutputFile.Close()

		txtOutputFile, err = os.Create(txtFilename)
		if err != nil {
			fmt.Printf("Gagal membuat file TXT output: %s\n", err)
			return
		}
		defer txtOutputFile.Close()

		fmt.Printf("Output akan disimpan ke: %s dan %s\n", jsonFilename, txtFilename)
	}

	var allResults []ScanResult
	var resultsMutex sync.Mutex

	// Process initial URLs
	for _, initialURL := range urls {
		results := processURLRecursively(initialURL, allowedDomains, customHeaders, 0, "")
		resultsMutex.Lock()
		allResults = append(allResults, results...)
		resultsMutex.Unlock()
	}

	// Write results to files if output files are specified
	if jsonOutputFile != nil && txtOutputFile != nil {
		writeJSONResults(jsonOutputFile, allResults)
		writeTXTResults(txtOutputFile, allResults)
		fmt.Printf("\nHasil berhasil disimpan ke: %s.json dan %s.txt\n", *outputFile, *outputFile)
	}

	// Display final summary
	fmt.Printf("\n%s\n", strings.Repeat("═", 80))
	fmt.Printf("%s %s\n", green("🎯 Final Summary:"), blue(fmt.Sprintf("Total URLs processed: %d", len(allResults))))
	fmt.Printf("%s\n", strings.Repeat("═", 80))
}

// Add this function to clean and validate URLs
func cleanAndValidateURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	
	// Remove trailing backslashes and clean up
	cleaned := strings.TrimRight(rawURL, "\\")
	cleaned = strings.TrimSpace(cleaned)
	
	// Skip if empty after cleaning
	if cleaned == "" {
		return ""
	}
	
	// Skip if it's just a scheme without content
	if cleaned == "http://" || cleaned == "https://" {
		return ""
	}
	
	return cleaned
}

func processURLRecursively(targetURL string, allowedDomains []string, customHeaders map[string]string, depth int, parentURL string) []ScanResult {
	var results []ScanResult
	
	// Clean and validate URL before processing
	cleanURL := cleanAndValidateURL(targetURL)
	if cleanURL == "" {
		return results
	}
	
	// Check if we've already processed this URL
	urlMutex.Lock()
	if processedURLs[cleanURL] {
		urlMutex.Unlock()
		return results
	}
	processedURLs[cleanURL] = true
	urlMutex.Unlock()

	// Check depth limit
	if *deepScan && depth > *maxDepth {
		return results
	}

	// Process current URL
	result := processURL(cleanURL, allowedDomains, customHeaders, depth, parentURL)
	results = append(results, result)

	// If deep scan is enabled and this scan was successful, look for JS files to scan
	if *deepScan && result.Error == "" && depth < *maxDepth {
		jsFiles := extractJSFiles(result.Paths, cleanURL)
		
		if len(jsFiles) > 0 {
			blue := color.New(color.FgBlue).SprintFunc()
			magenta := color.New(color.FgMagenta).SprintFunc()
			fmt.Printf("\n%s %s %s\n", blue("🔗 Deep scanning"), magenta(fmt.Sprintf("%d JS files", len(jsFiles))), blue("from this URL..."))
			
			var wg sync.WaitGroup
			sem := make(chan struct{}, 3) // Limit concurrent deep scans
			var deepResults []ScanResult
			var deepMutex sync.Mutex

			for _, jsFile := range jsFiles {
				wg.Add(1)
				go func(jsURL string) {
					defer wg.Done()
					sem <- struct{}{}
					
					deepScanResults := processURLRecursively(jsURL, allowedDomains, customHeaders, depth+1, cleanURL)
					
					deepMutex.Lock()
					deepResults = append(deepResults, deepScanResults...)
					deepMutex.Unlock()
					
					<-sem
				}(jsFile)
			}
			wg.Wait()
			
			results = append(results, deepResults...)
		}
	}

	return results
}

// Fixed extractJSFiles function to properly construct URLs
func extractJSFiles(paths []string, baseURL string) []string {
	var jsFiles []string
	seen := make(map[string]bool)

	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return jsFiles
	}

	for _, path := range paths {
		// Clean the path first
		cleanPath := cleanAndValidateURL(path)
		if cleanPath == "" {
			continue
		}
		
		if jsFileRegex.MatchString(cleanPath) {
			var fullURL string
			
			if strings.HasPrefix(cleanPath, "http://") || strings.HasPrefix(cleanPath, "https://") {
				// Already a full URL
				fullURL = cleanPath
			} else if strings.HasPrefix(cleanPath, "/") {
				// Absolute path - construct full URL with base domain
				fullURL = fmt.Sprintf("%s://%s%s", parsedBase.Scheme, parsedBase.Host, cleanPath)
			} else {
				// Relative path - this shouldn't happen often for JS files, but handle it
				baseDir := strings.TrimSuffix(parsedBase.Path, "/")
				if baseDir == "" {
					fullURL = fmt.Sprintf("%s://%s/%s", parsedBase.Scheme, parsedBase.Host, cleanPath)
				} else {
					fullURL = fmt.Sprintf("%s://%s%s/%s", parsedBase.Scheme, parsedBase.Host, baseDir, cleanPath)
				}
			}

			// Validate the constructed URL
			finalURL := cleanAndValidateURL(fullURL)
			if finalURL != "" && !seen[finalURL] {
				// Test if URL is parseable
				if parsedURL, err := url.Parse(finalURL); err == nil {
					// Additional validation - make sure it's a valid HTTP/HTTPS URL
					if parsedURL.Scheme == "http" || parsedURL.Scheme == "https" {
						seen[finalURL] = true
						jsFiles = append(jsFiles, finalURL)
					}
				}
			}
		}
	}

	return jsFiles
}

func getURLs() []string {
	var urls []string
	var rawURLs []string

	if *urlFile != "" {
		file, err := os.Open(*urlFile)
		if err != nil {
			fmt.Printf("Gagal membuka file: %s\n", err)
			return nil
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") { // Skip empty lines and comments
				rawURLs = append(rawURLs, line)
			}
		}
	} else if *singleURL != "" {
		rawURLs = append(rawURLs, *singleURL)
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" {
					rawURLs = append(rawURLs, line)
				}
			}
		}
	}
	
	// Clean and validate all URLs
	for _, rawURL := range rawURLs {
		cleanURL := cleanAndValidateURL(rawURL)
		if cleanURL != "" {
			// Additional validation - must be a valid URL
			if parsedURL, err := url.Parse(cleanURL); err == nil {
				// Make sure it's HTTP or HTTPS
				if parsedURL.Scheme == "http" || parsedURL.Scheme == "https" {
					urls = append(urls, cleanURL)
				}
			}
		}
	}
	
	return urls
}

func processURL(targetURL string, allowedDomains []string, customHeaders map[string]string, depth int, parentURL string) ScanResult {
	startTime := time.Now()
	
	// Validate URL before processing
	if targetURL == "" {
		return ScanResult{
			URL:       targetURL,
			Error:     "empty URL provided",
			ScanTime:  startTime,
			Duration:  time.Since(startTime).String(),
			Depth:     depth,
			ParentURL: parentURL,
		}
	}
	
	// Test URL parsing
	if _, err := url.Parse(targetURL); err != nil {
		return ScanResult{
			URL:       targetURL,
			Error:     fmt.Sprintf("invalid URL format: %s", err.Error()),
			ScanTime:  startTime,
			Duration:  time.Since(startTime).String(),
			Depth:     depth,
			ParentURL: parentURL,
		}
	}
	
	// Color definitions
	blue := color.New(color.FgBlue, color.Bold).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	white := color.New(color.FgWhite).SprintFunc()
	magenta := color.New(color.FgMagenta).SprintFunc()

	// Check if this is a JS file
	isJSFile := jsFileRegex.MatchString(targetURL)
	
	// Header dengan separator dan depth indicator
	fmt.Printf("\n%s\n", strings.Repeat("─", 80))
	if depth > 0 {
		indent := strings.Repeat("  ", depth)
		fmt.Printf("%s%s %s %s (depth: %d)\n", indent, blue("🔍 Deep Scanning:"), cyan(targetURL), magenta("[JS]"), depth)
		if parentURL != "" {
			fmt.Printf("%s%s %s\n", indent, blue("   ↳ From:"), white(parentURL))
		}
	} else {
		fmt.Printf("%s %s\n", blue("🔍 Scanning:"), cyan(targetURL))
	}
	fmt.Printf("%s\n", strings.Repeat("─", 80))

	content, err := fetcher.FetchWithHeaders(targetURL, customHeaders)
	if err != nil {
		fmt.Printf("%s %s %s\n", red("✗"), white("Error:"), err)
		return ScanResult{
			URL:       targetURL,
			Error:     err.Error(),
			ScanTime:  startTime,
			Duration:  time.Since(startTime).String(),
			Depth:     depth,
			IsJSFile:  isJSFile,
			ParentURL: parentURL,
		}
	}

	uniquePaths := make(map[string]bool)
	uniqueSecrets := make(map[string]bool)
	var mu sync.Mutex
	pathCount := 0
	secretCount := 0
	var resultPaths []string
	var resultSecrets []string

	// Process paths
	paths := parser.Parse(content)
	if len(paths) > 0 {
		fmt.Printf("\n%s %s\n", green("📂"), blue("Paths Found:"))
		fmt.Printf("%s\n", strings.Repeat("─", 40))
	}
	
	for _, path := range paths {
		cleanPath := cleanAndValidateURL(path) // Clean path before validation
		if cleanPath != "" && validPathRegex.MatchString(cleanPath) && isAllowedDomain(cleanPath, allowedDomains) {
			mu.Lock()
			if !uniquePaths[cleanPath] {
				uniquePaths[cleanPath] = true
				pathCount++
				resultPaths = append(resultPaths, cleanPath)
				
				// Highlight JS files
				if jsFileRegex.MatchString(cleanPath) {
					fmt.Printf("  %s %s %s\n", green("→"), formatPath(cleanPath), magenta("[JS]"))
				} else {
					fmt.Printf("  %s %s\n", green("→"), formatPath(cleanPath))
				}
			}
			mu.Unlock()
		}
	}

	// Process secrets
	secrets := scanner.Scan(content)
	filteredSecrets := filterUniqueSecrets(secrets, allowedDomains)
	
	if len(filteredSecrets) > 0 {
		fmt.Printf("\n%s %s\n", yellow("🔑"), blue("Secrets Found:"))
		fmt.Printf("%s\n", strings.Repeat("─", 40))
	}

	for _, secret := range filteredSecrets {
		mu.Lock()
		if !uniqueSecrets[secret] {
			uniqueSecrets[secret] = true
			secretCount++
			resultSecrets = append(resultSecrets, secret)
			fmt.Printf("  %s %s\n", red("⚠"), formatSecret(secret))
		}
		mu.Unlock()
	}

	// Summary
	fmt.Printf("\n%s\n", strings.Repeat("─", 40))
	fmt.Printf("%s %s: %d | %s: %d\n", 
		blue("📊 Summary"), 
		green("Paths"), pathCount, 
		yellow("Secrets"), secretCount)
	fmt.Printf("%s\n", strings.Repeat("═", 80))

	return ScanResult{
		URL:         targetURL,
		Paths:       resultPaths,
		Secrets:     resultSecrets,
		PathCount:   pathCount,
		SecretCount: secretCount,
		ScanTime:    startTime,
		Duration:    time.Since(startTime).String(),
		Depth:       depth,
		IsJSFile:    isJSFile,
		ParentURL:   parentURL,
	}
}

func filterUniqueSecrets(secrets []string, allowedDomains []string) []string {
	var filtered []string
	seen := make(map[string]bool)
	
	for _, secret := range secrets {
		if isAllowedDomainForSecret(secret, allowedDomains) && !seen[secret] {
			seen[secret] = true
			filtered = append(filtered, secret)
		}
	}
	
	return filtered
}

func formatPath(path string) string {
	cyan := color.New(color.FgCyan).SprintFunc()
	
	if len(path) <= 70 {
		return cyan(path)
	}
	
	// Truncate long paths nicely
	return cyan(path[:67] + "...")
}

func formatSecret(secret string) string {
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	
	// Split secret type from value
	parts := strings.SplitN(secret, ": ", 2)
	if len(parts) == 2 {
		secretType := strings.ToUpper(parts[0])
		secretValue := parts[1]
		
		// Truncate long secret values
		if len(secretValue) > 50 {
			secretValue = secretValue[:47] + "..."
		}
		
		return fmt.Sprintf("%s %s", yellow(secretType+":"), red(secretValue))
	}
	
	// Fallback for secrets without clear separation
	if len(secret) > 50 {
		secret = secret[:47] + "..."
	}
	return red(secret)
}

func showUsage() {
	blue := color.New(color.FgBlue, color.Bold).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	magenta := color.New(color.FgMagenta).SprintFunc()
	white := color.New(color.FgWhite).SprintFunc() // Added missing white color definition
	
	fmt.Printf("\n%s\n", blue("KODOK - JavaScript Security Scanner"))
	fmt.Printf("%s\n\n", strings.Repeat("═", 50))
	
	fmt.Printf("%s\n", blue("📋 Basic Usage:"))
	fmt.Printf("  %s\n", green("./kodok -u https://example.com/app.js"))
	fmt.Printf("  %s\n", green("./kodok -fj urls.txt"))
	fmt.Printf("  %s\n\n", green("./kodok -u https://example.com/app.js -o results"))
	
	fmt.Printf("%s\n", blue("🔍 Deep Scanning:"))
	fmt.Printf("  %s\n", magenta("./kodok -u https://example.com/page -deep"))
	fmt.Printf("  %s\n", magenta("./kodok -fj urls.txt -deep -depth 2"))
	fmt.Printf("  %s\n\n", magenta("./kodok -u https://example.com -deep -depth 3 -o results"))
	
	fmt.Printf("%s\n", blue("🔐 With Authentication:"))
	fmt.Printf("  %s\n", cyan("./kodok -u https://example.com/app.js -H 'Cookie: session=abc123'"))
	fmt.Printf("  %s\n", cyan("./kodok -u https://example.com/api.js -H 'Authorization: Bearer token123'"))
	fmt.Printf("  %s\n\n", cyan("./kodok -fj urls.txt -H 'X-API-Key: your-key' -deep -o results"))
	
	fmt.Printf("%s\n", blue("⚙️  Command Options:"))
	fmt.Printf("  %s  %s\n", yellow("-u"), "Target URL to scan")
	fmt.Printf("  %s  %s\n", yellow("-fj"), "File containing JavaScript URLs")
	fmt.Printf("  %s  %s\n", yellow("-H"), "Custom header (can be used multiple times)")
	fmt.Printf("  %s  %s\n", yellow("-ad"), "Allow domains (comma-separated)")
	fmt.Printf("  %s  %s\n", yellow("-o"), "Output filename (creates .json and .txt files)")
	fmt.Printf("  %s  %s\n", yellow("-deep"), "Enable deep scanning of discovered JS files")
	fmt.Printf("  %s  %s\n", yellow("-depth"), "Maximum depth for recursive scanning (default: 3)")
	fmt.Printf("  %s  %s\n", yellow("-h"), "Show this help message")
	fmt.Printf("\n%s\n", blue("📁 Output Files:"))
	fmt.Printf("  %s  %s\n", cyan("filename.json"), "Detailed results with metadata and depth info")
	fmt.Printf("  %s  %s\n", cyan("filename.txt"), "Clean paths and URLs only")
	fmt.Printf("\n%s\n", blue("🎯 Deep Scan Features:"))
	fmt.Printf("  • %s\n", white("Automatically discovers and scans JS files"))
	fmt.Printf("  • %s\n", white("Prevents infinite loops with URL tracking"))
	fmt.Printf("  • %s\n", white("Configurable depth limits"))
	fmt.Printf("  • %s\n", white("Parent-child URL relationship tracking"))
	fmt.Printf("\n%s\n", strings.Repeat("═", 50))
}

func parseHeaders(headersList []string) map[string]string {
	headers := make(map[string]string)
	for _, header := range headersList {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			headers[key] = value
		}
	}
	return headers
}

func maskSensitiveHeader(key, value string) string {
	sensitiveHeaders := []string{
		"authorization", "cookie", "x-api-key", "api-key", 
		"x-auth-token", "auth-token", "access-token", "bearer",
	}
	
	lowerKey := strings.ToLower(key)
	for _, sensitive := range sensitiveHeaders {
		if strings.Contains(lowerKey, sensitive) {
			if len(value) <= 8 {
				return strings.Repeat("*", len(value))
			}
			// Show first 4 and last 4 characters with stars in between
			return value[:4] + strings.Repeat("*", len(value)-8) + value[len(value)-4:]
		}
	}
	return value
}

func parseAllowedDomains(ad string) []string {
	if ad == "" {
		return nil
	}
	domains := strings.Split(ad, ",")
	for i, domain := range domains {
		domains[i] = strings.TrimSpace(domain)
	}
	return domains
}

func isAllowedDomain(rawURL string, allowedDomains []string) bool {
	if len(allowedDomains) == 0 {
		return true
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	host := parsedURL.Hostname()
	for _, domain := range allowedDomains {
		if strings.HasSuffix(host, domain) {
			return true
		}
	}
	return false
}

func isAllowedDomainForSecret(secret string, allowedDomains []string) bool {
	if len(allowedDomains) == 0 {
		return true
	}

	// For secrets, be more permissive since they might not contain URLs
	for _, domain := range allowedDomains {
		if strings.Contains(secret, domain) {
			return true
		}
	}
	
	// Allow secrets that don't contain domains (since secrets might not contain domains)
	return true
}

func writeJSONResults(file *os.File, results []ScanResult) {
	totalPaths := 0
	totalSecrets := 0
	successfulScans := 0

	for _, result := range results {
		if result.Error == "" {
			successfulScans++
			totalPaths += result.PathCount
			totalSecrets += result.SecretCount
		}
	}

	summary := OverallSummary{
		TotalURLs:       len(results),
		SuccessfulScans: successfulScans,
		FailedScans:     len(results) - successfulScans,
		TotalPaths:      totalPaths,
		TotalSecrets:    totalSecrets,
		DeepScanEnabled: *deepScan,
		MaxDepth:        *maxDepth,
		ScanDate:        time.Now(),
		Results:         results,
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(summary); err != nil {
		fmt.Printf("Error writing JSON file: %s\n", err)
	}
}

func writeTXTResults(file *os.File, results []ScanResult) {
	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// Separate full URLs and relative paths
	fullURLs := make(map[string]bool)
	relativePaths := make(map[string]bool)
	
	for _, result := range results {
		if result.Error == "" {
			// Add the original URL (always a full URL)
			fullURLs[result.URL] = true

			// Process all found paths
			for _, path := range result.Paths {
				// Check if it's a full URL (starts with http:// or https://)
				if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
					fullURLs[path] = true
				} else if strings.HasPrefix(path, "/") {
					// Relative path starting with /
					relativePaths[path] = true
				}
				// Skip relative paths that don't start with / as they're usually not useful endpoints
			}
		}
	}

	// Write full URLs first (sorted)
	var sortedURLs []string
	for url := range fullURLs {
		sortedURLs = append(sortedURLs, url)
	}
	sort.Strings(sortedURLs)
	
	for _, url := range sortedURLs {
		writer.WriteString(url + "\n")
	}

	// Write relative paths (sorted) 
	var sortedPaths []string
	for path := range relativePaths {
		sortedPaths = append(sortedPaths, path)
	}
	sort.Strings(sortedPaths)
	
	for _, path := range sortedPaths {
		writer.WriteString(path + "\n")
	}
}