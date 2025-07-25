package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
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
<<<<<<< HEAD
	urlFile       = flag.String("fj", "", "File daftar URL JS")
	singleURL     = flag.String("u", "", "URL tunggal untuk diproses")
	allowedDomain = flag.String("ad", "", "Domain yang diperbolehkan dalam output (pisahkan dengan koma)")
	outputFile    = flag.String("o", "", "Base filename untuk output (akan membuat .json dan .txt)")
=======
	urlFile       = flag.String("fj", "", "File containing list of JS URLs")
	singleURL     = flag.String("u", "", "Single URL to process")
	allowedDomain = flag.String("ad", "", "Allowed domains in output (comma separated)")
	outputFile    = flag.String("o", "", "Output filename (without extension, will create .json and .txt)")
	deepScan      = flag.Bool("deep", false, "Enable deep scanning of discovered JS files")
	maxDepth      = flag.Int("depth", 3, "Maximum depth for recursive JS scanning")
>>>>>>> bcdac2b92c7d2a18591b9f88d2c118c88011522b
	headers       headersFlag
	showHelp      = flag.Bool("h", false, "Show help")
)

<<<<<<< HEAD
// Enhanced regex that matches parser.go logic
var validPathRegex = regexp.MustCompile(`^(https?://[^\s<>]+|(?:/|\.\.?/)[^\s<>,;|*()\[\]{}\\]+)$`)

// JSONOutput structure for comprehensive JSON output
type JSONOutput struct {
	TotalURLs       int          `json:"total_urls"`
	SuccessfulScans int          `json:"successful_scans"`
	FailedScans     int          `json:"failed_scans"`
	SkippedScans    int          `json:"skipped_scans"`
	TotalPaths      int          `json:"total_paths"`
	TotalSecrets    int          `json:"total_secrets"`
	ScanDate        string       `json:"scan_date"`
	Results         []ScanResult `json:"results"`
}

// ScanResult holds the results for a single URL scan
=======
var (
	validPathRegex = regexp.MustCompile(`^(https?://|/)[^\s]+`)
	jsFileRegex    = regexp.MustCompile(`\.js(\?.*)?$`)
	processedURLs  = make(map[string]bool)
	urlMutex       sync.RWMutex
)

>>>>>>> bcdac2b92c7d2a18591b9f88d2c118c88011522b
type ScanResult struct {
	URL         string    `json:"url"`
	Paths       []string  `json:"paths"`
	Secrets     []string  `json:"secrets"`
	PathCount   int       `json:"path_count"`
	SecretCount int       `json:"secret_count"`
<<<<<<< HEAD
	ScanTime    string    `json:"scan_time"`
	Duration    string    `json:"duration"`
	IsJSFile    bool      `json:"is_js_file"`
	Error       string    `json:"error,omitempty"`
	Skipped     bool      `json:"skipped"`
	SkipReason  string    `json:"skip_reason,omitempty"`
=======
	Error       string    `json:"error,omitempty"`
	ScanTime    time.Time `json:"scan_time"`
	Duration    string    `json:"duration"`
	Depth       int       `json:"depth"`
	IsJSFile    bool      `json:"is_js_file"`
	ParentURL   string    `json:"parent_url,omitempty"`
}

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
>>>>>>> bcdac2b92c7d2a18591b9f88d2c118c88011522b
}

func main() {
	flag.Var(&headers, "H", "Custom header (can be used multiple times)")
	
	utils.PrintBanner()
	
	flag.Parse()
	
	if *showHelp || (flag.NArg() == 0 && *singleURL == "" && *urlFile == "" && isStdinEmpty()) {
		showUsage()
		return
	}

	allowedDomains := parseAllowedDomains(*allowedDomain)
	customHeaders := parseHeaders(headers)
	urls := getURLs()

	if len(urls) == 0 {
		fmt.Println("No URLs provided. Use -fj for file or -u for single URL.")
		showUsage()
		return
	}

	blue := color.New(color.FgBlue).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	
	fmt.Printf("%s %s\n", blue("[i] Deep Scan:"), cyan(fmt.Sprintf("%t", *deepScan)))
	if *deepScan {
		fmt.Printf("%s %s\n", blue("[i] Max Depth:"), cyan(fmt.Sprintf("%d", *maxDepth)))
	}

	if len(customHeaders) > 0 {
		fmt.Printf("%s %s\n", blue("[i] Using"), cyan(fmt.Sprintf("%d custom headers", len(customHeaders))))
		for key, value := range customHeaders {
			maskedValue := maskSensitiveHeader(key, value)
			fmt.Printf("│   %s: %s\n", key, maskedValue)
		}
		fmt.Println()
	}

<<<<<<< HEAD
	// Setup output files if specified
	var jsonOutputFile, txtOutputFile *os.File
	if *outputFile != "" {
		// Remove extension if provided and create base filename
		baseName := strings.TrimSuffix(*outputFile, filepath.Ext(*outputFile))
		
		// Create JSON output file
		jsonFileName := baseName + ".json"
		var err error
		jsonOutputFile, err = os.Create(jsonFileName)
		if err != nil {
			fmt.Printf("Gagal membuat file JSON output: %s\n", err)
			return
		}
		defer jsonOutputFile.Close()
		
		// Create TXT output file
		txtFileName := baseName + ".txt"
		txtOutputFile, err = os.Create(txtFileName)
		if err != nil {
			fmt.Printf("Gagal membuat file TXT output: %s\n", err)
			return
		}
		defer txtOutputFile.Close()
		
		fmt.Printf("Output akan disimpan ke:\n")
		fmt.Printf("  📄 JSON: %s\n", jsonFileName)
		fmt.Printf("  📄 TXT:  %s\n", txtFileName)
		fmt.Println()
=======
	var jsonOutputFile, txtOutputFile *os.File
	if *outputFile != "" {
		jsonFilename := *outputFile + ".json"
		txtFilename := *outputFile + ".txt"
		
		var err error
		jsonOutputFile, err = os.Create(jsonFilename)
		if err != nil {
			fmt.Printf("Failed to create JSON output file: %s\n", err)
			return
		}
		defer jsonOutputFile.Close()

		txtOutputFile, err = os.Create(txtFilename)
		if err != nil {
			fmt.Printf("Failed to create TXT output file: %s\n", err)
			return
		}
		defer txtOutputFile.Close()

		fmt.Printf("Output will be saved to: %s and %s\n", jsonFilename, txtFilename)
>>>>>>> bcdac2b92c7d2a18591b9f88d2c118c88011522b
	}

	var allResults []ScanResult
	var resultsMutex sync.Mutex

<<<<<<< HEAD
	for _, url := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}
			result := processURL(url, allowedDomains, customHeaders)
			if jsonOutputFile != nil && txtOutputFile != nil {
				resultsMutex.Lock()
				results = append(results, result)
				resultsMutex.Unlock()
			}
			<-sem
		}(url)
=======
	for _, initialURL := range urls {
		results := processURLRecursively(initialURL, allowedDomains, customHeaders, 0, "")
		resultsMutex.Lock()
		allResults = append(allResults, results...)
		resultsMutex.Unlock()
>>>>>>> bcdac2b92c7d2a18591b9f88d2c118c88011522b
	}

<<<<<<< HEAD
	// Write results to files if output files are specified
	if jsonOutputFile != nil && txtOutputFile != nil {
		// Write JSON results
		writeJSONResults(jsonOutputFile, results)
		
		// Write TXT results
		writeTXTResults(txtOutputFile, results)
		
		baseName := strings.TrimSuffix(*outputFile, filepath.Ext(*outputFile))
		fmt.Printf("\n✅ Hasil berhasil disimpan:\n")
		fmt.Printf("   📄 JSON: %s.json\n", baseName)
		fmt.Printf("   📄 TXT:  %s.txt\n", baseName)
=======
	if jsonOutputFile != nil && txtOutputFile != nil {
		writeJSONResults(jsonOutputFile, allResults)
		writeTXTResults(txtOutputFile, allResults)
		fmt.Printf("\nResults saved to: %s.json and %s.txt\n", *outputFile, *outputFile)
>>>>>>> bcdac2b92c7d2a18591b9f88d2c118c88011522b
	}

	fmt.Printf("\n%s\n", strings.Repeat("═", 80))
	fmt.Printf("%s %s\n", green("🎯 Final Summary:"), blue(fmt.Sprintf("Total URLs processed: %d", len(allResults))))
	fmt.Printf("%s\n", strings.Repeat("═", 80))
}

func isStdinEmpty() bool {
	stat, _ := os.Stdin.Stat()
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func cleanAndValidateURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	
	cleaned := strings.TrimRight(rawURL, "\\")
	cleaned = strings.TrimSpace(cleaned)
	
	if cleaned == "" || cleaned == "http://" || cleaned == "https://" {
		return ""
	}
	
	return cleaned
}

func getURLs() []string {
	var urls []string
	var rawURLs []string

	// Check for piped input first
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
<<<<<<< HEAD
			if line != "" && !strings.HasPrefix(line, "#") {
				urls = append(urls, line)
			}
		}
	} else if *singleURL != "" {
		urls = append(urls, *singleURL)
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					urls = append(urls, line)
				}
=======
			if line != "" {
				rawURLs = append(rawURLs, line)
>>>>>>> bcdac2b92c7d2a18591b9f88d2c118c88011522b
			}
		}
	}

	// Then check for file input
	if *urlFile != "" {
		file, err := os.Open(*urlFile)
		if err != nil {
			fmt.Printf("Failed to open file: %s\n", err)
		} else {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					rawURLs = append(rawURLs, line)
				}
			}
		}
	}

	// Finally check for single URL
	if *singleURL != "" {
		rawURLs = append(rawURLs, *singleURL)
	}

	// Clean and validate all URLs
	for _, rawURL := range rawURLs {
		cleanURL := cleanAndValidateURL(rawURL)
		if cleanURL != "" {
			if parsedURL, err := url.Parse(cleanURL); err == nil {
				if parsedURL.Scheme == "http" || parsedURL.Scheme == "https" {
					urls = append(urls, cleanURL)
				}
			}
		}
	}
	
	return urls
}

<<<<<<< HEAD
func processURL(url string, allowedDomains []string, customHeaders map[string]string) ScanResult {
	startTime := time.Now()
	
	// Color definitions
=======
func processURLRecursively(targetURL string, allowedDomains []string, customHeaders map[string]string, depth int, parentURL string) []ScanResult {
	var results []ScanResult
	
	cleanURL := cleanAndValidateURL(targetURL)
	if cleanURL == "" {
		return results
	}
	
	urlMutex.Lock()
	if processedURLs[cleanURL] {
		urlMutex.Unlock()
		return results
	}
	processedURLs[cleanURL] = true
	urlMutex.Unlock()

	if *deepScan && depth > *maxDepth {
		return results
	}

	result := processURL(cleanURL, allowedDomains, customHeaders, depth, parentURL)
	results = append(results, result)

	if *deepScan && result.Error == "" && depth < *maxDepth {
		jsFiles := extractJSFiles(result.Paths, cleanURL)
		
		if len(jsFiles) > 0 {
			blue := color.New(color.FgBlue).SprintFunc()
			magenta := color.New(color.FgMagenta).SprintFunc()
			fmt.Printf("\n%s %s %s\n", blue("🔗 Deep scanning"), magenta(fmt.Sprintf("%d JS files", len(jsFiles))), blue("from this URL..."))
			
			var wg sync.WaitGroup
			sem := make(chan struct{}, 3)
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

func extractJSFiles(paths []string, baseURL string) []string {
	var jsFiles []string
	seen := make(map[string]bool)

	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return jsFiles
	}

	for _, path := range paths {
		cleanPath := cleanAndValidateURL(path)
		if cleanPath == "" {
			continue
		}
		
		if jsFileRegex.MatchString(cleanPath) {
			var fullURL string
			
			if strings.HasPrefix(cleanPath, "http://") || strings.HasPrefix(cleanPath, "https://") {
				fullURL = cleanPath
			} else if strings.HasPrefix(cleanPath, "/") {
				fullURL = fmt.Sprintf("%s://%s%s", parsedBase.Scheme, parsedBase.Host, cleanPath)
			} else {
				baseDir := strings.TrimSuffix(parsedBase.Path, "/")
				if baseDir == "" {
					fullURL = fmt.Sprintf("%s://%s/%s", parsedBase.Scheme, parsedBase.Host, cleanPath)
				} else {
					fullURL = fmt.Sprintf("%s://%s%s/%s", parsedBase.Scheme, parsedBase.Host, baseDir, cleanPath)
				}
			}

			finalURL := cleanAndValidateURL(fullURL)
			if finalURL != "" && !seen[finalURL] {
				if parsedURL, err := url.Parse(finalURL); err == nil {
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

func processURL(targetURL string, allowedDomains []string, customHeaders map[string]string, depth int, parentURL string) ScanResult {
	startTime := time.Now()
	
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
	
>>>>>>> bcdac2b92c7d2a18591b9f88d2c118c88011522b
	blue := color.New(color.FgBlue, color.Bold).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	white := color.New(color.FgWhite).SprintFunc()
	magenta := color.New(color.FgMagenta).SprintFunc()

	isJSFile := jsFileRegex.MatchString(targetURL)
	
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

<<<<<<< HEAD
	// Use enhanced fetcher with proper error handling
	content, err := fetcher.FetchWithHeaders(url, customHeaders)
=======
	content, err := fetcher.FetchWithHeaders(targetURL, customHeaders)
>>>>>>> bcdac2b92c7d2a18591b9f88d2c118c88011522b
	if err != nil {
		duration := time.Since(startTime)
		// Check if it's a skip error (from fetcher filtering)
		if strings.Contains(err.Error(), "skipped:") {
			fmt.Printf("%s %s %s\n", yellow("⏭"), white("Skipped:"), magenta(err.Error()))
			return ScanResult{
				URL:        url,
				Skipped:    true,
				SkipReason: err.Error(),
				ScanTime:   startTime.Format(time.RFC3339),
				Duration:   duration.String(),
				IsJSFile:   isJavaScriptFile(url),
			}
		}
		// Real error
		fmt.Printf("%s %s %s\n", red("✗"), white("Error:"), err)
		return ScanResult{
<<<<<<< HEAD
			URL:      url,
			Error:    err.Error(),
			ScanTime: startTime.Format(time.RFC3339),
			Duration: duration.String(),
			IsJSFile: isJavaScriptFile(url),
=======
			URL:       targetURL,
			Error:     err.Error(),
			ScanTime:  startTime,
			Duration:  time.Since(startTime).String(),
			Depth:     depth,
			IsJSFile:  isJSFile,
			ParentURL: parentURL,
>>>>>>> bcdac2b92c7d2a18591b9f88d2c118c88011522b
		}
	}

	// Track unique results using maps for efficient deduplication
	uniquePaths := make(map[string]bool)
	uniqueSecrets := make(map[string]bool)
	var mu sync.Mutex
	pathCount := 0
	secretCount := 0
	var resultPaths []string
	var resultSecrets []string

<<<<<<< HEAD
	// Process paths using enhanced parser
=======
>>>>>>> bcdac2b92c7d2a18591b9f88d2c118c88011522b
	paths := parser.Parse(content)
	if len(paths) > 0 {
		fmt.Printf("\n%s %s\n", green("📂"), blue("Paths Found:"))
		fmt.Printf("%s\n", strings.Repeat("─", 40))
	}
	
	for _, path := range paths {
<<<<<<< HEAD
		// Use enhanced validation that matches parser.go logic
		if isValidPathForOutput(path) && isAllowedDomain(path, allowedDomains) {
=======
		cleanPath := cleanAndValidateURL(path)
		if cleanPath != "" && validPathRegex.MatchString(cleanPath) && isAllowedDomain(cleanPath, allowedDomains) {
>>>>>>> bcdac2b92c7d2a18591b9f88d2c118c88011522b
			mu.Lock()
			if !uniquePaths[cleanPath] {
				uniquePaths[cleanPath] = true
				pathCount++
				resultPaths = append(resultPaths, cleanPath)
				
				if jsFileRegex.MatchString(cleanPath) {
					fmt.Printf("  %s %s %s\n", green("→"), formatPath(cleanPath), magenta("[JS]"))
				} else {
					fmt.Printf("  %s %s\n", green("→"), formatPath(cleanPath))
				}
			}
			mu.Unlock()
		}
	}

<<<<<<< HEAD
	// Process secrets with enhanced filtering
=======
>>>>>>> bcdac2b92c7d2a18591b9f88d2c118c88011522b
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

<<<<<<< HEAD
	duration := time.Since(startTime)

	// Enhanced summary with more details
=======
>>>>>>> bcdac2b92c7d2a18591b9f88d2c118c88011522b
	fmt.Printf("\n%s\n", strings.Repeat("─", 40))
	fmt.Printf("%s %s: %d | %s: %d\n", 
		blue("📊 Summary"), 
		green("Paths"), pathCount, 
		yellow("Secrets"), secretCount)
	
	// Show content size info
	contentSize := len(content)
	var sizeStr string
	if contentSize > 1024*1024 {
		sizeStr = fmt.Sprintf("%.1fMB", float64(contentSize)/(1024*1024))
	} else if contentSize > 1024 {
		sizeStr = fmt.Sprintf("%.1fKB", float64(contentSize)/1024)
	} else {
		sizeStr = fmt.Sprintf("%dB", contentSize)
	}
	fmt.Printf("%s %s: %s | %s: %s\n", blue("📏 Content Size"), white(""), cyan(sizeStr), blue("Duration"), cyan(duration.String()))
	fmt.Printf("%s\n", strings.Repeat("═", 80))

	return ScanResult{
		URL:         targetURL,
		Paths:       resultPaths,
		Secrets:     resultSecrets,
		PathCount:   pathCount,
		SecretCount: secretCount,
<<<<<<< HEAD
		ScanTime:    startTime.Format(time.RFC3339),
		Duration:    duration.String(),
		IsJSFile:    isJavaScriptFile(url),
=======
		ScanTime:    startTime,
		Duration:    time.Since(startTime).String(),
		Depth:       depth,
		IsJSFile:    isJSFile,
		ParentURL:   parentURL,
>>>>>>> bcdac2b92c7d2a18591b9f88d2c118c88011522b
	}
}

// Enhanced path validation that matches parser.go logic
func isValidPathForOutput(path string) bool {
	// Use the same regex as parser for consistency
	if !validPathRegex.MatchString(path) {
		return false
	}
	
	// Additional checks that mirror parser.go validation
	if len(path) < 2 || len(path) > 2000 {
		return false
	}
	
	// Must start with valid characters (consistent with parser.go)
	if !strings.HasPrefix(path, "http://") && 
	   !strings.HasPrefix(path, "https://") && 
	   !strings.HasPrefix(path, "/") && 
	   !strings.HasPrefix(path, "./") && 
	   !strings.HasPrefix(path, "../") {
		return false
	}
	
	// Avoid paths that are just special characters
	if matched, _ := regexp.MatchString(`^[^a-zA-Z0-9]+$`, path); matched {
		return false
	}
	
	return true
}

func filterUniqueSecrets(secrets []string, allowedDomains []string) []string {
	var filtered []string
	seen := make(map[string]bool)
	
	for _, secret := range secrets {
		// Enhanced secret filtering
		if isValidSecret(secret) && isAllowedDomainForSecret(secret, allowedDomains) && !seen[secret] {
			seen[secret] = true
			filtered = append(filtered, secret)
		}
	}
	
	return filtered
}

// Enhanced secret validation
func isValidSecret(secret string) bool {
	// Basic length check
	if len(secret) < 5 || len(secret) > 1000 {
		return false
	}
	
	// Skip if it's mostly whitespace
	if len(strings.TrimSpace(secret)) < 5 {
		return false
	}
	
	// Skip common false positives
	falsePrefixes := []string{
		"console.", "window.", "document.", "function ", "var ", "let ", "const ",
		"return ", "if (", "for (", "while (", "// ", "/* ", "* ", "*/",
		"<script", "</script", "<style", "</style", "<!DOCTYPE", "<html",
	}
	
	secretLower := strings.ToLower(strings.TrimSpace(secret))
	for _, prefix := range falsePrefixes {
		if strings.HasPrefix(secretLower, prefix) {
			return false
		}
	}
	
	return true
}

func isJavaScriptFile(url string) bool {
	return strings.HasSuffix(strings.ToLower(url), ".js") || 
		   strings.Contains(strings.ToLower(url), ".js?") ||
		   strings.Contains(strings.ToLower(url), "javascript")
}

func formatPath(path string) string {
	cyan := color.New(color.FgCyan).SprintFunc()
	
	if len(path) <= 70 {
		return cyan(path)
	}
	
	return cyan(path[:67] + "...")
}

func formatSecret(secret string) string {
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	
	parts := strings.SplitN(secret, ": ", 2)
	if len(parts) == 2 {
		secretType := strings.ToUpper(parts[0])
		secretValue := parts[1]
		
		if len(secretValue) > 50 {
			secretValue = secretValue[:47] + "..."
		}
		
		return fmt.Sprintf("%s %s", yellow(secretType+":"), red(secretValue))
	}
	
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
	white := color.New(color.FgWhite).SprintFunc()
	
	fmt.Printf("\n%s\n", blue("KODOK - JavaScript Security Scanner"))
	fmt.Printf("%s\n\n", strings.Repeat("═", 50))
	
	fmt.Printf("%s\n", blue("📋 Basic Usage:"))
	fmt.Printf("  %s\n", green("./kodok -u https://example.com/app.js"))
	fmt.Printf("  %s\n", green("./kodok -fj urls.txt"))
<<<<<<< HEAD
	fmt.Printf("  %s\n\n", green("./kodok -u https://example.com/app.js -o results"))
	
	fmt.Printf("%s\n", blue("📄 Dual Output (JSON + TXT):"))
	fmt.Printf("  %s\n", cyan("./kodok -u https://example.com/app.js -o scan_results"))
	fmt.Printf("  %s\n", cyan("./kodok -fj urls.txt -o my_scan"))
	fmt.Printf("  %s\n", cyan("  ↳ Creates: scan_results.json + scan_results.txt"))
	fmt.Printf("  %s\n\n", cyan("  ↳ Creates: my_scan.json + my_scan.txt"))
	
	fmt.Printf("%s\n", blue("🔐 With Authentication:"))
	fmt.Printf("  %s\n", cyan("./kodok -u https://example.com/app.js -H 'Cookie: session=abc123'"))
	fmt.Printf("  %s\n", cyan("./kodok -u https://example.com/api.js -H 'Authorization: Bearer token123'"))
	fmt.Printf("  %s\n\n", cyan("./kodok -fj urls.txt -H 'X-API-Key: your-key' -o results"))
	
	fmt.Printf("%s\n", blue("⚙️  Command Options:"))
=======
	fmt.Printf("  %s\n", green("cat urls.txt | ./kodok -o results"))
	fmt.Printf("  %s\n\n", green("cat urls.txt | ./kodok -H 'Auth: token' -o results"))
	
	fmt.Printf("%s\n", blue("🔍 Deep Scanning:"))
	fmt.Printf("  %s\n", magenta("./kodok -u https://example.com/page -deep"))
	fmt.Printf("  %s\n", magenta("./kodok -fj urls.txt -deep -depth 2"))
	fmt.Printf("  %s\n\n", magenta("cat urls.txt | ./kodok -deep -depth 3 -o results"))
	
	fmt.Printf("%s\n", blue("🔐 With Authentication:"))
	fmt.Printf("  %s\n", cyan("./kodok -u https://example.com/app.js -H 'Cookie: session=abc123'"))
	fmt.Printf("  %s\n", cyan("cat urls.txt | ./kodok -H 'X-API-Key: your-key' -deep -o results"))
	fmt.Printf("\n%s\n", blue("⚙️  Command Options:"))
>>>>>>> bcdac2b92c7d2a18591b9f88d2c118c88011522b
	fmt.Printf("  %s  %s\n", yellow("-u"), "Target URL to scan")
	fmt.Printf("  %s  %s\n", yellow("-fj"), "File containing JavaScript URLs")
	fmt.Printf("  %s  %s\n", yellow("-H"), "Custom header (can be used multiple times)")
	fmt.Printf("  %s  %s\n", yellow("-ad"), "Allow domains (comma-separated)")
<<<<<<< HEAD
	fmt.Printf("  %s  %s\n", yellow("-o"), "Base filename for output (creates both .json and .txt)")
=======
	fmt.Printf("  %s  %s\n", yellow("-o"), "Output filename (creates .json and .txt files)")
	fmt.Printf("  %s  %s\n", yellow("-deep"), "Enable deep scanning of discovered JS files")
	fmt.Printf("  %s  %s\n", yellow("-depth"), "Maximum depth for recursive scanning (default: 3)")
>>>>>>> bcdac2b92c7d2a18591b9f88d2c118c88011522b
	fmt.Printf("  %s  %s\n", yellow("-h"), "Show this help message")
	fmt.Printf("\n%s\n", blue("📁 Output Files:"))
	fmt.Printf("  %s  %s\n", cyan("filename.json"), "Detailed results with metadata and depth info")
	fmt.Printf("  %s  %s\n", cyan("filename.txt"), "Clean paths and URLs only")
	fmt.Printf("\n%s\n", blue("🎯 Pipeline Examples:"))
	fmt.Printf("  • %s\n", white("cat urls.txt | ./kodok -o output"))
	fmt.Printf("  • %s\n", white("grep 'example.com' logs.txt | ./kodok -H 'Auth: token' -deep"))
	fmt.Printf("  • %s\n", white("subfinder -d example.com | ./kodok -o results"))
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
		"session", "token", "jwt", "apikey", "secret",
	}
	
	lowerKey := strings.ToLower(key)
	for _, sensitive := range sensitiveHeaders {
		if strings.Contains(lowerKey, sensitive) {
			if len(value) <= 8 {
				return strings.Repeat("*", len(value))
			}
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

	// Handle relative URLs
	if strings.HasPrefix(rawURL, "/") || strings.HasPrefix(rawURL, "./") || strings.HasPrefix(rawURL, "../") {
		return true // Allow relative URLs
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	host := parsedURL.Hostname()
	if host == "" {
		return true // Allow URLs without hostname (relative paths)
	}

	for _, domain := range allowedDomains {
		if strings.HasSuffix(host, domain) || host == domain {
			return true
		}
	}
	return false
}

func isAllowedDomainForSecret(secret string, allowedDomains []string) bool {
	if len(allowedDomains) == 0 {
		return true
	}

	for _, domain := range allowedDomains {
		if strings.Contains(secret, domain) {
			return true
		}
	}
	
	return true
}

<<<<<<< HEAD
// writeJSONResults writes comprehensive JSON output with metadata
func writeJSONResults(file *os.File, results []ScanResult) {
	totalPaths := 0
	totalSecrets := 0
	successfulScans := 0
	skippedScans := 0
	failedScans := 0

	for _, result := range results {
		if result.Error != "" {
			failedScans++
		} else if result.Skipped {
			skippedScans++
		} else {
			successfulScans++
		}
		totalPaths += result.PathCount
		totalSecrets += result.SecretCount
	}

	jsonOutput := JSONOutput{
		TotalURLs:       len(results),
		SuccessfulScans: successfulScans,
		FailedScans:     failedScans,
		SkippedScans:    skippedScans,
		TotalPaths:      totalPaths,
		TotalSecrets:    totalSecrets,
		ScanDate:        time.Now().Format(time.RFC3339),
		Results:         results,
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.Encode(jsonOutput)
}

// writeTXTResults writes clean text output with discovered URLs and paths
func writeTXTResults(file *os.File, results []ScanResult) {
	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// Write header
	writer.WriteString("=====================================\n")
	writer.WriteString("           KODOK SCAN RESULTS        \n")
	writer.WriteString("=====================================\n\n")

=======
func writeJSONResults(file *os.File, results []ScanResult) {
>>>>>>> bcdac2b92c7d2a18591b9f88d2c118c88011522b
	totalPaths := 0
	totalSecrets := 0
	successfulScans := 0
	skippedScans := 0

	// Write all discovered URLs and paths in clean format
	writer.WriteString("DISCOVERED URLS AND PATHS:\n")
	writer.WriteString(strings.Repeat("-", 40) + "\n")

	for _, result := range results {
<<<<<<< HEAD
		totalUrls++
		
		// Write the original URL
		writer.WriteString(fmt.Sprintf("%s\n", result.URL))

		if result.Error != "" {
			continue
		}

		if result.Skipped {
			skippedScans++
			continue
		}

		successfulScans++
		totalPaths += result.PathCount
		totalSecrets += result.SecretCount

		// Write all paths found
		for _, path := range result.Paths {
			writer.WriteString(fmt.Sprintf("%s\n", path))
		}
	}

	writer.WriteString("\n" + strings.Repeat("=", 40) + "\n")
	writer.WriteString("SECRETS FOUND:\n")
	writer.WriteString(strings.Repeat("-", 40) + "\n")

	// Write secrets section
	for _, result := range results {
		if len(result.Secrets) > 0 {
			writer.WriteString(fmt.Sprintf("\nFrom: %s\n", result.URL))
			for _, secret := range result.Secrets {
				writer.WriteString(fmt.Sprintf("  %s\n", secret))
			}
		}
	}

	// Write overall summary
	writer.WriteString("\n" + strings.Repeat("=", 40) + "\n")
	writer.WriteString("OVERALL SUMMARY:\n")
	writer.WriteString(strings.Repeat("-", 40) + "\n")
	writer.WriteString(fmt.Sprintf("Total URLs Processed: %d\n", totalUrls))
	writer.WriteString(fmt.Sprintf("Successful Scans: %d\n", successfulScans))
	writer.WriteString(fmt.Sprintf("Skipped URLs: %d\n", skippedScans))
	writer.WriteString(fmt.Sprintf("Failed Scans: %d\n", totalUrls-successfulScans-skippedScans))
	writer.WriteString(fmt.Sprintf("Total Paths Found: %d\n", totalPaths))
	writer.WriteString(fmt.Sprintf("Total Secrets Found: %d\n", totalSecrets))
	writer.WriteString(strings.Repeat("=", 40) + "\n")
=======
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

	fullURLs := make(map[string]bool)
	relativePaths := make(map[string]bool)
	
	for _, result := range results {
		if result.Error == "" {
			fullURLs[result.URL] = true

			for _, path := range result.Paths {
				if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
					fullURLs[path] = true
				} else if strings.HasPrefix(path, "/") {
					relativePaths[path] = true
				}
			}
		}
	}

	var sortedURLs []string
	for url := range fullURLs {
		sortedURLs = append(sortedURLs, url)
	}
	sort.Strings(sortedURLs)
	
	for _, url := range sortedURLs {
		writer.WriteString(url + "\n")
	}

	var sortedPaths []string
	for path := range relativePaths {
		sortedPaths = append(sortedPaths, path)
	}
	sort.Strings(sortedPaths)
	
	for _, path := range sortedPaths {
		writer.WriteString(path + "\n")
	}
>>>>>>> bcdac2b92c7d2a18591b9f88d2c118c88011522b
}