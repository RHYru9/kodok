package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"

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
	outputFile    = flag.String("o", "", "File output untuk menyimpan hasil")
	headers       headersFlag
	showHelp      = flag.Bool("h", false, "Show help")
)

var validPathRegex = regexp.MustCompile(`^(https?://|/)[^\s]+`)

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

	// Display header information
	if len(customHeaders) > 0 {
		blue := color.New(color.FgBlue).SprintFunc()
		cyan := color.New(color.FgCyan).SprintFunc()
		fmt.Printf("%s %s\n", blue("[i] Using"), cyan(fmt.Sprintf("%d custom headers", len(customHeaders))))
		for key, value := range customHeaders {
			maskedValue := maskSensitiveHeader(key, value)
			fmt.Printf("│   %s: %s\n", key, maskedValue)
		}
		fmt.Println()
	}

	// Setup output file if specified
	var outputWriter *os.File
	if *outputFile != "" {
		var err error
		outputWriter, err = os.Create(*outputFile)
		if err != nil {
			fmt.Printf("Gagal membuat file output: %s\n", err)
			return
		}
		defer outputWriter.Close()
		fmt.Printf("Output akan disimpan ke: %s\n", *outputFile)
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 5) // Batasi 5 goroutine untuk efisiensi CPU
	var results []ScanResult
	var resultsMutex sync.Mutex

	for _, url := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}
			result := processURL(url, allowedDomains, customHeaders)
			if outputWriter != nil {
				resultsMutex.Lock()
				results = append(results, result)
				resultsMutex.Unlock()
			}
			<-sem
		}(url)
	}
	wg.Wait()

	// Write results to file if output file is specified
	if outputWriter != nil {
		writeResultsToFile(outputWriter, results)
		fmt.Printf("\nHasil berhasil disimpan ke: %s\n", *outputFile)
	}
}

func getURLs() []string {
	var urls []string

	if *urlFile != "" {
		file, err := os.Open(*urlFile)
		if err != nil {
			fmt.Printf("Gagal membuka file: %s\n", err)
			return nil
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			urls = append(urls, scanner.Text())
		}
	} else if *singleURL != "" {
		urls = append(urls, *singleURL)
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				urls = append(urls, scanner.Text())
			}
		}
	}
	return urls
}

// ScanResult holds the results for a single URL scan
type ScanResult struct {
	URL         string
	Paths       []string
	Secrets     []string
	PathCount   int
	SecretCount int
	Error       string
}

func processURL(url string, allowedDomains []string, customHeaders map[string]string) ScanResult {
	// Color definitions
	blue := color.New(color.FgBlue, color.Bold).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	white := color.New(color.FgWhite).SprintFunc()

	// Header dengan separator
	fmt.Printf("\n%s\n", strings.Repeat("─", 80))
	fmt.Printf("%s %s\n", blue("🔍 Scanning:"), cyan(url))
	fmt.Printf("%s\n", strings.Repeat("─", 80))

	content, err := fetcher.FetchWithHeaders(url, customHeaders)
	if err != nil {
		fmt.Printf("%s %s %s\n", red("✗"), white("Error:"), err)
		return ScanResult{
			URL:   url,
			Error: err.Error(),
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
		if validPathRegex.MatchString(path) && isAllowedDomain(path, allowedDomains) {
			mu.Lock()
			if !uniquePaths[path] {
				uniquePaths[path] = true
				pathCount++
				resultPaths = append(resultPaths, path)
				fmt.Printf("  %s %s\n", green("→"), formatPath(path))
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
		URL:         url,
		Paths:       resultPaths,
		Secrets:     resultSecrets,
		PathCount:   pathCount,
		SecretCount: secretCount,
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
	
	fmt.Printf("\n%s\n", blue("KODOK - JavaScript Security Scanner"))
	fmt.Printf("%s\n\n", strings.Repeat("═", 50))
	
	fmt.Printf("%s\n", blue("📋 Basic Usage:"))
	fmt.Printf("  %s\n", green("./kodok -u https://example.com/app.js"))
	fmt.Printf("  %s\n", green("./kodok -fj urls.txt"))
	fmt.Printf("  %s\n\n", green("./kodok -u https://example.com/app.js -o results.txt"))
	
	fmt.Printf("%s\n", blue("🔐 With Authentication:"))
	fmt.Printf("  %s\n", cyan("./kodok -u https://example.com/app.js -H 'Cookie: session=abc123'"))
	fmt.Printf("  %s\n", cyan("./kodok -u https://example.com/api.js -H 'Authorization: Bearer token123'"))
	fmt.Printf("  %s\n\n", cyan("./kodok -fj urls.txt -H 'X-API-Key: your-key' -o results.txt"))
	
	fmt.Printf("%s\n", blue("⚙️  Command Options:"))
	fmt.Printf("  %s  %s\n", yellow("-u"), "Target URL to scan")
	fmt.Printf("  %s  %s\n", yellow("-fj"), "File containing JavaScript URLs")
	fmt.Printf("  %s  %s\n", yellow("-H"), "Custom header (can be used multiple times)")
	fmt.Printf("  %s  %s\n", yellow("-ad"), "Allow domains (comma-separated)")
	fmt.Printf("  %s  %s\n", yellow("-o"), "Output file for results")
	fmt.Printf("  %s  %s\n", yellow("-h"), "Show this help message")
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

func extractSecretValue(formattedSecret string) string {
	// Extract the actual secret value from formatted string
	parts := strings.SplitN(formattedSecret, ": ", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return formattedSecret
}

func writeResultsToFile(file *os.File, results []ScanResult) {
	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// Write header
	writer.WriteString("=====================================\n")
	writer.WriteString("           KODOK SCAN RESULTS        \n")
	writer.WriteString("=====================================\n\n")

	totalPaths := 0
	totalSecrets := 0
	totalUrls := 0
	successfulScans := 0

	for _, result := range results {
		totalUrls++
		writer.WriteString(fmt.Sprintf("URL: %s\n", result.URL))
		writer.WriteString(strings.Repeat("-", 80) + "\n")

		if result.Error != "" {
			writer.WriteString(fmt.Sprintf("ERROR: %s\n\n", result.Error))
			continue
		}

		successfulScans++
		totalPaths += result.PathCount
		totalSecrets += result.SecretCount

		// Write paths
		if len(result.Paths) > 0 {
			writer.WriteString("PATHS FOUND:\n")
			for i, path := range result.Paths {
				writer.WriteString(fmt.Sprintf("  %d. %s\n", i+1, path))
			}
			writer.WriteString("\n")
		}

		// Write secrets
		if len(result.Secrets) > 0 {
			writer.WriteString("SECRETS FOUND:\n")
			for i, secret := range result.Secrets {
				writer.WriteString(fmt.Sprintf("  %d. %s\n", i+1, secret))
			}
			writer.WriteString("\n")
		}

		// Write summary for this URL
		writer.WriteString(fmt.Sprintf("SUMMARY: Paths: %d | Secrets: %d\n", result.PathCount, result.SecretCount))
		writer.WriteString(strings.Repeat("=", 80) + "\n\n")
	}

	// Write overall summary
	writer.WriteString("OVERALL SUMMARY:\n")
	writer.WriteString(strings.Repeat("-", 40) + "\n")
	writer.WriteString(fmt.Sprintf("Total URLs Processed: %d\n", totalUrls))
	writer.WriteString(fmt.Sprintf("Successful Scans: %d\n", successfulScans))
	writer.WriteString(fmt.Sprintf("Failed Scans: %d\n", totalUrls-successfulScans))
	writer.WriteString(fmt.Sprintf("Total Paths Found: %d\n", totalPaths))
	writer.WriteString(fmt.Sprintf("Total Secrets Found: %d\n", totalSecrets))
	writer.WriteString(strings.Repeat("=", 40) + "\n")
}