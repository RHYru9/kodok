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
	"time"

	"github.com/rhyru9/kodok/internal/fetcher"
	"github.com/rhyru9/kodok/internal/parser"
	"github.com/rhyru9/kodok/internal/scanner"
	"github.com/rhyru9/kodok/internal/utils"

	"github.com/fatih/color"
)

// Command line flags
var (
	urlFile       = flag.String("fj", "", "File berisi daftar URL JavaScript untuk diproses")
	singleURL     = flag.String("u", "", "URL tunggal yang akan diproses")
	allowedDomain = flag.String("ad", "", "Domain yang diizinkan dalam output (pisahkan dengan koma)")
	headers       headerFlags
)

// headerFlags adalah custom flag type untuk multiple headers
type headerFlags []string

func (h *headerFlags) String() string {
	return strings.Join(*h, ", ")
}

func (h *headerFlags) Set(value string) error {
	*h = append(*h, value)
	return nil
}

// Regular expression untuk validasi path
var (
	validPathRegex = regexp.MustCompile(`^(https?://|/)[^\s]+`)
	dataURIRegex   = regexp.MustCompile(`(?i)^data:[^;]+;base64,`)
)

// Color definitions
var (
	blue    = color.New(color.FgBlue).SprintFunc()
	cyan    = color.New(color.FgCyan).SprintFunc()
	magenta = color.New(color.FgMagenta).SprintFunc()
	red     = color.New(color.FgRed).SprintFunc()
	yellow  = color.New(color.FgYellow).SprintFunc()
	green   = color.New(color.FgGreen).SprintFunc()
)

const (
	workerCount = 3
	timeout     = 10 * time.Second
)

func main() {
	flag.Var(&headers, "H", "Custom HTTP headers (dapat digunakan multiple kali)\nContoh: -H 'Cookie: test=value' -H 'Authorization: Bearer token'")
	flag.Parse()
	utils.PrintBanner()

	allowedDomains := parseAllowedDomains(*allowedDomain)
	customHeaders := parseHeaders(headers)
	urls := getURLs()

	if len(urls) == 0 {
		fmt.Printf("%s Tidak ada URL yang diberikan. Gunakan -fj untuk file atau -u untuk URL tunggal.\n", 
			red("[!]"))
		fmt.Printf("%s Contoh: %s -u https://example.com/app.js\n", 
			cyan("[i]"), os.Args[0])
		fmt.Printf("%s Dengan headers: %s -u https://example.com/app.js -H 'Cookie: session=abc123'\n", 
			cyan("[i]"), os.Args[0])
		return
	}

	fmt.Printf("%s Memproses %d URL dengan %d worker...\n", 
		green("[+]"), len(urls), workerCount)
	
	if len(customHeaders) > 0 {
		fmt.Printf("%s Menggunakan %d custom headers\n", 
			cyan("[i]"), len(customHeaders))
		for key, value := range customHeaders {
			// Mask sensitive headers
			displayValue := value
			if isSensitiveHeader(key) {
				displayValue = maskSensitiveValue(value)
			}
			fmt.Printf("%s   %s: %s\n", cyan("│"), magenta(key), displayValue)
		}
	}
	fmt.Println()

	processURLsConcurrently(urls, allowedDomains, customHeaders)
}

// getURLs mengambil daftar URL dari berbagai sumber input
func getURLs() []string {
	var urls []string

	switch {
	case *urlFile != "":
		urls = readURLsFromFile(*urlFile)
	case *singleURL != "":
		urls = append(urls, *singleURL)
	default:
		urls = readURLsFromStdin()
	}

	return filterValidURLs(urls)
}

// readURLsFromFile membaca URL dari file
func readURLsFromFile(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("%s Gagal membuka file %s: %v\n", red("[!]"), filename, err)
		return nil
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("%s Error membaca file: %v\n", red("[!]"), err)
	}

	return urls
}

// readURLsFromStdin membaca URL dari standard input
func readURLsFromStdin() []string {
	stat, err := os.Stdin.Stat()
	if err != nil || (stat.Mode()&os.ModeCharDevice) != 0 {
		return nil
	}

	var urls []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}

	return urls
}

// filterValidURLs memfilter URL yang valid
func filterValidURLs(urls []string) []string {
	var validURLs []string
	for _, rawURL := range urls {
		if isValidURL(rawURL) || isLocalFile(rawURL) {
			validURLs = append(validURLs, rawURL)
		} else {
			fmt.Printf("%s URL tidak valid diabaikan: %s\n", yellow("[!]"), rawURL)
		}
	}
	return validURLs
}

// isValidURL memeriksa apakah string adalah URL yang valid
func isValidURL(rawURL string) bool {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return false
	}
	_, err := url.Parse(rawURL)
	return err == nil
}

// processURLsConcurrently memproses URL secara concurrent
func processURLsConcurrently(urls []string, allowedDomains []string, customHeaders map[string]string) {
	var wg sync.WaitGroup
	urlChan := make(chan string, len(urls))

	// Start worker goroutines
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for url := range urlChan {
				processURL(url, allowedDomains, customHeaders, workerID)
			}
		}(i + 1)
	}

	// Send URLs to channel
	for _, url := range urls {
		urlChan <- url
	}
	close(urlChan)

	wg.Wait()
	fmt.Printf("\n%s Pemrosesan selesai.\n", green("[✓]"))
}

// processURL memproses satu URL dan mencari path serta secrets
func processURL(target string, allowedDomains []string, customHeaders map[string]string, workerID int) {
	fmt.Printf("%s [Worker-%d] Memproses: %s\n", blue("[+]"), workerID, cyan(target))

	content, err := getContent(target, customHeaders)
	if err != nil {
		fmt.Printf("%s [Worker-%d] Gagal mengambil konten dari %s: %v\n", 
			red("[!]"), workerID, target, err)
		return
	}

	if len(content) == 0 {
		fmt.Printf("%s [Worker-%d] Konten kosong dari %s\n", 
			yellow("[!]"), workerID, target)
		return
	}

	// Process paths and secrets concurrently
	var wg sync.WaitGroup
	pathResults := make(chan string, 100)
	secretResults := make(chan string, 100)

	// Parse paths
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(pathResults)
		
		paths := parser.Parse(content)
		uniquePaths := make(map[string]bool)
		
		for _, path := range paths {
			if validPathRegex.MatchString(path) && 
			   isAllowedDomain(path, allowedDomains) && 
			   !isDataURI(path) && 
			   !isLikelyBase64Content(path) {
				if !uniquePaths[path] {
					uniquePaths[path] = true
					pathResults <- path
				}
			}
		}
	}()

	// Scan for secrets
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(secretResults)
		
		secrets := scanner.Scan(content)
		uniqueSecrets := make(map[string]bool)
		
		for _, secret := range secrets {
			if isAllowedDomain(secret, allowedDomains) && 
			   !isDataURI(secret) && 
			   !isLikelyBase64Content(secret) {
				if !uniqueSecrets[secret] {
					uniqueSecrets[secret] = true
					secretResults <- secret
				}
			}
		}
	}()

	// Collect results
	go func() {
		wg.Wait()
	}()

	// Print results as they come
	var pathCount, secretCount int
	
	for {
		select {
		case path, ok := <-pathResults:
			if !ok {
				pathResults = nil
			} else {
				fmt.Printf("  %s %-20s %s\n", cyan("│ PATH   │"), magenta(path), "")
				pathCount++
			}
		case secret, ok := <-secretResults:
			if !ok {
				secretResults = nil
			} else {
				fmt.Printf("  %s %-20s %s\n", blue("│ SECRET │"), red(secret), yellow("(possible)"))
				secretCount++
			}
		}
		
		if pathResults == nil && secretResults == nil {
			break
		}
	}

	fmt.Printf("%s [Worker-%d] Selesai: %s - Ditemukan %d path, %d secret\n\n", 
		green("[✓]"), workerID, target, pathCount, secretCount)
}

// getContent mengambil konten dari URL atau file lokal
func getContent(target string, customHeaders map[string]string) (string, error) {
	if isLocalFile(target) {
		return readLocalFile(target)
	}
	return fetchURL(target, customHeaders)
}

// isLocalFile memeriksa apakah path adalah file lokal
func isLocalFile(path string) bool {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// readLocalFile membaca konten dari file lokal
func readLocalFile(filePath string) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("gagal membaca file %s: %w", filePath, err)
	}
	return string(content), nil
}

// fetchURL mengambil konten dari URL dengan timeout dan custom headers
func fetchURL(target string, customHeaders map[string]string) (string, error) {
	type result struct {
		content string
		err     error
	}

	resultChan := make(chan result, 1)

	go func() {
		content, err := fetcher.FetchWithHeaders(target, customHeaders)
		resultChan <- result{content: content, err: err}
	}()

	select {
	case res := <-resultChan:
		return res.content, res.err
	case <-time.After(timeout):
		return "", fmt.Errorf("timeout setelah %v saat mengambil konten dari %s", timeout, target)
	}
}

// parseAllowedDomains memparse string domain yang diizinkan
func parseAllowedDomains(domainStr string) []string {
	if domainStr == "" {
		return nil
	}

	domains := strings.Split(domainStr, ",")
	var cleanedDomains []string

	for _, domain := range domains {
		cleaned := strings.TrimSpace(domain)
		if cleaned != "" {
			cleanedDomains = append(cleanedDomains, cleaned)
		}
	}

	return cleanedDomains
}

// isAllowedDomain memeriksa apakah URL termasuk dalam domain yang diizinkan
func isAllowedDomain(rawURL string, allowedDomains []string) bool {
	if len(allowedDomains) == 0 {
		return true
	}

	// Handle relative paths
	if strings.HasPrefix(rawURL, "/") {
		return true
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	host := parsedURL.Hostname()
	if host == "" {
		return true // Allow relative URLs
	}

	for _, domain := range allowedDomains {
		if strings.HasSuffix(host, domain) || host == domain {
			return true
		}
	}

	return false
}

// parseHeaders memparse header flags menjadi map
func parseHeaders(headerFlags []string) map[string]string {
	headers := make(map[string]string)
	
	for _, header := range headerFlags {
		// Parse header dalam format "Key: Value"
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if key != "" && value != "" {
				headers[key] = value
			}
		} else {
			fmt.Printf("%s Header format tidak valid diabaikan: %s\n", yellow("[!]"), header)
			fmt.Printf("%s Format yang benar: 'Key: Value'\n", cyan("[i]"))
		}
	}
	
	return headers
}

// isSensitiveHeader memeriksa apakah header mengandung informasi sensitif
func isSensitiveHeader(key string) bool {
	sensitiveHeaders := []string{
		"authorization", "cookie", "x-api-key", "api-key", 
		"x-auth-token", "auth-token", "x-access-token", 
		"access-token", "bearer", "jwt", "session",
	}
	
	keyLower := strings.ToLower(key)
	for _, sensitive := range sensitiveHeaders {
		if strings.Contains(keyLower, sensitive) {
			return true
		}
	}
	
	return false
}

// maskSensitiveValue menyembunyikan sebagian nilai header sensitif
func maskSensitiveValue(value string) string {
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}
	
	// Show first 4 and last 4 characters, mask the middle
	prefix := value[:4]
	suffix := value[len(value)-4:]
	middle := strings.Repeat("*", len(value)-8)
	
	return prefix + middle + suffix
}

// isDataURI memeriksa apakah string adalah data URI
func isDataURI(path string) bool {
	return dataURIRegex.MatchString(path) || 
		   strings.HasPrefix(strings.ToLower(path), "data:") ||
		   strings.HasPrefix(strings.ToLower(path), "blob:")
}

// isLikelyBase64Content memeriksa apakah string kemungkinan berisi base64
func isLikelyBase64Content(path string) bool {
	// Skip very long strings that are likely base64
	if len(path) > 500 {
		return true
	}
	
	// Check for base64 patterns
	if len(path) > 100 {
		// Count base64 characters
		base64Chars := 0
		totalChars := len(path)
		
		for _, r := range path {
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || 
			   (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=' {
				base64Chars++
			}
		}
		
		// If more than 80% are base64 characters, likely base64
		if float64(base64Chars)/float64(totalChars) > 0.8 {
			return true
		}
	}
	
	// Check for common base64 image signatures
	base64ImagePatterns := []string{
		"iVBORw0KGgoAAAANSUhEUgAA", // PNG signature
		"R0lGODlhAQABAIAAAAAAAP",   // GIF signature  
		"/9j/4AAQSkZJRgABAQAAAQABAAD", // JPEG signature
		"PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmci", // SVG signature
	}
	
	for _, pattern := range base64ImagePatterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}
	
	return false
}