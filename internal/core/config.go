package core

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/rhyru9/kodok/pkg/types"
)

// ParseFlags parses command line flags and returns Config plus URL and FilePath
func ParseFlags() (*types.Config, string, string) {
	config := &types.Config{
		MaxWorkers:     10,
		MaxDepth:       3,
		CacheSize:      10000,
		RequestTimeout: 30 * time.Second,
		RetryAttempts:  3,
		CustomHeaders:  make(map[string]string),
		DeepScan:       false,
		OutputFile:     "kodok_results",
		Verbose:        false,
	}

	var (
		url          string
		filePath     string
		headers      string
		domains      string
		output       string
		maxWorkers   int
		maxDepth     int
		cacheSize    int
		timeout      int
		retries      int
		verbose      bool
		deepScan     bool
	)

	flag.StringVar(&url, "u", "", "Single URL to scan")
	flag.StringVar(&filePath, "f", "", "File containing URLs to scan (one per line)")
	flag.StringVar(&headers, "H", "", "Custom headers (format: 'Header1:Value1,Header2:Value2')")
	flag.StringVar(&domains, "ad", "", "Allowed domains (comma-separated)")
	flag.StringVar(&output, "o", "kodok_results", "Output base filename")
	flag.IntVar(&maxWorkers, "workers", 10, "Number of concurrent workers")
	flag.IntVar(&maxDepth, "depth", 3, "Maximum recursion depth")
	flag.IntVar(&cacheSize, "cache", 10000, "LRU cache size for deduplication")
	flag.IntVar(&timeout, "timeout", 30, "Request timeout in seconds")
	flag.IntVar(&retries, "retries", 3, "Number of retry attempts")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.BoolVar(&deepScan, "deep", false, "Enable deep scanning of JS files")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "🐸 KODOK - JavaScript Security Scanner\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nDomain Filtering Examples:\n")
		fmt.Fprintf(os.Stderr, "  -ad 'example.com'                   # Exact domain match\n")
		fmt.Fprintf(os.Stderr, "  -ad '*.example.com'                # All subdomains of example.com\n") 
		fmt.Fprintf(os.Stderr, "  -ad 'api.*.com,*.example.org'      # Multiple domains with wildcards\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -u https://example.com/app.js\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -f urls.txt -deep -depth 5 -o results -ad '*.example.com'\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -u https://target.com -H 'Authorization:Bearer token' -ad 'target.com,*.api.target.com'\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  cat urls.txt | %s -o results -ad '*.itb.ac.id,*.ui.ac.id'\n", os.Args[0])
	}

	flag.Parse()

	// Apply values to config
	config.MaxWorkers = maxWorkers
	config.MaxDepth = maxDepth
	config.CacheSize = cacheSize
	config.RequestTimeout = time.Duration(timeout) * time.Second
	config.RetryAttempts = retries
	config.DeepScan = deepScan
	config.OutputFile = output
	config.Verbose = verbose

	// Parse custom headers
	if headers != "" {
		headerPairs := strings.Split(headers, ",")
		for _, pair := range headerPairs {
			parts := strings.SplitN(pair, ":", 2)
			if len(parts) == 2 {
				config.CustomHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	// Parse allowed domains
	if domains != "" {
		config.AllowedDomains = strings.Split(domains, ",")
		for i, domain := range config.AllowedDomains {
			config.AllowedDomains[i] = strings.TrimSpace(domain)
		}
	}

	return config, url, filePath
}

// ValidateConfig validates the configuration
func ValidateConfig(config *types.Config) error {
	if config.MaxWorkers < 1 || config.MaxWorkers > 100 {
		return fmt.Errorf("workers must be between 1 and 100")
	}
	if config.MaxDepth < 0 || config.MaxDepth > 10 {
		return fmt.Errorf("depth must be between 0 and 10")
	}
	if config.CacheSize < 100 || config.CacheSize > 100000 {
		return fmt.Errorf("cache size must be between 100 and 100000")
	}
	if config.RequestTimeout < 1*time.Second || config.RequestTimeout > 300*time.Second {
		return fmt.Errorf("timeout must be between 1 and 300 seconds")
	}
	if config.RetryAttempts < 0 || config.RetryAttempts > 10 {
		return fmt.Errorf("retries must be between 0 and 10")
	}

	return nil
}

// ReadURLsFromFile reads URLs from a file
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
func GetURLsFromInput(singleURL, filePath string) ([]string, error) {
	var urls []string

	// Priority 1: Single URL from -u flag
	if singleURL != "" {
		urls = append(urls, singleURL)
		color.Green("📥 Got 1 URL from -u flag")
		return urls, nil
	}

	// Priority 2: File from -f flag
	if filePath != "" {
		fileURLs, err := ReadURLsFromFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %w", err)
		}
		urls = append(urls, fileURLs...)
		color.Green("📥 Read %d URLs from file: %s", len(fileURLs), filePath)

		if len(urls) > 0 {
			return deduplicateURLs(urls), nil
		}
	}

	// Priority 3: Read from stdin
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			url := strings.TrimSpace(scanner.Text())
			if url != "" && !strings.HasPrefix(url, "#") {
				urls = append(urls, url)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading from stdin: %w", err)
		}

		if len(urls) > 0 {
			color.Green("📥 Read %d URLs from stdin", len(urls))
			return deduplicateURLs(urls), nil
		}
	}

	// No URLs found
	return nil, fmt.Errorf("no URLs provided. Use -u for single URL, -f for file, or pipe URLs to stdin")
}

// deduplicateURLs removes duplicate URLs
func deduplicateURLs(urls []string) []string {
	seen := make(map[string]bool)
	unique := make([]string, 0, len(urls))

	for _, url := range urls {
		if !seen[url] {
			seen[url] = true
			unique = append(unique, url)
		}
	}

	if len(unique) < len(urls) {
		color.Yellow("⚠️  Removed %d duplicate URLs", len(urls)-len(unique))
	}

	color.Green("📝 Processing %d unique URLs", len(unique))
	return unique
}