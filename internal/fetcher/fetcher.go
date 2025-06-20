package fetcher

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTPClient interface untuk testing
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// DefaultClient adalah HTTP client default
var DefaultClient HTTPClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
	},
}

// Fetch mengambil konten dari URL (backward compatibility)
func Fetch(url string) (string, error) {
	return FetchWithHeaders(url, nil)
}

// FetchWithHeaders mengambil konten dari URL dengan custom headers
func FetchWithHeaders(url string, customHeaders map[string]string) (string, error) {
	if url == "" {
		return "", fmt.Errorf("URL tidak boleh kosong")
	}

	// Buat HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("gagal membuat request: %w", err)
	}

	// Set default headers
	setDefaultHeaders(req)

	// Set custom headers
	if customHeaders != nil {
		for key, value := range customHeaders {
			req.Header.Set(key, value)
		}
	}

	// Lakukan request
	resp, err := DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("gagal melakukan request: %w", err)
	}
	defer resp.Body.Close()

	// Cek status code
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP error: %d %s", resp.StatusCode, resp.Status)
	}

	// Baca response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("gagal membaca response body: %w", err)
	}

	return string(body), nil
}

// FetchWithConfig mengambil konten dengan konfigurasi lengkap
func FetchWithConfig(config FetchConfig) (string, error) {
	if config.URL == "" {
		return "", fmt.Errorf("URL tidak boleh kosong")
	}

	// Buat HTTP request
	method := config.Method
	if method == "" {
		method = "GET"
	}

	var body io.Reader
	if config.Body != "" {
		body = strings.NewReader(config.Body)
	}

	req, err := http.NewRequest(method, config.URL, body)
	if err != nil {
		return "", fmt.Errorf("gagal membuat request: %w", err)
	}

	// Set default headers
	setDefaultHeaders(req)

	// Set custom headers
	if config.Headers != nil {
		for key, value := range config.Headers {
			req.Header.Set(key, value)
		}
	}

	// Set Content-Type untuk POST/PUT
	if config.Body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	// Setup client dengan timeout custom
	client := DefaultClient
	if config.Timeout > 0 {
		client = &http.Client{
			Timeout: config.Timeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
			},
		}
	}

	// Lakukan request
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("gagal melakukan request: %w", err)
	}
	defer resp.Body.Close()

	// Cek status code
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP error: %d %s", resp.StatusCode, resp.Status)
	}

	// Baca response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("gagal membaca response body: %w", err)
	}

	return string(responseBody), nil
}

// FetchConfig adalah konfigurasi untuk request HTTP
type FetchConfig struct {
	URL     string
	Method  string
	Headers map[string]string
	Body    string
	Timeout time.Duration
}

// setDefaultHeaders mengset header default untuk request
func setDefaultHeaders(req *http.Request) {
	// Set User-Agent yang realistis
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	}
	
	// Gunakan User-Agent berdasarkan hash URL untuk konsistensi
	hash := 0
	for _, c := range req.URL.String() {
		hash = hash*31 + int(c)
	}
	if hash < 0 {
		hash = -hash
	}
	userAgent := userAgents[hash%len(userAgents)]
	
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,id;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
}

// BatchFetch mengambil multiple URL secara concurrent
func BatchFetch(urls []string, headers map[string]string, workers int) map[string]FetchResult {
	if workers <= 0 {
		workers = 5
	}

	results := make(map[string]FetchResult)
	resultsChan := make(chan FetchResult, len(urls))
	urlsChan := make(chan string, len(urls))

	// Start workers
	for i := 0; i < workers; i++ {
		go func() {
			for url := range urlsChan {
				content, err := FetchWithHeaders(url, headers)
				resultsChan <- FetchResult{
					URL:     url,
					Content: content,
					Error:   err,
				}
			}
		}()
	}

	// Send URLs to workers
	for _, url := range urls {
		urlsChan <- url
	}
	close(urlsChan)

	// Collect results
	for i := 0; i < len(urls); i++ {
		result := <-resultsChan
		results[result.URL] = result
	}

	return results
}

// FetchResult adalah hasil dari fetch operation
type FetchResult struct {
	URL     string
	Content string
	Error   error
}

// ValidateHeaders memvalidasi format headers
func ValidateHeaders(headers map[string]string) error {
	for key, value := range headers {
		if key == "" {
			return fmt.Errorf("header key tidak boleh kosong")
		}
		if value == "" {
			return fmt.Errorf("header value untuk '%s' tidak boleh kosong", key)
		}
		
		// Validasi karakter header key
		for _, char := range key {
			if char < 33 || char > 126 || char == ':' {
				return fmt.Errorf("header key '%s' mengandung karakter tidak valid", key)
			}
		}
	}
	
	return nil
}