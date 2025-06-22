package fetcher

import (
	"io"
	"net/http"
	"time"
)

// Fetch performs a basic GET request without custom headers (backward compatibility)
func Fetch(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	
	return string(body), nil
}

// FetchWithHeaders performs a GET request with custom headers support
func FetchWithHeaders(url string, headers map[string]string) (string, error) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Create new request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	// Set default User-Agent if not provided in custom headers
	if headers["User-Agent"] == "" {
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Kodok/1.0)")
	}

	// Set custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}