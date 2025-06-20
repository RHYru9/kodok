package parser

import (
	"regexp"
	"strings"
)

// Regular expressions untuk berbagai jenis path dan URL
var (
	// URL patterns
	fullURLRegex = regexp.MustCompile(`(?i)(?:"|'|` + "`" + `)(https?://[^\s"'` + "`" + `<>(){}[\]]+)(?:"|'|` + "`" + `)`)
	
	// Path patterns
	absolutePathRegex = regexp.MustCompile(`(?:"|'|` + "`" + `)(\/[^\s"'` + "`" + `<>(){}[\]]*[^\s"'` + "`" + `<>(){}[\].,;])(?:"|'|` + "`" + `)`)
	relativePathRegex = regexp.MustCompile(`(?:"|'|` + "`" + `)(\.\.?\/[^\s"'` + "`" + `<>(){}[\]]*[^\s"'` + "`" + `<>(){}[\].,;])(?:"|'|` + "`" + `)`)
	
	// API endpoints
	apiPathRegex = regexp.MustCompile(`(?:"|'|` + "`" + `)(\/(?:api|v\d+|rest|graphql)\/[^\s"'` + "`" + `<>(){}[\]]*[^\s"'` + "`" + `<>(){}[\].,;])(?:"|'|` + "`" + `)`)
	
	// Static resources
	staticResourceRegex = regexp.MustCompile(`(?:"|'|` + "`" + `)(\/[^\s"'` + "`" + `<>(){}[\]]*\.(?:js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|pdf|zip|json|xml|txt|map))(?:"|'|` + "`" + `)`)
	
	// Clean up patterns
	cleanupRegex = regexp.MustCompile(`[?&#][^"'` + "`" + `\s]*$`)
	
	// Data URI pattern
	dataURIRegex = regexp.MustCompile(`(?i)^data:[a-z]+\/[a-z]+;base64,`)
)

// Parse mengekstrak semua path dan URL dari konten JavaScript
func Parse(content string) []string {
	if content == "" {
		return nil
	}

	uniqueResults := make(map[string]bool)
	
	// Extract different types of URLs and paths
	extractMatches(content, fullURLRegex, uniqueResults)
	extractMatches(content, absolutePathRegex, uniqueResults)
	extractMatches(content, relativePathRegex, uniqueResults)
	extractMatches(content, apiPathRegex, uniqueResults)
	extractMatches(content, staticResourceRegex, uniqueResults)
	
	// Convert map to slice
	results := make([]string, 0, len(uniqueResults))
	for match := range uniqueResults {
		if isValidPath(match) {
			results = append(results, match)
		}
	}
	
	return results
}

// extractMatches mengekstrak matches dari regex dan menambahkannya ke map
func extractMatches(content string, regex *regexp.Regexp, results map[string]bool) {
	matches := regex.FindAllStringSubmatch(content, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			cleaned := cleanPath(match[1])
			if cleaned != "" && !results[cleaned] && !isDataURI(cleaned) {
				results[cleaned] = true
			}
		}
	}
}

// cleanPath membersihkan path dari karakter yang tidak diinginkan
func cleanPath(path string) string {
	// Remove quotes and backticks
	path = strings.Trim(path, `"'` + "`")
	
	// Remove trailing punctuation and fragments
	path = cleanupRegex.ReplaceAllString(path, "")
	
	// Remove trailing punctuation
	path = strings.TrimRight(path, ".,;:!?")
	
	// Trim whitespace
	path = strings.TrimSpace(path)
	
	return path
}

// isValidPath memeriksa apakah path valid
func isValidPath(path string) bool {
	if path == "" {
		return false
	}
	
	// Skip very short paths
	if len(path) < 2 {
		return false
	}
	
	// Skip data URIs (base64 images, SVG, etc.)
	if strings.HasPrefix(strings.ToLower(path), "data:") {
		return false
	}
	
	// Skip blob URLs
	if strings.HasPrefix(strings.ToLower(path), "blob:") {
		return false
	}
	
	// Skip javascript: and other protocol schemes
	protocolsToSkip := []string{
		"javascript:", "mailto:", "tel:", "sms:", "ftp:", "file:",
		"chrome:", "chrome-extension:", "moz-extension:", "safari-extension:",
	}
	
	pathLower := strings.ToLower(path)
	for _, protocol := range protocolsToSkip {
		if strings.HasPrefix(pathLower, protocol) {
			return false
		}
	}
	
	// Skip common false positives
	invalidPaths := []string{
		"/", "//", "///",
		"./", "../", 
		"http://", "https://",
		"*/", "*//*",
	}
	
	for _, invalid := range invalidPaths {
		if path == invalid {
			return false
		}
	}
	
	// Skip paths with only special characters
	if strings.Trim(path, "/.?&=#-_") == "" {
		return false
	}
	
	// Skip very long paths (likely base64 or minified content)
	if len(path) > 500 {
		return false
	}
	
	// Skip paths that look like base64 content
	if isLikelyBase64Content(path) {
		return false
	}
	
	// Must start with valid characters
	validStarts := []string{"http://", "https://", "/", "./", "../"}
	isValidStart := false
	for _, start := range validStarts {
		if strings.HasPrefix(path, start) {
			isValidStart = true
			break
		}
	}
	
	return isValidStart
}

// isDataURI memeriksa apakah string adalah data URI
func isDataURI(path string) bool {
	return dataURIRegex.MatchString(path) || 
		   strings.HasPrefix(strings.ToLower(path), "data:") ||
		   strings.HasPrefix(strings.ToLower(path), "blob:")
}

// ParseURLs khusus untuk mengekstrak URL lengkap saja
func ParseURLs(content string) []string {
	if content == "" {
		return nil
	}

	uniqueResults := make(map[string]bool)
	extractMatches(content, fullURLRegex, uniqueResults)
	
	results := make([]string, 0, len(uniqueResults))
	for match := range uniqueResults {
		if isValidURL(match) {
			results = append(results, match)
		}
	}
	
	return results
}

// ParsePaths khusus untuk mengekstrak path saja (tanpa URL lengkap)
func ParsePaths(content string) []string {
	if content == "" {
		return nil
	}

	uniqueResults := make(map[string]bool)
	extractMatches(content, absolutePathRegex, uniqueResults)
	extractMatches(content, relativePathRegex, uniqueResults)
	extractMatches(content, apiPathRegex, uniqueResults)
	extractMatches(content, staticResourceRegex, uniqueResults)
	
	results := make([]string, 0, len(uniqueResults))
	for match := range uniqueResults {
		if isValidPath(match) && !strings.HasPrefix(match, "http") {
			results = append(results, match)
		}
	}
	
	return results
}

// isValidURL memeriksa apakah string adalah URL yang valid
func isValidURL(rawURL string) bool {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return false
	}
	
	// Skip data URIs
	if strings.HasPrefix(strings.ToLower(rawURL), "data:") {
		return false
	}
	
	// Skip blob URLs
	if strings.HasPrefix(strings.ToLower(rawURL), "blob:") {
		return false
	}
	
	// Basic validation
	if len(rawURL) < 10 { // Minimal length for valid URL
		return false
	}
	
	// Should have domain part
	if !strings.Contains(rawURL[8:], ".") {
		return false
	}
	
	// Skip very long URLs (likely containing base64)
	if len(rawURL) > 1000 {
		return false
	}
	
	return true
}

// isLikelyBase64Content memeriksa apakah string kemungkinan berisi base64
func isLikelyBase64Content(path string) bool {
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
	
	// Check for common base64 patterns in URLs
	base64Patterns := []string{
		"base64,", "charset=", "encoding=", 
		"iVBORw0KGgoAAAANSUhEUgAA", // PNG signature in base64
		"R0lGODlhAQABAIAAAAAAAP", // GIF signature in base64
		"/9j/4AAQSkZJRgABAQAAAQABAAD", // JPEG signature in base64
		"PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmci", // SVG in base64
	}
	
	pathLower := strings.ToLower(path)
	for _, pattern := range base64Patterns {
		if strings.Contains(pathLower, strings.ToLower(pattern)) {
			return true
		}
	}
	
	return false
}