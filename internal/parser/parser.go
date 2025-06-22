package parser

import (
	"regexp"
	"strings"
)

func Parse(content string) []string {
	regex := regexp.MustCompile(`(?:"|')(https?:\/\/[^"'\/]+[^"']*|(?:\/|\.\.?\/)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]*)(?:"|')`)
	matches := regex.FindAllString(content, -1)
	uniqueMatches := make(map[string]bool)

	for _, match := range matches {
		cleanedMatch := match[1 : len(match)-1]
		
		// Skip jika URL adalah image, SVG, atau base64
		if isImageOrSVG(cleanedMatch) {
			continue
		}
		
		uniqueMatches[cleanedMatch] = true
	}

	var results []string
	for match := range uniqueMatches {
		results = append(results, match)
	}
	return results
}

// isImageOrSVG mengecek apakah URL adalah gambar, SVG, atau base64
func isImageOrSVG(url string) bool {
	url = strings.ToLower(url)
	
	// Cek ekstensi file gambar umum
	imageExtensions := []string{
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", 
		".svg", ".ico", ".tiff", ".tga", ".psd", ".eps",
	}
	
	for _, ext := range imageExtensions {
		if strings.HasSuffix(url, ext) {
			return true
		}
	}
	
	// Cek base64 data URI untuk gambar
	if strings.HasPrefix(url, "data:image/") {
		return true
	}
	
	// Cek SVG data URI
	if strings.HasPrefix(url, "data:image/svg+xml") {
		return true
	}
	// Cek base64 string yang panjang (kemungkinan embedded content)
	if len(url) > 500 && strings.Contains(url, "base64") {
		return true
	}
	

	
	return false
}