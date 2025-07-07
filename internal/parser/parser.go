package parser

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode"
)

func Parse(content string) []string {
	// Pre-filter: Remove obvious binary/base64 content blocks
	content = cleanBinaryContent(content)
	
	// Enhanced regex for better URL/path extraction
	regex := regexp.MustCompile(`(?:"|')((?:https?:\/\/[^"'\s<>]+|(?:\/|\.\.?\/)[^"'\s<>,;|*()\[\]{}\\]+))(?:"|')`)
	matches := regex.FindAllStringSubmatch(content, -1)
	uniqueMatches := make(map[string]bool)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		
		cleanedMatch := strings.TrimSpace(match[1])

		// Enhanced validation chain
		if !isValidPath(cleanedMatch) {
			continue
		}

		// Skip if URL is a blacklisted file
		if isBlacklistedFile(cleanedMatch) {
			continue
		}

		// Skip if contains unusual characters
		if containsUnusualCharacters(cleanedMatch) {
			continue
		}

		// Skip if looks like binary data
		if isLikelyBinaryData(cleanedMatch) {
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

// cleanBinaryContent removes large blocks of base64 or binary data
func cleanBinaryContent(content string) string {
	// Remove data URLs with base64 content
	dataURLRegex := regexp.MustCompile(`data:[^;]+;base64,[A-Za-z0-9+/=]{100,}`)
	content = dataURLRegex.ReplaceAllString(content, "")
	
	// Remove long base64 strings (likely embedded images/files)
	base64Regex := regexp.MustCompile(`[A-Za-z0-9+/=]{500,}`)
	content = base64Regex.ReplaceAllString(content, "")
	
	// Remove obvious binary chunks (sequences of non-printable characters)
	binaryRegex := regexp.MustCompile(`[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\xFF]{20,}`)
	content = binaryRegex.ReplaceAllString(content, "")
	
	return content
}

// isValidPath performs basic validation on extracted paths
func isValidPath(path string) bool {
	// Must have minimum length
	if len(path) < 2 {
		return false
	}
	
	// Must not exceed reasonable length
	if len(path) > 2000 {
		return false
	}
	
	// Must start with valid characters
	if !strings.HasPrefix(path, "http://") && 
	   !strings.HasPrefix(path, "https://") && 
	   !strings.HasPrefix(path, "/") && 
	   !strings.HasPrefix(path, "./") && 
	   !strings.HasPrefix(path, "../") {
		return false
	}
	
	// Must not be just special characters
	if matched, _ := regexp.MatchString(`^[^a-zA-Z0-9]+$`, path); matched {
		return false
	}
	
	return true
}

// isBlacklistedFile checks if URL/path is a blacklisted file type
func isBlacklistedFile(url string) bool {
	url = strings.ToLower(url)

	// Enhanced blacklist of file extensions
	blacklistedExtensions := []string{
		// Images
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".ico", 
		".tiff", ".tga", ".psd", ".eps", ".avif", ".jfif", ".pjpeg", ".pjp",
		".heic", ".heif", ".raw", ".cr2", ".nef", ".arw", ".dng",

		// Documents
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".odt", ".ods", ".odp", ".rtf", ".txt", ".epub", ".mobi",

		// Archives
		".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".lzma",
		".cab", ".ace", ".arj", ".lha", ".sit", ".sitx", ".sea",

		// Fonts
		".woff", ".woff2", ".ttf", ".otf", ".eot", ".pfb", ".pfm", ".afm",
		".fon", ".fnt", ".bdf", ".pcf", ".snf",

		// Media
		".mp4", ".avi", ".mov", ".wmv", ".flv", ".mkv", ".webm", ".m4v",
		".mpg", ".mpeg", ".3gp", ".ogv", ".ts", ".vob", ".rm", ".asf",
		".mp3", ".wav", ".ogg", ".aac", ".flac", ".wma", ".m4a", ".opus",
		".ape", ".ac3", ".dts", ".ra", ".au", ".aiff",

		// Data files
		".csv", ".tsv", ".xml", ".yaml", ".yml", ".toml", ".ini",
		".sql", ".db", ".sqlite", ".mdb", ".accdb",

		// Executables and packages
		".exe", ".msi", ".dmg", ".pkg", ".deb", ".rpm", ".appimage",
		".apk", ".ipa", ".jar", ".war", ".ear", ".iso", ".img",

		// CAD and design
		".dwg", ".dxf", ".step", ".iges", ".stl", ".obj", ".fbx", ".dae",
		".3ds", ".max", ".blend", ".ma", ".mb", ".c4d", ".skp",

		// Other
		".log", ".bak", ".tmp", ".temp", ".cache", ".lock", ".pid",
	}

	// Check file extensions
	for _, ext := range blacklistedExtensions {
		if strings.HasSuffix(url, ext) || strings.Contains(url, ext+"?") {
			return true
		}
	}

	// Enhanced data URI detection
	dataURIPrefixes := []string{
		"data:image/", "data:video/", "data:audio/", "data:application/pdf",
		"data:application/zip", "data:font/", "data:application/font",
		"data:application/octet-stream", "data:text/plain;base64",
		"data:application/vnd", "data:model/", "data:chemical/",
	}

	for _, prefix := range dataURIPrefixes {
		if strings.HasPrefix(url, prefix) {
			return true
		}
	}

	// Check for base64 encoded content
	if strings.Contains(url, ";base64,") && len(url) > 100 {
		return true
	}

	// Enhanced static asset patterns
	staticPatterns := []string{
		"/static/", "/assets/", "/public/", "/uploads/", "/images/", "/img/",
		"/media/", "/files/", "/download/", "/docs/", "/fonts/", "/css/",
		"/styles/", "/scss/", "/sass/", "/less/", "/stylesheets/",
		"/_next/static/", "/webpack/", "/node_modules/", "/.well-known/",
		"/dist/", "/build/", "/compiled/", "/generated/", "/cache/",
		"/tmp/", "/temp/", "/backup/", "/backups/", "/logs/", "/log/",
		"/vendor/", "/lib/", "/libs/", "/external/", "/third-party/",
		"/assets/vendor/", "/assets/fonts/", "/assets/images/",
		"/wp-content/uploads/", "/wp-includes/", "/wp-admin/",
		"/storage/", "/var/", "/home/", "/usr/", "/opt/", "/etc/",
	}

	for _, pattern := range staticPatterns {
		if strings.Contains(url, pattern) {
			return true
		}
	}

	// Enhanced download parameter detection
	downloadParams := []string{
		"download=", "attachment=", "export=", "format=pdf", "format=excel",
		"format=csv", "format=doc", "format=xls", "type=pdf", "type=image",
		"output=pdf", "output=excel", "render=pdf", "export_format=",
		"file_type=", "content_type=", "mime_type=", "force_download=",
	}

	for _, param := range downloadParams {
		if strings.Contains(url, param) {
			return true
		}
	}

	// Check for common CDN/asset hosting patterns
	cdnPatterns := []string{
		"amazonaws.com", "cloudfront.net", "googleapis.com", "gstatic.com",
		"bootstrapcdn.com", "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
		"fontawesome.com", "fonts.googleapis.com", "ajax.googleapis.com",
	}

	for _, pattern := range cdnPatterns {
		if strings.Contains(url, pattern) && (strings.Contains(url, "/fonts/") || 
			strings.Contains(url, "/css/") || strings.Contains(url, "/images/")) {
			return true
		}
	}

	return false
}

// isLikelyBinaryData detects if a string contains binary data
func isLikelyBinaryData(data string) bool {
	if len(data) < 10 {
		return false
	}

	// Check for base64 pattern
	if isBase64Like(data) && len(data) > 100 {
		return true
	}

	// Check for high ratio of non-printable ASCII characters
	nonPrintable := 0
	for _, r := range data {
		if r < 32 && r != 9 && r != 10 && r != 13 { // Allow tab, newline, CR
			nonPrintable++
		}
		if r > 126 && r < 160 { // Control characters in extended ASCII
			nonPrintable++
		}
	}

	// If more than 10% non-printable, likely binary
	if float64(nonPrintable)/float64(len(data)) > 0.1 {
		return true
	}

	// Check for sequences of null bytes or other binary signatures
	binaryPatterns := []string{
		"\x00\x00", "\xFF\xFE", "\xFE\xFF", "\xEF\xBB\xBF", // BOM and null sequences
		"\x1F\x8B", "\x50\x4B", "\x52\x61\x72", // GZIP, ZIP, RAR signatures
	}

	for _, pattern := range binaryPatterns {
		if strings.Contains(data, pattern) {
			return true
		}
	}

	return false
}

// isBase64Like checks if string looks like base64 encoded data
func isBase64Like(s string) bool {
	// Remove common base64 padding and separators
	cleaned := strings.ReplaceAll(s, "=", "")
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "\n", "")
	cleaned = strings.ReplaceAll(cleaned, "\r", "")
	cleaned = strings.ReplaceAll(cleaned, "\t", "")

	if len(cleaned) < 20 {
		return false
	}

	// Check if it's valid base64 characters
	validBase64 := regexp.MustCompile(`^[A-Za-z0-9+/]*$`)
	if !validBase64.MatchString(cleaned) {
		return false
	}

	// Try to decode a small portion to verify
	testPortion := cleaned
	if len(testPortion) > 100 {
		testPortion = testPortion[:100]
	}
	
	// Add padding if needed
	for len(testPortion)%4 != 0 {
		testPortion += "="
	}

	_, err := base64.StdEncoding.DecodeString(testPortion)
	return err == nil
}

// containsUnusualCharacters detects unusual Unicode or control characters
func containsUnusualCharacters(url string) bool {
	// Count different character types
	nonASCII := 0
	controlChars := 0
	totalChars := len([]rune(url))

	for _, r := range url {
		// Count non-ASCII characters
		if r > 127 {
			nonASCII++
		}

		// Count control characters (except common whitespace)
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			controlChars++
		}

		// Specific problematic characters
		if r == 0x00 || r == 0xFEFF || r == 0x200B || r == 0x200C || r == 0x200D {
			return true
		}
	}

	// If more than 30% non-ASCII, likely problematic
	if totalChars > 0 && float64(nonASCII)/float64(totalChars) > 0.3 {
		return true
	}

	// Any control characters are suspicious in URLs
	if controlChars > 0 {
		return true
	}

	// Check for excessive repeating characters
	if hasExcessiveRepeatingChars(url) {
		return true
	}

	// Check for suspicious Unicode ranges
	for _, r := range url {
		// Private use areas
		if (r >= 0xE000 && r <= 0xF8FF) || (r >= 0xF0000 && r <= 0xFFFFD) || (r >= 0x100000 && r <= 0x10FFFD) {
			return true
		}
		
		// Unassigned code points that might indicate corruption
		if r >= 0xFDD0 && r <= 0xFDEF {
			return true
		}
		
		// Non-characters
		if (r&0xFFFE) == 0xFFFE {
			return true
		}
	}

	return false
}

// hasExcessiveRepeatingChars detects excessive character repetition
func hasExcessiveRepeatingChars(url string) bool {
	if len(url) < 10 {
		return false
	}

	// Check for single character repetition
	charCount := make(map[rune]int)
	for _, r := range url {
		charCount[r]++
	}

	totalRunes := len([]rune(url))
	for _, count := range charCount {
		if float64(count)/float64(totalRunes) > 0.4 {
			return true
		}
	}

	// Check for repeating patterns
	repeatingPatterns := []string{
		"....", "////", "----", "====", "____", "~~~~", "????", "!!!!",
		"@@@@", "####", "$$$$", "%%%%", "&&&&", "****", "++++", "||||",
		"\\\\\\\\", ":::::", ";;;;;", "<<<<<", ">>>>>", "[[[[[", "]]]]]",
	}

	for _, pattern := range repeatingPatterns {
		if strings.Contains(url, pattern) {
			return true
		}
	}

	// Check for alternating patterns
	if len(url) > 20 {
		alternatingPatterns := []string{
			"ababab", "121212", "010101", "abcabc", "123123",
		}
		
		lowerURL := strings.ToLower(url)
		for _, pattern := range alternatingPatterns {
			if strings.Contains(lowerURL, pattern) {
				return true
			}
		}
	}

	return false
}