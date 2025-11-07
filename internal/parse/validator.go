package parse

import (
    "net/url"
    "regexp"
    "strings"
)

// Validator validates and cleans URLs
type Validator struct {
    validationRegex *regexp.Regexp
    domainRegex     *regexp.Regexp
    pathRegex       *regexp.Regexp
}

// NewValidator creates a new URL validator
func NewValidator() *Validator {
    // Enhanced validation pattern for URLs and paths
    validationPattern := `^(https?://[^\s<>]+|(?:/|\.\.?/)[^\s<>,;|*()\[\]{}\\]+)$`
    
    // Domain extraction pattern
    domainPattern := `^(?:https?://)?([^/:]+)`
    
    // Path validation pattern (more permissive)
    pathPattern := `^((?:https?://[^\s<>]+)|(?:/|\.\.?/|\./?)[^\s<>,;|*()\[\]{}\\]+)$`
    
    return &Validator{
        validationRegex: regexp.MustCompile(validationPattern),
        domainRegex:     regexp.MustCompile(domainPattern),
        pathRegex:       regexp.MustCompile(pathPattern),
    }
}

// IsValid checks if a URL is valid
func (v *Validator) IsValid(rawURL string) bool {
    if rawURL == "" {
        return false
    }
    
    // Length check
    if len(rawURL) < 2 || len(rawURL) > 2000 {
        return false
    }
    
    // Basic pattern validation
    if !v.validationRegex.MatchString(rawURL) {
        return false
    }
    
    // Check for suspicious patterns
    if v.containsSuspiciousPatterns(rawURL) {
        return false
    }
    
    // For HTTP URLs, validate properly
    if strings.HasPrefix(rawURL, "http") {
        parsed, err := url.Parse(rawURL)
        if err != nil {
            return false
        }
        
        // Validate host
        if parsed.Host == "" {
            return false
        }
        
        // Check for common issues
        if strings.Contains(parsed.Host, "..") {
            return false
        }
    }
    
    return true
}

// IsValidPath validates if a string is a valid path (more permissive than full URL)
func (v *Validator) IsValidPath(path string) bool {
    if path == "" {
        return false
    }
    
    // Length check
    if len(path) < 1 || len(path) > 2000 {
        return false
    }
    
    // Check for suspicious patterns
    if v.containsSuspiciousPatterns(path) {
        return false
    }
    
    // ENHANCED: membolehkan query parameters and fragments
    // Basic path pattern validation (more permissive)
    if !v.pathRegex.MatchString(path) {
        return false
    }
    
    // For relative paths, basic validation
    if strings.HasPrefix(path, "/") || strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../") {
        return !v.containsSuspiciousPatterns(path)
    }
    
    // For absolute URLs, use normal validation
    return v.IsValid(path)
}

// FIXED: Clean method - preserve query and fragment
// Clean cleans and normalizes a URL
func (v *Validator) Clean(rawURL string) string {
    url := strings.TrimSpace(rawURL)
    
    // FIXED: Jangan potong karakter valid seperti ?, &, =, #
    // Hanya trim karakter yang PASTI tidak valid di akhir URL
    url = strings.TrimRightFunc(url, func(r rune) bool {
        return r == '\\' || r == ',' || r == ';' || r == ')' || 
               r == ']' || r == '}' || r == ' ' || r == '\t'
    })
    
    // Normalize protocol-relative URLs
    if strings.HasPrefix(url, "//") {
        url = "https:" + url
    }
    
    return url
}

// ExtractDomain extracts the domain from a URL
func (v *Validator) ExtractDomain(rawURL string) string {
    matches := v.domainRegex.FindStringSubmatch(rawURL)
    if len(matches) > 1 {
        return matches[1]
    }
    return ""
}

// ExtractURLsFromConcat attempts to extract URLs from concatenated strings
func (v *Validator) ExtractURLsFromConcat(content string) []string {
    patterns := []*regexp.Regexp{
        regexp.MustCompile(`["'` + "`" + `]\s*\+\s*["'` + "`" + `]([^"']+)`),
        regexp.MustCompile(`\b(?:url|path|endpoint|api|src|href)\s*=\s*["'` + "`" + `]([^"']+)["'` + "`" + `]`),
        regexp.MustCompile(`(?:fetch|axios|ajax|XMLHttpRequest)\(['"` + "`" + `]([^'"` + "`" + `]+)`),
    }
    
    var urls []string
    for _, pattern := range patterns {
        matches := pattern.FindAllStringSubmatch(content, -1)
        for _, match := range matches {
            if len(match) > 1 && v.IsValidPath(match[1]) {
                cleaned := v.Clean(match[1])
                if cleaned != "" {
                    urls = append(urls, cleaned)
                }
            }
        }
    }
    
    return urls
}

// containsSuspiciousPatterns checks for potentially malicious patterns
func (v *Validator) containsSuspiciousPatterns(url string) bool {
    suspiciousPatterns := []string{
        "javascript:",
        "data:",
        "vbscript:",
        "file:",
        "ftp:",
        "mailto:",
        "tel:",
        "{{",
        "}}",
        "../../../", // Excessive path traversal
        "//..",     // Double dot patterns
        "<!--",
        "-->",
        "eval(",
        "document.cookie",
        "localStorage",
        "sessionStorage",
        "window.location",
        "document.domain",
    }
    
    lowerURL := strings.ToLower(url)
    for _, pattern := range suspiciousPatterns {
        if strings.Contains(lowerURL, pattern) {
            return true
        }
    }
    
    return false
}

// IsSameDomain checks if two URLs are from the same domain
func (v *Validator) IsSameDomain(url1, url2 string) bool {
    domain1 := v.ExtractDomain(url1)
    domain2 := v.ExtractDomain(url2)
    
    if domain1 == "" || domain2 == "" {
        return false
    }
    
    return domain1 == domain2
}

// NormalizeDomain normalizes domain for comparison
func (v *Validator) NormalizeDomain(domain string) string {
    domain = strings.ToLower(strings.TrimSpace(domain))
    // Remove www. prefix for normalization
    if strings.HasPrefix(domain, "www.") {
        domain = domain[4:]
    }
    return domain
}