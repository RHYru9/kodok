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
}

// NewValidator creates a new URL validator
func NewValidator() *Validator {
    // Validation pattern for URLs and paths
    validationPattern := `^(https?://[^\s<>]+|(?:/|\.\.?/)[^\s<>,;|*()\[\]{}\\]+)$`
    
    // Domain extraction pattern
    domainPattern := `^(?:https?://)?([^/:]+)`
    
    return &Validator{
        validationRegex: regexp.MustCompile(validationPattern),
        domainRegex:     regexp.MustCompile(domainPattern),
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

// Clean cleans and normalizes a URL
func (v *Validator) Clean(rawURL string) string {
    url := strings.TrimSpace(rawURL)
    
    // Remove common trailing issues
    url = strings.TrimRight(url, "\\")
    url = strings.TrimRight(url, "/")
    url = strings.TrimRight(url, ",")
    url = strings.TrimRight(url, ";")
    url = strings.TrimRight(url, ".")
    
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
    }
    
    for _, pattern := range suspiciousPatterns {
        if strings.Contains(strings.ToLower(url), pattern) {
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