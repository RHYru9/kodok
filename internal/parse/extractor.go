package parse

import (
    "regexp"
    "strings"
)

// Extractor extracts URLs and paths from JavaScript content
type Extractor struct {
    extractionRegex *regexp.Regexp
    jsFileRegex     *regexp.Regexp
}

// NewExtractor creates a new extractor
func NewExtractor() *Extractor {
    // Pattern to extract URLs and paths from JavaScript
    extractionPattern := `(?:"|')((?:https?:\/\/[^"'\s<>]+|(?:\/|\.\.?\/)[^"'\s<>,;|*()\[\]{}\\]+))(?:"|')`
    
    // Pattern to identify JavaScript files
    jsFilePattern := `\.js(?:\?[^"'\s]*)?(?:"|')`
    
    return &Extractor{
        extractionRegex: regexp.MustCompile(extractionPattern),
        jsFileRegex:     regexp.MustCompile(jsFilePattern),
    }
}

// Extract extracts URLs and paths from content
func (e *Extractor) Extract(content string) []string {
    matches := e.extractionRegex.FindAllStringSubmatch(content, -1)
    
    urls := make([]string, 0, len(matches))
    seen := make(map[string]bool)
    
    for _, match := range matches {
        if len(match) > 1 {
            url := strings.Trim(match[1], `"'`)
            url = strings.TrimSpace(url)
            
            // Clean up common issues
            url = e.cleanURL(url)
            
            if url != "" && !seen[url] {
                seen[url] = true
                urls = append(urls, url)
            }
        }
    }
    
    return urls
}

// cleanURL cleans and normalizes extracted URLs
func (e *Extractor) cleanURL(url string) string {
    // Remove common trailing characters
    url = strings.TrimRight(url, "\\")
    url = strings.TrimRight(url, ",")
    url = strings.TrimRight(url, ";")
    url = strings.TrimRight(url, ")")
    url = strings.TrimRight(url, "]")
    url = strings.TrimRight(url, "}")
    
    // Remove JavaScript escapes
    url = strings.ReplaceAll(url, `\/`, `/`)
    url = strings.ReplaceAll(url, `\u002F`, `/`)
    
    // Remove control characters
    url = strings.Map(func(r rune) rune {
        if r >= 32 && r != 127 { // Allow printable chars except DEL
            return r
        }
        return -1
    }, url)
    
    return url
}

// IsJSFile checks if a URL points to a JavaScript file
func (e *Extractor) IsJSFile(url string) bool {
    return e.jsFileRegex.MatchString(url) ||
           strings.Contains(strings.ToLower(url), ".js") ||
           strings.Contains(strings.ToLower(url), "/js/")
}