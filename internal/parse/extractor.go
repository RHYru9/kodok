package parse

import (
    "regexp"
    "strings"
)

// Extractor extracts URLs and paths from JavaScript content
type Extractor struct {
    extractionRegex     *regexp.Regexp
    templateRegex       *regexp.Regexp
    jsFileRegex         *regexp.Regexp
    commonPathPattern   *regexp.Regexp
    objPropertyRegex    *regexp.Regexp
    concatRegex         *regexp.Regexp
    functionCallRegex   *regexp.Regexp
    heuristicPathRegex  *regexp.Regexp
    objInFunctionRegex  *regexp.Regexp
}

// NewExtractor creates a new extractor
func NewExtractor() *Extractor {
    extractionPattern := `(?:"|'|` + "`" + `)((?:https?:\/\/[^"'\s<>` + "`" + `]+|(?:\/|\.\.?\/)[^"'\s<>,;|*()\[\]{}\\` + "`" + `]*))(?:"|'|` + "`" + `)`
    
    templatePattern := "`" + `([^` + "`" + `{]*[a-zA-Z0-9/._\-?=&%#]+)` + "`"
    
    jsFilePattern := `\.js(?:\?[^"'\s` + "`" + `]*)?(?:"|'|` + "`" + `)`
    
    heuristicPattern := `(\/(?:api|v[0-9]+|rest|graphql|oauth|oauth2|auth|login|logout|register|user|admin|config|internal|proxy|service|data|upload|download|file|assets|static|cdn|_next|wp-json|webhook|billing|payment|checkout|callback|sso|identity|gateway|microsvc|health|metrics|docs|swagger|openapi|debug|test|staging|dev|beta|alpha)\/[^\s"'` + "`" + `<>{}\[\]()]*)`
    
    objPropertyPattern := `(?:path|url|endpoint|api|uri|route|link|target|dest|source|src|href|action|formAction|redirect|callback|next|returnTo|continue|goto|baseUrl|baseURL|apiUrl|apiURL|apiPath|serviceUrl|serviceURL|graphqlUrl|graphqlURL|restUrl|restURL|config|settings|options|params|query|payload|to|hrefTo|as|pathname|search|hash|resource|objectUrl|objectURL|dataUrl|dataURL|fileUrl|fileURL|loc|location|addr|address|pathName)\s*[:=]\s*["'` + "`" + `]([^"'\s` + "`" + `<>]*)["'` + "`" + `]`
    
    functionCallPattern := `(?i)\b(?:fetch|axios\.(?:get|post|put|patch|delete|head|options|request)|api\.(?:get|post|put|patch|delete|head|options|request)|\$\.get|\$\.post|\$\.ajax|jQuery\.get|jQuery\.post|jQuery\.ajax|ky\.(?:get|post|put|patch|delete|head|options)|got\.(?:get|post|put|patch|delete|head|options)|request\.(?:get|post|put|patch|delete|head|options)|superagent\.(?:get|post|put|patch|delete|head|options)|http(?:Client|Service|Client|Api|Request)?\.(?:get|post|put|patch|delete|head|options|request)|(?:call|send|make|execute)(?:Api|Request|Http)?|(?:load|send|request|call)\w*|navigate|router\.push|window\.location\.assign)\s*\(\s*["'` + "`" + `]([^"'\s` + "`" + `<>]*)["'` + "`" + `]`
    
    objInFunctionPattern := `\b(?:pathname|path|to|href|url)\s*:\s*["'` + "`" + `]([^"'` + "`" + `\s<>{}]+)["'` + "`" + `]`
    
    // Concatenation patterns
    concatPattern := `["'` + "`" + `]\s*\+\s*["'` + "`" + `]([^"']+)["'` + "`" + `]|\b(?:url|path|endpoint)\s*=\s*["'` + "`" + `]([^"']+)["'` + "`" + `]`
    
    return &Extractor{
        extractionRegex:    regexp.MustCompile(extractionPattern),
        templateRegex:      regexp.MustCompile(templatePattern),
        jsFileRegex:        regexp.MustCompile(jsFilePattern),
        commonPathPattern:  regexp.MustCompile(heuristicPattern),
        objPropertyRegex:   regexp.MustCompile(objPropertyPattern),
        functionCallRegex:  regexp.MustCompile(functionCallPattern),
        heuristicPathRegex: regexp.MustCompile(heuristicPattern),
        objInFunctionRegex: regexp.MustCompile(objInFunctionPattern),
        concatRegex:        regexp.MustCompile(concatPattern),
    }
}

// Extract extracts URLs and paths from content
func (e *Extractor) Extract(content string) []string {
    urls := make([]string, 0)
    seen := make(map[string]bool)
    
    urls = append(urls, e.extractFromLiterals(content, seen)...)
    
    urls = append(urls, e.extractFromTemplates(content, seen)...)
    
    urls = append(urls, e.extractFromFunctionCalls(content, seen)...)
    
    urls = append(urls, e.extractFromObjectProperties(content, seen)...)
    
    urls = append(urls, e.extractFromObjectInFunction(content, seen)...)
    
    urls = append(urls, e.extractHeuristicPaths(content, seen)...)
    
    // 7. Extract from concatenated strings
    urls = append(urls, e.extractFromConcatenation(content, seen)...)
    
    return urls
}

// extractFromLiterals extracts from single/double quotes and backticks
func (e *Extractor) extractFromLiterals(content string, seen map[string]bool) []string {
    matches := e.extractionRegex.FindAllStringSubmatch(content, -1)
    return e.processMatches(matches, seen)
}

// extractFromTemplates extracts from template literals
func (e *Extractor) extractFromTemplates(content string, seen map[string]bool) []string {
    matches := e.templateRegex.FindAllStringSubmatch(content, -1)
    return e.processMatches(matches, seen)
}

// NEW: extractFromFunctionCalls
func (e *Extractor) extractFromFunctionCalls(content string, seen map[string]bool) []string {
    matches := e.functionCallRegex.FindAllStringSubmatch(content, -1)
    return e.processMatches(matches, seen)
}

// extractFromObjectProperties extracts from object properties
func (e *Extractor) extractFromObjectProperties(content string, seen map[string]bool) []string {
    matches := e.objPropertyRegex.FindAllStringSubmatch(content, -1)
    return e.processMatches(matches, seen)
}

// NEW: extractFromObjectInFunction
func (e *Extractor) extractFromObjectInFunction(content string, seen map[string]bool) []string {
    matches := e.objInFunctionRegex.FindAllStringSubmatch(content, -1)
    return e.processMatches(matches, seen)
}

// ENHANCED: extractHeuristicPaths - tangkap path mentah
func (e *Extractor) extractHeuristicPaths(content string, seen map[string]bool) []string {
    matches := e.heuristicPathRegex.FindAllStringSubmatch(content, -1)
    urls := make([]string, 0)
    
    for _, match := range matches {
        if len(match) > 1 && match[1] != "" {
            url := strings.TrimSpace(match[1])
            url = e.cleanURL(url)
            
            if url != "" && !seen[url] {
                seen[url] = true
                urls = append(urls, url)
            }
        }
    }
    
    return urls
}

// extractFromConcatenation extracts from concatenated strings
func (e *Extractor) extractFromConcatenation(content string, seen map[string]bool) []string {
    matches := e.concatRegex.FindAllStringSubmatch(content, -1)
    urls := make([]string, 0)
    
    for _, match := range matches {
        for i := 1; i < len(match); i++ {
            if match[i] != "" {
                url := strings.TrimSpace(match[i])
                url = e.cleanURL(url)
                
                if url != "" && !seen[url] {
                    seen[url] = true
                    urls = append(urls, url)
                }
            }
        }
    }
    
    return urls
}

// processMatches processes regex matches and returns unique URLs
func (e *Extractor) processMatches(matches [][]string, seen map[string]bool) []string {
    urls := make([]string, 0, len(matches))
    
    for _, match := range matches {
        var url string
        if len(match) > 1 && match[1] != "" {
            url = strings.Trim(match[1], `"'` + "`")
        } else if len(match) > 0 {
            url = strings.Trim(match[0], `"'` + "`")
        } else {
            continue
        }
        
        url = strings.TrimSpace(url)
        url = e.cleanURL(url)
        
        if url != "" && !seen[url] {
            seen[url] = true
            urls = append(urls, url)
        }
    }
    
    return urls
}

// FIXED: cleanURL - JANGAN potong query/fragment
func (e *Extractor) cleanURL(url string) string {
    if url == "" {
        return ""
    }
    
    // Remove common trailing characters (but preserve query parameters and fragments)
    url = strings.TrimRightFunc(url, func(r rune) bool {
        return r == '\\' || r == ',' || r == ';' || r == ')' || r == ']' || r == '}'
    })
    
    // Remove JavaScript escapes
    url = strings.ReplaceAll(url, `\/`, `/`)
    url = strings.ReplaceAll(url, `\u002F`, `/`)
    
    // FIXED: Preserve valid URL characters including ? & = # % + - _ ~ . : /
    url = strings.Map(func(r rune) rune {
        // Allow printable chars, URL components, and common URL symbols
        if (r >= 32 && r != 127) || 
           r == '?' || r == '&' || r == '=' || r == '#' || r == '%' || 
           r == '+' || r == '-' || r == '_' || r == '~' || 
           r == '.' || r == ':' || r == '/' {
            return r
        }
        return -1
    }, url)
    
    return url
}

// IsJSFile checks if a URL points to a JavaScript file
func (e *Extractor) IsJSFile(url string) bool {
    lower := strings.ToLower(url)
    return strings.HasSuffix(lower, ".js") ||
           strings.Contains(lower, ".js?") ||
           strings.Contains(lower, "/js/") ||
           strings.Contains(lower, ".js#") ||
           strings.Contains(lower, ".js&") ||
           strings.Contains(lower, ".js%") ||
           (strings.Contains(lower, "javascript") || strings.Contains(lower, "script")) &&
           (strings.Contains(lower, "src=") || strings.Contains(lower, "href="))
}