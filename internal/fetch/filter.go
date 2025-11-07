package fetch

import (
    "compress/gzip"
    "fmt"
    "io"
    "net/http"
)

// ContentFilter handles content filtering and processing
type ContentFilter struct {
    maxSize int64
}

// NewContentFilter creates a new content filter
func NewContentFilter() *ContentFilter {
    return &ContentFilter{
        maxSize: 50 * 1024 * 1024, // 50MB
    }
}

// ReadAndFilter reads and filters content from a response
func (f *ContentFilter) ReadAndFilter(body io.Reader, headers http.Header) (string, error) {
    var reader io.Reader = body
    
    // Handle gzip encoding
    if headers.Get("Content-Encoding") == "gzip" {
        gzReader, err := gzip.NewReader(body)
        if err != nil {
            return "", err
        }
        defer gzReader.Close()
        reader = gzReader
    }
    
    // Read with size limit
    limitedReader := io.LimitReader(reader, f.maxSize)
    
    content, err := io.ReadAll(limitedReader)
    if err != nil {
        return "", err
    }
    
    // Convert to string and filter binary content
    contentStr := string(content)
    
    // Skip binary content
    if f.isBinary(contentStr) {
        return "", fmt.Errorf("binary content detected")
    }
    
    return contentStr, nil
}

// isBinary checks if content appears to be binary
func (f *ContentFilter) isBinary(content string) bool {
    if len(content) == 0 {
        return false
    }
    
    // Check for null bytes and low percentage of printable characters
    printable := 0
    sampleSize := min(len(content), 1000)
    
    for i := 0; i < sampleSize; i++ {
        if content[i] == 0 {
            return true // Null byte found
        }
        if content[i] >= 32 && content[i] <= 126 || content[i] == 9 || content[i] == 10 || content[i] == 13 {
            printable++
        }
    }
    
    // If less than 80% of first 1000 chars are printable, consider it binary
    if float64(printable)/float64(sampleSize) < 0.8 {
        return true
    }
    
    return false
}

// min returns the minimum of two integers
func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}