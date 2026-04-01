package output

import (
    "bufio"
    "encoding/json"
    "fmt"
    "os"
    "sort"
    "sync"

    "github.com/rhyru9/kodok/pkg/types"
)

// Writer handles thread-safe output writing
type Writer struct {
    jsonFile *os.File
    txtFile  *os.File
    mu       sync.Mutex
}

// NewWriter creates a new output writer
func NewWriter(baseFilename string) (*Writer, error) {
    jsonFilename := baseFilename + ".json"
    txtFilename := baseFilename + ".txt"
    
    jsonFile, err := os.Create(jsonFilename)
    if err != nil {
        return nil, fmt.Errorf("creating JSON file: %w", err)
    }
    
    txtFile, err := os.Create(txtFilename)
    if err != nil {
        jsonFile.Close()
        return nil, fmt.Errorf("creating TXT file: %w", err)
    }
    
    return &Writer{
        jsonFile: jsonFile,
        txtFile:  txtFile,
    }, nil
}

// WriteResults writes scan results to output files
func (w *Writer) WriteResults(results []types.ScanResult, summary *types.Summary) error {
    w.mu.Lock()
    defer w.mu.Unlock()
    
    // Write JSON output
    if err := w.writeJSON(results, summary); err != nil {
        return fmt.Errorf("writing JSON: %w", err)
    }
    
    // Write TXT output
    if err := w.writeTXT(results); err != nil {
        return fmt.Errorf("writing TXT: %w", err)
    }
    
    return nil
}

// writeJSON writes detailed results in JSON format
func (w *Writer) writeJSON(results []types.ScanResult, summary *types.Summary) error {
    output := struct {
        Summary *types.Summary    `json:"summary"`
        Results []types.ScanResult `json:"results"`
    }{
        Summary: summary,
        Results: results,
    }
    
    encoder := json.NewEncoder(w.jsonFile)
    encoder.SetIndent("", "  ")
    
    if err := encoder.Encode(output); err != nil {
        return fmt.Errorf("encoding JSON: %w", err)
    }
    
    return w.jsonFile.Sync()
}

// writeTXT writes clean URLs to a text file
func (w *Writer) writeTXT(results []types.ScanResult) error {
    uniqueURLs := make(map[string]bool)
    
    // Collect all unique URLs
    for _, result := range results {
        if result.Error == "" {
            uniqueURLs[result.URL] = true
            for _, path := range result.Paths {
                uniqueURLs[path] = true
            }
        }
    }
    
    // Convert to slice and sort
    urls := make([]string, 0, len(uniqueURLs))
    for url := range uniqueURLs {
        urls = append(urls, url)
    }
    sort.Strings(urls)
    
    // Write to file
    writer := bufio.NewWriter(w.txtFile)

    for _, url := range urls {
        if _, err := writer.WriteString(url + "\n"); err != nil {
            return fmt.Errorf("writing URL: %w", err)
        }
    }

    return writer.Flush()
}

// Close closes the output files
func (w *Writer) Close() error {
    w.mu.Lock()
    defer w.mu.Unlock()
    
    var errs []error
    
    if w.jsonFile != nil {
        if err := w.jsonFile.Close(); err != nil {
            errs = append(errs, err)
        }
    }
    
    if w.txtFile != nil {
        if err := w.txtFile.Close(); err != nil {
            errs = append(errs, err)
        }
    }
    
    if len(errs) > 0 {
        return fmt.Errorf("closing files: %v", errs)
    }
    
    return nil
}

// GetFilenames returns the output filenames
func (w *Writer) GetFilenames() (string, string) {
    if w.jsonFile == nil || w.txtFile == nil {
        return "", ""
    }
    
    return w.jsonFile.Name(), w.txtFile.Name()
}