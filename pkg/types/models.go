package types

import (
    "time"
)

// Config holds all configuration parameters
type Config struct {
    MaxWorkers     int
    MaxDepth       int
    CacheSize      int
    RequestTimeout time.Duration
    RetryAttempts  int
    CustomHeaders  map[string]string
    AllowedDomains []string
    DeepScan       bool
    OutputFile     string
    Verbose        bool
}

// ScanResult represents the result of scanning a single URL
type ScanResult struct {
    URL         string        `json:"url"`
    Paths       []string      `json:"paths"`
    Secrets     []Secret      `json:"secrets"`
    PathCount   int           `json:"path_count"`
    SecretCount int           `json:"secret_count"`
    Depth       int           `json:"depth"`
    ParentURL   string        `json:"parent_url,omitempty"`
    Error       string        `json:"error,omitempty"`
    ScanTime    time.Time     `json:"scan_time"`
    Duration    time.Duration `json:"duration"`
    IsJSFile    bool          `json:"is_js_file"`
    StatusCode  int           `json:"status_code,omitempty"`
}

// Secret represents a detected secret/credential
type Secret struct {
    Type    string `json:"type"`
    Value   string `json:"value"`
    Context string `json:"context,omitempty"`
    Line    int    `json:"line,omitempty"`
}

// Summary represents the overall scan summary
type Summary struct {
    TotalURLs     int           `json:"total_urls"`
    SuccessCount  int           `json:"success_count"`
    FailedCount   int           `json:"failed_count"`
    TotalPaths    int           `json:"total_paths"`
    TotalSecrets  int           `json:"total_secrets"`
    TotalTime     time.Duration `json:"total_time"`
    Results       []ScanResult  `json:"results"`
    StartTime     time.Time     `json:"start_time"`
    EndTime       time.Time     `json:"end_time"`
}