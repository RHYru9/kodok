package scan

import (
    "regexp"
    "strings"

    "github.com//kodok/pkg/types"
)

// SecretScanner scans for secrets and credentials
type SecretScanner struct {
    patterns []SecretPattern
}

// SecretPattern defines a pattern for secret detection
type SecretPattern struct {
    Name        string
    Pattern     *regexp.Regexp
    Description string
    Confidence  int // 1-100
}

// NewSecretScanner creates a new secret scanner
func NewSecretScanner() *SecretScanner {
    scanner := &SecretScanner{}
    scanner.initPatterns()
    return scanner
}

// initPatterns initializes the secret detection patterns
func (s *SecretScanner) initPatterns() {
    s.patterns = []SecretPattern{
        {
            Name:        "AWS Access Key ID",
            Pattern:     regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
            Description: "AWS Access Key ID",
            Confidence:  90,
        },
        {
            Name:        "AWS Secret Key",
            Pattern:     regexp.MustCompile(`(?i)aws_secret.*?=.*?['"]([A-Za-z0-9+/]{40})['"]`),
            Description: "AWS Secret Access Key",
            Confidence:  85,
        },
        {
            Name:        "Stripe API Key",
            Pattern:     regexp.MustCompile(`(sk_live_[0-9a-zA-Z]{24}|rk_live_[0-9a-zA-Z]{24})`),
            Description: "Stripe Secret Key",
            Confidence:  95,
        },
        {
            Name:        "Stripe Publishable Key",
            Pattern:     regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24}`),
            Description: "Stripe Publishable Key",
            Confidence:  80,
        },
        {
            Name:        "GitHub Token",
            Pattern:     regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
            Description: "GitHub Personal Access Token",
            Confidence:  90,
        },
        {
            Name:        "Generic API Key",
            Pattern:     regexp.MustCompile(`(?i)(api_key|apikey|secret_key|secretkey).*?=.*?['"]([0-9a-zA-Z]{32,45})['"]`),
            Description: "Generic API Key",
            Confidence:  70,
        },
        {
            Name:        "JWT Token",
            Pattern:     regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`),
            Description: "JSON Web Token",
            Confidence:  60,
        },
        {
            Name:        "Email Address",
            Pattern:     regexp.MustCompile(`(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`),
            Description: "Email Address",
            Confidence:  50,
        },
        {
            Name:        "Password in URL",
            Pattern:     regexp.MustCompile(`(?i)[a-z]+://[^:]+:([^@]+)@`),
            Description: "Password in URL",
            Confidence:  80,
        },
        {
            Name:        "Google API Key",
            Pattern:     regexp.MustCompile(`AIza[0-9A-Za-z\\-_]{35}`),
            Description: "Google API Key",
            Confidence:  85,
        },
        {
            Name:        "Slack Token",
            Pattern:     regexp.MustCompile(`xox[baprs]-([0-9a-zA-Z]{10,48})?`),
            Description: "Slack Token",
            Confidence:  85,
        },
    }
}

// Scan scans content for secrets
func (s *SecretScanner) Scan(content string) []types.Secret {
    var secrets []types.Secret
    lines := strings.Split(content, "\n")
    
    for lineNum, line := range lines {
        for _, pattern := range s.patterns {
            matches := pattern.Pattern.FindAllStringSubmatch(line, -1)
            for _, match := range matches {
                if len(match) > 0 {
                    secretValue := match[0]
                    if len(match) > 1 {
                        secretValue = match[1] // Use captured group if available
                    }
                    
                    // Additional validation
                    if s.validateSecret(pattern.Name, secretValue) {
                        secret := types.Secret{
                            Type:    pattern.Name,
                            Value:   s.maskSecret(secretValue),
                            Context: s.extractContext(line, secretValue),
                            Line:    lineNum + 1,
                        }
                        secrets = append(secrets, secret)
                    }
                }
            }
        }
    }
    
    return s.deduplicateSecrets(secrets)
}

// validateSecret performs additional validation on detected secrets
func (s *SecretScanner) validateSecret(secretType, value string) bool {
    // Skip common false positives
    falsePositives := []string{
        "example",
        "test",
        "demo",
        "placeholder",
        "changeme",
        "your_",
        "fake_",
        "dummy_",
    }
    
    valueLower := strings.ToLower(value)
    for _, fp := range falsePositives {
        if strings.Contains(valueLower, fp) {
            return false
        }
    }
    
    // Type-specific validation
    switch secretType {
    case "Email Address":
        // Skip common example emails
        if strings.Contains(valueLower, "example.com") || 
           strings.Contains(valueLower, "test.com") ||
           strings.Contains(valueLower, "admin@localhost") {
            return false
        }
    case "Generic API Key":
        // Skip sequential or repeating patterns
        if s.isSequential(value) || s.isRepeating(value) {
            return false
        }
    }
    
    return true
}

// maskSecret masks sensitive parts of secrets
func (s *SecretScanner) maskSecret(secret string) string {
    if len(secret) <= 8 {
        return secret // Too short to mask meaningfully
    }
    
    // Keep first 4 and last 4 characters, mask the middle
    if len(secret) > 12 {
        return secret[:4] + "****" + secret[len(secret)-4:]
    }
    
    // For shorter secrets, keep first 2 and last 2
    return secret[:2] + "****" + secret[len(secret)-2:]
}

// extractContext extracts context around the secret
func (s *SecretScanner) extractContext(line, secret string) string {
    index := strings.Index(line, secret)
    if index == -1 {
        return strings.TrimSpace(line)
    }
    
    // Extract ~50 characters around the secret
    start := max(0, index-25)
    end := min(len(line), index+len(secret)+25)
    
    context := line[start:end]
    return strings.TrimSpace(context)
}

// deduplicateSecrets removes duplicate secrets
func (s *SecretScanner) deduplicateSecrets(secrets []types.Secret) []types.Secret {
    seen := make(map[string]bool)
    unique := make([]types.Secret, 0)
    
    for _, secret := range secrets {
        key := secret.Type + ":" + secret.Value
        if !seen[key] {
            seen[key] = true
            unique = append(unique, secret)
        }
    }
    
    return unique
}

// isSequential checks if a string is sequential (e.g., "123456")
func (s *SecretScanner) isSequential(str string) bool {
    if len(str) < 3 {
        return false
    }
    
    // Check numeric sequences
    isNumericSeq := true
    for i := 1; i < len(str); i++ {
        if str[i] != str[i-1]+1 {
            isNumericSeq = false
            break
        }
    }
    
    return isNumericSeq
}

// isRepeating checks if a string is repeating (e.g., "aaaaaa")
func (s *SecretScanner) isRepeating(str string) bool {
    if len(str) < 3 {
        return false
    }
    
    firstChar := str[0]
    for i := 1; i < len(str); i++ {
        if str[i] != firstChar {
            return false
        }
    }
    
    return true
}

// max returns the maximum of two integers
func max(a, b int) int {
    if a > b {
        return a
    }
    return b
}

// min returns the minimum of two integers
func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}