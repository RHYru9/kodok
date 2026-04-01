package scan

import (
	"math"
	"regexp"
	"strings"

	"github.com/rhyru9/kodok/pkg/types"
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
	ValueGroup  int // which capture group contains the secret value (0 = full match)
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
		// ✅ Cloud Provider Keys (unik, false positive rendah)
		{
			Name:        "AWS Access Key ID",
			Pattern:     regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
			Description: "AWS Access Key ID",
			Confidence:  90,
			ValueGroup:  0, // full match is the complete key
		},
		{
			Name:        "Google API Key",
			Pattern:     regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
			Description: "Google API Key",
			Confidence:  85,
			ValueGroup:  0,
		},

		// ✅ Payment Processing
		{
			Name:        "Midtrans Server Key",
			Pattern:     regexp.MustCompile(`Basic U0ItTWlkLXNlcnZlci1[\w\-]+[:=]`),
			Description: "Midtrans Server Key (Basic Auth Base64-encoded)",
			Confidence:  90,
			ValueGroup:  0,
		},
		{
			Name:        "Stripe Secret Key",
			Pattern:     regexp.MustCompile(`(sk|rk)_live_[0-9a-zA-Z]{24}`),
			Description: "Stripe Secret Key",
			Confidence:  95,
			ValueGroup:  0, // full match is the complete key (group 1 is just prefix "sk"/"rk")
		},
		{
			Name:        "Square Token",
			Pattern:     regexp.MustCompile(`sq0(a|c)sp-[0-9A-Za-z\-_]{22,43}`),
			Description: "Square Access Token or OAuth Secret",
			Confidence:  90,
			ValueGroup:  0, // full match is the complete token (group 1 is just "a"/"c")
		},
		{
			Name:        "Braintree Access Token",
			Pattern:     regexp.MustCompile(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`),
			Description: "Braintree Access Token",
			Confidence:  90,
			ValueGroup:  0,
		},

		// ✅ Version Control & CI/CD
		{
			Name:        "GitHub Token",
			Pattern:     regexp.MustCompile(`gh[opsr]_[0-9a-zA-Z]{36}|ghr_[0-9a-zA-Z]{76}`),
			Description: "GitHub Personal, OAuth, App, or Refresh Token",
			Confidence:  90,
			ValueGroup:  0,
		},
		{
			Name:        "GitLab Personal Access Token",
			Pattern:     regexp.MustCompile(`glpat-[0-9a-zA-Z\-_]{20}`),
			Description: "GitLab Personal Access Token",
			Confidence:  90,
			ValueGroup:  0,
		},

		// Communication & Messaging
		{
			Name:        "Slack Token",
			Pattern:     regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,48}`),
			Description: "Slack Bot, User, or Webhook Token",
			Confidence:  85,
			ValueGroup:  0,
		},
		{
			Name:        "Slack Webhook URL",
			Pattern:     regexp.MustCompile(`(?:^|[\s"'` + "`" + `(,=])(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)(?:[\s"'` + "`" + `),]|$)`),
			Description: "Slack Incoming Webhook URL",
			Confidence:  95,
			ValueGroup:  1,
		},
		{
			Name:        "Discord Bot Token",
			Pattern:     regexp.MustCompile(`[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}`),
			Description: "Discord Bot Token",
			Confidence:  90,
			ValueGroup:  0,
		},
		{
			Name:        "Telegram Bot Token",
			Pattern:     regexp.MustCompile(`\d{9,10}:[A-Za-z0-9_-]{35}`),
			Description: "Telegram Bot API Token",
			Confidence:  90,
			ValueGroup:  0,
		},
		{
			Name:        "SendGrid API Key",
			Pattern:     regexp.MustCompile(`SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`),
			Description: "SendGrid API Key",
			Confidence:  95,
			ValueGroup:  0,
		},
		{
			Name:        "Mailgun API Key",
			Pattern:     regexp.MustCompile(`key-[0-9a-z]{32}`),
			Description: "Mailgun API Key",
			Confidence:  80,
			ValueGroup:  0,
		},
		{
			Name:        "Twilio API Key",
			Pattern:     regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
			Description: "Twilio API Key",
			Confidence:  90,
			ValueGroup:  0,
		},

		// ✅ Database Connection Strings
		{
			Name:        "Database Connection String with Password",
			Pattern:     regexp.MustCompile(`(postgres|mysql|mongodb|redis)(?:ql|\+srv)?://[^:]+:([^@\s]{4,})@[^/\s]+`),
			Description: "Database connection string containing password",
			Confidence:  85,
			ValueGroup:  2, // group 2 = actual password (group 1 = db type like "postgres")
		},

		// ✅ Package Managers
		{
			Name:        "NPM Token",
			Pattern:     regexp.MustCompile(`npm_[0-9A-Za-z]{36}`),
			Description: "NPM Access Token",
			Confidence:  90,
			ValueGroup:  0,
		},
		{
			Name:        "PyPI Upload Token",
			Pattern:     regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}`),
			Description: "PyPI Upload Token",
			Confidence:  95,
			ValueGroup:  0,
		},
		{
			Name:        "Docker Hub Token",
			Pattern:     regexp.MustCompile(`dckr_pat_[a-zA-Z0-9_-]{40,}`),
			Description: "Docker Hub Personal Access Token",
			Confidence:  90,
			ValueGroup:  0,
		},

		// ✅ Private Keys
		{
			Name:        "Private Key (RSA, SSH, PGP)",
			Pattern:     regexp.MustCompile(`-----BEGIN (RSA|OPENSSH|PGP PRIVATE KEY) PRIVATE KEY-----`),
			Description: "RSA, OpenSSH, or PGP Private Key header",
			Confidence:  95,
			ValueGroup:  0, // full match is the header line
		},

		// ✅ Password-Specific (dengan konteks eksplisit)
		{
			Name:        "Hardcoded Password",
			Pattern:     regexp.MustCompile(`(?i)\b(password|passwd|pwd|pass|dbpass|db_password|userpass|admin_pass|root_password|cred|credentials?|auth_password)\b[\s]*[=:][\s]*['"]([^'"\s]{8,})['"]`),
			Description: "Hardcoded password in assignment",
			Confidence:  75,
			ValueGroup:  2, // group 2 = actual value (group 1 = keyword like "password")
		},
		{
			Name:        "Password in JSON/Object",
			Pattern:     regexp.MustCompile(`(?i)"(password|passwd|pwd|pass|credentials?)"\s*:\s*"([^"]{8,})"`),
			Description: "Password inside JSON or object",
			Confidence:  70,
			ValueGroup:  2, // group 2 = actual value (group 1 = key name)
		},
		{
			Name:        "Password in URL",
			Pattern:     regexp.MustCompile(`(?i)\bhttps?://[^:@/\s]+\b:([^@]{6,})@[^/\s]`),
			Description: "HTTP(S) URL with embedded password",
			Confidence:  70,
			ValueGroup:  1, // group 1 = password
		},

		// ✅ Generic Patterns (dengan konteks atau struktur khas)
		{
			Name:        "JWT Token",
			Pattern:     regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`),
			Description: "JSON Web Token (JWT)",
			Confidence:  60,
			ValueGroup:  0,
		},
		{
			Name:        "Bearer Token",
			Pattern:     regexp.MustCompile(`(?i)bearer\s+([A-Za-z0-9\-._~+/]{20,})`),
			Description: "Bearer token in Authorization header",
			Confidence:  75,
			ValueGroup:  1, // group 1 = token value
		},
		{
			Name:        "Basic Auth Credentials",
			Pattern:     regexp.MustCompile(`(?i)basic\s+([A-Za-z0-9+/]{20,}={0,2})`),
			Description: "Basic authentication Base64 credentials",
			Confidence:  80,
			ValueGroup:  1, // group 1 = credentials
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
					if pattern.ValueGroup > 0 && len(match) > pattern.ValueGroup && match[pattern.ValueGroup] != "" {
						secretValue = match[pattern.ValueGroup]
					}
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
	falsePositives := []string{
		"example", "test", "demo", "placeholder", "changeme",
		"your_", "fake_", "dummy_", "123456", "password",
		"guest", "letmein", "welcome", "qwerty", "default",
		"iloveyou",
	}
	valueLower := strings.ToLower(value)
	for _, fp := range falsePositives {
		if strings.Contains(valueLower, fp) {
			return false
		}
	}

	switch secretType {
	case "Email Address":
		if strings.Contains(valueLower, "example.com") ||
			strings.Contains(valueLower, "test.com") ||
			strings.Contains(valueLower, "admin@localhost") {
			return false
		}
	case "Generic API Key", "Hardcoded Password":
		if s.isSequential(value) || s.isRepeating(value) {
			return false
		}
		if s.isOnlyLetters(value) || s.isOnlyDigits(value) {
			return false
		}
		if s.calculateEntropy(value) < 2.5 {
			return false
		}
		// Must contain letter + (digit or special)
		hasLetter, hasDigit, hasSpecial := false, false, false
		for _, r := range value {
			switch {
			case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
				hasLetter = true
			case r >= '0' && r <= '9':
				hasDigit = true
			default:
				hasSpecial = true
			}
		}
		if !(hasLetter && (hasDigit || hasSpecial)) {
			return false
		}
	}

	return true
}

// Helper functions
func (s *SecretScanner) isOnlyLetters(str string) bool {
	for _, r := range str {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return len(str) > 0
}

func (s *SecretScanner) isOnlyDigits(str string) bool {
	for _, r := range str {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(str) > 0
}

func (s *SecretScanner) calculateEntropy(str string) float64 {
	if len(str) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, r := range str {
		freq[r]++
	}
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / float64(len(str))
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func (s *SecretScanner) maskSecret(secret string) string {
	if len(secret) <= 8 {
		return secret
	}
	if len(secret) > 12 {
		return secret[:4] + "****" + secret[len(secret)-4:]
	}
	return secret[:2] + "****" + secret[len(secret)-2:]
}

func (s *SecretScanner) extractContext(line, secret string) string {
	index := strings.Index(line, secret)
	if index == -1 {
		return strings.TrimSpace(line)
	}
	start := max(0, index-15)
	end := min(len(line), index+len(secret)+15)
	return strings.TrimSpace(line[start:end])
}

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

func (s *SecretScanner) isSequential(str string) bool {
	if len(str) < 3 {
		return false
	}
	for i := 1; i < len(str); i++ {
		if str[i] != str[i-1]+1 {
			return false
		}
	}
	return true
}

func (s *SecretScanner) isRepeating(str string) bool {
	if len(str) < 3 {
		return false
	}
	first := str[0]
	for i := 1; i < len(str); i++ {
		if str[i] != first {
			return false
		}
	}
	return true
}

