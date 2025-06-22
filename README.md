# Kodok - JavaScript Path & Secret Scanner

A sophisticated JavaScript scanner designed to analyze JavaScript files for paths, secrets, and sensitive information with advanced deep scanning capabilities. Built for security researchers and developers who need to audit JavaScript applications efficiently.

## Features

### Core Scanning Capabilities
- Single URL or batch processing from files
- Path discovery and endpoint extraction from JavaScript code
- Secret detection for API keys, tokens, and credentials
- Custom header support with automatic sensitive data masking
- Domain filtering to control scope of results

### Advanced Scanning Features
- Deep scanning with automatic JavaScript file discovery
- Recursive analysis with configurable depth limits
- Parent-child relationship tracking between discovered files
- Dual output formats (detailed JSON and clean text)
- URL validation and deduplication
- Concurrent processing with rate limiting

## Installation

```bash
# Install directly from GitHub
go install github.com/rhyru9/kodok@latest

# Build from source
git clone https://github.com/rhyru9/kodok.git
cd kodok
go build -o kodok .
```

## Basic Usage

### Standard Scanning

```bash
# Scan single JavaScript file
./kodok -u https://example.com/app.js

# Scan multiple URLs from file
./kodok -fj urls.txt

# Scan with output files
./kodok -u https://example.com/app.js -o results
```

### Deep Scanning

```bash
# Enable deep scanning to discover linked JS files
./kodok -u https://example.com/index.html -deep

# Deep scan with custom depth limit
./kodok -u https://example.com/app.js -deep -depth 5

# Deep scan with authentication and output
./kodok -fj urls.txt -deep -depth 3 -H 'Cookie: session=abc123' -o comprehensive_scan
```

## Authentication

### Common Authentication Headers

```bash
# Bearer Token Authentication
./kodok -u https://api.example.com/client.js -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...'

# Session Cookie Authentication
./kodok -u https://app.example.com/main.js -H 'Cookie: sessionid=abc123; csrftoken=xyz789'

# API Key Authentication
./kodok -u https://example.com/secure.js -H 'X-API-Key: your-secret-api-key'
```

### Multiple Headers

```bash
./kodok -u https://example.com/app.js \
  -H 'Cookie: session=abc123' \
  -H 'Authorization: Bearer token123' \
  -H 'X-Requested-With: XMLHttpRequest'
```

### Enterprise Authentication Scenarios

```bash
# Corporate environment with proxy headers
./kodok -u https://internal.company.com/app.js \
  -H 'Authorization: Bearer corporate-token' \
  -H 'X-Forwarded-For: 10.0.0.1' \
  -H 'User-Agent: Internal Security Scanner'

# Single Page Application with CSRF protection
./kodok -u https://webapp.example.com/main.js \
  -H 'Cookie: csrftoken=abc123; sessionid=xyz789' \
  -H 'X-CSRFToken: abc123' \
  -H 'Referer: https://webapp.example.com/'
```

## Deep Scanning Methodology

Deep scanning automatically discovers and analyzes JavaScript files referenced within initial targets.

### Process Flow

1. **Initial Analysis** - Scans specified URLs for paths and secrets
2. **JavaScript Discovery** - Extracts JavaScript file references from discovered paths
3. **Recursive Processing** - Automatically scans discovered JavaScript files
4. **Depth Management** - Prevents infinite loops with configurable depth limits
5. **Relationship Tracking** - Maps parent-child relationships between files

### Deep Scanning Examples

```bash
# Discover all JavaScript files from main application page
./kodok -u https://example.com/dashboard -deep

# Limit recursive scanning to 2 levels deep
./kodok -u https://example.com/app -deep -depth 2

# Deep scan with domain restriction
./kodok -u https://example.com/main.js -deep -ad "example.com,cdn.example.com"

# Complete application mapping
./kodok -fj entry_points.txt -deep -depth 4 -o full_app_scan \
  -H 'Cookie: session=authenticated' \
  -ad "myapp.com,api.myapp.com,static.myapp.com"
```

## Output Formats

### JSON Output Format

Comprehensive results with metadata and relationship information:

```json
{
  "total_urls": 15,
  "successful_scans": 14,
  "failed_scans": 1,
  "total_paths": 127,
  "total_secrets": 8,
  "deep_scan_enabled": true,
  "max_depth": 3,
  "scan_date": "2024-01-15T10:30:00Z",
  "results": [
    {
      "url": "https://example.com/app.js",
      "paths": ["https://api.example.com/v1/users", "/dashboard"],
      "secrets": ["API_KEY: sk_live_abc123"],
      "path_count": 23,
      "secret_count": 2,
      "scan_time": "2024-01-15T10:30:00Z",
      "duration": "1.2s",
      "depth": 0,
      "is_js_file": true,
      "parent_url": ""
    }
  ]
}
```

### Text Output Format

Clean list of discovered URLs and paths:

```
https://example.com/app.js
https://api.example.com/v1/users
https://api.example.com/v1/posts
/dashboard
/admin/users
```

## Command Line Options

| Option | Description | Example Usage |
|--------|-------------|---------------|
| `-u` | Target URL to scan | `-u https://example.com/app.js` |
| `-fj` | File containing JavaScript URLs | `-fj urls.txt` |
| `-H` | Custom header (can be repeated) | `-H 'Cookie: session=abc'` |
| `-ad` | Allowed domains (comma-separated) | `-ad "example.com,api.example.com"` |
| `-o` | Output filename (creates .json and .txt files) | `-o scan_results` |
| `-deep` | Enable deep scanning | `-deep` |
| `-depth` | Maximum depth for recursive scanning (default: 3) | `-depth 5` |
| `-h` | Display help message | `-h` |

## Input File Format

Create a text file containing URLs to scan (one per line):

```
# Main application JavaScript files
https://example.com/static/js/app.js
https://example.com/static/js/vendor.js

# API configuration files
https://api.example.com/v1/config.js
https://api.example.com/v2/client.js

# CDN hosted resources
https://cdn.example.com/assets/main.js
https://cdn.example.com/lib/utils.js

# Comments and disabled entries
# https://example.com/old-file.js (commented out)
```

## Security Features

### Automatic Header Masking

Sensitive headers are automatically masked in console output:

```
[i] Using 3 custom headers
│   Cookie: sess****3xyz
│   Authorization: Bear****oken
│   X-API-Key: sk_l****abc123
```

### Protected Header Types

The following header types are automatically masked:
- Authorization headers (Bearer tokens, Basic authentication)
- Cookie headers (Session cookies, authentication cookies)
- API Key headers (X-API-Key, API-Key)
- Authentication token headers (X-Auth-Token, Auth-Token, Access-Token)

### URL Deduplication

The scanner prevents processing the same URL multiple times during recursive scanning operations.

## Real-World Usage Examples

### Bug Bounty Reconnaissance

```bash
# Comprehensive application mapping for security research
./kodok -u https://target.com -deep -depth 3 -o recon_results \
  -ad "target.com,api.target.com,cdn.target.com,static.target.com"
```

### Authenticated Application Security Audit

```bash
# Deep scan of authenticated application areas
./kodok -u https://app.company.com/dashboard -deep -depth 2 \
  -H 'Cookie: session_token=your_session_here' \
  -H 'X-Requested-With: XMLHttpRequest' \
  -o authenticated_audit
```

### CI/CD Pipeline Integration

```bash
# Automated security scanning in continuous integration
./kodok -fj production_js_files.txt \
  -H 'Authorization: Bearer ${CI_API_TOKEN}' \
  -ad "mycompany.com" \
  -o security_scan_$(date +%Y%m%d)
```

### Multi-Domain Application Analysis

```bash
# Cross-domain application security assessment
./kodok -fj app_entry_points.txt -deep -depth 4 \
  -H 'Cookie: auth_token=abc123' \
  -ad "main.com,api.main.com,cdn.main.com,static.main.com,admin.main.com" \
  -o comprehensive_domain_scan
```

## Advanced Usage Patterns

### Integration with Security Tools

```bash
# Combine with subdomain enumeration tools
subfinder -d example.com | httpx -path /static/js/ | ./kodok -deep -o comprehensive_scan

# Pipeline with historical URL discovery
waybackurls example.com | grep -E '\\.js$' | ./kodok -fj /dev/stdin -deep
```

### Multi-Stage Analysis Workflow

```bash
# Stage 1: Discover entry points
./kodok -u https://example.com -deep -depth 1 -o entry_discovery

# Stage 2: Extract JavaScript files from results
cat entry_discovery.txt | grep -E '\\.js$' > discovered_js_files.txt

# Stage 3: Deep analysis of discovered files
./kodok -fj discovered_js_files.txt -deep -depth 3 -o deep_analysis
```

## Console Output Interpretation

### Standard Scan Output

```
Scanning: https://example.com/app.js
────────────────────────────────────────────────────────────────────────────────

Paths Found:
────────────────────────────────
  → https://api.example.com/v1/users
  → /dashboard/admin
  → /api/config.json [JS]

Secrets Found:
────────────────────────────────
  ⚠ API_KEY: sk_live_abc123def456
  ⚠ DATABASE_URL: postgres://user:pass@db.example.com/prod

────────────────────────────────
Summary Paths: 15 | Secrets: 2
════════════════════════════════════════════════════════════════════════════════
```

### Deep Scan Output

```
Deep scanning 3 JS files from this URL...
  Deep Scanning: https://example.com/vendor.js [JS] (depth: 1)
     ↳ From: https://example.com/app.js
```

### Result Priority Classification

1. **Secrets** - Immediate review required for sensitive data exposure
2. **JavaScript Files** - Marked with [JS] tag for further analysis potential
3. **API Endpoints** - Evaluate for authentication bypasses or data exposure
4. **Internal Paths** - Review for application structure and hidden functionality

## Best Practices

### Security Considerations

#### Authentication Management
- Never commit files containing real authentication tokens
- Use environment variables for sensitive header values
- Clear command history after using sensitive authentication data
- Validate scanning scope to remain within authorized boundaries

#### Scope Management
- Always implement domain filtering to reduce result noise
- Use appropriate depth limits to prevent excessive resource consumption
- Start with conservative depth settings and increase as needed

### Performance Optimization

#### Scanning Strategy
- Begin with broad reconnaissance using deep scanning on main pages
- Use authenticated sessions when available to reveal additional attack surface
- Process discovered JavaScript files as input for subsequent deeper analysis
- Maintain detailed documentation using JSON output for analysis and reporting

#### Resource Management
- Use file input for multiple URLs rather than individual command executions
- Implement output files for large scans to prevent console overflow
- Configure appropriate concurrent processing limits based on target capacity

### Effective Reconnaissance Methodology

#### Progressive Analysis Approach
1. **Initial Discovery** - Start with main application pages using shallow deep scanning
2. **Authentication Integration** - Incorporate valid authentication headers for comprehensive coverage
3. **Iterative Deepening** - Use discovered JavaScript files as input for subsequent analysis phases
4. **Documentation and Reporting** - Utilize JSON output format for detailed findings documentation

## Contributing

Contributions are welcome and encouraged. Please ensure:

- All pull requests include appropriate test coverage
- Code follows existing style conventions and formatting
- New features include corresponding documentation updates
- Security implications are properly addressed and documented

## License

This project is licensed under the MIT License. See the LICENSE file for complete details.

## Version History

### Current Release Features
- Deep scanning with recursive JavaScript file discovery
- Configurable depth limits for controlled recursive analysis
- Parent-child URL relationship tracking and documentation
- Dual output format support (comprehensive JSON and clean text)
- Enhanced URL validation and cleaning mechanisms
- Concurrent scanning capabilities with configurable rate limiting
- Improved error handling and comprehensive reporting