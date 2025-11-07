<div align="center">

![KODOK Banner](assets/banner.svg)

# KODOK - JavaScript Security Scanner

A high-performance, concurrent JavaScript security scanner designed to extract endpoints, API paths, and detect sensitive information from JavaScript files.

</div>

## Overview

KODOK is a command-line tool that recursively crawls JavaScript files to discover:
- API endpoints and URL paths
- Hardcoded secrets and credentials
- Internal service URLs
- Configuration endpoints

Built with Go for speed and efficiency, KODOK uses concurrent workers, intelligent caching, and advanced pattern matching to scan large codebases quickly.

## Features

### Core Capabilities
- **Concurrent Scanning**: Configurable worker pool for parallel processing
- **Recursive Discovery**: Deep scanning of JavaScript dependencies
- **Smart Deduplication**: LRU cache prevents redundant processing
- **Domain Filtering**: Wildcard support for scoping scans to specific domains
- **Secret Detection**: Pattern-based identification of 30+ credential types
- **SSRF Protection**: Built-in validation against internal/private addresses

### Input Flexibility
- Single URL via `-u` flag
- File input via `-f` flag
- Pipeline support via stdin

### Output Formats
- **JSON**: Detailed results with metadata
- **TXT**: Clean list of discovered URLs

## Installation

```bash
# Clone the repository
git clone https://github.com/rhyru9/kodok.git
cd kodok

# Build the binary
go build -o kodok cmd/kodok/main.go

# Optional: Install to PATH
go install ./cmd/kodok
```

## Usage

### Basic Examples

Scan a single JavaScript file:
```bash
kodok -u https://example.com/app.js
```

Scan multiple URLs from a file:
```bash
kodok -f urls.txt
```

Read URLs from stdin:
```bash
cat urls.txt | kodok -o results
```

### Advanced Usage

Enable deep scanning with custom depth:
```bash
kodok -f urls.txt -deep -depth 5 -workers 20
```

Scope scan to specific domains:
```bash
kodok -u https://target.com -ad "target.com,*.api.target.com"
```

Use custom headers for authentication:
```bash
kodok -u https://api.example.com/app.js \
  -H "Authorization:Bearer token123,X-Custom-Header:value"
```

Combine multiple options:
```bash
cat urls.txt | kodok \
  -deep \
  -depth 3 \
  -workers 15 \
  -ad "*.itb.ac.id,*.ui.ac.id" \
  -timeout 45 \
  -o university_scan
```

## Command-Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-u` | - | Single URL to scan |
| `-f` | - | File containing URLs (one per line) |
| `-o` | `kodok_results` | Output base filename |
| `-workers` | `10` | Number of concurrent workers (1-100) |
| `-depth` | `3` | Maximum recursion depth (0-10) |
| `-cache` | `10000` | LRU cache size for deduplication |
| `-timeout` | `30` | Request timeout in seconds |
| `-retries` | `3` | Number of retry attempts |
| `-deep` | `false` | Enable deep scanning of JS dependencies |
| `-ad` | - | Allowed domains (comma-separated, supports wildcards) |
| `-H` | - | Custom headers (format: `Header1:Value1,Header2:Value2`) |
| `-v` | `false` | Verbose output |

## Domain Filtering

KODOK supports flexible domain filtering with wildcard patterns:

### Exact Domain Match
```bash
kodok -u https://example.com/app.js -ad "example.com"
```
Matches: `example.com` only

### Wildcard Subdomain Match
```bash
kodok -u https://api.example.com/app.js -ad "*.example.com"
```
Matches: `api.example.com`, `sub.example.com`, `a.b.example.com`

### Multiple Domain Patterns
```bash
kodok -f urls.txt -ad "*.itb.ac.id,*.ui.ac.id,example.com"
```
Matches: All subdomains of `itb.ac.id` and `ui.ac.id`, plus `example.com`

### Important Notes
- Wildcard `*.example.com` also matches the base domain `example.com`
- Domain matching is case-insensitive
- The scanner normalizes domains by removing `www.` prefix

## Secret Detection

KODOK detects 30+ types of sensitive information:

### Cloud Provider Keys
- AWS Access Keys (AKIA*, ASIA*, etc.)
- Google API Keys
- Azure credentials

### Payment Processing
- Stripe API keys
- Square tokens
- Midtrans server keys
- Braintree tokens

### Version Control & CI/CD
- GitHub tokens (personal, OAuth, app)
- GitLab tokens
- NPM tokens

### Communication Services
- Slack tokens and webhooks
- Discord bot tokens
- Telegram bot tokens
- SendGrid API keys
- Twilio credentials

### Database Credentials
- Connection strings with embedded passwords
- Hardcoded database credentials

### Generic Patterns
- JWT tokens
- Bearer tokens
- Basic authentication credentials
- Private keys (RSA, SSH, PGP)

### Example Output
```json
{
  "type": "AWS Access Key ID",
  "value": "AKIA****WXYZ",
  "context": "const key = 'AKIAIOSFODNN7EXAMPLE'",
  "line": 42
}
```

## Path Extraction

KODOK uses multiple extraction methods to discover endpoints:

### Pattern Matching
Detects paths in:
- String literals (`'`, `"`)
- Template literals (backticks)
- Object properties (`path:`, `url:`, `endpoint:`)
- Function calls (`fetch()`, `axios.get()`)
- Concatenated strings

### Heuristic Detection
Automatically identifies common API patterns:
```javascript
/api/v1/users
/graphql/query
/oauth/token
/auth/login
/admin/config
```

### Example Extracted Paths
```javascript
// From: const api = '/api/v1/users?limit=10';
Output: /api/v1/users?limit=10

// From: fetch(baseURL + '/config');
Output: /config

// From: { endpoint: 'https://api.example.com/data' }
Output: https://api.example.com/data
```

## SSRF Protection

KODOK includes built-in protection against Server-Side Request Forgery:

### Blocked Targets
- Loopback addresses: `127.0.0.1`, `::1`, `localhost`
- Private networks: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Link-local: `169.254.169.254` (AWS metadata)
- Cloud metadata services
- Kubernetes internal APIs

### Example
```bash
# These will be rejected:
kodok -u http://localhost/app.js
kodok -u http://169.254.169.254/latest/meta-data/
kodok -u http://metadata.google.internal/
```

## Architecture

### Components

**Worker Pool** (`internal/core/workerpool.go`)
- Manages concurrent goroutines
- Buffered task queue
- Graceful shutdown support

**Processor** (`internal/core/processor.go`)
- Orchestrates scanning workflow
- Handles recursive discovery
- Aggregates results

**Fetcher** (`internal/fetch/fetcher.go`)
- HTTP client with retry logic
- SSRF validation
- Content filtering

**Extractor** (`internal/parse/extractor.go`)
- Multi-method path extraction
- Regex-based pattern matching
- URL validation and normalization

**Secret Scanner** (`internal/scan/secrets.go`)
- Pattern-based detection
- Entropy analysis
- False positive filtering

**Deduplicator** (`internal/cache/dedup.go`)
- LRU cache implementation
- Thread-safe operations
- Prevents redundant scanning

## Output Format

### JSON Output (`kodok_results.json`)
```json
{
  "summary": {
    "total_urls": 50,
    "success_count": 48,
    "failed_count": 2,
    "total_paths": 342,
    "total_secrets": 5,
    "total_time": "45.2s"
  },
  "results": [
    {
      "url": "https://example.com/app.js",
      "paths": ["/api/users", "/api/config"],
      "secrets": [...],
      "path_count": 2,
      "secret_count": 0,
      "depth": 0,
      "duration": "1.2s",
      "status_code": 200
    }
  ]
}
```

### TXT Output (`kodok_results.txt`)
```
https://example.com/api/users
https://example.com/api/config
https://example.com/static/vendor.js
...
```

## Performance Considerations

### Optimization Tips
1. **Adjust worker count** based on network bandwidth:
   ```bash
   kodok -f urls.txt -workers 20  # For high-bandwidth
   kodok -f urls.txt -workers 5   # For rate-limited targets
   ```

2. **Set appropriate depth** to balance coverage and time:
   ```bash
   kodok -u https://example.com -deep -depth 2  # Faster
   kodok -u https://example.com -deep -depth 5  # More thorough
   ```

3. **Use domain filtering** to reduce scope:
   ```bash
   kodok -f urls.txt -ad "*.target.com"  # Only scan target domain
   ```

### Resource Usage
- Memory: ~50-100MB base + (cache_size × 100 bytes)
- Network: Concurrent connections = worker count
- CPU: Minimal (I/O bound)

## Limitations

### Current Constraints
1. **Dynamic Path Construction**: Cannot resolve runtime-evaluated paths
   ```javascript
   // Not detected:
   const endpoint = "/api/" + resource + "/" + id;
   ```

2. **Obfuscated Code**: Limited support for minified/obfuscated JavaScript

3. **Template Literals**: Partial support for complex template expressions

4. **JavaScript Execution**: No runtime evaluation (static analysis only)

### Workarounds
- Use verbose mode (`-v`) to see intermediate results
- Increase depth for better coverage
- Manually review complex JavaScript files

## Troubleshooting

### Common Issues

**No URLs found**
```bash
# Check input format:
cat urls.txt | kodok -v
```

**Rate limiting**
```bash
# Reduce workers and add delay:
kodok -f urls.txt -workers 3 -timeout 60
```

**Connection timeouts**
```bash
# Increase timeout:
kodok -u https://slow-site.com -timeout 120
```

**Memory usage**
```bash
# Reduce cache size:
kodok -f large_list.txt -cache 5000
```

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Acknowledgments

Built with:
- [fatih/color](https://github.com/fatih/color) - Terminal colors
- [hashicorp/golang-lru](https://github.com/hashicorp/golang-lru) - LRU cache

## Security Notice

KODOK is designed for authorized security testing only. Users are responsible for:
- Obtaining proper authorization before scanning
- Complying with applicable laws and regulations
- Respecting rate limits and terms of service
- Using findings responsibly

**Do not use this tool for unauthorized access or malicious purposes.**

---

<div align="center">
Made with ❤️ by <a href="https://github.com/rhyru9">Rhyru9</a>
</div>
