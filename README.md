# Kodok - JavaScript Path & Secret Scanner

A sophisticated JavaScript scanner designed to analyze JavaScript files for paths, secrets, and sensitive information. Built for security researchers and developers who need to audit JavaScript applications efficiently.

## Features

- Scan single URLs or batch process from files
- Custom header support for authenticated scanning
- Domain filtering capabilities
- Automatic sensitive data masking

## Installation

```bash
# Install directly from GitHub
go install github.com/rhyru9/kodok@latest
```

## Basic Usage

### Single URL Scanning

```bash
# Basic scan without headers
./kodok -u https://example.com/app.js

# Scan with authentication cookie
./kodok -u https://example.com/app.js -H 'Cookie: session=abc123; user=admin'

# Scan with Bearer token authorization
./kodok -u https://example.com/api.js -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'

# Multiple headers example
./kodok -u https://example.com/app.js \
  -H 'Cookie: session=abc123' \
  -H 'Authorization: Bearer token123' \
  -H 'X-API-Key: your-api-key'

# Custom User-Agent
./kodok -u https://example.com/app.js -H 'User-Agent: Mozilla/5.0 Custom Bot'
```

### Batch Scanning from File

```bash
# Scan multiple URLs from file with headers
./kodok -fj urls.txt -H 'Cookie: session=abc123'
```

## Common Header Examples

### Authentication Headers

```bash
# Bearer Token
-H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'

# Basic Authentication
-H 'Authorization: Basic dXNlcjpwYXNzd29yZA=='

# API Key Authentication
-H 'X-API-Key: your-secret-api-key'
-H 'X-Auth-Token: your-auth-token'
```

### Session and Cookie Headers

```bash
# PHP Session
-H 'Cookie: PHPSESSID=abcd1234; remember_token=xyz'

# Django/Generic Session
-H 'Cookie: sessionid=abc123; csrftoken=xyz789'
```

### Request Context Headers

```bash
# AJAX Request Indicator
-H 'X-Requested-With: XMLHttpRequest'

# IP Forwarding
-H 'X-Forwarded-For: 127.0.0.1'
-H 'X-Real-IP: 192.168.1.1'

# Referrer
-H 'Referer: https://example.com/login'

# Content Negotiation
-H 'Accept: application/json'
-H 'Content-Type: application/json'
```

## Domain Filtering

Control which domains the scanner should process results from:

```bash
# Single domain filter
./kodok -u https://example.com/app.js -ad "example.com" -H 'Cookie: session=abc123'

# Multiple domains
./kodok -fj urls.txt -ad "example.com,api.example.com,cdn.example.com" -H 'Authorization: Bearer token'
```

## Input File Format

Create a `urls.txt` file with JavaScript URLs to scan:

```
https://example.com/static/js/app.js
https://api.example.com/v1/config.js
https://cdn.example.com/assets/main.js
https://example.com/admin/dashboard.js

# Comments are ignored
# https://example.com/commented-out.js
```

## Security Features

### Header Masking

The application automatically masks sensitive header values in output for security:

```
[i] Using 2 custom headers
│   Cookie: sess****abc123
│   Authorization: Bear****token
```

### Sensitive Headers List

The following headers are automatically masked:
- `Authorization`
- `Cookie`
- `X-API-Key`
- `API-Key`
- Any header containing authentication tokens

## Command Line Options

| Option | Description |
|--------|-------------|
| `-u` | Target URL to scan |
| `-fj` | File containing JavaScript URLs |
| `-H` | Custom header (can be used multiple times) |
| `-ad` | Allow domains (comma-separated list) |

## Examples

### Complete Workflow Example

```bash
# 1. Create URL list
echo "https://example.com/js/app.js" > targets.txt
echo "https://example.com/js/config.js" >> targets.txt

# 2. Run authenticated scan with domain filtering
./kodok -fj targets.txt \
  -H 'Cookie: sessionid=your-session-here' \
  -H 'X-API-Key: your-api-key' \
  -ad "example.com,api.example.com"
```

### Testing Different Authentication Methods

```bash
# Test with session cookie
./kodok -u https://app.example.com/main.js -H 'Cookie: session=test123'

# Test with JWT token
./kodok -u https://api.example.com/client.js -H 'Authorization: Bearer jwt-token-here'

# Test with API key
./kodok -u https://example.com/secure.js -H 'X-API-Key: api-key-here'
```

## Best Practices

1. **Always use domain filtering** when scanning to avoid processing irrelevant external resources
2. **Test authentication headers** on a single URL before batch processing
3. **Use appropriate User-Agent strings** to avoid being blocked by WAF/CDN
4. **Keep sensitive headers secure** - the tool masks them in output but be careful with command history
5. **Process results systematically** - review all discovered paths and secrets thoroughly

## Contributing

Contributions are welcome. Please ensure all pull requests include appropriate tests and follow the existing code style.

## License

This project is licensed under the MIT License. See LICENSE file for details.