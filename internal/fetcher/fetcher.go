package fetcher

import (
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

// Blacklist ekstensi file yang tidak perlu diproses (hanya file biner dan media)
var blacklistedExtensions = map[string]bool{
	// Images (kecuali SVG yang akan diproses)
	".png":   true,
	".jpg":   true,
	".jpeg":  true,
	".gif":   true,
	".webp":  true,
	".ico":   true,
	".bmp":   true,
	".tiff":  true,
	".tif":   true,
	".avif":  true,
	".heic":  true,
	".heif":  true,
	".raw":   true,
	".cr2":   true,
	".nef":   true,
	".arw":   true,
	".dng":   true,
	".psd":   true,
	".ai":    true,
	".eps":   true,
	".jfif":  true,
	".pjpeg": true,
	".pjp":   true,
	".apng":  true,
	".jxl":   true,

	// Documents (binary)
	".pdf":  true,
	".doc":  true,
	".docx": true,
	".xls":  true,
	".xlsx": true,
	".ppt":  true,
	".pptx": true,
	".odt":  true,
	".ods":  true,
	".odp":  true,
	".rtf":  true,
	".epub": true,
	".mobi": true,
	".djvu": true,

	// Archives
	".zip":  true,
	".rar":  true,
	".7z":   true,
	".tar":  true,
	".gz":   true,
	".bz2":  true,
	".xz":   true,
	".lzma": true,
	".cab":  true,
	".ace":  true,
	".arj":  true,
	".lha":  true,
	".sit":  true,
	".sitx": true,
	".sea":  true,
	".iso":  true,
	".img":  true,
	".dmg":  true,

	// Fonts
	".woff":  true,
	".woff2": true,
	".ttf":   true,
	".eot":   true,
	".otf":   true,
	".pfb":   true,
	".pfm":   true,
	".afm":   true,
	".fon":   true,
	".fnt":   true,
	".bdf":   true,
	".pcf":   true,
	".snf":   true,

	// Media
	".mp4":  true,
	".mp3":  true,
	".wav":  true,
	".avi":  true,
	".mov":  true,
	".wmv":  true,
	".flv":  true,
	".mkv":  true,
	".webm": true,
	".m4v":  true,
	".mpg":  true,
	".mpeg": true,
	".3gp":  true,
	".ogv":  true,
	".ts":   true,
	".vob":  true,
	".rm":   true,
	".asf":  true,
	".ogg":  true,
	".aac":  true,
	".flac": true,
	".wma":  true,
	".m4a":  true,
	".opus": true,
	".ape":  true,
	".ac3":  true,
	".dts":  true,
	".ra":   true,
	".au":   true,
	".aiff": true,

	// Executables and packages
	".exe":      true,
	".msi":      true,
	".pkg":      true,
	".deb":      true,
	".rpm":      true,
	".appimage": true,
	".apk":      true,
	".ipa":      true,
	".jar":      true,
	".war":      true,
	".ear":      true,

	// Binary data files
	".db":     true,
	".sqlite": true,
	".mdb":    true,
	".accdb":  true,

	// CAD and 3D
	".dwg":   true,
	".dxf":   true,
	".step":  true,
	".iges":  true,
	".stl":   true,
	".obj":   true,
	".fbx":   true,
	".dae":   true,
	".3ds":   true,
	".max":   true,
	".blend": true,
	".ma":    true,
	".mb":    true,
	".c4d":   true,
	".skp":   true,

	// Others
	".log":   true,
	".bak":   true,
	".tmp":   true,
	".temp":  true,
	".cache": true,
	".lock":  true,
	".pid":   true,
}

// Content-types yang diblacklist (hanya tipe biner)
var blacklistedContentTypes = []string{
	"image/png",
	"image/jpeg",
	"image/gif",
	"image/webp",
	"image/bmp",
	"image/tiff",
	"image/x-icon",
	"video/",
	"audio/",
	"application/pdf",
	"application/zip",
	"application/x-rar",
	"application/x-7z-compressed",
	"application/x-tar",
	"application/gzip",
	"application/x-bzip2",
	"application/vnd.ms-excel",
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	"application/msword",
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	"application/vnd.ms-powerpoint",
	"application/vnd.openxmlformats-officedocument.presentationml.presentation",
	"application/rtf",
	"application/epub+zip",
	"font/",
	"application/font-",
	"application/x-font-",
	"application/vnd.ms-fontobject",
	"application/x-executable",
	"application/x-msdos-program",
	"application/x-msdownload",
	"application/vnd.android.package-archive",
	"application/java-archive",
	"application/x-iso9660-image",
	"application/x-apple-diskimage",
}

// Fetch performs a basic GET request without custom headers (backward compatibility)
func Fetch(url string) (string, error) {
	return FetchWithHeaders(url, nil)
}

// FetchWithHeaders performs a GET request with custom headers support and enhanced filtering
func FetchWithHeaders(url string, headers map[string]string) (string, error) {
	// Check blacklisted extension first
	if isBlacklistedExtension(url) {
		return "", fmt.Errorf("skipped: blacklisted file extension")
	}

	// Check for suspicious URL patterns (hanya yang benar-benar biner)
	if hasSuspiciousBinaryURLPattern(url) {
		return "", fmt.Errorf("skipped: suspicious binary URL pattern")
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Create new request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	// Set default User-Agent if not provided in custom headers
	if headers == nil || headers["User-Agent"] == "" {
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Kodok/1.0)")
	}

	// Set custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Check content type (hanya blokir yang benar-benar biner)
	contentType := resp.Header.Get("Content-Type")
	if isBlacklistedContentType(contentType) {
		return "", fmt.Errorf("skipped: blacklisted content-type: %s", contentType)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Check content-disposition header for binary downloads
	contentDisposition := resp.Header.Get("Content-Disposition")
	if strings.Contains(strings.ToLower(contentDisposition), "attachment") && 
	   !isTextualAttachment(contentDisposition) {
		return "", fmt.Errorf("skipped: binary file download detected")
	}

	// Check content-length for very large files
	contentLength := resp.Header.Get("Content-Length")
	if contentLength != "" {
		// Skip files larger than 50MB
		if len(contentLength) > 8 {
			return "", fmt.Errorf("skipped: file too large")
		}
	}

	// Read response body with size limit (50MB)
	limitedReader := io.LimitReader(resp.Body, 50*1024*1024)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return "", err
	}

	content := string(body)

	// Enhanced content validation - lebih permisif untuk text/code
	if !isValidTextContent(content, url) {
		return "", fmt.Errorf("skipped: binary content detected")
	}

	return content, nil
}

// Enhanced extension checking - hanya blokir ekstensi biner
func isBlacklistedExtension(url string) bool {
	// Clean URL
	cleanURL := cleanURLForExtensionCheck(url)
	
	// Check file extension
	ext := strings.ToLower(filepath.Ext(cleanURL))
	if blacklistedExtensions[ext] {
		return true
	}

	// Check for double extensions (hanya yang biner)
	if strings.Contains(cleanURL, ".tar.") {
		parts := strings.Split(cleanURL, ".")
		if len(parts) >= 3 {
			doubleExt := "." + parts[len(parts)-2] + "." + parts[len(parts)-1]
			doubleExtLower := strings.ToLower(doubleExt)
			binaryDoubleExts := []string{".tar.gz", ".tar.bz2", ".tar.xz"}
			for _, dext := range binaryDoubleExts {
				if doubleExtLower == dext {
					return true
				}
			}
		}
	}

	return false
}

// Clean URL for extension checking
func cleanURLForExtensionCheck(url string) string {
	// Remove query parameters
	if idx := strings.Index(url, "?"); idx != -1 {
		url = url[:idx]
	}
	
	// Remove fragment
	if idx := strings.Index(url, "#"); idx != -1 {
		url = url[:idx]
	}
	
	// Remove trailing slash
	url = strings.TrimRight(url, "/")
	
	return url
}

// Enhanced content-type checking - hanya blokir tipe biner
func isBlacklistedContentType(contentType string) bool {
	if contentType == "" {
		return false
	}

	contentType = strings.ToLower(strings.TrimSpace(contentType))
	
	// Remove charset and other parameters
	if idx := strings.Index(contentType, ";"); idx != -1 {
		contentType = contentType[:idx]
	}

	// Allow semua text/* dan application/* kecuali yang biner
	allowedPrefixes := []string{
		"text/",
		"application/javascript",
		"application/json",
		"application/xml",
		"application/xhtml+xml",
		"application/x-httpd-php",
		"application/x-javascript",
		"application/ecmascript",
	}

	for _, allowed := range allowedPrefixes {
		if strings.HasPrefix(contentType, allowed) {
			return false
		}
	}

	// Check blacklisted types
	for _, blacklisted := range blacklistedContentTypes {
		if strings.HasPrefix(contentType, blacklisted) {
			return true
		}
	}

	// Default allow untuk content-type yang tidak dikenal
	return false
}

// Check for suspicious binary URL patterns
func hasSuspiciousBinaryURLPattern(url string) bool {
	urlLower := strings.ToLower(url)
	
	// Check for data URLs (hanya yang biner)
	if strings.HasPrefix(urlLower, "data:image/") ||
	   strings.HasPrefix(urlLower, "data:video/") ||
	   strings.HasPrefix(urlLower, "data:audio/") ||
	   strings.HasPrefix(urlLower, "data:font/") ||
	   strings.HasPrefix(urlLower, "data:application/pdf") ||
	   strings.HasPrefix(urlLower, "data:application/zip") ||
	   strings.HasPrefix(urlLower, "data:application/octet-stream") {
		return true
	}
	
	// Check for binary file download patterns
	binaryPatterns := []string{
		"/download/binary/", "/downloads/files/", "/media/video/", "/media/audio/",
		"/images/", "/img/", "/assets/img/", "/static/img/", "/public/img/",
		"/pdf/", "/export/pdf/", "/backup/", "/backups/",
		"/fonts/", "/font/", "/.git/objects/",
		"/storage/files/", "/tmp/files/", "/temp/files/", "/cache/files/",
	}
	
	for _, pattern := range binaryPatterns {
		if strings.Contains(urlLower, pattern) {
			return true
		}
	}
	
	// Check for binary file download parameters
	binaryParams := []string{
		"type=pdf", "type=doc", "type=xls", "type=image", "render=pdf",
		"format=binary", "output=binary", "mime_type=image/", "mime_type=video/", "mime_type=audio/",
	}
	
	for _, param := range binaryParams {
		if strings.Contains(urlLower, param) {
			return true
		}
	}
	
	return false
}

// Check if attachment is textual
func isTextualAttachment(contentDisposition string) bool {
	lower := strings.ToLower(contentDisposition)
	textualExtensions := []string{
		".txt", ".html", ".htm", ".js", ".css", ".json", ".xml", ".csv", ".tsv",
		".php", ".asp", ".aspx", ".jsp", ".py", ".go", ".java", ".c", ".cpp",
		".h", ".hpp", ".rb", ".pl", ".sh", ".bat", ".cmd", ".sql", ".yaml", ".yml",
		".ini", ".cfg", ".conf", ".log", ".md", ".rst", ".tex", ".r", ".scala",
		".swift", ".kt", ".dart", ".ts", ".vue", ".svelte", ".jsx", ".tsx",
	}
	
	for _, ext := range textualExtensions {
		if strings.Contains(lower, ext) {
			return true
		}
	}
	
	return false
}

// Enhanced text content validation - lebih permisif
func isValidTextContent(content string, url string) bool {
	// Allow empty content
	if len(content) == 0 {
		return true
	}

	// Check for obvious binary signatures
	if hasObviousBinaryContent(content) {
		return false
	}

	// Check for excessive binary data
	if hasExcessiveBinaryData(content) {
		return false
	}

	// Allow semua content text-based lainnya
	return true
}

// Check for obvious binary content signatures
func hasObviousBinaryContent(content string) bool {
	if len(content) < 4 {
		return false
	}

	// Check for binary signatures
	binarySignatures := [][]byte{
		{0x89, 0x50, 0x4E, 0x47}, // PNG
		{0xFF, 0xD8, 0xFF},       // JPEG
		{0x47, 0x49, 0x46, 0x38}, // GIF
		{0x25, 0x50, 0x44, 0x46}, // PDF
		{0x50, 0x4B, 0x03, 0x04}, // ZIP
		{0x52, 0x61, 0x72, 0x21}, // RAR
		{0x37, 0x7A, 0xBC, 0xAF}, // 7Z
		{0x1F, 0x8B, 0x08},       // GZIP
		{0x42, 0x5A, 0x68},       // BZIP2
		{0x00, 0x00, 0x01, 0x00}, // ICO
		{0x52, 0x49, 0x46, 0x46}, // RIFF (WAV, AVI)
		{0x66, 0x74, 0x79, 0x70}, // MP4
		{0x4F, 0x67, 0x67, 0x53}, // OGG
	}

	contentBytes := []byte(content)
	for _, sig := range binarySignatures {
		if len(contentBytes) >= len(sig) {
			match := true
			for i, b := range sig {
				if contentBytes[i] != b {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}

	return false
}

// Check for excessive binary data
func hasExcessiveBinaryData(content string) bool {
	if len(content) < 100 {
		return false
	}

	// Check for high ratio of non-printable characters (lebih permisif)
	nonPrintable := 0
	checkLength := len(content)
	if checkLength > 2000 {
		checkLength = 2000 // Check first 2000 chars
	}

	for i := 0; i < checkLength; i++ {
		r := rune(content[i])
		// Allow more characters as printable
		if r < 9 || (r > 13 && r < 32) || r == 127 {
			nonPrintable++
		}
	}

	// More permissive: allow up to 30% non-printable
	if float64(nonPrintable)/float64(checkLength) > 0.3 {
		return true
	}

	return false
}