package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rhyru9/kodok/internal/fetcher"
	"github.com/rhyru9/kodok/internal/parser"
	"github.com/rhyru9/kodok/internal/scanner"
	"github.com/rhyru9/kodok/internal/utils"

	"github.com/fatih/color"
)

var (
	urlFile       = flag.String("fj", "", "File daftar URL JS")
	singleURL     = flag.String("u", "", "URL tunggal untuk diproses")
	allowedDomain = flag.String("ad", "", "Domain yang diperbolehkan dalam output (pisahkan dengan koma)")
)

var validPathRegex = regexp.MustCompile(`^(https?://|/)[^\s]+`)

func main() {
	flag.Parse()
	utils.PrintBanner()

	allowedDomains := parseAllowedDomains(*allowedDomain)
	urls := getURLs()

	if len(urls) == 0 {
		fmt.Println("Tidak ada URL yang diberikan. Gunakan -fj untuk file atau -u untuk URL tunggal.")
		return
	}

	var wg sync.WaitGroup
	numWorkers := 3 // Worker pool 3
	urlChan := make(chan string, len(urls))

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urlChan {
				processURL(url, allowedDomains)
			}
		}()
	}

	for _, url := range urls {
		urlChan <- url
	}
	close(urlChan)

	wg.Wait()
}

func getURLs() []string {
	var urls []string

	if *urlFile != "" {
		file, err := os.Open(*urlFile)
		if err != nil {
			fmt.Printf("Gagal membuka file: %s\n", err)
			return nil
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			urls = append(urls, scanner.Text())
		}
	} else if *singleURL != "" {
		urls = append(urls, *singleURL)
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				urls = append(urls, scanner.Text())
			}
		}
	}

	return urls
}

func processURL(url string, allowedDomains []string) {
	blue := color.New(color.FgBlue).SprintFunc()
	azure := color.New(color.FgCyan).SprintFunc()
	magenta := color.New(color.FgMagenta).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	orange := color.New(color.FgYellow).SprintFunc()

	fmt.Printf("%s [%s]\n", blue("[+]"), azure(url))

	contentChan := make(chan string, 1)
	errChan := make(chan error, 1)

	go func() {
		content, err := fetcher.Fetch(url)
		if err != nil {
			errChan <- err
			return
		}
		contentChan <- content
	}()

	var content string
	select {
	case content = <-contentChan:
	case err := <-errChan:
		fmt.Printf("%s Gagal mengambil konten: %s\n", blue("[+]"), err)
		return
	case <-time.After(10 * time.Second): // Timeout 10 sec
		fmt.Printf("%s Timeout saat mengambil konten dari %s\n", blue("[+]"), url)
		return
	}

	uniquePaths := sync.Map{}
	uniqueSecrets := sync.Map{}

	paths := parser.Parse(content)
	for _, path := range paths {
		if validPathRegex.MatchString(path) && isAllowedDomain(path, allowedDomains) {
			if _, loaded := uniquePaths.LoadOrStore(path, true); !loaded {
				fmt.Printf("%s %-25s %s\n", azure("[+] found path  |"), magenta(formatMultiline(path)), "")
			}
		}
	}

	secrets := scanner.Scan(content)
	for _, secret := range secrets {
		if isAllowedDomain(secret, allowedDomains) {
			if _, loaded := uniqueSecrets.LoadOrStore(secret, true); !loaded {
				fmt.Printf("%s %-25s %s\n", blue("[+] found API   |"), red(formatMultiline(secret)), orange("possibly"))
			}
		}
	}
}

func parseAllowedDomains(ad string) []string {
	if ad == "" {
		return nil
	}
	domains := strings.Split(ad, ",")
	for i, domain := range domains {
		domains[i] = strings.TrimSpace(domain)
	}
	return domains
}

func isAllowedDomain(rawURL string, allowedDomains []string) bool {
	if len(allowedDomains) == 0 {
		return true
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	host := parsedURL.Hostname()
	for _, domain := range allowedDomains {
		if strings.HasSuffix(host, domain) {
			return true
		}
	}
	return false
}

func formatMultiline(text string) string {
	const lineLength = 80
	var result string
	for i := 0; i < len(text); i += lineLength {
		if i+lineLength < len(text) {
			result += text[i:i+lineLength] + "\n\t\t"
		} else {
			result += text[i:]
		}
	}
	return result
}
