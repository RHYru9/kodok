package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/rhyru9/kodok/internal/fetcher"
	"github.com/rhyru9/kodok/internal/parser"
	"github.com/rhyru9/kodok/internal/scanner"
	"github.com/rhyru9/kodok/internal/utils"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"

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
	sem := make(chan struct{}, 5) // Batasi 5 goroutine untuk efisiensi CPU

	for _, url := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}
			processURL(url, allowedDomains)
			<-sem
		}(url)
	}

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

	content, err := fetcher.Fetch(url)
	if err != nil {
		fmt.Printf("%s Gagal mengambil konten: %s\n", blue("[+]"), err)
		return
	}

	uniquePaths := make(map[string]bool)
	uniqueSecrets := make(map[string]bool)
	var mu sync.Mutex

	paths := parser.Parse(content)
	for _, path := range paths {
		if validPathRegex.MatchString(path) && isAllowedDomain(path, allowedDomains) {
			mu.Lock()
			if !uniquePaths[path] {
				uniquePaths[path] = true
				fmt.Printf("%s %-25s %s\n", azure("[+] found path  |"), magenta(formatMultiline(path)), "")
			}
			mu.Unlock()
		}
	}

	secrets := scanner.Scan(content)
	for _, secret := range secrets {
		if isAllowedDomain(secret, allowedDomains) {
			mu.Lock()
			if !uniqueSecrets[secret] {
				uniqueSecrets[secret] = true
				fmt.Printf("%s %-25s %s\n", blue("[+] found API   |"), red(formatMultiline(secret)), orange("possibly"))
			}
			mu.Unlock()
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
