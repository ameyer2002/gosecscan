package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var commonHeaders = []string{
	"Content-Security-Policy",
	"X-Content-Type-Options",
	"X-Frame-Options",
	"Strict-Transport-Security",
	"Referrer-Policy",
}

// checkHeaders checks for common security headers and TLS cert details
func checkHeaders(target string) {
	fmt.Println("\n Security Header & TLS Check for:", target)

	// Parse URL for TLS check
	parsedUrl, err := url.Parse(target)
	if err != nil {
		fmt.Println("[!] Invalid URL:", err)
		return
	}

	// TLS cert check (only if https)
	if parsedUrl.Scheme == "https" {
		conn, err := tls.Dial("tcp", parsedUrl.Host+":443", &tls.Config{})
		if err != nil {
			fmt.Println("[!] TLS connection error:", err)
		} else {
			certs := conn.ConnectionState().PeerCertificates
			cert := certs[0]
			fmt.Printf("[+] TLS Cert Subject: %s\n", cert.Subject.CommonName)
			fmt.Printf("[+] TLS Cert Issuer: %s\n", cert.Issuer.CommonName)
			fmt.Printf("[+] TLS Cert Expiry: %s\n", cert.NotAfter.Format("2006-01-02"))
			conn.Close()
		}
	} else {
		fmt.Println("[-] Not HTTPS, skipping TLS cert check")
	}

	// HTTP client with no redirects (to detect if redirects happen)
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Stop after first redirect
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(target)
	if err != nil {
		fmt.Println("[!] Error fetching URL:", err)
		return
	}
	defer resp.Body.Close()

	// Check for redirects
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc, err := resp.Location()
		if err == nil {
			fmt.Printf("[!] Redirect detected: %s -> %s\n", target, loc.String())
		} else {
			fmt.Printf("[!] Redirect detected with unknown location (status %d)\n", resp.StatusCode)
		}
	} else {
		fmt.Printf("[+] No redirect detected (status %d)\n", resp.StatusCode)
	}

	// Check common security headers
	for _, header := range commonHeaders {
		if resp.Header.Get(header) == "" {
			fmt.Printf("[-] Missing header: %s\n", header)
		} else {
			fmt.Printf("[+] Found header: %s\n", header)
		}
	}
}

// dirBruteForce does multithreaded directory brute forcing
func dirBruteForce(url string, wordlist string) {
	file, err := os.Open(wordlist)
	if err != nil {
		fmt.Println("[!] Failed to open wordlist:", err)
		return
	}
	defer file.Close()

	fmt.Println("\n Directory Bruteforce Results:")
	scanner := bufio.NewScanner(file)
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 5 * time.Second}

	for scanner.Scan() {
		path := scanner.Text()
		fullURL := fmt.Sprintf("%s/%s", strings.TrimRight(url, "/"), strings.TrimLeft(path, "/"))

		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			resp, err := client.Get(u)
			if err == nil {
				// Consider anything other than 404 and 400 as interesting
				if resp.StatusCode != 404 && resp.StatusCode != 400 {
					fmt.Printf("[+] %s [%d]\n", u, resp.StatusCode)
				}
				resp.Body.Close()
			}
		}(fullURL)
	}
	wg.Wait()
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: gosecscan <url> <wordlist>")
		return
	}

	target := os.Args[1]
	wordlist := os.Args[2]

	checkHeaders(target)
	dirBruteForce(target, wordlist)

	fmt.Println("\n Scan Complete.")
}
