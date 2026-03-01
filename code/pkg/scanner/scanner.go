package scanner

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"xoxo/internal/config"
	"xoxo/internal/types"
)

type Scanner struct {
	config  *config.Config
	client  *http.Client
	results chan *types.ScanResult
}

func NewScanner(cfg *config.Config) *Scanner {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Scanner{
		config:  cfg,
		client:  client,
		results: make(chan *types.ScanResult, 256),
	}
}

func (s *Scanner) Run() error {
	urls, err := s.readURLs()
	if err != nil {
		return err
	}
	if len(urls) == 0 {
		return fmt.Errorf("no URLs found in file")
	}

	var wgPrint sync.WaitGroup
	wgPrint.Add(1)
	go func() {
		defer wgPrint.Done()
		s.printResults()
	}()

	s.processURLs(urls)

	close(s.results)
	wgPrint.Wait()
	return nil
}

func (s *Scanner) readURLs() ([]string, error) {
	file, err := os.Open(s.config.URLFile)
	if err != nil {
		return nil, fmt.Errorf("Error reading URLs: %v", err)
	}
	defer file.Close()

	var (
		urls  []string
		count int
	)

	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		urls = append(urls, line)
		count++
		fmt.Printf("\rloading urls [ %d / %d ]", count, count)
	}
	fmt.Println()

	if err := sc.Err(); err != nil {
		return nil, err
	}
	return urls, nil
}

func (s *Scanner) processURLs(urls []string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, s.config.Workers)

	for _, u := range urls {
		u := u
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if s.config.PathMode {
				s.processPath(u)
			} else {
				s.processURL(u)
			}
		}()
	}
	wg.Wait()
}

func (s *Scanner) processURL(targetURL string) {
	// Base payloads closely match those inferred from the original binary.
	basePayloads := []string{
		`<script>alert(1)</script>`,
		`"><script>alert(1)</script>`,
		`'><script>alert(1)</script>`,
		`<img src=x onerror=alert(1)>`,
		`javascript:alert(1)`,
		`<svg onload=alert(1)>`,
	}

	// Extend with advanced payload sets.
	var payloads []string
	payloads = append(payloads, basePayloads...)
	for _, set := range AdvancedPayloads {
		payloads = append(payloads, set.Payloads...)
	}

	parsed, err := url.Parse(targetURL)
	if err != nil {
		s.results <- &types.ScanResult{URL: targetURL, Error: err.Error()}
		return
	}

	for _, payload := range payloads {
		testURL := s.injectPayload(parsed, payload)
		if s.testReflection(testURL, payload) {
			// The scanner currently reports a coarse context; this can be
			// refined later by analyzing the response body.
			s.results <- &types.ScanResult{
				URL:        targetURL,
				Vulnerable: true,
				Payload:    payload,
				Context:    "query_parameter",
			}
			return
		}
	}

	s.results <- &types.ScanResult{
		URL:        targetURL,
		Vulnerable: false,
	}
}

func (s *Scanner) processPath(targetURL string) {
	payloads := []string{
		`<script>alert(1)</script>`,
		`'"><script>alert(1)</script>`,
	}

	parsed, err := url.Parse(targetURL)
	if err != nil {
		s.results <- &types.ScanResult{URL: targetURL, Error: err.Error()}
		return
	}

	for _, payload := range payloads {
		testPath := parsed.Path + "/" + url.PathEscape(payload)
		testURL := parsed.Scheme + "://" + parsed.Host + testPath
		if s.testReflection(testURL, payload) {
			s.results <- &types.ScanResult{
				URL:        targetURL,
				Vulnerable: true,
				Payload:    payload,
				Context:    "path_segment",
			}
			return
		}
	}

	s.results <- &types.ScanResult{
		URL:        targetURL,
		Vulnerable: false,
	}
}

func (s *Scanner) injectPayload(parsed *url.URL, payload string) string {
	q := parsed.Query()
	q.Set("xss", payload)
	for k := range q {
		if k != "xss" {
			q.Set(k, payload)
			break
		}
	}
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func (s *Scanner) testReflection(testURL, payload string) bool {
	req, err := http.NewRequest(http.MethodGet, testURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (XoXo-Scanner/1.0)")

	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		return false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	return strings.Contains(string(body), payload)
}

func (s *Scanner) printResults() {
	for r := range s.results {
		if r.Error != "" {
			fmt.Printf("[ERROR] %s: %s\n", r.URL, r.Error)
			continue
		}
		if r.Vulnerable {
			fmt.Printf("[VULN] %s  Payload: %s  Context: %s\n",
				r.URL, r.Payload, r.Context)
		}
	}
}
