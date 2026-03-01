package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"xoxo/internal/config"
	"xoxo/pkg/license"
	"xoxo/pkg/scanner"
)

const (
	AppName    = "xoxo-xss-scanner"
	AppVersion = "1.0.0"
)

func main() {
	// Parse flags into config
	cfg := parseFlags()

	// Validate required URL file parameter
	if cfg.URLFile == "" {
		fmt.Println("Error: Please provide a file with URLs using -l flag")
		os.Exit(1)
	}

	// Get license key from flag or environment
	licenseKey := cfg.LicenseKey
	if licenseKey == "" {
		licenseKey = os.Getenv("XSS_TOOL_KEY")
	}
	if licenseKey == "" {
		fmt.Println("Error: no key provided (use -key or XSS_TOOL_KEY env)")
		os.Exit(1)
	}

	// Validate license
	validator := license.NewValidator()
	if !validator.CheckLicense(licenseKey) {
		fmt.Println("License check failed: invalid license")
		os.Exit(1)
	}

	// Print banner (matches binary)
	printBanner()

	// Initialize scanner
	scanEngine := scanner.NewScanner(cfg)

	// Run scan
	if err := scanEngine.Run(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags() *config.Config {
	cfg := &config.Config{}

	flag.StringVar(&cfg.LicenseKey, "key", "", "License key")
	flag.StringVar(&cfg.URLFile, "l", "", "File containing list of URLs")
	flag.StringVar(&cfg.LicenseServer, "ls", "", "License server URL (optional)")
	flag.BoolVar(&cfg.PathMode, "path", false, "Enable testing path/directory segment reflections")
	flag.IntVar(&cfg.Workers, "w", 10, "Number of worker goroutines")

	flag.Parse()
	return cfg
}

func printBanner() {
	now := time.Now().Format("15:04:05 - 2006-01-02")
	fmt.Printf("[ * ] starting xoxo-xss scanner [ %s ]\n", now)
}
