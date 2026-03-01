package license

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	// Hardcoded master license key extracted from .rodata at 0x74f69c
	MasterLicenseKey = "Kassem@Xoxo@123%N"

	// License key must be exactly 17 bytes (0x11)
	RequiredKeyLength = 0x11

	// Local cache file name
	CacheFileName = ".xss_tool_license_cache"
)

type Validator struct {
	cacheFile string
}

type LicenseRequest struct {
	Key        string            `json:"key"`
	SystemInfo map[string]string `json:"system_info"`
	Timestamp  int64             `json:"timestamp"`
}

type LicenseResponse struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message"`
	Expires int64  `json:"expires,omitempty"`
}

func NewValidator() *Validator {
	homeDir, _ := os.UserHomeDir()
	if homeDir == "" {
		homeDir = "."
	}
	cachePath := filepath.Join(homeDir, CacheFileName)
	return &Validator{cacheFile: cachePath}
}

// CheckLicense is the high-level equivalent of main.checkLicense in the binary.
func (v *Validator) CheckLicense(key string) bool {
	if len(key) == 0 {
		return false
	}

	// Hardcoded master key path
	if len(key) == RequiredKeyLength && key == MasterLicenseKey {
		return true
	}

	// Optional: trust cached key
	if cached, ok := v.readLocalCache(); ok && cached == key {
		return true
	}

	// Fallback to online validation (will usually fail in CTF environment)
	return v.validateOnline(key)
}

func (v *Validator) validateOnline(key string) bool {
	reqPayload := LicenseRequest{
		Key:       key,
		Timestamp: time.Now().Unix(),
		SystemInfo: map[string]string{
			"platform": "linux",
			"arch":     "amd64",
		},
	}

	payload, err := json.Marshal(reqPayload)
	if err != nil {
		return false
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// Placeholder — actual URL is embedded in the original binary
	serverURL := "https://license-server.xoxo.example/verify"

	resp, err := client.Post(serverURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		fmt.Printf("license server unreachable: Try again later\n")
		return false
	}
	defer resp.Body.Close()

	var licResp LicenseResponse
	if err := json.NewDecoder(resp.Body).Decode(&licResp); err != nil {
		return false
	}

	if licResp.Valid {
		_ = v.writeLocalCache(key)
		return true
	}

	return false
}

func (v *Validator) writeLocalCache(key string) error {
	data := map[string]any{
		"key":       key,
		"validated": time.Now().Unix(),
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return os.WriteFile(v.cacheFile, jsonData, fs.FileMode(0o600))
}

func (v *Validator) readLocalCache() (string, bool) {
	data, err := os.ReadFile(v.cacheFile)
	if err != nil {
		return "", false
	}
	var cache map[string]any
	if err := json.Unmarshal(data, &cache); err != nil {
		return "", false
	}
	if key, ok := cache["key"].(string); ok {
		return key, true
	}
	return "", false
}
