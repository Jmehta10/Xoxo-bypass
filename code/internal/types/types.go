package types

type ScanResult struct {
	URL        string
	Vulnerable bool
	Payload    string
	Context    string
	Error      string
}
