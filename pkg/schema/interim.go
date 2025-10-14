// Package schema defines the standardized data structures for cryptographic scan results.
// It provides the interim JSON schema format that is shared across all scanner implementations,
// ensuring consistent output for consumption by the SCANOSS ecosystem.
package schema

// InterimReport is the standardized output format for all scanners.
// This format provides a unified representation of cryptographic findings
// that can be consumed by the SCANOSS ecosystem and other downstream tools.
type InterimReport struct {
	// Version of the interim report schema (e.g., "1.0")
	Version string `json:"version"`

	// Tool contains information about the scanner that generated this report
	Tool ToolInfo `json:"tool"`

	// Findings contains all detected cryptographic assets grouped by file
	Findings []Finding `json:"findings"`
}

// ToolInfo contains metadata about the scanner that produced the report.
type ToolInfo struct {
	// Name of the scanner tool (e.g., "scanoss-cf", "cbom-toolkit", etc)
	Name string `json:"name"`

	// Version of the scanner tool (e.g., "1.45.0")
	Version string `json:"version"`
}

// Finding represents all cryptographic assets discovered in a single file.
// Each file that contains cryptographic material will have one Finding entry.
type Finding struct {
	// FilePath is the path to the file containing cryptographic assets
	FilePath string `json:"file_path"`

	// Language is the programming language of the file (e.g., "java", "python", "go")
	Language string `json:"language"`

	// CryptographicAssets contains all cryptographic materials found in this file
	CryptographicAssets []CryptographicAsset `json:"cryptographic_assets"`

	// TimestampUTC is the ISO 8601 timestamp when this file was scanned
	TimestampUTC string `json:"timestamp_utc"`
}

// CryptographicAsset represents a single detected cryptographic element.
type CryptographicAsset struct {
	// MatchType indicates the detection method used
	// Values: "semgrep", "cbom_toolkit", "keyword_search"
	MatchType string `json:"match_type"`

	// LineNumber is the line number where the asset was detected
	LineNumber int `json:"line_number"`

	// Match is the actual code snippet that was matched
	Match string `json:"match"`

	// Rule contains information about the detection rule that triggered this finding
	Rule RuleInfo `json:"rule"`

	// Type categorizes the cryptographic asset
	// Values: "algorithm", "certificate", "key"
	Type string `json:"type"`

	// Algorithm is the specific algorithm name
	// Examples: "AES", "RSA", "SHA256", "X509"
	Algorithm string `json:"algorithm,omitempty"`

	// Primitive describes the cryptographic primitive category
	// Values: "block-cipher", "stream-cipher", "hash", "asymmetric", "symmetric"
	Primitive string `json:"primitive"`

	// Mode specifies the mode of operation (optional)
	// Examples: "CBC", "GCM", "ECB", "CTR"
	Mode string `json:"mode,omitempty"`

	// Padding specifies the padding scheme used (optional)
	// Examples: "PKCS7", "PKCS5", "NoPadding", "OAEP"
	Padding string `json:"padding,omitempty"`

	// KeySizeBits is the key size in bits (optional)
	KeySizeBits int `json:"key_size_bits,omitempty"`

	// Provider identifies the cryptographic provider (optional)
	// Examples: "unknown", "BouncyCastle", "OpenSSL", "JCE"
	Provider string `json:"provider,omitempty"`

	// Status represents the current state of this finding
	// Values: "pending", "identified", "dismissed", "reviewed"
	// TODO: TBD
	Status string `json:"status"`
}

// RuleInfo contains information about the detection rule that identified the cryptographic asset.
type RuleInfo struct {
	// ID is the unique identifier for the rule
	// Example: "<language>.crypto.<library>.<operation>-<specifics>"
	ID string `json:"id"`

	// Message is a human-readable description of what was detected
	Message string `json:"message"`

	// Severity indicates the importance level of the finding
	// Values: "WARNING", "ERROR", "INFO"
	Severity string `json:"severity"`
}
