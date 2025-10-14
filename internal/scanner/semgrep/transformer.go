package semgrep

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-enry/go-enry/v2"
	"github.com/scanoss/crypto-finder/pkg/schema"
)

// transformToInterim converts Semgrep results to the interim JSON format.
func transformToInterim(semgrepOutput *schema.SemgrepOutput, scannerVersion string) (*schema.InterimReport, error) {
	// Group results by file path
	findingsByFile := groupByFile(semgrepOutput.Results)

	// Transform each file's findings
	findings := make([]schema.Finding, 0, len(findingsByFile))
	for filePath, results := range findingsByFile {
		finding, err := transformFileFinding(filePath, results)
		if err != nil {
			// Log error but continue with other files
			continue
		}
		findings = append(findings, finding)
	}

	// Create interim report
	report := &schema.InterimReport{
		Version: "1.0",
		Tool: schema.ToolInfo{
			Name:    "semgrep",
			Version: scannerVersion,
		},
		Findings: findings,
	}

	return report, nil
}

// groupByFile groups Semgrep results by file path.
func groupByFile(results []schema.SemgrepResult) map[string][]schema.SemgrepResult {
	grouped := make(map[string][]schema.SemgrepResult)
	for _, result := range results {
		grouped[result.Path] = append(grouped[result.Path], result)
	}
	return grouped
}

// transformFileFinding transforms all findings for a single file.
func transformFileFinding(filePath string, results []schema.SemgrepResult) (schema.Finding, error) {
	// Detect language
	language := detectLanguage(filePath)

	// Transform each result to a cryptographic asset
	assets := make([]schema.CryptographicAsset, 0, len(results))
	for _, result := range results {
		asset := transformToCryptographicAsset(result)
		assets = append(assets, asset)
	}

	finding := schema.Finding{
		FilePath:            filePath,
		Language:            language,
		CryptographicAssets: assets,
		TimestampUTC:        time.Now().UTC().Format(time.RFC3339),
	}

	return finding, nil
}

// transformToCryptographicAsset converts a single Semgrep result to a CryptographicAsset.
func transformToCryptographicAsset(result schema.SemgrepResult) schema.CryptographicAsset {
	asset := schema.CryptographicAsset{
		MatchType:  "semgrep",
		LineNumber: result.Start.Line,
		Match:      strings.TrimSpace(result.Extra.Lines),
		Rule: schema.RuleInfo{
			ID:       result.CheckID,
			Message:  result.Message,
			Severity: strings.ToUpper(result.Severity),
		},
		Status: "identified",
	}

	// Extract cryptographic details from rule metadata
	if result.Extra.Metadata != nil {
		extractCryptoMetadata(&asset, result.Extra.Metadata)
	}

	// If no algorithm/primitive was extracted, use defaults
	if asset.Algorithm == "" {
		asset.Algorithm = "unknown"
	}
	if asset.Primitive == "" {
		asset.Primitive = "unknown"
	}

	return asset
}

// extractCryptoMetadata extracts cryptographic details from Semgrep rule metadata.
//
// Expected metadata structure (from rule YAML):
//
//	metadata:
//	  crypto:
//	    algorithm: "AES"
//	    primitive: "block-cipher"
//	    mode: "CBC"
//	    padding: "PKCS7"
//	    key_size_bits: 128
//	    provider: "JCE"
func extractCryptoMetadata(asset *schema.CryptographicAsset, metadata map[string]interface{}) {
	// Check if crypto metadata exists
	cryptoData, ok := metadata["crypto"]
	if !ok {
		return
	}

	cryptoMap, ok := cryptoData.(map[string]interface{})
	if !ok {
		return
	}

	// Extract fields
	if algorithm, ok := cryptoMap["algorithm"].(string); ok {
		asset.Algorithm = algorithm
	}
	if primitive, ok := cryptoMap["primitive"].(string); ok {
		asset.Primitive = primitive
	}
	if mode, ok := cryptoMap["mode"].(string); ok {
		asset.Mode = mode
	}
	if padding, ok := cryptoMap["padding"].(string); ok {
		asset.Padding = padding
	}
	if keySize, ok := cryptoMap["key_size_bits"].(float64); ok {
		asset.KeySizeBits = int(keySize)
	}
	if provider, ok := cryptoMap["provider"].(string); ok {
		asset.Provider = provider
	}

	// Extract type (algorithm, certificate, key)
	if assetType, ok := cryptoMap["type"].(string); ok {
		asset.Type = assetType
	} else {
		asset.Type = "algorithm" // Default type
	}
}

// detectLanguage uses go-enry to detect the programming language of a file.
func detectLanguage(filePath string) string {
	// Try detection by filename first
	lang := enry.GetLanguage(filepath.Base(filePath), nil)
	if lang != "" {
		return strings.ToLower(lang)
	}

	// Try detection by file extension
	ext := filepath.Ext(filePath)
	if ext != "" {
		lang = enry.GetLanguage(fmt.Sprintf("file%s", ext), nil)
		if lang != "" {
			return strings.ToLower(lang)
		}
	}

	return "unknown"
}
