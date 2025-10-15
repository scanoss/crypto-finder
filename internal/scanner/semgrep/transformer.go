package semgrep

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-enry/go-enry/v2"
	"github.com/rs/zerolog/log"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/utils"
)

// transformToInterim converts Semgrep results to the interim JSON format.
func transformToInterim(semgrepOutput *entities.SemgrepOutput, scannerVersion string) (*entities.InterimReport, error) {
	// Group results by file path
	findingsByFile := groupByFile(semgrepOutput.Results)

	// Transform each file's findings
	findings := make([]entities.Finding, 0, len(findingsByFile))
	for filePath, results := range findingsByFile {
		finding, err := transformFileFinding(filePath, results)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to transform findings for file %s", filePath)
			continue
		}
		findings = append(findings, finding)
	}

	// Create interim report
	report := &entities.InterimReport{
		Version: "1.0", // TODO: Use proper version number
		Tool: entities.ToolInfo{
			Name:    SCANNER_NAME,
			Version: scannerVersion,
		},
		Findings: findings,
	}

	return report, nil
}

// groupByFile groups Semgrep results by file path.
func groupByFile(results []entities.SemgrepResult) map[string][]entities.SemgrepResult {
	grouped := make(map[string][]entities.SemgrepResult)
	for _, result := range results {
		grouped[result.Path] = append(grouped[result.Path], result)
	}
	return grouped
}

// transformFileFinding transforms all findings for a single file.
func transformFileFinding(filePath string, results []entities.SemgrepResult) (entities.Finding, error) {
	// Detect language
	language := detectLanguage(filePath)

	// Transform each result to a cryptographic asset
	assets := make([]entities.CryptographicAsset, 0, len(results))
	for _, result := range results {
		asset := transformToCryptographicAsset(result)
		assets = append(assets, asset)
	}

	finding := entities.Finding{
		FilePath:            filePath,
		Language:            language,
		CryptographicAssets: assets,
		TimestampUTC:        time.Now().UTC().Format(time.RFC3339),
	}

	return finding, nil
}

// transformToCryptographicAsset converts a single Semgrep result to a CryptographicAsset.
func transformToCryptographicAsset(result entities.SemgrepResult) entities.CryptographicAsset {
	asset := entities.CryptographicAsset{
		MatchType:  SCANNER_NAME,
		LineNumber: result.Start.Line,
		Match:      strings.TrimSpace(result.Extra.Lines),
		Rule: entities.RuleInfo{
			ID:       result.CheckID,
			Message:  result.Message,
			Severity: strings.ToUpper(result.Severity),
		},
		Metadata: make(map[string]string),
		Status:   "pending", // TODO: Implement status logic
	}

	// Extract cryptographic details from rule metadata
	if result.Extra.Metadata.Crypto != nil {
		extractCryptoMetadata(&asset, result.Extra.Metadata.Crypto, result.Extra.Metavars)
	}

	return asset
}

// Helper function to safely get metavariable values
func getMetavarValue(metavars map[string]entities.MetavarInfo, key string) string {
	if key == "" {
		return ""
	}

	// If the key doesn't start with $, assume it's a direct value not a metavariable
	if !strings.HasPrefix(key, "$") {
		return strings.Trim(key, "\"")
	}

	if mv, ok := metavars[key]; ok {
		// Remove surrounding quotes if present (often added by Semgrep)
		if mv.PropagatedValue != nil {
			return strings.Trim(mv.PropagatedValue.SvalueAbstractContent, "\"")
		}
		return strings.Trim(mv.AbstractContent, "\"")
	}

	// Also try without the $ prefix for named group variables
	keyWithoutDollar := strings.TrimPrefix(key, "$")
	if mv, ok := metavars[keyWithoutDollar]; ok {
		if mv.PropagatedValue != nil {
			return strings.Trim(mv.PropagatedValue.SvalueAbstractContent, "\"")
		}
		return strings.Trim(mv.AbstractContent, "\"")
	}

	return ""
}

// extractCryptoMetadata extracts cryptographic details from Semgrep rule metadata.
//
// Expected metadata structure (from rule YAML):
//
//	metadata:
//	  crypto:
//	    algorithm: "AES" or $ALGORITHM
//	    primitive: "block-cipher"
//	    mode: "CBC" or $MODE
//	    padding: "PKCS7"
//	    key_size_bits: 128
//	    provider: "JCE"
func extractCryptoMetadata(asset *entities.CryptographicAsset, cryptoMetadata map[string]any, metavars map[string]entities.MetavarInfo) {
	for key, metavarValue := range cryptoMetadata {
		var value string

		// Handle different types of values in the cryptoMetadata map
		switch v := metavarValue.(type) {
		case string:
			// If it's a string that starts with $, treat it as a metavariable reference
			if strings.HasPrefix(v, "$") {
				value = getMetavarValue(metavars, v)
			} else {
				// Otherwise use the string value directly
				value = v
			}
		case bool:
			// Convert boolean to string
			if v {
				value = "true"
			} else {
				value = "false"
			}
		case float64:
			// Convert number to string using strconv
			value = strconv.FormatFloat(v, 'f', -1, 64)
		default:
			// For any other type, use fmt.Sprint
			value = fmt.Sprint(v)
		}

		// We use CamelToSnake here until we update all rules to use snake_case keys
		key := utils.CamelToSnake(key)
		asset.Metadata[key] = value
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
