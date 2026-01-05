package semgrep

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-enry/go-enry/v2"
	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// TransformSemgrepCompatibleOutputToInterimFormat converts Semgrep compatible results to SCANOSS interim JSON format.
// This function can be reused by other compatible scanners (e.g., OpenGrep).
func TransformSemgrepCompatibleOutputToInterimFormat(semgrepOutput *entities.SemgrepOutput, toolInfo entities.ToolInfo, target string) *entities.InterimReport {
	// Group results by file path
	findingsByFile := groupByFile(semgrepOutput.Results)

	// Transform each file's findings
	findings := make([]entities.Finding, 0, len(findingsByFile))
	for filePath, results := range findingsByFile {
		finding := transformFileFinding(filePath, results, target)
		findings = append(findings, finding)
	}

	// Create interim report
	report := &entities.InterimReport{
		Version:  "1.0", // TODO: Use proper version number
		Tool:     toolInfo,
		Findings: findings,
	}

	return report
}

// groupByFile groups Semgrep results by file path.
func groupByFile(results []entities.SemgrepResult) map[string][]entities.SemgrepResult {
	grouped := make(map[string][]entities.SemgrepResult)
	for i := range results {
		result := &results[i]
		grouped[result.Path] = append(grouped[result.Path], *result)
	}
	return grouped
}

// transformFileFinding transforms all findings for a single file.
func transformFileFinding(filePath string, results []entities.SemgrepResult, target string) entities.Finding {
	// Detect language
	language := detectLanguage(filePath)

	// Transform each result to a cryptographic asset
	assets := make([]entities.CryptographicAsset, 0, len(results))
	for i := range results {
		asset := transformToCryptographicAsset(&results[i])
		assets = append(assets, asset)
	}

	relativePath, err := filepath.Rel(target, filePath)
	if err != nil {
		log.Warn().Msgf("Failed to get relative path for %s", filePath)
		relativePath = filePath
	}

	return entities.Finding{
		FilePath:            relativePath,
		Language:            language,
		CryptographicAssets: assets,
		TimestampUTC:        time.Now().UTC().Format(time.RFC3339),
	}
}

// transformToCryptographicAsset converts a single Semgrep result to a CryptographicAsset.
func transformToCryptographicAsset(result *entities.SemgrepResult) entities.CryptographicAsset {
	asset := entities.CryptographicAsset{
		MatchType: ScannerName,
		StartLine: result.Start.Line,
		EndLine:   result.End.Line,
		Match:     strings.TrimSpace(result.Extra.Lines),
		Rule: entities.RuleInfo{
			ID:       result.CheckID,
			Message:  result.Extra.Message,
			Severity: strings.ToUpper(result.Extra.Severity),
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

// Helper function to safely get metavariable values.
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

// resolveMetavars replaces all metavariable references ($VAR) in a string with their actual values.
// If a metavariable is not found in the metavars map, the original reference is kept.
// Examples:
//   - "SHA-$variant" with $variant=256 becomes "SHA-256"
//   - "AES-$MODE-$PADDING" becomes "AES-CBC-PKCS5" if those metavars exist
//   - "SHA-$unknown" stays as "SHA-$unknown" if $unknown is not in metavars
func resolveMetavars(s string, metavars map[string]entities.MetavarInfo) string {
	// If the string doesn't contain $, return as-is for efficiency
	if !strings.Contains(s, "$") {
		return s
	}

	// Regular expression to match metavariable names: $WORD
	// Metavariable names follow identifier rules (letters, numbers, underscores)
	re := regexp.MustCompile(`\$[a-zA-Z_][a-zA-Z0-9_]*`)

	// Replace all metavariable references with their values
	result := re.ReplaceAllStringFunc(s, func(match string) string {
		value := getMetavarValue(metavars, match)
		if value != "" {
			return value
		}
		// If metavar not found, keep the original reference
		return match
	})

	return result
}

// extractCryptoMetadata extracts cryptographic details from Semgrep rule metadata.
//
// Expected metadata structure (from rule YAML):
//
//	metadata:
//	  crypto:
//	    algorithmFamily: "AES"
//	    algorithmName: "AES-128-GCM"
//	    algorithmPrimitive: "block-cipher"
//	    algorithmMode: "CBC" or $MODE
//	    algorithmPadding: "PKCS7"
//	    algorithmParameterSetIdentifier: 128
//	    library: "OpenSSL"
func extractCryptoMetadata(asset *entities.CryptographicAsset, cryptoMetadata map[string]any, metavars map[string]entities.MetavarInfo) {
	for key, metavarValue := range cryptoMetadata {
		var value string

		// Handle different types of values in the cryptoMetadata map
		switch v := metavarValue.(type) {
		case string:
			// Replace any metavariable references in the string (e.g., "SHA-$variant" -> "SHA-256")
			value = resolveMetavars(v, metavars)
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

		// Maintain camelCase format to align with CycloneDX 1.6 specification
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
