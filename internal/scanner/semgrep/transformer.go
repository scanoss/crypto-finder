// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package semgrep

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-enry/go-enry/v2"
	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/config"
	"github.com/scanoss/crypto-finder/internal/deduplicator"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// TransformSemgrepCompatibleOutputToInterimFormat converts Semgrep compatible results to SCANOSS interim JSON format.
// This function can be reused by other compatible scanners (e.g., OpenGrep).
func TransformSemgrepCompatibleOutputToInterimFormat(semgrepOutput *entities.SemgrepOutput, toolInfo entities.ToolInfo, target string, rulePaths []string, disableDedup bool) *entities.InterimReport {
	// Group results by file path
	findingsByFile := groupByFile(semgrepOutput.Results)
	ruleVersion := detectRuleVersion(rulePaths)

	// Transform each file's findings
	findings := make([]entities.Finding, 0, len(findingsByFile))
	for filePath, results := range findingsByFile {
		finding := transformFileFinding(filePath, results, target, rulePaths, ruleVersion)
		findings = append(findings, finding)
	}

	// Create interim report
	report := &entities.InterimReport{
		Version:  "1.1", // Updated to v1.1 to support multiple rules per asset
		Tool:     toolInfo,
		Findings: findings,
	}

	// Deduplicate findings at the same location before returning (unless disabled)
	if !disableDedup {
		report = deduplicator.DeduplicateInterimReport(report)
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
func transformFileFinding(filePath string, results []entities.SemgrepResult, target string, rulePaths []string, ruleVersion string) entities.Finding {
	// Detect language
	language := detectLanguage(filePath)

	// Transform each result to a cryptographic asset
	assets := make([]entities.CryptographicAsset, 0, len(results))
	for i := range results {
		asset := transformToCryptographicAsset(&results[i], rulePaths, ruleVersion)
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
func transformToCryptographicAsset(result *entities.SemgrepResult, rulePaths []string, ruleVersion string) entities.CryptographicAsset {
	// Create the rule info for this detection
	ruleInfo := entities.RuleInfo{
		ID:       cleanRuleID(result.CheckID, rulePaths),
		Message:  result.Extra.Message,
		Severity: strings.ToUpper(result.Extra.Severity),
		Version:  ruleVersion,
	}

	asset := entities.CryptographicAsset{
		MatchType: ScannerName,
		StartLine: result.Start.Line,
		EndLine:   result.End.Line,
		Match:     strings.TrimSpace(result.Extra.Lines),
		Rules:     []entities.RuleInfo{ruleInfo}, // Now an array to support multiple rules
		Metadata:  make(map[string]string),
		Status:    "pending", // TODO: Implement status logic
	}

	// Extract cryptographic details from rule metadata
	if result.Extra.Metadata.Crypto != nil {
		extractCryptoMetadata(&asset, result.Extra.Metadata.Crypto, result.Extra.Metavars)
	}

	return asset
}

func detectRuleVersion(rulePaths []string) string {
	if len(rulePaths) == 0 {
		return ""
	}

	rulesetsDir, err := config.GetRulesetsDir()
	if err != nil {
		return ""
	}

	version := ""
	rulesetsDir = filepath.Clean(rulesetsDir)
	for _, rulePath := range rulePaths {
		if rulePath == "" {
			continue
		}

		absPath := rulePath
		if resolved, err := filepath.Abs(rulePath); err == nil {
			absPath = resolved
		}

		rel, err := filepath.Rel(rulesetsDir, absPath)
		if err != nil || strings.HasPrefix(rel, "..") {
			continue
		}

		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) < 2 {
			continue
		}

		rulesetRoot := filepath.Join(rulesetsDir, parts[0], parts[1])
		candidate := readRulesetManifestVersion(filepath.Join(rulesetRoot, "manifest.json"))
		if candidate == "" {
			continue
		}

		if version == "" {
			version = candidate
			continue
		}

		if version != candidate {
			return ""
		}
	}

	return version
}

func readRulesetManifestVersion(manifestPath string) string {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return ""
	}

	var manifest struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return ""
	}

	return manifest.Version
}

func cleanRuleID(ruleID string, rulePaths []string) string {
	if ruleID == "" || len(rulePaths) == 0 {
		return ruleID
	}

	prefixes := buildRuleIDPrefixes(rulePaths)
	for _, prefix := range prefixes {
		cleaned, ok := stripRuleIDPrefix(ruleID, prefix)
		if ok {
			return cleaned
		}
	}

	return ruleID
}

func buildRuleIDPrefixes(rulePaths []string) []string {
	prefixes := make(map[string]struct{})

	for _, rulePath := range rulePaths {
		if rulePath == "" {
			continue
		}

		absPath := rulePath
		if resolved, err := filepath.Abs(rulePath); err == nil {
			absPath = resolved
		}

		addRuleIDPrefix(prefixes, absPath)

		if ext := filepath.Ext(absPath); ext != "" {
			addRuleIDPrefix(prefixes, strings.TrimSuffix(absPath, ext))
			addRuleIDPrefix(prefixes, filepath.Dir(absPath))
		}
	}

	values := make([]string, 0, len(prefixes))
	for prefix := range prefixes {
		values = append(values, prefix)
	}

	sort.Slice(values, func(i, j int) bool {
		return len(values[i]) > len(values[j])
	})

	return values
}

func addRuleIDPrefix(prefixes map[string]struct{}, path string) {
	if path == "" {
		return
	}

	normalized := filepath.Clean(path)
	slash := filepath.ToSlash(normalized)
	slash = strings.TrimPrefix(slash, "./")
	slash = strings.TrimPrefix(slash, "/")
	slash = strings.TrimSuffix(slash, "/")
	if slash != "" {
		prefixes[slash] = struct{}{}
	}

	dot := strings.ReplaceAll(slash, "/", ".")
	dot = strings.Trim(dot, ".")
	if dot != "" {
		prefixes[dot] = struct{}{}
	}
}

func stripRuleIDPrefix(ruleID, prefix string) (string, bool) {
	if prefix == "" {
		return ruleID, false
	}

	if strings.HasPrefix(ruleID, prefix+".") {
		return strings.TrimPrefix(ruleID, prefix+"."), true
	}

	if strings.HasPrefix(ruleID, prefix+"/") {
		return strings.TrimPrefix(ruleID, prefix+"/"), true
	}

	if strings.HasPrefix(ruleID, prefix+"\\") {
		return strings.TrimPrefix(ruleID, prefix+"\\"), true
	}

	return ruleID, false
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
//   - "ECDSA-$2" with $2=256 becomes "ECDSA-256" (numbered capture groups from regex)
func resolveMetavars(s string, metavars map[string]entities.MetavarInfo) string {
	// If the string doesn't contain $, return as-is for efficiency
	if !strings.Contains(s, "$") {
		return s
	}

	// Regular expression to match metavariable names:
	// - Traditional metavars: $WORD (letters, numbers, underscores, must start with letter/underscore)
	// - Numbered metavars: $1, $2, etc. (from regex capture groups)
	// Pattern matches either: $[a-zA-Z_][a-zA-Z0-9_]* OR $[0-9]+
	re := regexp.MustCompile(`\$(?:[a-zA-Z_][a-zA-Z0-9_]*|[0-9]+)`)

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
