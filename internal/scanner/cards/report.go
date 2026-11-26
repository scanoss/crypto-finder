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

package cards

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/go-enry/go-enry/v2"
	"github.com/rs/zerolog/log"
	"github.com/scanoss/reach/paramcondition"
	"github.com/scanoss/reach/purl"

	"github.com/scanoss/crypto-finder/internal/config"
	"github.com/scanoss/crypto-finder/internal/deduplicator"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// detection is one card match, located and carrying its rule's fields.
// Lines and columns are 1-based; endCol is exclusive (one past the last
// matched character).
type detection struct {
	ruleID   string // the rule's check id, before cleanRuleID
	path     string
	start    position
	end      position
	message  string
	severity string
	lines    string // the matched source text
	purl     string
	crypto   map[string]any // the rule's metadata.crypto
	// terminalCol and terminalEndCol are the matched call's columns when the
	// detection is reported at a part of it; 0 otherwise.
	terminalCol, terminalEndCol int
	// language is the cards language whose rules matched (Options.Language).
	language string
}

// position is a line and column in a source file.
type position struct{ line, col int }

// transformToInterimReport builds the interim report of the detections.
func transformToInterimReport(detections []detection, toolInfo entities.ToolInfo, target string, rulePaths []string, disableDedup bool) *entities.InterimReport {
	// Group results by file path
	findingsByFile := groupByFile(detections)
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

// unknownResult is the language of a file language detection cannot name.
const unknownResult = "unknown"

// groupByFile groups detections by file path.
func groupByFile(results []detection) map[string][]detection {
	grouped := make(map[string][]detection)
	for i := range results {
		result := &results[i]
		grouped[result.path] = append(grouped[result.path], *result)
	}
	return grouped
}

// transformFileFinding transforms all findings for a single file.
func transformFileFinding(filePath string, results []detection, target string, rulePaths []string, ruleVersion string) entities.Finding {
	// Detect language
	language := detectLanguage(filePath, results[0].language)

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
	}
}

// transformToCryptographicAsset converts a single detection to a CryptographicAsset.
func transformToCryptographicAsset(result *detection, rulePaths []string, ruleVersion string) entities.CryptographicAsset {
	// Create the rule info for this detection
	ruleInfo := entities.RuleInfo{
		ID:       cleanRuleID(result.ruleID, rulePaths),
		Message:  result.message,
		Severity: strings.ToUpper(result.severity),
		Version:  ruleVersion,
	}

	asset := entities.CryptographicAsset{
		StartLine: result.start.line,
		EndLine:   result.end.line,
		StartCol:  result.start.col,
		EndCol:    result.end.col,
		Match:     strings.TrimSpace(result.lines),
		Rules:     []entities.RuleInfo{ruleInfo}, // Now an array to support multiple rules
		Metadata:  make(map[string]string),
		Status:    "pending", // TODO: Implement status logic
		PURL:      purl.Rule(result.purl),
	}
	if result.terminalCol > 0 && result.terminalEndCol > 0 {
		asset.TerminalStartCol, asset.TerminalEndCol = result.terminalCol, result.terminalEndCol
	}

	// Extract cryptographic details from rule metadata
	if result.crypto != nil {
		extractCryptoMetadata(&asset, result.crypto)
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

		candidate := cachedRulesetVersion(rulesetsDir, rel)
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

// cachedRulesetVersion returns the version of the cached ruleset that holds
// rel (a path relative to the rulesets dir), or "" when it cannot tell.
func cachedRulesetVersion(rulesetsDir, rel string) string {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) < 2 {
		return ""
	}
	// A per-run copy (a leased ruleset decrypted for this run, or a filtered
	// copy) lives in <name>/.crypto-finder-filtered/<version>/run-* and
	// belongs to the cached ruleset <name>/<version>.
	if parts[1] == config.FilteredRulesDirName {
		if len(parts) < 3 {
			return ""
		}
		parts = []string{parts[0], parts[2]}
	}
	return readCachedVersion(filepath.Join(rulesetsDir, parts[0], parts[1], ".cache-meta.json"))
}

// readCachedVersion returns the version recorded in a cached ruleset's
// .cache-meta.json, or "" when it cannot be read.
func readCachedVersion(metadataPath string) string {
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return ""
	}

	var metadata struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return ""
	}

	return metadata.Version
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

// metavarReference matches a metavariable reference in a rule's metadata
// value: a named metavar ($WORD, starting with a letter or underscore) or a
// numbered regex capture group ($1, $2, ...). A card match binds none, so a
// value that holds one is a template that cannot be filled.
var metavarReference = regexp.MustCompile(`\$(?:[a-zA-Z_][a-zA-Z0-9_]*|\d+)`)

// extractCryptoMetadata extracts cryptographic details from a rule's metadata.crypto.
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
func extractCryptoMetadata(asset *entities.CryptographicAsset, cryptoMetadata map[string]any) {
	for key, raw := range cryptoMetadata {
		var value string

		// Handle different types of values in the cryptoMetadata map
		switch v := raw.(type) {
		case string:
			// A template with a reference would emit a valid-looking but
			// wrong value ("ECDH-$1" -> "ECDH-"), so the field is left out.
			// parameterCondition is a predicate, not a template: its "$" may
			// be a regex anchor or a literal, so it keeps what it has.
			if metavarReference.MatchString(v) && key != "parameterCondition" {
				continue
			}
			value = v
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

		if value != "" {
			// Maintain camelCase format to align with CycloneDX 1.6 specification
			asset.Metadata[key] = value
		}
	}

	if asset.Metadata["cryptoFunction"] == "" && asset.Metadata["operation"] != "" {
		asset.Metadata["cryptoFunction"] = asset.Metadata["operation"]
	}

	if raw := asset.Metadata["parameterCondition"]; raw != "" {
		if conds, err := paramcondition.ParseAll(raw); err == nil {
			asset.ParameterConditions = conds
		} else {
			log.Debug().Err(err).Str("raw", raw).Msg("parameterCondition parse skipped (should have failed at rule-load)")
		}
	}

	normalizeRelatedCryptoKeySizes(asset)
}

func normalizeRelatedCryptoKeySizes(asset *entities.CryptographicAsset) {
	if asset == nil {
		return
	}

	materialSize := strings.TrimSpace(asset.Metadata["materialSize"])
	if materialSize == "" {
		return
	}

	switch strings.ToLower(strings.TrimSpace(asset.Metadata["materialType"])) {
	case "public-key":
		if strings.TrimSpace(asset.Metadata["publicKeySize"]) == "" {
			asset.Metadata["publicKeySize"] = materialSize
		}
	case "private-key":
		if strings.TrimSpace(asset.Metadata["privateKeySize"]) == "" {
			asset.Metadata["privateKeySize"] = materialSize
		}
	}
}

// detectLanguage uses go-enry to detect the programming language of a file.
// languageSniffLimit bounds how much of a file is read to disambiguate its
// language. enry's content strategies look at shebangs, keywords and a handful
// of declarations, all of which appear far earlier than this; the cap is here so
// a large generated source costs a bounded read rather than its whole size.
const languageSniffLimit = 16 * 1024

// sniffLanguageContent returns the leading bytes of filePath, or nil if it
// cannot be read. nil is a valid input to enry -- it just falls back to deciding
// on the name alone.
func sniffLanguageContent(filePath string) []byte {
	file, err := os.Open(filePath)
	if err != nil {
		return nil
	}

	buf := make([]byte, languageSniffLimit)
	n, readErr := io.ReadFull(file, buf)
	if closeErr := file.Close(); closeErr != nil {
		log.Debug().Err(closeErr).Str("path", filePath).Msg("failed to close file after language sniff")
	}
	// io.ReadFull reports ErrUnexpectedEOF for any file shorter than the buffer,
	// which is the common case and not a failure. Only a read that produced
	// nothing is.
	if n == 0 && readErr != nil {
		return nil
	}
	return buf[:n]
}

// detectLanguage names the language of filePath.
//
// THE CONTENT IS NOT OPTIONAL. Several extensions map to more than one language,
// and asked by name alone enry answers with the wrong one:
//
//	.rs   -> XML        (candidates: RenderScript, Rust, XML)
//	.cs   -> Smalltalk  (candidates: C#, Smalltalk)
//	.php  -> Hack       (candidates: Hack, PHP)
//
// Those are silent: the wrong name is stored on every finding and travels
// downstream, and "xml" is not a language any consumer here recognizes, so it
// simply contributes nothing rather than failing loudly. Passing the file's
// leading bytes resolves all three, and also lets a C++ header be told from a C
// one -- which is why reportOccurrenceKeyEcosystems now tests the C family
// rather than the literal "c".
//
// CONTENT ONLY EVER REFINES AN ANSWER, IT NEVER ERASES ONE. enry returns the
// empty string when it decides the bytes are binary, and it decides that for
// some legitimate sources -- a 2 MB generated tree-sitter parser.c is one, its
// dense state tables trip the heuristic. Reading content must not turn that file
// from "c" into "unknown", so each lookup is retried without content whenever
// the content-informed one comes back empty. The same retry covers a file that
// cannot be read at all, where a possibly-wrong language beats none, and it is
// what keeps the name-only cases in TestDetectLanguage meaningful.
//
// A FILE THAT CANNOT BE READ IS NAMED AFTER THE CARDS THAT MATCHED IT. annotate
// matches a stored graph with no source tree, so every name-only answer above
// would be the wrong one; matched, the cards language whose rules matched the
// file, picks the candidate the content would have picked.
func detectLanguage(filePath, matched string) string {
	content := sniffLanguageContent(filePath)
	if len(content) == 0 {
		if lang := matchedCandidate(filepath.Base(filePath), matched); lang != "" {
			return lang
		}
	}

	// Try detection by filename first
	if lang := lookupLanguage(filepath.Base(filePath), content); lang != "" {
		return lang
	}

	// Try detection by file extension
	if ext := filepath.Ext(filePath); ext != "" {
		if lang := lookupLanguage(fmt.Sprintf("file%s", ext), content); lang != "" {
			return lang
		}
	}

	return unknownResult
}

// matchedCandidate is, of the languages a file named name may be written in,
// the one of the cards language matched (its name or an alias): "rust" for
// lib.rs, "typescript" for index.ts matched by javascript's cards. It is empty
// when matched is no cards language or none of the candidates is matched's.
func matchedCandidate(name, matched string) string {
	want, ok := ForName(matched)
	if !ok {
		return ""
	}
	candidates := enry.GetLanguagesByFilename(name, nil, nil)
	if len(candidates) == 0 {
		candidates = enry.GetLanguagesByExtension(name, nil, nil)
	}
	for _, candidate := range candidates {
		if l, ok := ForName(candidate); ok && l.Name == want.Name {
			return strings.ToLower(candidate)
		}
	}
	return ""
}

// lookupLanguage asks enry with the content and falls back to asking without it,
// so a content-informed answer is preferred but an empty one never wins.
func lookupLanguage(name string, content []byte) string {
	if len(content) > 0 {
		if lang := enry.GetLanguage(name, content); lang != "" {
			return strings.ToLower(lang)
		}
	}
	return strings.ToLower(enry.GetLanguage(name, nil))
}
