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

package opengrep

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// coreOutput is the part of opengrep-core's -json output the adapter reads.
type coreOutput struct {
	Results []coreMatch `json:"results"`
	Errors  []coreError `json:"errors"`
}

type coreMatch struct {
	CheckID string                   `json:"check_id"`
	Path    string                   `json:"path"`
	Start   entities.SemgrepLocation `json:"start"`
	End     entities.SemgrepLocation `json:"end"`
	Extra   coreMatchExtra           `json:"extra"`
}

type coreMatchExtra struct {
	Message   string                          `json:"message"`
	Metadata  map[string]any                  `json:"metadata"`
	Metavars  map[string]entities.MetavarInfo `json:"metavars"`
	Severity  string                          `json:"severity"`
	IsIgnored bool                            `json:"is_ignored"`
}

type coreError struct {
	ErrorType json.RawMessage `json:"error_type"`
	Severity  string          `json:"severity"`
	Message   string          `json:"message"`
	RuleID    string          `json:"rule_id"`
	Location  *coreLocation   `json:"location"`
}

type coreLocation struct {
	Path  string                   `json:"path"`
	Start entities.SemgrepLocation `json:"start"`
	End   entities.SemgrepLocation `json:"end"`
}

// CLI exit codes the CLI stamps on core errors.
const (
	cliOKExitCode            = 0
	cliFatalExitCode         = 2
	cliTargetParseExitCode   = 3
	coreErrorTypePartial     = "PartialParsing"
	coreErrorTypePattern     = "PatternParseError"
	coreErrorTypeIncompat    = "IncompatibleRule"
	coreErrorTypeRuleParse   = "Rule parse error"
	coreErrorTypeSyntax      = "Syntax error"
	coreErrorTypeLexical     = "Lexical error"
	coreErrorTypePatternMsg  = "Pattern parse error"
	coreErrorTypeInvalidYAML = "Invalid YAML"
)

// Severities the CLI leaves out of its output (output.py
// DEFAULT_SHOWN_SEVERITIES): their rules run, their matches are not shown.
const (
	severityInventory  = "INVENTORY"
	severityExperiment = "EXPERIMENT"
)

// parseCoreOutput reads opengrep-core's stdout: progress dots, then one JSON
// document.
func parseCoreOutput(stdout []byte) (*coreOutput, error) {
	start := bytes.IndexByte(stdout, '{')
	if start < 0 {
		return nil, fmt.Errorf("opengrep: opengrep-core printed no JSON")
	}
	var out coreOutput
	if err := json.Unmarshal(stdout[start:], &out); err != nil {
		return nil, fmt.Errorf("opengrep: parse opengrep-core output: %w", err)
	}
	return &out, nil
}

// convertCoreOutput turns core output into what the CLI prints for the same
// scan: matches a nosemgrep comment silences are dropped, so are matches of
// the severities the CLI does not show, each result gains its rule's
// severity, its rule metadata and the source lines it spans, and results are
// ordered as the CLI orders them, by location and then by rule id. useBase
// says opengrep-core knew the rules by their base ids; results then get the
// prefixed ids the CLI reports. Relative paths lie in dir. A rule core could
// not load makes the conversion fail with errCoreUnavailable: the CLI
// validates its rules before scanning and fails the run instead.
func convertCoreOutput(core *coreOutput, rules []*coreRule, useBase bool, dir string) (*entities.SemgrepOutput, error) {
	index := make(map[string]int, len(rules))
	for i, rule := range rules {
		key := rule.id
		if useBase {
			key = rule.baseID
		}
		if _, ok := index[key]; !ok {
			index[key] = i
		}
	}
	results, err := convertCoreResults(core.Results, rules, index, newLineReader(dir))
	if err != nil {
		return nil, err
	}
	sortLikeCLI(results)
	out := &entities.SemgrepOutput{Results: results, Errors: make([]entities.SemgrepError, 0, len(core.Errors))}
	for i := range core.Errors {
		coreErr := core.Errors[i]
		if ruleIndex, ok := index[coreErr.RuleID]; ok && coreErr.RuleID != "" {
			coreErr.RuleID = rules[ruleIndex].id
		}
		converted, err := convertCoreErrorOrFail(&coreErr)
		if err != nil {
			return nil, err
		}
		out.Errors = append(out.Errors, converted)
	}
	return out, nil
}

// convertCoreResults converts the matches the CLI would show, in core's
// order. index maps the ids core knows the rules by to their position.
func convertCoreResults(matches []coreMatch, rules []*coreRule, index map[string]int, lines *lineReader) ([]entities.SemgrepResult, error) {
	results := make([]entities.SemgrepResult, 0, len(matches))
	for i := range matches {
		match := &matches[i]
		if match.Extra.IsIgnored {
			continue
		}
		ruleIndex, ok := index[match.CheckID]
		if !ok {
			return nil, fmt.Errorf("opengrep: opengrep-core reported unknown rule %s", match.CheckID)
		}
		rule := rules[ruleIndex]
		result, err := convertMatch(match, rule, lines)
		if err != nil {
			return nil, err
		}
		if result.Extra.Severity == severityInventory || result.Extra.Severity == severityExperiment {
			continue
		}
		result.CheckID = rule.id
		results = append(results, result)
	}
	return results, nil
}

// convertCoreErrorOrFail converts a core error the CLI would report, and
// fails with errCoreUnavailable for a rule core could not load.
func convertCoreErrorOrFail(e *coreError) (entities.SemgrepError, error) {
	if reason := ruleLoadFailure(e); reason != "" {
		return entities.SemgrepError{}, fmt.Errorf("%w: %s", errCoreUnavailable, reason)
	}
	return convertCoreError(e), nil
}

// ruleLoadFailure describes the rule opengrep-core could not load, or is ""
// when e reports something else. Core drops such a rule, reports it under
// one of these error types (Core_error.error_of_rule_error in opengrep
// 1.30.2) and scans with the rest, at exit 0; the CLI validates the rules
// before scanning and fails the whole run: exit 7 for a schema error such
// as a misspelled key, 8 for an unknown language, 2 for a pattern or regex
// core cannot parse. Core's error does not say which of those the CLI would
// pick, so the scan has to run the CLI to reproduce it. Rules core skips
// without failing, incompatible with its version or missing a plugin, are
// skipped by the CLI too and are not load failures.
func ruleLoadFailure(e *coreError) string {
	_, kind, label := e.decodedType()
	if label != coreErrorTypeRuleParse && kind != coreErrorTypePattern && label != coreErrorTypeInvalidYAML {
		return ""
	}
	return fmt.Sprintf("opengrep-core could not load rule %s (%s): %s", e.RuleID, label, strings.TrimSpace(e.Message))
}

// decodedType returns the error type as JSON holds it, its constructor and
// the string the CLI prints for it.
func (e *coreError) decodedType() (errorType any, kind, label string) {
	if err := json.Unmarshal(e.ErrorType, &errorType); err != nil {
		errorType = string(e.ErrorType)
	}
	kind, label = errorTypeKind(errorType)
	return errorType, kind, label
}

func convertMatch(match *coreMatch, rule *coreRule, lines *lineReader) (entities.SemgrepResult, error) {
	message := match.Extra.Message
	if message == "" {
		message = rule.message
	}
	severity := match.Extra.Severity
	if severity == "" {
		severity = rule.severity
	}
	var metadata entities.SemgrepMetadata
	merged := make(map[string]any)
	if len(rule.metadata) > 0 {
		if err := json.Unmarshal(rule.metadata, &merged); err != nil {
			return entities.SemgrepResult{}, fmt.Errorf("opengrep: decode metadata of rule %s: %w", rule.id, err)
		}
	}
	for key, value := range match.Extra.Metadata {
		merged[key] = value
	}
	encoded, err := json.Marshal(merged)
	if err != nil {
		return entities.SemgrepResult{}, fmt.Errorf("opengrep: encode metadata of rule %s: %w", rule.id, err)
	}
	if err := json.Unmarshal(encoded, &metadata); err != nil {
		return entities.SemgrepResult{}, fmt.Errorf("opengrep: decode metadata of rule %s: %w", rule.id, err)
	}
	metavars := match.Extra.Metavars
	if metavars == nil {
		metavars = map[string]entities.MetavarInfo{}
	}
	return entities.SemgrepResult{
		CheckID: match.CheckID,
		Path:    match.Path,
		Start:   match.Start,
		End:     match.End,
		Extra: entities.SemgrepExtra{
			Message:  message,
			Metadata: metadata,
			Metavars: metavars,
			Severity: severity,
			Lines:    lines.span(match.Path, match.Start.Line, match.End.Line),
		},
	}, nil
}

// sortLikeCLI orders results by the CLI's ordering key: path, start, end,
// rule id and message. The CLI sorts every result by that key whatever the
// order of its rules, so two rules matching the same span come out by id;
// ordering by rule first instead changes which rule a deduplicated asset
// lists first.
func sortLikeCLI(results []entities.SemgrepResult) {
	sort.SliceStable(results, func(i, j int) bool {
		ra, rb := &results[i], &results[j]
		if ra.Path != rb.Path {
			return ra.Path < rb.Path
		}
		if c := comparePosition(ra.Start, rb.Start); c != 0 {
			return c < 0
		}
		if c := comparePosition(ra.End, rb.End); c != 0 {
			return c < 0
		}
		if ra.CheckID != rb.CheckID {
			return ra.CheckID < rb.CheckID
		}
		return ra.Extra.Message < rb.Extra.Message
	})
}

func comparePosition(a, b entities.SemgrepLocation) int {
	switch {
	case a.Line != b.Line:
		return a.Line - b.Line
	case a.Col != b.Col:
		return a.Col - b.Col
	default:
		return a.Offset - b.Offset
	}
}

// convertCoreError builds the error the CLI reports for a core error.
func convertCoreError(e *coreError) entities.SemgrepError {
	errorType, kind, label := e.decodedType()
	out := entities.SemgrepError{
		Type:    errorType,
		Level:   e.Severity,
		Message: cliErrorMessage(e, kind, label),
		RuleID:  e.RuleID,
	}
	switch {
	case e.Severity == "info":
		out.Code = cliOKExitCode
	case kind == coreErrorTypePartial || label == coreErrorTypeSyntax || label == coreErrorTypeLexical:
		out.Code = cliTargetParseExitCode
	default:
		out.Code = cliFatalExitCode
	}
	if e.Location != nil && kind != coreErrorTypePattern && label != coreErrorTypeRuleParse {
		out.Path = e.Location.Path
	}
	switch {
	case kind == coreErrorTypePartial:
		out.Spans = partialParsingSpans(errorType)
	case kind == coreErrorTypePattern && e.Location != nil:
		out.Spans = []entities.SemgrepErrorSpan{{File: e.Location.Path, Start: e.Location.Start, End: e.Location.End}}
	}
	return out
}

// errorTypeKind returns the constructor of an error type and the string the
// CLI prints for it.
func errorTypeKind(errorType any) (kind, label string) {
	switch value := errorType.(type) {
	case string:
		return value, value
	case []any:
		if len(value) == 0 {
			return "", ""
		}
		kind, _ = value[0].(string) //nolint:errcheck // A non-string constructor has no label.
		switch kind {
		case coreErrorTypePartial:
			return kind, coreErrorTypeSyntax
		case coreErrorTypePattern:
			return kind, coreErrorTypePatternMsg
		case coreErrorTypeIncompat:
			return kind, "Incompatible rule"
		default:
			return kind, kind
		}
	default:
		return "", fmt.Sprint(errorType)
	}
}

// cliErrorMessage is the CLI's SemgrepCoreError message.
func cliErrorMessage(e *coreError, kind, label string) string {
	var context string
	switch {
	case e.RuleID != "" && (kind == coreErrorTypePattern || label == coreErrorTypeRuleParse):
		context = "in rule " + e.RuleID
	case e.RuleID != "" && kind == coreErrorTypeIncompat:
		context = e.RuleID
	case e.RuleID != "" && label == "Missing plugin":
		context = "for rule " + e.RuleID
	case e.RuleID != "" && e.Location != nil:
		context = fmt.Sprintf("when running %s on %s", e.RuleID, e.Location.Path)
	case e.RuleID != "":
		context = "when running " + e.RuleID
	case e.Location != nil:
		context = fmt.Sprintf("at line %s:%d", e.Location.Path, e.Location.Start.Line)
	}
	return fmt.Sprintf("%s %s:\n %s", label, context, e.Message)
}

func partialParsingSpans(errorType any) []entities.SemgrepErrorSpan {
	value, ok := errorType.([]any)
	if !ok || len(value) < 2 {
		return nil
	}
	encoded, err := json.Marshal(value[1])
	if err != nil {
		return nil
	}
	var locations []coreLocation
	if json.Unmarshal(encoded, &locations) != nil {
		return nil
	}
	spans := make([]entities.SemgrepErrorSpan, 0, len(locations))
	for _, location := range locations {
		spans = append(spans, entities.SemgrepErrorSpan{File: location.Path, Start: location.Start, End: location.End})
	}
	return spans
}

// lineReader returns source lines as the CLI's get_lines_from_file reads
// them: decoded with replacement of invalid UTF-8, universal newlines.
type lineReader struct {
	files map[string][]string
	// dir is the directory relative paths lie in.
	dir string
}

func newLineReader(dir string) *lineReader {
	return &lineReader{files: make(map[string][]string), dir: dir}
}

// span joins lines start..end (1-based, inclusive) of path without their
// line breaks, as the CLI's "lines" field holds them.
func (r *lineReader) span(path string, start, end int) string {
	lines, ok := r.files[path]
	if !ok {
		data, err := os.ReadFile(fsPath(r.dir, path)) // #nosec G304 G703 -- a target file opengrep-core just scanned.
		if err == nil {
			text := decodeLikePython(data)
			text = strings.ReplaceAll(text, "\r\n", "\n")
			text = strings.ReplaceAll(text, "\r", "\n")
			lines = strings.Split(text, "\n")
		}
		r.files[path] = lines
	}
	if start < 1 {
		start = 1
	}
	if end > len(lines) {
		end = len(lines)
	}
	if start > end {
		return ""
	}
	return strings.Join(lines[start-1:end], "\n")
}

// decodeLikePython decodes data as Python's bytes.decode("utf-8",
// "replace") does: each maximal invalid prefix, an unexpected byte or a
// multi-byte sequence cut short, becomes one U+FFFD. strings.ToValidUTF8
// would fold a whole run of invalid bytes into one replacement, where the
// CLI's "lines" text holds one per stray byte.
func decodeLikePython(data []byte) string {
	var text strings.Builder
	text.Grow(len(data))
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size <= 1 {
			size = invalidUTF8Prefix(data[i:])
			text.WriteRune(utf8.RuneError)
		} else {
			text.Write(data[i : i+size])
		}
		i += size
	}
	return text.String()
}

// invalidUTF8Prefix is the length of the invalid sequence data starts with,
// as CPython's decoder measures it: a lead byte with the continuation bytes
// that fit it (E0, ED, F0 and F4 narrow their second byte), else one byte.
func invalidUTF8Prefix(data []byte) int {
	lead := data[0]
	var need int
	lo, hi := byte(0x80), byte(0xBF)
	switch {
	case lead >= 0xC2 && lead <= 0xDF:
		need = 1
	case lead >= 0xE0 && lead <= 0xEF:
		need = 2
		switch lead {
		case 0xE0:
			lo = 0xA0
		case 0xED:
			hi = 0x9F
		}
	case lead >= 0xF0 && lead <= 0xF4:
		need = 3
		switch lead {
		case 0xF0:
			lo = 0x90
		case 0xF4:
			hi = 0x8F
		}
	default:
		return 1
	}
	n := 1
	for ; n <= need && n < len(data); n++ {
		if data[n] < lo || data[n] > hi {
			break
		}
		lo, hi = 0x80, 0xBF
	}
	return n
}
