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
	cliOKExitCode           = 0
	cliFatalExitCode        = 2
	cliTargetParseExitCode  = 3
	coreErrorTypePartial    = "PartialParsing"
	coreErrorTypePattern    = "PatternParseError"
	coreErrorTypeIncompat   = "IncompatibleRule"
	coreErrorTypeRuleParse  = "Rule parse error"
	coreErrorTypeSyntax     = "Syntax error"
	coreErrorTypeLexical    = "Lexical error"
	coreErrorTypePatternMsg = "Pattern parse error"
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
// scan: matches a nosemgrep comment silences are dropped, each result gains
// its rule's severity, its rule metadata and the source lines it spans, and
// results are ordered as the CLI orders them, by rule and then by location.
// useBase says opengrep-core knew the rules by their base ids; results then
// get the prefixed ids the CLI reports.
func convertCoreOutput(core *coreOutput, rules []*coreRule, useBase bool) (*entities.SemgrepOutput, error) {
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
	lines := newLineReader()
	out := &entities.SemgrepOutput{Results: make([]entities.SemgrepResult, 0, len(core.Results)), Errors: make([]entities.SemgrepError, 0, len(core.Errors))}
	order := make([]int, 0, len(core.Results))
	for i := range core.Results {
		match := &core.Results[i]
		if match.Extra.IsIgnored {
			continue
		}
		ruleIndex, ok := index[match.CheckID]
		if !ok {
			return nil, fmt.Errorf("opengrep: opengrep-core reported unknown rule %s", match.CheckID)
		}
		rule := rules[ruleIndex]
		result, err := convertMatch(match, rule, lines)
		result.CheckID = rule.id
		if err != nil {
			return nil, err
		}
		out.Results = append(out.Results, result)
		order = append(order, ruleIndex)
	}
	sortLikeCLI(out.Results, order)
	for i := range core.Errors {
		coreErr := core.Errors[i]
		if ruleIndex, ok := index[coreErr.RuleID]; ok && coreErr.RuleID != "" {
			coreErr.RuleID = rules[ruleIndex].id
		}
		out.Errors = append(out.Errors, convertCoreError(&coreErr))
	}
	return out, nil
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

// sortLikeCLI orders results by rule, in the CLI's rule order, then by the
// CLI's ordering key: path, start, end, rule id and message.
func sortLikeCLI(results []entities.SemgrepResult, ruleOrder []int) {
	idx := make([]int, len(results))
	for i := range idx {
		idx[i] = i
	}
	less := func(a, b int) bool {
		if ruleOrder[a] != ruleOrder[b] {
			return ruleOrder[a] < ruleOrder[b]
		}
		ra, rb := &results[a], &results[b]
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
	}
	sort.SliceStable(idx, func(i, j int) bool { return less(idx[i], idx[j]) })
	sorted := make([]entities.SemgrepResult, len(results))
	for i, j := range idx {
		sorted[i] = results[j]
	}
	copy(results, sorted)
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
	var errorType any
	if err := json.Unmarshal(e.ErrorType, &errorType); err != nil {
		errorType = string(e.ErrorType)
	}
	kind, label := errorTypeKind(errorType)
	out := entities.SemgrepError{
		Type:    errorType,
		Level:   e.Severity,
		Message: cliErrorMessage(e, kind, label),
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
}

func newLineReader() *lineReader {
	return &lineReader{files: make(map[string][]string)}
}

// span joins lines start..end (1-based, inclusive) of path without their
// line breaks, as the CLI's "lines" field holds them.
func (r *lineReader) span(path string, start, end int) string {
	lines, ok := r.files[path]
	if !ok {
		data, err := os.ReadFile(path) // #nosec G304 G703 -- a target file opengrep-core just scanned.
		if err == nil {
			text := strings.ToValidUTF8(string(data), "\uFFFD")
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
