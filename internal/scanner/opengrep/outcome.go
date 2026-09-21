// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package opengrep adapts native execution and optional invocation evidence.
package opengrep

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
)

// One-entry, version/profile-bound allowlist, not a generic warning classifier.
// OpenGrep v1.29.0 Scan_CLI.ml1435 emits this API-stability notice before quiet.
const (
	unknownWire   = "unknown-wire"
	unknownResult = "unknown-result"
	unknownTarget = "unknown-target-evidence"
	nullJSON      = "null"
)

var stabilityNotice = regexp.MustCompile(`^\[[0-9]{2}\.[0-9]{2}\]\[WARNING\]: !!! You're using one or more options starting with '--x-'\. These options are not part of the opengrep API\. They will change or will be removed without notice !!! \n$`)

func (s *Scanner) certify(target string, rules, args []string, output []byte, stderr string) (bool, string) {
	expected := make([]string, 0, 7+2*len(rules))
	expected = append(expected, "--json", "--taint-intrafile", "--x-ignore-semgrepignore-files")
	for _, rule := range rules {
		expected = append(expected, "--config", rule)
	}
	expected = append(expected, "--quiet", "--jobs", "2", target)
	if s.version != "1.29.0" || len(s.env) != 0 || s.workDir != "" || len(rules) != 1 || !reflect.DeepEqual(args, expected) {
		return false, "unknown-profile"
	}
	if !stabilityNotice.MatchString(stderr) {
		return false, "unknown-diagnostic"
	}
	if reason := validateWire(output, target, rules); reason != "" {
		return false, reason
	}
	return true, "recognized-api-stability-notice"
}

// Reject unobserved fields instead of treating a permissive report decoder as proof.
func knownFields(raw json.RawMessage, keys []string) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(keys) {
		return nil, false
	}
	for _, key := range keys {
		if len(fields[key]) == 0 || string(fields[key]) == nullJSON {
			return nil, false
		}
	}
	return fields, true
}

func validateWire(output []byte, target string, rules []string) string {
	var wire map[string]json.RawMessage
	if json.Unmarshal(output, &wire) != nil {
		return unknownWire
	}
	for _, key := range []string{"version", "results", "errors", "paths", "interfile_languages_used", "skipped_rules"} {
		if len(wire[key]) == 0 || string(wire[key]) == nullJSON {
			return unknownWire
		}
	}
	// This exact capture has six top-level fields. Unknown telemetry is not proof.
	if len(wire) != 6 {
		return unknownWire
	}
	var version string
	if json.Unmarshal(wire["version"], &version) != nil || version != "1.29.0" {
		return "unknown-version"
	}
	for _, key := range []string{"errors", "interfile_languages_used", "skipped_rules"} {
		var entries []json.RawMessage
		if json.Unmarshal(wire[key], &entries) != nil {
			return unknownWire
		}
		if len(entries) != 0 {
			return "native-diagnostic-or-skip"
		}
	}
	var results []json.RawMessage
	if json.Unmarshal(wire["results"], &results) != nil {
		return unknownWire
	}
	if reason := validateResults(results); reason != "" {
		return reason
	}
	return validateScope(wire["paths"], target, rules, results)
}

func validateResults(results []json.RawMessage) string {
	for _, result := range results {
		fields, ok := knownFields(result, []string{"check_id", "path", "start", "end", "extra"})
		if !ok {
			return unknownResult
		}
		for _, key := range []string{"start", "end"} {
			if _, ok := knownFields(fields[key], []string{"line", "col", "offset"}); !ok {
				return unknownResult
			}
		}
		extra, ok := knownFields(fields["extra"], []string{"metavars", "message", "metadata", "severity", "fingerprint", "lines", "is_ignored", "validation_state", "engine_kind"})
		if !ok || string(extra["engine_kind"]) != `"OSS"` || string(extra["is_ignored"]) != "false" {
			return unknownResult
		}
	}
	return ""
}

func validateScope(raw json.RawMessage, target string, rules []string, results []json.RawMessage) string {
	var paths map[string]json.RawMessage
	if json.Unmarshal(raw, &paths) != nil || len(paths) != 1 {
		return unknownTarget
	}
	var scanned []string
	if len(paths["scanned"]) == 0 || string(paths["scanned"]) == nullJSON || json.Unmarshal(paths["scanned"], &scanned) != nil {
		return unknownTarget
	}
	seen := make(map[string]bool, len(scanned))
	for _, path := range scanned {
		if !filepath.IsAbs(path) || seen[path] {
			return unknownTarget
		}
		seen[path] = true
	}
	if !resultPathsInScanned(results, seen) {
		return unknownTarget
	}
	if !readableRules(rules) {
		return "uncertain-rules"
	}
	if !scannedFilesMatch(target, seen) {
		return "uncertain-target-scope"
	}
	return ""
}

// Reported findings must resolve exactly to verified scanned files.
func resultPathsInScanned(results []json.RawMessage, scanned map[string]bool) bool {
	for _, rawResult := range results {
		var result struct {
			Path string `json:"path"`
		}
		if json.Unmarshal(rawResult, &result) != nil || !filepath.IsAbs(result.Path) ||
			filepath.Clean(result.Path) != result.Path || !scanned[result.Path] {
			return false
		}
	}
	return true
}

func readableRules(rules []string) bool {
	for _, rule := range rules {
		info, err := os.Lstat(rule)
		if err != nil || !info.Mode().IsRegular() {
			return false
		}
		if _, err := os.ReadFile(rule); err != nil {
			return false
		}
	}
	return true
}

func scannedFilesMatch(target string, seen map[string]bool) bool {
	if len(seen) == 0 {
		return false
	}
	err := filepath.WalkDir(target, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() || !seen[path] {
			return fs.ErrInvalid
		}
		if _, err := os.ReadFile(path); err != nil {
			return err
		}
		delete(seen, path)
		return nil
	})
	return err == nil && len(seen) == 0
}
