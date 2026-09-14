// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Command dispositions snapshots the resolved algorithm TEST-METADATA
// vocabulary from the pinned crypto_rules fixture corpus.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const pinnedRevision = "c8db56bd3c4cb64dac36cbdc6b531b1701d8c6c7"

var selectorKeys = []string{
	"assetType", "algorithmName", "algorithmFamily", "algorithmPrimitive",
	"algorithmMode", "algorithmParameterSetIdentifier", "cryptoFunction",
	"ellipticCurve", "curve", "keyLengthCapture",
}

type disposition struct {
	Signature       string            `json:"signature_sha256"`
	Source          string            `json:"source"`
	Selector        map[string]string `json:"selector"`
	Outcome         string            `json:"outcome"`
	Record          string            `json:"record,omitempty"`
	RecordReference string            `json:"record_reference"`
	Evidence        string            `json:"evidence"`
}

// sourceRow keeps fixture provenance separate from its semantic OID selector.
// Many independent rules may carry identical selector facts and intentionally
// resolve to one catalog record; only an identical pinned source row is a
// corpus integrity error.
type sourceRow struct {
	source string
	facts  map[string]string
}

func main() {
	refresh := flag.Bool("refresh", false, "write the current pinned fixture snapshot")
	check := flag.Bool("check", false, "compare the pinned fixture corpus with the committed snapshot")
	rulesDir := flag.String("rules-dir", "", "path to crypto_rules checkout")
	snapshot := flag.String("snapshot", "internal/oid/testdata/fixture-dispositions.json", "snapshot path")
	flag.Parse()
	if *refresh == *check || *rulesDir == "" {
		fmt.Fprintln(os.Stderr, "exactly one of --refresh or --check and --rules-dir are required")
		os.Exit(2)
	}
	rows, err := generate(*rulesDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	committed, err := readSnapshot(*snapshot)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	merged, err := mergeExpected(rows, committed)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	data, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	data = append(data, '\n')
	if *refresh {
		if err = writeSnapshot(*snapshot, data); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	expected, err := os.ReadFile(*snapshot)
	if err != nil || !bytes.Equal(expected, data) {
		if err == nil {
			err = fmt.Errorf("fixture selector snapshot differs; curated expectations must be updated separately")
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate(rulesDir string) ([]disposition, error) {
	files, err := git(rulesDir, "ls-tree", "-r", "--name-only", pinnedRevision, "--", "tests/integration/fixtures")
	if err != nil {
		return nil, fmt.Errorf("dispositions: list pinned fixtures: %w", err)
	}
	var sourceRows []sourceRow
	for _, file := range strings.Fields(string(files)) {
		body, showErr := git(rulesDir, "show", pinnedRevision+":"+file)
		if showErr != nil {
			return nil, fmt.Errorf("dispositions: read pinned fixture %q: %w", file, showErr)
		}
		for ordinal, metadata := range expectations(string(body)) {
			if metadata["assetType"] != "algorithm" {
				continue
			}
			sourceRows = append(sourceRows, sourceRow{source: fmt.Sprintf("%s#%06d", file, ordinal+1), facts: selector(metadata)})
		}
	}
	unique, err := deduplicateSourceRows(sourceRows)
	if err != nil {
		return nil, err
	}
	semanticRows := collapseSemanticRows(unique)
	if len(semanticRows) != 759 {
		return nil, fmt.Errorf("dispositions: expected 759 concrete algorithm signatures, got %d", len(semanticRows))
	}
	rows := make([]disposition, 0, len(semanticRows))
	for _, source := range semanticRows {
		key := canonical(source.facts)
		digest := sha256.Sum256([]byte(key))
		rows = append(rows, disposition{Signature: hex.EncodeToString(digest[:]), Source: source.source, Selector: source.facts})
	}
	return rows, nil
}

// deduplicateSourceRows rejects only a complete pinned source-row collision.
func deduplicateSourceRows(rows []sourceRow) ([]sourceRow, error) {
	unique := make(map[string]sourceRow, len(rows))
	for _, row := range rows {
		key := row.source
		if _, exists := unique[key]; exists {
			return nil, fmt.Errorf("dispositions: duplicate source identity %q", key)
		}
		unique[key] = row
	}
	result := make([]sourceRow, 0, len(unique))
	for _, row := range unique {
		result = append(result, row)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].source < result[j].source })
	return result, nil
}

// collapseSemanticRows makes the snapshot one deterministic row per OID
// selector while retaining provenance of the lexicographically first source.
func collapseSemanticRows(rows []sourceRow) []sourceRow {
	semantic := make(map[string]sourceRow, len(rows))
	for _, row := range rows {
		key := canonical(row.facts)
		if prior, exists := semantic[key]; !exists || row.source < prior.source {
			semantic[key] = row
		}
	}
	result := make([]sourceRow, 0, len(semantic))
	for _, row := range semantic {
		result = append(result, row)
	}
	sort.Slice(result, func(i, j int) bool {
		return canonical(result[i].facts) < canonical(result[j].facts)
	})
	return result
}

func readSnapshot(path string) ([]disposition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rows []disposition
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// mergeExpected binds source-derived selector signatures to independently
// curated outcome/record evidence. It intentionally never invokes Resolver.
func mergeExpected(observed, expected []disposition) ([]disposition, error) {
	bySignature := make(map[string]disposition, len(expected))
	for _, row := range expected {
		if row.Signature == "" || row.Outcome == "" || row.RecordReference == "" || row.Evidence == "" {
			return nil, fmt.Errorf("dispositions: incomplete curated expectation %q", row.Signature)
		}
		if _, exists := bySignature[row.Signature]; exists {
			return nil, fmt.Errorf("dispositions: duplicate curated signature %q", row.Signature)
		}
		bySignature[row.Signature] = row
	}
	merged := make([]disposition, 0, len(observed))
	for _, row := range observed {
		want, ok := bySignature[row.Signature]
		if !ok {
			return nil, fmt.Errorf("dispositions: unclassified signature %q", row.Signature)
		}
		if canonical(row.Selector) != canonical(want.Selector) {
			return nil, fmt.Errorf("dispositions: selector drift for %q", row.Signature)
		}
		if want.Source != "" && want.Source != row.Source {
			return nil, fmt.Errorf("dispositions: source provenance drift for %q", row.Signature)
		}
		want.Source = row.Source
		merged = append(merged, want)
	}
	if len(merged) != len(expected) {
		return nil, fmt.Errorf("dispositions: curated entries removed")
	}
	return merged, nil
}

func git(dir string, args ...string) ([]byte, error) {
	command := exec.CommandContext(context.Background(), "git", append([]string{"-C", dir}, args...)...)
	return command.Output()
}

func writeSnapshot(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func expectations(content string) []map[string]string {
	var found []map[string]string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "// TEST-METADATA:") && !strings.HasPrefix(line, "# TEST-METADATA:") {
			continue
		}
		value := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		facts := map[string]string{}
		if strings.Contains(value, "=") {
			for _, pair := range strings.Split(value, ",") {
				addPair(facts, pair, "=")
			}
		} else {
			for _, pair := range strings.Fields(value) {
				addPair(facts, pair, ":")
			}
		}
		if len(facts) > 0 {
			found = append(found, facts)
		}
	}
	return found
}

func addPair(facts map[string]string, pair, separator string) {
	parts := strings.SplitN(strings.TrimSpace(pair), separator, 2)
	if len(parts) == 2 && strings.TrimSpace(parts[0]) != "" {
		facts[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
}

func selector(metadata map[string]string) map[string]string {
	facts := make(map[string]string)
	for _, key := range selectorKeys {
		if value := metadata[key]; value != "" {
			facts[key] = value
		}
	}
	return facts
}

func canonical(facts map[string]string) string {
	keys := make([]string, 0, len(facts))
	for key := range facts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+facts[key])
	}
	return strings.Join(parts, "\x00")
}
