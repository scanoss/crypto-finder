package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.yaml.in/yaml/v3"

	"github.com/scanoss/crypto-finder/internal/config"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/scanner/opengrep"
)

func writeRuleFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestRuleLanguages(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	good := writeRuleFile(t, dir, "go.yaml", `rules:
  - id: test
    languages: [Go, go, PYTHON]
`)

	langs, empty := ruleLanguages(good)
	if empty {
		t.Fatalf("expected non-empty rule file")
	}
	if len(langs) != 2 {
		t.Fatalf("ruleLanguages len = %d, want 2", len(langs))
	}
	if langs[0] != "go" && langs[1] != "go" {
		t.Fatalf("expected normalized go language in %v", langs)
	}

	if got, empty := ruleLanguages(filepath.Join(dir, "missing.yaml")); got != nil || empty {
		t.Fatalf("expected nil/non-empty for missing file, got %v empty=%v", got, empty)
	}

	invalid := writeRuleFile(t, dir, "invalid.yaml", `: not-yaml`)
	if got, empty := ruleLanguages(invalid); got != nil || empty {
		t.Fatalf("expected nil/non-empty for invalid yaml, got %v empty=%v", got, empty)
	}

	emptyFile := writeRuleFile(t, dir, "empty.yaml", `rules: []`)
	if _, empty := ruleLanguages(emptyFile); !empty {
		t.Fatalf("expected empty=true for zero-rule file")
	}
}

func TestFilterRulesByLanguages(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	goRule := writeRuleFile(t, dir, "go.yaml", `rules:
  - id: go-rule
    languages: [go]
`)
	pyRule := writeRuleFile(t, dir, "python.yaml", `rules:
  - id: py-rule
    languages: [python]
`)
	unknownLangRule := writeRuleFile(t, dir, "unknown.yaml", `rules:
  - id: unknown-rule
`)

	all := []string{goRule, pyRule, unknownLangRule}

	if got := filterRulesByLanguages(all, nil); len(got) != len(all) {
		t.Fatalf("expected all rules when no languages provided, got %d", len(got))
	}

	filtered := filterRulesByLanguages(all, []string{"GO"})
	if len(filtered) != 2 {
		t.Fatalf("filtered len = %d, want 2", len(filtered))
	}
	seen := map[string]bool{}
	for _, p := range filtered {
		seen[p] = true
	}
	if !seen[goRule] || !seen[unknownLangRule] {
		t.Fatalf("unexpected filtered rules: %#v", filtered)
	}

	fallback := filterRulesByLanguages([]string{pyRule}, []string{"go"})
	if len(fallback) != 1 || fallback[0] != pyRule {
		t.Fatalf("expected fallback to all rules, got %#v", fallback)
	}
}

// The detector names C++ and C# "c++" and "c#"; rule files say cpp and csharp.
// A tree holding both C and C++ sources used to keep only the C rules: they
// matched "c", so the empty-result fallback never ran and every C++-only rule
// was silently skipped.
func TestFilterRulesByLanguages_DetectorNamesMatchRuleIDs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cRule := writeRuleFile(t, dir, "c.yaml", `rules:
  - id: c-rule
    languages: [c, cpp]
`)
	cppRule := writeRuleFile(t, dir, "cpp.yaml", `rules:
  - id: cpp-rule
    languages: [cpp]
`)
	csharpRule := writeRuleFile(t, dir, "csharp.yaml", `rules:
  - id: csharp-rule
    languages: [csharp]
`)
	goRule := writeRuleFile(t, dir, "go.yaml", `rules:
  - id: go-rule
    languages: [go]
`)
	all := []string{cRule, cppRule, csharpRule, goRule}

	mixed := filterRulesByLanguages(all, []string{"c", "c++"})
	if len(mixed) != 2 || mixed[0] != cRule || mixed[1] != cppRule {
		t.Fatalf("mixed C/C++ tree: want the c and cpp rules, got %#v", mixed)
	}

	csharp := filterRulesByLanguages(all, []string{"C#"})
	if len(csharp) != 1 || csharp[0] != csharpRule {
		t.Fatalf("C# tree: want only the csharp rule, got %#v", csharp)
	}
}

// A rule file with zero rules (`rules: []`) must never survive language
// filtering. When it was the sole survivor, opengrep received a config with
// no rules and failed the whole scan with exit code 7.
func TestFilterRulesByLanguages_ExcludesEmptyRuleFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pyRule := writeRuleFile(t, dir, "python.yaml", `rules:
  - id: py-rule
    languages: [python]
`)
	emptyRule := writeRuleFile(t, dir, "empty.yaml", `rules: []
`)

	// No detected language matches any real rule: the empty file must not be
	// the lone survivor — the zero-match fallback to all rules must trigger.
	fallback := filterRulesByLanguages([]string{pyRule, emptyRule}, []string{"c++"})
	if len(fallback) != 2 {
		t.Fatalf("expected fallback to all rules, got %#v", fallback)
	}

	// With a matching language, the empty file is still excluded.
	filtered := filterRulesByLanguages([]string{pyRule, emptyRule}, []string{"python"})
	if len(filtered) != 1 || filtered[0] != pyRule {
		t.Fatalf("expected only python rule, got %#v", filtered)
	}
}

func TestFilterRulesByLanguages_DirectoryInput(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	rulesDir := filepath.Join(root, "rules")
	if err := os.MkdirAll(filepath.Join(rulesDir, "nested"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	goRule := writeRuleFile(t, rulesDir, "go.yaml", `rules:
  - id: go-rule
    languages: [go]
`)
	_ = writeRuleFile(t, filepath.Join(rulesDir, "nested"), "python.yaml", `rules:
  - id: py-rule
    languages: [python]
`)
	_ = writeRuleFile(t, rulesDir, "README.txt", "not-a-rule")

	filtered := filterRulesByLanguages([]string{rulesDir}, []string{"go"})
	if len(filtered) != 1 {
		t.Fatalf("filtered len = %d, want 1", len(filtered))
	}
	if filtered[0] != goRule {
		t.Fatalf("expected go rule path, got %#v", filtered)
	}
}

// OpenGrep compiles every config file it is given, single-threaded, once per
// invocation; one merged file loads measurably faster than hundreds of small
// ones. The merged rules carry the directory prefix OpenGrep used to derive
// from each file's location, so finding rule IDs do not change.
func TestPrepareRulePathsForScanner_MergesFilteredRulesIntoOneFile(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	rulesDir := filepath.Join(root, "semgrep-rules")
	if err := os.MkdirAll(filepath.Join(rulesDir, "nested", "deeper"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	_ = writeRuleFile(t, rulesDir, "go.yaml", `rules:
  - id: go-rule
    languages: [go]
    message: "keeps \"quoted\" text"
    pattern: md5.New()
`)
	_ = writeRuleFile(t, filepath.Join(rulesDir, "nested"), "a-kept.yaml", "rules:\n  - id: kept\n    languages: [go]\n    message: |+\n      text\n\n")
	_ = writeRuleFile(t, filepath.Join(rulesDir, "nested", "deeper"), "go-extra.yaml", `rules:
  - id: go-rule
    languages: [go]
    pattern-either:
      - pattern: sha1.New()
      - pattern: |
          sha256.New()
  - id: go-extra
    languages: [go]
    pattern: sha512.New()
`)
	_ = writeRuleFile(t, rulesDir, "python.yaml", `rules:
  - id: py-rule
    languages: [python]
    pattern: hashlib.md5()
`)

	paths, cleanup, err := prepareRulePathsForScanner([]string{rulesDir}, []string{"go"})
	if err != nil {
		t.Fatalf("prepareRulePathsForScanner() error = %v", err)
	}
	defer cleanup()
	if len(paths) != 1 {
		t.Fatalf("prepareRulePathsForScanner() paths len = %d, want 1", len(paths))
	}

	files := collectRuleFiles(paths[0])
	if len(files) != 1 {
		t.Fatalf("scanner config holds %d rule files, want one merged file: %v", len(files), files)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("read merged rules: %v", err)
	}
	var merged map[string][]map[string]any
	if err := yaml.Unmarshal(data, &merged); err != nil {
		t.Fatalf("merged rules are not one YAML document with a rules sequence: %v\n%s", err, data)
	}
	if len(merged) != 1 {
		t.Fatalf("merged file top-level keys = %v, want only rules", merged)
	}
	want := []map[string]any{
		{"id": "go-rule", "languages": []any{"go"}, "message": `keeps "quoted" text`, "pattern": "md5.New()"},
		{"id": "nested.kept", "languages": []any{"go"}, "message": "text\n\n"},
		{"id": "nested.deeper.go-rule", "languages": []any{"go"}, "pattern-either": []any{
			map[string]any{"pattern": "sha1.New()"},
			map[string]any{"pattern": "sha256.New()\n"},
		}},
		{"id": "nested.deeper.go-extra", "languages": []any{"go"}, "pattern": "sha512.New()"},
	}
	if !reflect.DeepEqual(merged["rules"], want) {
		t.Fatalf("merged rules:\n got %#v\nwant %#v", merged["rules"], want)
	}
}

// OpenGrep loads a rules file of JSON text about seven times faster than the
// same rules as YAML, so the merged file holds one JSON rule per line. Each
// scalar keeps the meaning OpenGrep's YAML parser gives it.
func TestMaterializeRuleFiles_WritesMergedRulesAsJSONLines(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	first := writeRuleFile(t, dir, "a.yaml", `rules:
  - id: a1
    languages: [javascript, typescript]
    severity: INFO
    message: |
      keeps "quoted" text
      and <html> & lines
    pattern-either:
      - pattern: crypto.createHash('md5')
      - patterns:
          - pattern-inside: $X = require('crypto')
          - pattern: $X.createHash(...)
    metadata:
      protocolVersion: 2.0
      keySize: 128
      exponent: 1e3
      fips: True
      approved: false
      shouted: FALSE
      word: yes
      mixed: tRUE
      since: 2001-12-14
      quoted: "2.0"
`)
	second := writeRuleFile(t, dir, "b.yaml", "rules:\n  - id: b1\n    languages: [go]\n    pattern: md5.New()\n")

	paths, cleanup, err := materializeRuleFiles([]string{first, second})
	if err != nil {
		t.Fatalf("materializeRuleFiles: %v", err)
	}
	defer cleanup()
	data, err := os.ReadFile(filepath.Join(paths[0], mergedRulesFileName))
	if err != nil {
		t.Fatalf("read merged rules: %v", err)
	}
	if !json.Valid(data) {
		t.Fatalf("merged rules are not JSON:\n%s", data)
	}

	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 4 || lines[0] != `{"rules":[` || lines[3] != "]}" {
		t.Fatalf("want one rule per line between the rules brackets:\n%s", data)
	}
	ids := make([]string, 0, 2)
	for _, line := range lines[1:3] {
		var rule struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSuffix(line, ",")), &rule); err != nil {
			t.Fatalf("rule line %q is not one JSON object: %v", line, err)
		}
		ids = append(ids, rule.ID)
	}
	if !reflect.DeepEqual(ids, []string{"a1", "b1"}) {
		t.Fatalf("rule lines hold ids %v, want [a1 b1]", ids)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var merged struct {
		Rules []map[string]any `json:"rules"`
	}
	if err := decoder.Decode(&merged); err != nil {
		t.Fatalf("decode merged rules: %v", err)
	}
	want := map[string]any{
		"id":        "a1",
		"languages": []any{"javascript", "typescript"},
		"severity":  "INFO",
		"message":   "keeps \"quoted\" text\nand <html> & lines\n",
		"pattern-either": []any{
			map[string]any{"pattern": "crypto.createHash('md5')"},
			map[string]any{"patterns": []any{
				map[string]any{"pattern-inside": "$X = require('crypto')"},
				map[string]any{"pattern": "$X.createHash(...)"},
			}},
		},
		"metadata": map[string]any{
			"protocolVersion": json.Number("2.0"),
			"keySize":         json.Number("128"),
			"exponent":        json.Number("1e3"),
			"fips":            true,
			"approved":        false,
			"shouted":         false,
			"word":            "yes",
			"mixed":           "tRUE",
			"since":           "2001-12-14",
			"quoted":          "2.0",
		},
	}
	if !reflect.DeepEqual(merged.Rules[0], want) {
		t.Fatalf("merged rule:\n got %#v\nwant %#v", merged.Rules[0], want)
	}
}

// A file whose YAML has no JSON spelling with the meaning OpenGrep gives it
// reaches the scanner verbatim: numbers JSON cannot write as they are (0x10,
// 0o17, 017, 0b101, 1_000, +5, .5, 1.), aliases and merge keys, repeated
// keys and other tags.
func TestMaterializeRuleFiles_PassesYAMLWithoutJSONFormVerbatim(t *testing.T) {
	t.Parallel()

	head := "rules:\n  - id: r\n    languages: [go]\n    pattern: md5.New()\n"
	cases := map[string]string{
		"hex.yaml":       head + "    metadata: {n: 0x10}\n",
		"octal.yaml":     head + "    metadata: {n: 0o17}\n",
		"legacy.yaml":    head + "    metadata: {n: 017}\n",
		"under.yaml":     head + "    metadata: {n: 1_000}\n",
		"plus.yaml":      head + "    metadata: {n: +5}\n",
		"dot.yaml":       head + "    metadata: {n: .5}\n",
		"inf.yaml":       head + "    metadata: {n: .inf}\n",
		"binary.yaml":    head + "    metadata: {n: 0b101}\n",
		"trailing.yaml":  head + "    metadata: {n: 1.}\n",
		"alias.yaml":     "rules:\n  - id: r\n    languages: &l [go]\n    message: m\n  - id: s\n    languages: *l\n",
		"merge.yaml":     "rules:\n  - &base {id: r, languages: [go]}\n  - <<: *base\n    id: s\n",
		"duplicate.yaml": head + "    pattern: sha1.New()\n",
		"tagged.yaml":    head + "    metadata: {n: !!binary aGk=}\n",
	}
	dir := t.TempDir()
	files := make([]string, 0, len(cases))
	for name, content := range cases {
		files = append(files, writeRuleFile(t, dir, name, content))
	}
	sort.Strings(files)

	paths, cleanup, err := materializeRuleFiles(files)
	if err != nil {
		t.Fatalf("materializeRuleFiles: %v", err)
	}
	defer cleanup()
	for name, content := range cases {
		got, err := os.ReadFile(filepath.Join(paths[0], name))
		if err != nil || string(got) != content {
			t.Fatalf("%s must reach the scanner unchanged: err=%v got %q", name, err, got)
		}
	}
	merged, err := os.ReadFile(filepath.Join(paths[0], mergedRulesFileName))
	if err != nil {
		t.Fatalf("read merged rules: %v", err)
	}
	if string(merged) != `{"rules":[]}`+"\n" {
		t.Fatalf("merged rules = %q, want an empty rules list", merged)
	}
}

// Files the merge cannot represent faithfully reach the scanner byte for byte,
// so OpenGrep keeps judging them as it did when every file was passed alone:
// it rejects invalid YAML and skips *.test.yaml fixtures inside a rules dir.
func TestPrepareRulePathsForScanner_PassesUnmergeableFilesThrough(t *testing.T) {
	t.Parallel()

	rulesDir := filepath.Join(t.TempDir(), "rules")
	if err := os.MkdirAll(filepath.Join(rulesDir, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	_ = writeRuleFile(t, rulesDir, "good.yaml", `rules:
  - id: good
    languages: [go]
`)
	broken := "rules:\n  - id: broken\n    languages: [go\n"
	fixture := "rules:\n  - id: fixture\n    languages: [go]\n"
	extraKeys := "rules:\n  - id: extra\n    languages: [go]\nother: true\n"
	_ = writeRuleFile(t, rulesDir, "broken.yaml", broken)
	_ = writeRuleFile(t, filepath.Join(rulesDir, "sub"), "fixture.test.yaml", fixture)
	_ = writeRuleFile(t, filepath.Join(rulesDir, "sub"), "extra.yaml", extraKeys)

	paths, cleanup, err := prepareRulePathsForScanner([]string{rulesDir}, []string{"go"})
	if err != nil {
		t.Fatalf("prepareRulePathsForScanner() error = %v", err)
	}
	defer cleanup()

	verbatim := map[string]string{
		"broken.yaml":           broken,
		"sub/fixture.test.yaml": fixture,
		"sub/extra.yaml":        extraKeys,
	}
	var merged []string
	for _, file := range collectRuleFiles(paths[0]) {
		rel, err := filepath.Rel(paths[0], file)
		if err != nil {
			t.Fatalf("rel %s: %v", file, err)
		}
		content, ok := verbatim[filepath.ToSlash(rel)]
		if !ok {
			merged = append(merged, file)
			continue
		}
		if got, err := os.ReadFile(file); err != nil || string(got) != content {
			t.Fatalf("%s must reach the scanner unchanged: err=%v got %q", rel, err, got)
		}
		delete(verbatim, filepath.ToSlash(rel))
	}
	if len(verbatim) != 0 {
		t.Fatalf("missing verbatim copies: %v", verbatim)
	}
	if len(merged) != 1 {
		t.Fatalf("want one merged file beside the verbatim copies, got %v", merged)
	}
	var rules map[string][]map[string]any
	data, err := os.ReadFile(merged[0])
	if err != nil || yaml.Unmarshal(data, &rules) != nil {
		t.Fatalf("read merged rules: err=%v\n%s", err, data)
	}
	if want := []map[string]any{{"id": "good", "languages": []any{"go"}}}; !reflect.DeepEqual(rules["rules"], want) {
		t.Fatalf("merged rules = %#v, want only the good rule", rules["rules"])
	}
}

// The dependency findings cache keys on the prepared rules; two runs over the
// same rule content must agree even though each lives in its own temp dir.
func TestPrepareRulePathsForScanner_RulesHashIsDeterministic(t *testing.T) {
	t.Parallel()

	rulesDir := filepath.Join(t.TempDir(), "rules")
	if err := os.MkdirAll(filepath.Join(rulesDir, "nested"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	_ = writeRuleFile(t, rulesDir, "a.yaml", "rules:\n  - id: a\n    languages: [go]\n")
	nested := writeRuleFile(t, filepath.Join(rulesDir, "nested"), "b.yaml", "rules:\n  - id: b\n    languages: [go]\n")

	hash := func() string {
		t.Helper()
		paths, cleanup, err := prepareRulePathsForScanner([]string{rulesDir}, []string{"go"})
		if err != nil {
			t.Fatalf("prepareRulePathsForScanner() error = %v", err)
		}
		defer cleanup()
		got, err := ComputeRulesHash(paths)
		if err != nil {
			t.Fatalf("ComputeRulesHash() error = %v", err)
		}
		return got
	}

	first := hash()
	if second := hash(); second != first {
		t.Fatalf("rules hash changed between identical runs: %s then %s", first, second)
	}
	if err := os.WriteFile(nested, []byte("rules:\n  - id: b\n    languages: [go]\n    pattern: x\n"), 0o600); err != nil {
		t.Fatalf("rewrite rule: %v", err)
	}
	if changed := hash(); changed == first {
		t.Fatalf("rules hash %s did not change with rule content", changed)
	}
}

// Real OpenGrep run: merged rules must yield exactly the findings and rule IDs
// of the same filtered files loaded one by one, including rule IDs repeated
// across directories and within one directory (OpenGrep runs both copies).
func TestPrepareRulePathsForScanner_MergedRulesKeepFindingsIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a real OpenGrep subprocess")
	}
	if _, err := exec.LookPath("opengrep"); err != nil {
		t.Skip("OpenGrep not installed")
	}

	root := t.TempDir()
	rulesDir := filepath.Join(root, "rules")
	javaDir := filepath.Join(rulesDir, "java")
	for _, dir := range []string{"java/jca/md5", "java/other", "python"} {
		if err := os.MkdirAll(filepath.Join(rulesDir, dir), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	rule := func(id, pattern string) string {
		return "rules:\n  - id: " + id + "\n    languages: [java]\n    severity: INFO\n    message: m\n    pattern: " + pattern +
			"\n    metadata:\n      crypto:\n        assetType: algorithm\n        protocolVersion: 2.5\n        keySize: 128\n        fips: True\n        note: yes\n"
	}
	_ = writeRuleFile(t, filepath.Join(javaDir, "jca", "md5"), "rules.yaml", rule("dup", `MessageDigest.getInstance("MD5")`))
	_ = writeRuleFile(t, filepath.Join(javaDir, "jca", "md5"), "extra.yaml", rule("dup", `MessageDigest.getInstance("SHA-256")`))
	_ = writeRuleFile(t, filepath.Join(javaDir, "other"), "rules.yaml", rule("dup", `MessageDigest.getInstance("MD5")`))
	_ = writeRuleFile(t, javaDir, "top.yaml", rule("top", `MessageDigest.getInstance("SHA-256")`))
	_ = writeRuleFile(t, javaDir, "skipped.test.yaml", rule("fixture", `MessageDigest.getInstance(...)`))
	_ = writeRuleFile(t, filepath.Join(rulesDir, "python"), "rules.yaml", `rules:
  - id: py
    languages: [python]
    severity: INFO
    message: m
    pattern: hashlib.md5()
`)

	src := filepath.Join(root, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	_ = writeRuleFile(t, src, "Hash.java", `import java.security.MessageDigest;

class Hash {
    byte[] md5(byte[] in) throws Exception {
        return MessageDigest.getInstance("MD5").digest(in);
    }

    byte[] sha(byte[] in) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(in);
    }
}
`)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	scan := func(rulePaths []string) []string {
		t.Helper()
		s := opengrep.NewScanner()
		if err := s.Initialize(ctx, scanner.Config{Timeout: time.Minute, ExtraArgs: []string{"--jobs", "1"}}); err != nil {
			t.Fatalf("initialize opengrep: %v", err)
		}
		report, err := s.Scan(ctx, src, rulePaths, entities.ToolInfo{Name: "opengrep"})
		if err != nil {
			t.Fatalf("scan with %v: %v", rulePaths, err)
		}
		var got []string
		for _, finding := range report.Findings {
			for _, asset := range finding.CryptographicAssets {
				metadata, err := json.Marshal(asset.Metadata)
				if err != nil {
					t.Fatalf("marshal metadata: %v", err)
				}
				for _, r := range asset.Rules {
					got = append(got, strconv.Itoa(asset.StartLine)+":"+r.ID+" "+string(metadata))
				}
			}
		}
		sort.Strings(got)
		return got
	}

	const metadata = ` {"assetType":"algorithm","fips":"true","keySize":"128","note":"yes","protocolVersion":"2.5"}`
	want := []string{"5:jca.md5.dup" + metadata, "5:other.dup" + metadata, "9:jca.md5.dup" + metadata, "9:top" + metadata}
	if perFile := scan([]string{javaDir}); !reflect.DeepEqual(perFile, want) {
		t.Fatalf("per-file baseline findings = %v, want %v", perFile, want)
	}

	paths, cleanup, err := prepareRulePathsForScanner([]string{rulesDir}, []string{"java"})
	if err != nil {
		t.Fatalf("prepareRulePathsForScanner() error = %v", err)
	}
	defer cleanup()
	if got := scan(paths); !reflect.DeepEqual(got, want) {
		t.Fatalf("merged rules findings = %v, want %v", got, want)
	}
}

// TestCollectRuleFiles_SkipsFilteredDir is the regression guard for the
// self-nesting cache bug: collectRuleFiles must never descend into the
// materialized .crypto-finder-filtered dir, otherwise each scan re-ingests the
// previous run's copies and the ruleset cache grows geometrically.
func TestCollectRuleFiles_SkipsFilteredDir(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	_ = writeRuleFile(t, root, "real.yaml", `rules:
  - id: real
    languages: [go]
`)

	// Simulate a prior run's materialized output living inside the tree.
	filteredRun := filepath.Join(root, config.FilteredRulesDirName, "run-123", "latest")
	if err := os.MkdirAll(filteredRun, 0o755); err != nil {
		t.Fatalf("mkdir filtered run: %v", err)
	}
	_ = writeRuleFile(t, filteredRun, "copy.yaml", `rules:
  - id: copy
    languages: [go]
`)

	files := collectRuleFiles(root)
	if len(files) != 1 {
		t.Fatalf("collectRuleFiles len = %d, want 1 (must skip %s); got %v",
			len(files), config.FilteredRulesDirName, files)
	}
	if filepath.Base(files[0]) != "real.yaml" {
		t.Fatalf("collectRuleFiles returned %v, want only real.yaml", files)
	}
}

// TestMaterializeRuleFiles_OutsideRulesetTree proves filtered working copies
// cannot be re-ingested by a walk of the cached ruleset.
func TestMaterializeRuleFiles_OutsideRulesetTree(t *testing.T) {
	// Cannot be parallel: overrides HOME so GetRulesetsDir resolves under temp,
	// which is required for materializeRuleFiles to recognize the cache tree.
	home := t.TempDir()
	t.Setenv("HOME", home)

	rulesetsDir, err := config.GetRulesetsDir()
	if err != nil {
		t.Fatalf("GetRulesetsDir: %v", err)
	}
	versionRoot := filepath.Join(rulesetsDir, "dca", "latest")
	if err := os.MkdirAll(versionRoot, 0o755); err != nil {
		t.Fatalf("mkdir version root: %v", err)
	}
	a := writeRuleFile(t, versionRoot, "a.yaml", `rules:
  - id: a
    languages: [go]
`)
	b := writeRuleFile(t, versionRoot, "b.yaml", `rules:
  - id: b
    languages: [go]
`)

	before := len(collectRuleFiles(versionRoot))
	if before != 2 {
		t.Fatalf("setup: collectRuleFiles before = %d, want 2", before)
	}

	paths, _, err := optimizeRulePathsForScanner([]string{a, b})
	if err != nil {
		t.Fatalf("optimizeRulePathsForScanner: %v", err)
	}

	filteredParent := filepath.Join(filepath.Dir(versionRoot), config.FilteredRulesDirName, filepath.Base(versionRoot))
	if !strings.HasPrefix(paths[0], filteredParent+string(os.PathSeparator)) {
		t.Fatalf("materialized path %s must be outside version root under %s", paths[0], filteredParent)
	}
	after := len(collectRuleFiles(versionRoot))
	if after != before {
		t.Fatalf("collectRuleFiles after materialize = %d, want %d (cache is re-ingesting itself)", after, before)
	}
}

func TestMaterializeRuleFiles_SurvivesRulesetReplacement(t *testing.T) {
	// Cannot be parallel: HOME controls the shared ruleset cache location.
	home := t.TempDir()
	t.Setenv("HOME", home)

	rulesetsDir, err := config.GetRulesetsDir()
	if err != nil {
		t.Fatalf("GetRulesetsDir: %v", err)
	}
	versionRoot := filepath.Join(rulesetsDir, "dca", "latest")
	if err := os.MkdirAll(versionRoot, 0o755); err != nil {
		t.Fatalf("mkdir version root: %v", err)
	}
	a := writeRuleFile(t, versionRoot, "a.yaml", "rules:\n  - id: a\n    languages: [go]\n")
	b := writeRuleFile(t, versionRoot, "b.yaml", "rules:\n  - id: b\n    languages: [go]\n")

	paths, cleanup, err := materializeRuleFiles([]string{a, b})
	if err != nil {
		t.Fatalf("materializeRuleFiles: %v", err)
	}
	defer cleanup()

	if err := os.RemoveAll(versionRoot); err != nil {
		t.Fatalf("replace ruleset: %v", err)
	}
	files := collectRuleFiles(paths[0])
	survived := make([]string, 0, len(files))
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("in-flight filtered rules must survive cache replacement: %v", err)
		}
		survived = append(survived, string(data))
	}
	all := strings.Join(survived, "\n")
	if !strings.Contains(all, `"id":"a"`) || !strings.Contains(all, `"id":"b"`) {
		t.Fatalf("in-flight filtered rules lost after cache replacement: %q", all)
	}
}

// OpenGrep reports an invalid merged rule as a line of merged-rules.yaml, a
// file removed after the scan. The debug log must map that line back to the
// source rule file.
func TestMaterializeRuleFiles_LogsMergedLineOfEachSourceFile(t *testing.T) {
	previous := log.Logger
	t.Cleanup(func() { log.Logger = previous })
	var output bytes.Buffer
	log.Logger = zerolog.New(&output).Level(zerolog.DebugLevel)

	dir := t.TempDir()
	first := writeRuleFile(t, dir, "a.yaml", "rules:\n  - id: a1\n    languages: [go]\n    message: |\n      two\n      lines\n  - id: a2\n    languages: [go]\n")
	second := writeRuleFile(t, dir, "b.yaml", "rules:\n  - id: b1\n    languages: [go]\n")

	paths, cleanup, err := materializeRuleFiles([]string{first, second})
	if err != nil {
		t.Fatalf("materializeRuleFiles: %v", err)
	}
	defer cleanup()
	merged, err := os.ReadFile(filepath.Join(paths[0], mergedRulesFileName))
	if err != nil {
		t.Fatalf("read merged rules: %v", err)
	}
	lines := strings.Split(string(merged), "\n")

	starts := map[string]int{}
	for _, line := range strings.Split(output.String(), "\n") {
		var entry struct {
			Path string `json:"path"`
			Line int    `json:"mergedLine"`
		}
		if json.Unmarshal([]byte(line), &entry) == nil && entry.Line > 0 {
			starts[entry.Path] = entry.Line
		}
	}
	for path, wantID := range map[string]string{first: "a1", second: "b1"} {
		line := starts[path]
		var rule struct {
			ID string `json:"id"`
		}
		if line < 1 || line > len(lines) || json.Unmarshal([]byte(strings.TrimSuffix(lines[line-1], ",")), &rule) != nil || rule.ID != wantID {
			t.Fatalf("log maps %s to merged line %d, want the line of rule %s:\n%s", path, line, wantID, merged)
		}
	}
}

func TestPruneStaleFilteredRuns(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	stale := filepath.Join(parent, "run-stale")
	fresh := filepath.Join(parent, "run-fresh")
	keep := filepath.Join(parent, "not-a-run")
	for _, d := range []string{stale, fresh, keep} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	old := time.Now().Add(-3 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	pruneStaleFilteredRuns(parent)

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("expected stale run-* pruned, err=%v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatalf("expected fresh run-* kept: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("expected non-run dir untouched: %v", err)
	}
}

func TestPrepareRulePathsForScanner_CleanupRemovesMaterializedDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	first := writeRuleFile(t, dir, "first.yaml", `rules:
  - id: first
    languages: [go]
`)
	second := writeRuleFile(t, dir, "second.yaml", `rules:
  - id: second
    languages: [python]
`)

	paths, cleanup, err := prepareRulePathsForScanner([]string{first, second}, []string{"go", "python"})
	if err != nil {
		t.Fatalf("prepareRulePathsForScanner() error = %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("prepareRulePathsForScanner() paths len = %d, want 1", len(paths))
	}

	materializedRoot := paths[0]
	cleanup()

	if _, err := os.Stat(materializedRoot); !os.IsNotExist(err) {
		t.Fatalf("expected cleanup to remove %s, got err=%v", materializedRoot, err)
	}
}
