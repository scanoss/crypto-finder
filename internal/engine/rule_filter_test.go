package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/config"
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

	langs := ruleLanguages(good)
	if len(langs) != 2 {
		t.Fatalf("ruleLanguages len = %d, want 2", len(langs))
	}
	if langs[0] != "go" && langs[1] != "go" {
		t.Fatalf("expected normalized go language in %v", langs)
	}

	if got := ruleLanguages(filepath.Join(dir, "missing.yaml")); got != nil {
		t.Fatalf("expected nil for missing file, got %v", got)
	}

	invalid := writeRuleFile(t, dir, "invalid.yaml", `: not-yaml`)
	if got := ruleLanguages(invalid); got != nil {
		t.Fatalf("expected nil for invalid yaml, got %v", got)
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

func TestPrepareRulePathsForScanner_MaterializesFilteredFiles(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	rulesDir := filepath.Join(root, "semgrep-rules")
	if err := os.MkdirAll(filepath.Join(rulesDir, "nested"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	_ = writeRuleFile(t, rulesDir, "go.yaml", `rules:
  - id: go-rule
    languages: [go]
`)
	_ = writeRuleFile(t, filepath.Join(rulesDir, "nested"), "go-extra.yaml", `rules:
  - id: go-extra
    languages: [go]
`)

	paths, cleanup, err := prepareRulePathsForScanner([]string{rulesDir}, []string{"go"})
	if err != nil {
		t.Fatalf("prepareRulePathsForScanner() error = %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("prepareRulePathsForScanner() paths len = %d, want 1", len(paths))
	}
	defer cleanup()

	info, err := os.Stat(paths[0])
	if err != nil {
		t.Fatalf("stat materialized path: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("materialized path must be a directory, got file: %s", paths[0])
	}

	goCopy := filepath.Join(paths[0], "go.yaml")
	if _, err := os.Stat(goCopy); err != nil {
		t.Fatalf("expected copied go rule at %s: %v", goCopy, err)
	}

	if _, err := os.Stat(filepath.Join(paths[0], "nested", "go-extra.yaml")); err != nil {
		t.Fatalf("expected copied nested go rule: %v", err)
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

// TestMaterializeRuleFiles_NoGeometricGrowth proves that materializing rules
// inside the ruleset tree does not cause the next rule-tree walk to re-ingest
// the materialized copy. Without the SkipDir guard, the second walk would see
// the originals PLUS run-*'s copies and the count would balloon every scan.
func TestMaterializeRuleFiles_NoGeometricGrowth(t *testing.T) {
	// Cannot be parallel: overrides HOME so GetRulesetsDir resolves under temp,
	// which is required for materializeRuleFiles to write inside the tree.
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

	// Materialize once, leaving the run-* dir in place (simulating a SIGKILLed
	// job that never ran its cleanup).
	_, _, err = optimizeRulePathsForScanner([]string{a, b})
	if err != nil {
		t.Fatalf("optimizeRulePathsForScanner: %v", err)
	}

	// The filtered dir must now exist inside the tree...
	if _, err := os.Stat(filepath.Join(versionRoot, config.FilteredRulesDirName)); err != nil {
		t.Fatalf("expected materialized dir inside version root: %v", err)
	}
	// ...but the next walk must still see only the two originals.
	after := len(collectRuleFiles(versionRoot))
	if after != before {
		t.Fatalf("collectRuleFiles after materialize = %d, want %d (cache is re-ingesting itself)", after, before)
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
