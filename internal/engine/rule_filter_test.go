package engine

import (
	"os"
	"path/filepath"
	"testing"
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
