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
