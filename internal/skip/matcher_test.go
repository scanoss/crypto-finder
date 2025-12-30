package skip

import (
	"testing"
)

func TestGitIgnoreMatcher(t *testing.T) {
	patterns := []string{
		"node_modules/",
		"*.min.js",
		"test/",
		".git/",
	}

	matcher := NewGitIgnoreMatcher(patterns)

	tests := []struct {
		path     string
		isDir    bool
		expected bool
		desc     string
	}{
		{"node_modules", true, true, "should skip node_modules dir"},
		{"src/node_modules", true, true, "should skip nested node_modules"},
		{"app.min.js", false, true, "should skip minified js files"},
		{"src/app.min.js", false, true, "should skip nested minified js"},
		{"test", true, true, "should skip test dir"},
		{"app.js", false, false, "should not skip regular js files"},
		{"src/main.go", false, false, "should not skip go files"},
		{".hidden", true, true, "should skip hidden dirs"},
		{".git", true, true, "should skip .git dir"},
	}

	for _, tt := range tests {
		result := matcher.ShouldSkip(tt.path, tt.isDir)
		if result != tt.expected {
			t.Errorf("%s: ShouldSkip(%q, %v) = %v, want %v", tt.desc, tt.path, tt.isDir, result, tt.expected)
		}
	}
}

func TestMultiSource(t *testing.T) {
	// Create multiple sources
	defaultsSource := NewDefaultsSource()

	// Test MultiSource with single source
	single := NewMultiSource(defaultsSource)
	patterns, err := single.Load()
	if err != nil {
		t.Fatalf("MultiSource.Load() failed: %v", err)
	}
	if len(patterns) == 0 {
		t.Error("MultiSource with defaults should return patterns")
	}

	// Test MultiSource deduplicates patterns
	// Create a custom source that returns duplicate patterns
	customSource := &mockPatternSource{
		patterns: []string{"node_modules/", "vendor/", "node_modules/"}, // duplicate
		name:     "custom",
	}

	multi := NewMultiSource(defaultsSource, customSource)
	patterns, err = multi.Load()
	if err != nil {
		t.Fatalf("MultiSource.Load() failed: %v", err)
	}

	// Check for duplicates
	seen := make(map[string]bool)
	for _, p := range patterns {
		if seen[p] {
			t.Errorf("MultiSource contains duplicate: %s", p)
		}
		seen[p] = true

		// Check no empty strings
		if p == "" {
			t.Error("MultiSource contains empty string")
		}
	}
}

// mockPatternSource is a test helper that implements PatternSource.
type mockPatternSource struct {
	patterns []string
	name     string
	err      error
}

func (m *mockPatternSource) Load() ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.patterns, nil
}

func (m *mockPatternSource) Name() string {
	return m.name
}

func TestMatcherWithDefaults(t *testing.T) {
	// Create matcher using DefaultsSource
	source := NewDefaultsSource()
	patterns, err := source.Load()
	if err != nil {
		t.Fatalf("Failed to load defaults: %v", err)
	}

	matcher := NewGitIgnoreMatcher(patterns)
	if matcher == nil {
		t.Fatal("NewGitIgnoreMatcher() returned nil")
	}

	// Test that it skips common directories
	if !matcher.ShouldSkip("vendor", true) {
		t.Error("Default matcher should skip vendor")
	}
	if !matcher.ShouldSkip("node_modules", true) {
		t.Error("Default matcher should skip node_modules")
	}
}

func TestDefaultsSource(t *testing.T) {
	source := NewDefaultsSource()

	patterns, err := source.Load()
	if err != nil {
		t.Fatalf("DefaultsSource.Load() failed: %v", err)
	}

	if len(patterns) == 0 {
		t.Error("DefaultsSource should return patterns")
	}

	if source.Name() != "defaults" {
		t.Errorf("DefaultsSource.Name() = %s, want 'defaults'", source.Name())
	}

	// Verify it includes common directories
	hasNodeModules := false
	hasVendor := false
	for _, p := range patterns {
		if p == "node_modules" {
			hasNodeModules = true
		}
		if p == "vendor" {
			hasVendor = true
		}
	}

	if !hasNodeModules && !hasVendor {
		t.Error("DefaultsSource should include common directories like node_modules or vendor")
	}
}

func TestMultiSource_Name(t *testing.T) {
	t.Parallel()

	// Test empty MultiSource
	empty := NewMultiSource()
	if empty.Name() != "MultiSource(empty)" {
		t.Errorf("Empty MultiSource name should be 'MultiSource(empty)', got: %s", empty.Name())
	}

	// Test MultiSource with single source
	source1 := &mockPatternSource{name: "test-source"}
	single := NewMultiSource(source1)
	name := single.Name()

	if name == "" {
		t.Error("MultiSource name should not be empty")
	}

	// Test MultiSource with multiple sources
	source2 := &mockPatternSource{name: "other-source"}
	multi := NewMultiSource(source1, source2)
	multiName := multi.Name()

	if multiName == "" {
		t.Error("MultiSource name should not be empty")
	}
}
