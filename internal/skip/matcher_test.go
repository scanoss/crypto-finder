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

package skip

import (
	"os"
	"path/filepath"
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

func TestDefaultSkipPatternsKeepExamplePaths(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"example", "examples"} {
		if containsPattern(DefaultSkippedDirs, name) {
			t.Errorf("DefaultSkippedDirs must not contain %q; fingerprinting skips hide shipped crypto", name)
		}
	}

	matcher := NewGitIgnoreMatcher(DefaultSkippedDirs)
	cases := []struct {
		path  string
		isDir bool
	}{
		{path: "example", isDir: true},
		{path: "examples", isDir: true},
		{path: "src/com/example", isDir: true},
		{path: "src/com/example/earnie/JcaUsage.java", isDir: false},
		{path: "src/main/java/com/example/crypto/Aes.java", isDir: false},
		{path: "examples/sdk/demo.go", isDir: false},
		{path: "src/examples/reference.rs", isDir: false},
	}
	for _, tc := range cases {
		if matcher.ShouldSkip(tc.path, tc.isDir) {
			t.Errorf("ShouldSkip(%q, %v) = true, want false", tc.path, tc.isDir)
		}
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

func TestDefaultTestPatternsHelpers(t *testing.T) {
	patterns := []string{"vendor", "src/test/", "custom/"}

	withTestsExcluded := WithDefaultTestPatterns(patterns)
	if !containsPattern(withTestsExcluded, "vendor") || !containsPattern(withTestsExcluded, "src/test/") {
		t.Fatalf("WithDefaultTestPatterns lost expected patterns: %#v", withTestsExcluded)
	}
	if !containsPattern(withTestsExcluded, "**/*Test.java") {
		t.Fatalf("WithDefaultTestPatterns did not append default test patterns: %#v", withTestsExcluded)
	}

	onlyTests := OnlyDefaultTestPatterns(withTestsExcluded)
	if containsPattern(onlyTests, "vendor") || containsPattern(onlyTests, "custom/") {
		t.Fatalf("OnlyDefaultTestPatterns kept non-test patterns: %#v", onlyTests)
	}
	if !containsPattern(onlyTests, "src/test/") || !containsPattern(onlyTests, "**/*Test.java") {
		t.Fatalf("OnlyDefaultTestPatterns lost test patterns: %#v", onlyTests)
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

func containsPattern(patterns []string, want string) bool {
	for _, pattern := range patterns {
		if pattern == want {
			return true
		}
	}
	return false
}

// TestDefaultTestPatternsSkipBundledCTestSources pins the C/C++ test, bench and
// known-answer generator sources a vendored library ships but never compiles,
// and that product sources with similar names stay in the scan.
func TestDefaultTestPatternsSkipBundledCTestSources(t *testing.T) {
	t.Parallel()

	matcher := NewGitIgnoreMatcher(DefaultSkippedCTestPatterns)
	skipped := []string{
		"extras/libargon2/src/test.c",
		"extras/libargon2/src/bench.c",
		"extras/libargon2/src/genkat.c",
		"lib/tests.c",
		"lib/test_vectors.c",
		"lib/aes_test.c",
		"lib/aes_tests.cc",
		"lib/bench_sha.cpp",
		"lib/sha_bench.c",
		"lib/test.cpp",
		"genkat.cc",
	}
	for _, p := range skipped {
		if !matcher.ShouldSkip(p, false) {
			t.Errorf("ShouldSkip(%q) = false, want true", p)
		}
	}
	kept := []string{
		"extras/libargon2/src/core.c",
		"extras/libargon2/src/argon2.c",
		"lib/attest.c",
		"lib/testing.c",
		"lib/benchmark.c",
		"lib/contest_util.cpp",
		"lib/test.h",
		"lib/latest.c",
	}
	for _, p := range kept {
		if matcher.ShouldSkip(p, false) {
			t.Errorf("ShouldSkip(%q) = true, want false", p)
		}
	}
}

// TestCTestPatternsFor_OnlyBesideProductSources pins the #490 rule for the C
// test patterns: they never exclude the only C/C++ source a package has.
func TestCTestPatternsFor_OnlyBesideProductSources(t *testing.T) {
	t.Parallel()

	write := func(t *testing.T, root string, files ...string) {
		t.Helper()
		for _, f := range files {
			path := filepath.Join(root, filepath.FromSlash(f))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("int x;\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}

	bundled := t.TempDir()
	write(t, bundled, "pkg/hash.py", "extras/argon2/src/core.c", "extras/argon2/src/test.c", "extras/argon2/src/genkat.c")
	if got := CTestPatternsFor(bundled); len(got) == 0 {
		t.Errorf("CTestPatternsFor(bundled) = nil, want the patterns beside core.c")
	}

	onlyTests := t.TempDir()
	write(t, onlyTests, "pkg/hash.py", "src/test.c", "src/bench.c")
	if got := CTestPatternsFor(onlyTests); got != nil {
		t.Errorf("CTestPatternsFor(onlyTests) = %v, want nil: test.c is the only C source", got)
	}

	// Product sources the scan never reads do not count.
	hidden := t.TempDir()
	write(t, hidden, "src/test.c", "node_modules/dep/core.c", "tests/helper.c")
	if got := CTestPatternsFor(hidden); got != nil {
		t.Errorf("CTestPatternsFor(hidden) = %v, want nil", got)
	}

	if got := cTestPatternsFor(bundled, 1); got != nil {
		t.Errorf("cTestPatternsFor past the cap = %v, want nil", got)
	}
}
