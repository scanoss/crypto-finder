package engine

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestDiskFindingsCache_GetPut_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskFindingsCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskFindingsCacheWithDir: %v", err)
	}

	ctx := context.Background()
	key := "org.bouncycastle:bcprov-jdk18on@1.78:abcd1234"

	report := &entities.InterimReport{
		Version: "1.2",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "0.1.0"},
		Findings: []entities.Finding{
			{
				FilePath: "src/main/java/Crypto.java",
				Language: "java",
				CryptographicAssets: []entities.CryptographicAsset{
					{
						StartLine: 10,
						EndLine:   12,
						Match:     "Cipher.getInstance(\"AES\")",
						Rules: []entities.RuleInfo{
							{ID: "java.crypto.aes", Message: "AES usage", Severity: "WARNING"},
						},
						Status:   "pending",
						Metadata: map[string]string{"assetType": "algorithm", "algorithmName": "AES"},
					},
				},
			},
		},
	}

	// Put
	if err := cache.Put(ctx, key, report); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Get — should hit
	got, ok, err := cache.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("expected cache hit, got miss")
	}

	if got.Version != report.Version {
		t.Errorf("version: got %q, want %q", got.Version, report.Version)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("findings count: got %d, want 1", len(got.Findings))
	}
	if got.Findings[0].FilePath != report.Findings[0].FilePath {
		t.Errorf("file path: got %q, want %q", got.Findings[0].FilePath, report.Findings[0].FilePath)
	}
	if len(got.Findings[0].CryptographicAssets) != 1 {
		t.Fatalf("assets count: got %d, want 1", len(got.Findings[0].CryptographicAssets))
	}
	gotAsset := got.Findings[0].CryptographicAssets[0]
	if gotAsset.Match != "Cipher.getInstance(\"AES\")" {
		t.Errorf("match: got %q, want %q", gotAsset.Match, "Cipher.getInstance(\"AES\")")
	}
}

func TestDiskFindingsCache_Get_Miss(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskFindingsCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskFindingsCacheWithDir: %v", err)
	}

	got, ok, err := cache.Get(context.Background(), "nonexistent@1.0:abc123")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Fatal("expected cache miss, got hit")
	}
	if got != nil {
		t.Fatal("expected nil report on miss")
	}
}

func TestDiskFindingsCache_CorruptedFile(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskFindingsCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskFindingsCacheWithDir: %v", err)
	}

	// Write corrupted JSON
	key := "corrupt@1.0:abc123"
	path := filepath.Join(dir, cacheKeyToFilename(key))
	if err := os.WriteFile(path, []byte("{invalid json"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Should return miss (not error) and remove the corrupted file
	got, ok, err := cache.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Fatal("expected cache miss for corrupted file")
	}
	if got != nil {
		t.Fatal("expected nil report for corrupted file")
	}

	// Corrupted file should be removed
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("expected corrupted cache file to be removed")
	}
}

func TestDiskFindingsCache_VersionMismatch(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskFindingsCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskFindingsCacheWithDir: %v", err)
	}

	key := "stale@1.0:abc123"
	path := filepath.Join(dir, cacheKeyToFilename(key))
	payload, err := json.Marshal(findingsCacheEnvelope{
		Version: findingsCacheVersion + 1,
		Report:  &entities.InterimReport{Version: "1.2"},
	})
	if err != nil {
		t.Fatalf("Marshal stale envelope: %v", err)
	}
	if err := os.WriteFile(path, payload, 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, ok, err := cache.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Fatal("expected cache miss for version-mismatched file")
	}
	if got != nil {
		t.Fatal("expected nil report for version-mismatched file")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("expected version-mismatched cache file to be removed")
	}
}

func TestNewDiskFindingsCache_UsesConfiguredCacheDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cache, err := NewDiskFindingsCache()
	if err != nil {
		t.Fatalf("NewDiskFindingsCache: %v", err)
	}

	want := filepath.Join(home, ".scanoss", "crypto-finder", "cache", findingsCacheDirName)
	if cache.dir != want {
		t.Fatalf("cache.dir = %q, want %q", cache.dir, want)
	}
	if info, err := os.Stat(cache.dir); err != nil || !info.IsDir() {
		t.Fatalf("expected cache dir to exist, stat err=%v info=%v", err, info)
	}
}

func TestNewDiskFindingsCacheWithDir_ErrorWhenPathIsFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "cache-file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := NewDiskFindingsCacheWithDir(file); err == nil {
		t.Fatal("expected error when cache dir path is a file")
	}
}

func TestNewDiskFindingsCache_ErrorPaths(t *testing.T) {
	t.Run("cache dir lookup fails", func(t *testing.T) {
		homeFile := filepath.Join(t.TempDir(), "home-file")
		if err := os.WriteFile(homeFile, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("HOME", homeFile)

		if _, err := NewDiskFindingsCache(); err == nil {
			t.Fatal("expected cache dir lookup error")
		}
	})

	t.Run("findings dir create fails", func(t *testing.T) {
		homeDir := t.TempDir()
		t.Setenv("HOME", homeDir)

		cacheDir := filepath.Join(homeDir, ".scanoss", "crypto-finder", "cache")
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cacheDir, findingsCacheDirName), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}

		if _, err := NewDiskFindingsCache(); err == nil {
			t.Fatal("expected findings dir create error")
		}
	})
}

func TestDiskFindingsCache_Get_ReadError(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskFindingsCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskFindingsCacheWithDir: %v", err)
	}

	key := "read-error@1.0:abc"
	path := filepath.Join(dir, cacheKeyToFilename(key))
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, ok, err := cache.Get(context.Background(), key); err == nil || ok {
		t.Fatalf("expected read error and miss, got ok=%v err=%v", ok, err)
	}
}

func TestDiskFindingsCache_Get_RemoveCorruptedFileFailure(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskFindingsCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskFindingsCacheWithDir: %v", err)
	}

	key := "remove-error@1.0:abc"
	path := filepath.Join(dir, cacheKeyToFilename(key))
	if err := os.WriteFile(path, []byte("{invalid json"), 0o640); err != nil {
		t.Fatal(err)
	}

	originalRemove := removeFindingsCacheFile
	removeFindingsCacheFile = func(removePath string) error {
		if removePath == path {
			return errors.New("simulated remove failure")
		}
		return originalRemove(removePath)
	}
	t.Cleanup(func() {
		removeFindingsCacheFile = originalRemove
	})

	if _, _, err := cache.Get(context.Background(), key); err == nil || !strings.Contains(err.Error(), "failed to remove corrupted cache file") {
		t.Fatalf("expected remove failure, got %v", err)
	}
}

func TestDiskFindingsCache_Get_VersionMismatchAndNilReportAreRemoved(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload string
	}{
		{
			name:    "version mismatch",
			payload: `{"version":999,"report":{"version":"1.0","findings":[]}}`,
		},
		{
			name:    "nil report",
			payload: `{"version":1,"report":null}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cache, err := NewDiskFindingsCacheWithDir(dir)
			if err != nil {
				t.Fatalf("NewDiskFindingsCacheWithDir: %v", err)
			}

			key := "invalid-envelope@1.0:abc"
			path := filepath.Join(dir, cacheKeyToFilename(key))
			if err := os.WriteFile(path, []byte(tt.payload), 0o640); err != nil {
				t.Fatal(err)
			}

			report, ok, err := cache.Get(context.Background(), key)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if ok || report != nil {
				t.Fatalf("expected cache miss for invalid envelope, got ok=%v report=%#v", ok, report)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("expected invalid cache file to be removed, stat err=%v", err)
			}
		})
	}
}

func TestDiskFindingsCache_Put_CreateTempFailure(t *testing.T) {
	cache := &DiskFindingsCache{dir: filepath.Join(t.TempDir(), "missing")}

	err := cache.Put(context.Background(), "key", &entities.InterimReport{Version: "1.0"})
	if err == nil || !strings.Contains(err.Error(), "failed to create temp cache file") {
		t.Fatalf("expected create temp error, got %v", err)
	}
}

func TestDiskFindingsCache_Put_RenameFailureCleansTemp(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskFindingsCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskFindingsCacheWithDir: %v", err)
	}

	key := "rename-error@1.0:abc"
	path := filepath.Join(dir, cacheKeyToFilename(key))
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}

	err = cache.Put(context.Background(), key, &entities.InterimReport{Version: "1.0"})
	if err == nil || !strings.Contains(err.Error(), "failed to rename cache file") {
		t.Fatalf("expected rename error, got %v", err)
	}

	matches, globErr := filepath.Glob(filepath.Join(dir, filepath.Base(path)+".*.tmp"))
	if globErr != nil {
		t.Fatalf("Glob: %v", globErr)
	}
	if len(matches) != 0 {
		t.Fatalf("expected temp files to be cleaned up, found %v", matches)
	}
}

func TestCacheKeyToFilename(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{
			key:  "org.bouncycastle:bcprov-jdk18on@1.78:abcd1234",
			want: "org.bouncycastle_bcprov-jdk18on_1.78_abcd1234.json",
		},
		{
			key:  "golang.org/x/crypto@v0.17.0:abcd1234",
			want: "golang.org_x_crypto_v0.17.0_abcd1234.json",
		},
		{
			key:  "github.com/foo/bar@v1.0.0:abcd1234",
			want: "github.com_foo_bar_v1.0.0_abcd1234.json",
		},
		{
			key:  `group:artifact@1.0.0:rules<>:"/\\|?*hash`,
			want: "group_artifact_1.0.0_rules__________hash.json",
		},
	}

	for _, tt := range tests {
		got := cacheKeyToFilename(tt.key)
		if got != tt.want {
			t.Errorf("cacheKeyToFilename(%q) = %q, want %q", tt.key, got, tt.want)
		}
	}
}

func TestComputeRulesHash_Deterministic(t *testing.T) {
	dir := t.TempDir()

	// Create two rule files
	rule1 := filepath.Join(dir, "rule1.yaml")
	rule2 := filepath.Join(dir, "rule2.yaml")
	if err := os.WriteFile(rule1, []byte("rule: aes-detect"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rule2, []byte("rule: rsa-detect"), 0o640); err != nil {
		t.Fatal(err)
	}

	// Same paths in different order should produce the same hash
	hash1, err := ComputeRulesHash([]string{rule1, rule2})
	if err != nil {
		t.Fatalf("ComputeRulesHash: %v", err)
	}
	hash2, err := ComputeRulesHash([]string{rule2, rule1})
	if err != nil {
		t.Fatalf("ComputeRulesHash: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("hash should be order-independent: %q != %q", hash1, hash2)
	}

	if len(hash1) != 16 {
		t.Errorf("hash length: got %d, want 16", len(hash1))
	}
}

func TestComputeRulesHash_ChangesWithContent(t *testing.T) {
	dir := t.TempDir()
	rule := filepath.Join(dir, "rule.yaml")

	if err := os.WriteFile(rule, []byte("rule: aes-detect"), 0o640); err != nil {
		t.Fatal(err)
	}
	hash1, err := ComputeRulesHash([]string{rule})
	if err != nil {
		t.Fatalf("ComputeRulesHash: %v", err)
	}

	// Modify the rule file content
	if err := os.WriteFile(rule, []byte("rule: aes-detect-v2"), 0o640); err != nil {
		t.Fatal(err)
	}
	hash2, err := ComputeRulesHash([]string{rule})
	if err != nil {
		t.Fatalf("ComputeRulesHash: %v", err)
	}

	if hash1 == hash2 {
		t.Error("hash should change when rule content changes")
	}
}

func TestComputeRulesHash_DirectoryPath(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	nestedDir := filepath.Join(rulesDir, "go")

	if err := os.MkdirAll(nestedDir, 0o750); err != nil {
		t.Fatal(err)
	}

	rule1 := filepath.Join(rulesDir, "base.yaml")
	rule2 := filepath.Join(nestedDir, "crypto.yml")
	nonRuleFile := filepath.Join(rulesDir, "manifest.json")

	if err := os.WriteFile(rule1, []byte("rule: base"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rule2, []byte("rule: nested"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nonRuleFile, []byte(`{"checksum":"abc"}`), 0o640); err != nil {
		t.Fatal(err)
	}

	hashFromDir, err := ComputeRulesHash([]string{rulesDir})
	if err != nil {
		t.Fatalf("ComputeRulesHash directory: %v", err)
	}
	hashFromFiles, err := ComputeRulesHash([]string{rule1, rule2})
	if err != nil {
		t.Fatalf("ComputeRulesHash files: %v", err)
	}

	if hashFromDir != hashFromFiles {
		t.Errorf("directory hash should match explicit rule file hash: %q != %q", hashFromDir, hashFromFiles)
	}
}

func TestComputeRulesHash_DirectoryWithoutRuleFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}

	_, err := ComputeRulesHash([]string{dir})
	if err == nil {
		t.Fatal("expected error for directory without rule files")
	}
	if !strings.Contains(err.Error(), "no rule files found in directory") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestComputeRulesHash_AllowsOverlappingRulePaths(t *testing.T) {
	rulesDir := t.TempDir()
	nestedDir := filepath.Join(rulesDir, "nested")
	if err := os.MkdirAll(nestedDir, 0o755); err != nil {
		t.Fatal(err)
	}

	rule1 := filepath.Join(rulesDir, "base.yaml")
	rule2 := filepath.Join(nestedDir, "crypto.yml")
	if err := os.WriteFile(rule1, []byte("rule: base"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rule2, []byte("rule: nested"), 0o640); err != nil {
		t.Fatal(err)
	}

	hashFromOverlappingPaths, err := ComputeRulesHash([]string{rulesDir, nestedDir})
	if err != nil {
		t.Fatalf("ComputeRulesHash overlapping paths: %v", err)
	}
	hashFromDir, err := ComputeRulesHash([]string{rulesDir})
	if err != nil {
		t.Fatalf("ComputeRulesHash directory: %v", err)
	}

	if hashFromOverlappingPaths != hashFromDir {
		t.Fatalf("overlapping path hash = %q, want %q", hashFromOverlappingPaths, hashFromDir)
	}
}

func TestComputeRulesHash_EmptyPaths(t *testing.T) {
	if _, err := ComputeRulesHash(nil); err == nil || !strings.Contains(err.Error(), "no rule files provided") {
		t.Fatalf("expected no rule files provided error, got %v", err)
	}
}

func TestExpandRulePathForHash_MissingPath(t *testing.T) {
	var files []string
	seen := map[string]struct{}{}

	if _, _, err := expandRulePathForHash(filepath.Join(t.TempDir(), "missing"), &files, seen); err == nil || !strings.Contains(err.Error(), "failed to stat rule path") {
		t.Fatalf("expected stat error, got %v", err)
	}
}

func TestExpandRulePathForHash_DirectFileAndDuplicate(t *testing.T) {
	dir := t.TempDir()
	rule := filepath.Join(dir, "rule.yaml")
	if err := os.WriteFile(rule, []byte("rule: x"), 0o600); err != nil {
		t.Fatal(err)
	}

	var files []string
	seen := map[string]struct{}{}

	found, added, err := expandRulePathForHash(rule, &files, seen)
	if err != nil {
		t.Fatalf("expandRulePathForHash first call: %v", err)
	}
	if !found || !added {
		t.Fatalf("expected first file call to be found+added, got found=%v added=%v", found, added)
	}

	found, added, err = expandRulePathForHash(rule, &files, seen)
	if err != nil {
		t.Fatalf("expandRulePathForHash second call: %v", err)
	}
	if !found || added {
		t.Fatalf("expected duplicate file call to be found without add, got found=%v added=%v", found, added)
	}
}

func TestAddUniqueRulePathAndIsRuleFile(t *testing.T) {
	var files []string
	seen := map[string]struct{}{}

	if !addUniqueRulePath("a.yaml", &files, seen) {
		t.Fatal("expected first addUniqueRulePath call to add file")
	}
	if addUniqueRulePath("a.yaml", &files, seen) {
		t.Fatal("expected duplicate addUniqueRulePath call to return false")
	}
	if len(files) != 1 || files[0] != "a.yaml" {
		t.Fatalf("files = %#v, want [a.yaml]", files)
	}

	if !isRuleFile("rule.yaml") || !isRuleFile("rule.YML") {
		t.Fatal("expected yaml/yml files to be recognized")
	}
	if isRuleFile("rule.json") {
		t.Fatal("expected non-yaml file to be rejected")
	}
}
