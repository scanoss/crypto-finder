package engine

import (
	"context"
	"os"
	"path/filepath"
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
						MatchType: "semgrep",
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

func TestCacheKeyToFilename(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{
			key:  "org.bouncycastle:bcprov-jdk18on@1.78:abcd1234",
			want: "org.bouncycastle:bcprov-jdk18on@1.78:abcd1234.json",
		},
		{
			key:  "golang.org/x/crypto@v0.17.0:abcd1234",
			want: "golang.org_x_crypto@v0.17.0:abcd1234.json",
		},
		{
			key:  "github.com/foo/bar@v1.0.0:abcd1234",
			want: "github.com_foo_bar@v1.0.0:abcd1234.json",
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
