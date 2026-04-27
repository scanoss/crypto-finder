package callgraph

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCachedBytecodeIndex_MarshalUnmarshalJSON(t *testing.T) {
	original := CachedBytecodeIndex{
		SchemaVersion: bytecodeCacheSchemaVersion,
		ArtifactKey:   "io.jsonwebtoken:jjwt-api@0.12.5",
		MethodsIndex: map[string][]methodSignature{
			"JwtBuilder.signWith": {{
				className:  "JwtBuilder",
				methodName: "signWith",
				paramTypes: []string{"SignatureAlgorithm", "byte[]"},
				returnType: "JwtBuilder",
				fullClass:  "io.jsonwebtoken.JwtBuilder",
			}},
		},
		TypeHierarchy: map[string][]string{
			"io.jsonwebtoken.JwtBuilder": {"io.jsonwebtoken.ClaimsMutator"},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	var decoded CachedBytecodeIndex
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}

	if !reflect.DeepEqual(decoded, original) {
		t.Fatalf("decoded = %#v, want %#v", decoded, original)
	}
}

func TestDiskBytecodeIndexCache_GetPut_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskBytecodeIndexCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskBytecodeIndexCacheWithDir: %v", err)
	}

	key := bytecodeCacheStorageKey("io.jsonwebtoken:jjwt-api@0.12.5")
	entry := &CachedBytecodeIndex{
		SchemaVersion: bytecodeCacheSchemaVersion,
		ArtifactKey:   "io.jsonwebtoken:jjwt-api@0.12.5",
		MethodsIndex: map[string][]methodSignature{
			"JwtBuilder.signWith": {{
				className:  "JwtBuilder",
				methodName: "signWith",
				paramTypes: []string{"SignatureAlgorithm", "byte[]"},
				returnType: "JwtBuilder",
				fullClass:  "io.jsonwebtoken.JwtBuilder",
			}},
		},
		TypeHierarchy: map[string][]string{
			"JwtBuilder": {"ClaimsMutator"},
		},
	}

	if err := cache.Put(context.Background(), key, entry); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, ok, err := cache.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("expected cache hit, got miss")
	}

	if got.SchemaVersion != entry.SchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", got.SchemaVersion, entry.SchemaVersion)
	}
	if got.ArtifactKey != entry.ArtifactKey {
		t.Fatalf("ArtifactKey = %q, want %q", got.ArtifactKey, entry.ArtifactKey)
	}
	if !reflect.DeepEqual(got.MethodsIndex, entry.MethodsIndex) {
		t.Fatalf("MethodsIndex mismatch: got %#v want %#v", got.MethodsIndex, entry.MethodsIndex)
	}
	if !reflect.DeepEqual(got.TypeHierarchy, entry.TypeHierarchy) {
		t.Fatalf("TypeHierarchy mismatch: got %#v want %#v", got.TypeHierarchy, entry.TypeHierarchy)
	}
}

func TestDiskBytecodeIndexCache_Get_Miss(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskBytecodeIndexCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskBytecodeIndexCacheWithDir: %v", err)
	}

	got, ok, err := cache.Get(context.Background(), bytecodeCacheStorageKey("missing@1.0.0"))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Fatal("expected cache miss, got hit")
	}
	if got != nil {
		t.Fatal("expected nil entry on miss")
	}
}

func TestDiskBytecodeIndexCache_Get_MissWithoutLegacyKey(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskBytecodeIndexCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskBytecodeIndexCacheWithDir: %v", err)
	}

	got, ok, err := cache.Get(context.Background(), "not-versioned-key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Fatal("expected cache miss, got hit")
	}
	if got != nil {
		t.Fatal("expected nil entry on miss")
	}
}

func TestDiskBytecodeIndexCache_CorruptedFile(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskBytecodeIndexCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskBytecodeIndexCacheWithDir: %v", err)
	}

	key := bytecodeCacheStorageKey("corrupt@1.0.0")
	path := filepath.Join(dir, bytecodeCacheKeyToFilename(key))
	if err := os.WriteFile(path, []byte("{invalid json"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, ok, err := cache.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Fatal("expected cache miss for corrupted file")
	}
	if got != nil {
		t.Fatal("expected nil entry for corrupted file")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("expected corrupted cache file to be removed")
	}
}

func TestDiskBytecodeIndexCache_SchemaMismatch(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskBytecodeIndexCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskBytecodeIndexCacheWithDir: %v", err)
	}

	key := bytecodeCacheStorageKey("io.jsonwebtoken:jjwt-api@0.12.5")
	path := filepath.Join(dir, bytecodeCacheKeyToFilename(key))
	stale := []byte(`{"schema_version":999,"artifact_key":"io.jsonwebtoken:jjwt-api@0.12.5","methods_index":{},"type_hierarchy":{}}`)
	if err := os.WriteFile(path, stale, 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, ok, err := cache.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Fatal("expected cache miss for schema mismatch")
	}
	if got != nil {
		t.Fatal("expected nil entry for schema mismatch")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("expected schema-mismatched cache file to be removed")
	}
}

func TestReadBytecodeCacheFile_SchemaMismatchRemoveFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stale.json")
	stale := []byte(`{"schema_version":999,"artifact_key":"io.jsonwebtoken:jjwt-api@0.12.5","methods_index":{},"type_hierarchy":{}}`)
	if err := os.WriteFile(path, stale, 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	originalRemove := removeBytecodeCacheFile
	removeBytecodeCacheFile = func(removePath string) error {
		if removePath == path {
			return errors.New("simulated remove failure")
		}
		return originalRemove(removePath)
	}
	t.Cleanup(func() {
		removeBytecodeCacheFile = originalRemove
	})

	got, ok, err := readBytecodeCacheFile(path, bytecodeCacheSchemaVersion)
	if err == nil || !strings.Contains(err.Error(), "failed to remove corrupted cache file") {
		t.Fatalf("expected schema mismatch cleanup failure, got %v", err)
	}
	if ok {
		t.Fatal("expected cache miss on schema mismatch")
	}
	if got != nil {
		t.Fatal("expected nil entry on schema mismatch")
	}
}

func TestDiskBytecodeIndexCache_Get_LegacyEntryPromotesToCurrentPath(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskBytecodeIndexCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskBytecodeIndexCacheWithDir: %v", err)
	}

	currentKey := bytecodeCacheStorageKey("io.jsonwebtoken:jjwt-api@0.12.5")
	legacyKey, ok := legacyBytecodeCacheStorageKey(currentKey)
	if !ok {
		t.Fatalf("legacyBytecodeCacheStorageKey(%q) = !ok", currentKey)
	}

	legacyPath := filepath.Join(dir, legacyBytecodeCacheKeyToFilename(legacyKey))
	legacyEntry := []byte(`{"schema_version":1,"artifact_key":"io.jsonwebtoken:jjwt-api@0.12.5","methods_index":{"io.jsonwebtoken.JwtBuilder.signWith":[{"class_name":"JwtBuilder","method_name":"signWith","param_types":["SignatureAlgorithm","byte[]"],"return_type":"JwtBuilder","full_class":"io.jsonwebtoken.JwtBuilder"}]},"type_hierarchy":{"io.jsonwebtoken.JwtBuilder":["io.jsonwebtoken.ClaimsMutator"]}}`)
	if err := os.WriteFile(legacyPath, legacyEntry, 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, ok, err := cache.Get(context.Background(), currentKey)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok || got == nil {
		t.Fatalf("expected promoted cache hit, got ok=%v entry=%#v", ok, got)
	}
	if got.SchemaVersion != bytecodeCacheSchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", got.SchemaVersion, bytecodeCacheSchemaVersion)
	}

	currentPath := filepath.Join(dir, bytecodeCacheKeyToFilename(currentKey))
	if _, err := os.Stat(currentPath); err != nil {
		t.Fatalf("expected promoted current cache file at %s: %v", currentPath, err)
	}
}

func TestNewDiskBytecodeIndexCache_UsesConfiguredCacheDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cache, err := NewDiskBytecodeIndexCache()
	if err != nil {
		t.Fatalf("NewDiskBytecodeIndexCache: %v", err)
	}

	want := filepath.Join(home, ".scanoss", "crypto-finder", "cache", bytecodeCacheDirName)
	if cache.dir != want {
		t.Fatalf("cache.dir = %q, want %q", cache.dir, want)
	}
}

func TestNewDiskBytecodeIndexCache_GetCacheDirError(t *testing.T) {
	homeFile := filepath.Join(t.TempDir(), "home-file")
	if err := os.WriteFile(homeFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", homeFile)

	if _, err := NewDiskBytecodeIndexCache(); err == nil {
		t.Fatal("expected cache dir lookup error")
	}
}

func TestNewDiskBytecodeIndexCacheWithDir_ErrorWhenPathIsFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "cache-file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := NewDiskBytecodeIndexCacheWithDir(file); err == nil {
		t.Fatal("expected error when bytecode cache dir path is a file")
	}
}

func TestDiskBytecodeIndexCache_Get_ReadError(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskBytecodeIndexCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskBytecodeIndexCacheWithDir: %v", err)
	}

	key := bytecodeCacheStorageKey("read-error@1.0.0")
	path := filepath.Join(dir, bytecodeCacheKeyToFilename(key))
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, ok, err := cache.Get(context.Background(), key); err == nil || ok {
		t.Fatalf("expected read error and miss, got ok=%v err=%v", ok, err)
	}
}

func TestDiskBytecodeIndexCache_Get_RemoveInvalidFileFailure(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskBytecodeIndexCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskBytecodeIndexCacheWithDir: %v", err)
	}

	key := bytecodeCacheStorageKey("remove-error@1.0.0")
	path := filepath.Join(dir, bytecodeCacheKeyToFilename(key))
	if err := os.WriteFile(path, []byte("{invalid json"), 0o640); err != nil {
		t.Fatal(err)
	}

	originalRemove := removeBytecodeCacheFile
	removeBytecodeCacheFile = func(removePath string) error {
		if removePath == path {
			return errors.New("simulated remove failure")
		}
		return originalRemove(removePath)
	}
	t.Cleanup(func() {
		removeBytecodeCacheFile = originalRemove
	})

	if _, _, err := cache.Get(context.Background(), key); err == nil || !strings.Contains(err.Error(), "failed to remove corrupted cache file") {
		t.Fatalf("expected remove invalid cache failure, got %v", err)
	}
}

func TestDiskBytecodeIndexCache_Put_WriteAndRenameFailures(t *testing.T) {
	t.Run("write error", func(t *testing.T) {
		cache := &DiskBytecodeIndexCache{dir: filepath.Join(t.TempDir(), "missing")}
		err := cache.Put(context.Background(), bytecodeCacheStorageKey("write-error@1.0.0"), &CachedBytecodeIndex{})
		if err == nil || !strings.Contains(err.Error(), "failed to write cache file") {
			t.Fatalf("expected write error, got %v", err)
		}
	})

	t.Run("rename error cleans temp", func(t *testing.T) {
		dir := t.TempDir()
		cache, err := NewDiskBytecodeIndexCacheWithDir(dir)
		if err != nil {
			t.Fatalf("NewDiskBytecodeIndexCacheWithDir: %v", err)
		}

		key := bytecodeCacheStorageKey("rename-error@1.0.0")
		path := filepath.Join(dir, bytecodeCacheKeyToFilename(key))
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}

		err = cache.Put(context.Background(), key, &CachedBytecodeIndex{})
		if err == nil || !strings.Contains(err.Error(), "failed to rename cache file") {
			t.Fatalf("expected rename error, got %v", err)
		}

		if matches, globErr := filepath.Glob(filepath.Join(dir, bytecodeCacheKeyToFilename(key)+".tmp-*")); globErr != nil {
			t.Fatalf("Glob: %v", globErr)
		} else if len(matches) != 0 {
			t.Fatalf("expected temp file cleanup, found %v", matches)
		}
	})
}

func TestBytecodeCacheStorageKey(t *testing.T) {
	if got := bytecodeCacheStorageKey(""); got != "" {
		t.Fatalf("bytecodeCacheStorageKey(empty) = %q, want empty", got)
	}
	if got := bytecodeCacheStorageKey("group:artifact@1.0.0"); !strings.HasPrefix(got, "v3:") {
		t.Fatalf("bytecodeCacheStorageKey = %q, want versioned prefix", got)
	}
}

func TestRemoveInvalidBytecodeCacheFile(t *testing.T) {
	if err := removeInvalidBytecodeCacheFile(filepath.Join(t.TempDir(), "missing.json")); err != nil {
		t.Fatalf("removeInvalidBytecodeCacheFile missing: %v", err)
	}

	dir := t.TempDir()
	nonEmptyDir := filepath.Join(dir, "non-empty")
	if err := os.Mkdir(nonEmptyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nonEmptyDir, "child"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := removeInvalidBytecodeCacheFile(nonEmptyDir); err == nil || !strings.Contains(err.Error(), "failed to remove corrupted cache file") {
		t.Fatalf("expected remove error for non-empty dir, got %v", err)
	}
}

func TestBytecodeCacheKeyToFilename_SanitizesUnsafeCharacters(t *testing.T) {
	key := "v1:group/artifact@version<bad>\\name|with?chars*\"\x00"

	got := bytecodeCacheKeyToFilename(key)
	want := "v1_group_artifact_version_bad__name_with_chars___.json"

	if got != want {
		t.Fatalf("bytecodeCacheKeyToFilename(%q) = %q, want %q", key, got, want)
	}
}

func TestLegacyBytecodeCacheKeyToFilename_PreservesLegacyLayout(t *testing.T) {
	key := "v1:group/artifact@1.0.0"
	got := legacyBytecodeCacheKeyToFilename(key)
	want := "v1:group_artifact@1.0.0.json"
	if got != want {
		t.Fatalf("legacyBytecodeCacheKeyToFilename(%q) = %q, want %q", key, got, want)
	}
}
