package dependency

import (
	"archive/zip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func createZipArchive(t *testing.T, path string, files map[string]string) {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer func() { _ = f.Close() }()

	zw := zip.NewWriter(f)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
}

func setTestHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}
}

func TestNewSourceCacheAndCachedDir(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	cache, err := NewSourceCache()
	if err != nil {
		t.Fatalf("NewSourceCache: %v", err)
	}

	if cache.CachedDir("org.example:lib", "1.0.0") != "" {
		t.Fatal("expected cache miss for missing dir")
	}

	existing := filepath.Join(cache.baseDir, "org.example:lib", "1.0.0")
	if err := os.MkdirAll(existing, 0o750); err != nil {
		t.Fatalf("mkdir existing cache dir: %v", err)
	}

	if got := cache.CachedDir("org.example:lib", "1.0.0"); got != existing {
		t.Fatalf("CachedDir() = %q, want %q", got, existing)
	}
}

func TestSourceCache_ExtractZip(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	cache, err := NewSourceCache()
	if err != nil {
		t.Fatalf("NewSourceCache: %v", err)
	}

	archive := filepath.Join(t.TempDir(), "sources.jar")
	createZipArchive(t, archive, map[string]string{
		"src/Main.java":       "class Main {}",
		"src/readme.txt":      "not java",
		"../evil/attack.java": "class Attack {}",
	})

	dir, err := cache.ExtractZip(archive, "org.example:lib", "1.2.3", []string{".java"})
	if err != nil {
		t.Fatalf("ExtractZip: %v", err)
	}

	javaFile := filepath.Join(dir, "src", "Main.java")
	if _, err := os.Stat(javaFile); err != nil {
		t.Fatalf("expected java file to be extracted: %v", err)
	}

	nonJava := filepath.Join(dir, "src", "readme.txt")
	if _, err := os.Stat(nonJava); !os.IsNotExist(err) {
		t.Fatalf("expected non-java file to be skipped")
	}

	zipSlip := filepath.Join(cache.baseDir, "org.example:lib", "evil", "attack.java")
	if _, err := os.Stat(zipSlip); !os.IsNotExist(err) {
		t.Fatalf("expected zip slip path not to be extracted")
	}

	// Second extraction should hit already extracted cache dir.
	dir2, err := cache.ExtractZip(archive, "org.example:lib", "1.2.3", []string{".java"})
	if err != nil {
		t.Fatalf("ExtractZip second call: %v", err)
	}
	if dir2 != dir {
		t.Fatalf("expected same cached dir, got %q and %q", dir2, dir)
	}
}

func TestSourceCache_ExtractZip_InvalidArchive(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	cache, err := NewSourceCache()
	if err != nil {
		t.Fatalf("NewSourceCache: %v", err)
	}

	invalid := filepath.Join(t.TempDir(), "not-a-zip.jar")
	if err := os.WriteFile(invalid, []byte("invalid zip"), 0o600); err != nil {
		t.Fatalf("write invalid archive: %v", err)
	}

	_, err = cache.ExtractZip(invalid, "org.example:broken", "0.0.1", []string{".java"})
	if err == nil || !strings.Contains(err.Error(), "open archive") {
		t.Fatalf("expected archive open error, got %v", err)
	}

	if got := cache.CachedDir("org.example:broken", "0.0.1"); got != "" {
		t.Fatalf("expected no cached dir after failed extraction, got %q", got)
	}
}

func TestHasMatchingExtension(t *testing.T) {
	t.Parallel()

	if !hasMatchingExtension("x/Main.java", []string{".java"}) {
		t.Fatal("expected .java match")
	}
	if hasMatchingExtension("x/README.md", []string{".java", ".py"}) {
		t.Fatal("expected extension mismatch")
	}
}
