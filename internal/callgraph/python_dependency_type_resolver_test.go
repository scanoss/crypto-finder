// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// findInstalledCryptographyPackageDir shells out to `python3` to locate a
// locally installed `cryptography` distribution's source directory, for the
// 12.7 integration test. Returns "" when python3 or the package is
// unavailable — the caller skips gracefully rather than failing.
func findInstalledCryptographyPackageDir(t *testing.T) string {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "python3", "-c", "import cryptography, os; print(os.path.dirname(cryptography.__file__))").Output()
	if err != nil {
		t.Logf("python3/cryptography not available: %v", err)
		return ""
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		return ""
	}
	if info, statErr := os.Stat(dir); statErr != nil || !info.IsDir() {
		return ""
	}
	return dir
}

// fakePythonSignatureCache is an in-memory PythonSignatureIndexCache test
// double that also counts Get/Put calls, so tests can assert cache-hit
// behavior without depending on disk I/O timing.
type fakePythonSignatureCache struct {
	entries map[string]*CachedPythonSignatureIndex
	gets    int
	puts    int
}

func newFakePythonSignatureCache() *fakePythonSignatureCache {
	return &fakePythonSignatureCache{entries: make(map[string]*CachedPythonSignatureIndex)}
}

func (c *fakePythonSignatureCache) Get(_ context.Context, key string) (*CachedPythonSignatureIndex, bool, error) {
	c.gets++
	entry, ok := c.entries[key]
	return entry, ok, nil
}

func (c *fakePythonSignatureCache) Put(_ context.Context, key string, value *CachedPythonSignatureIndex) error {
	c.puts++
	c.entries[key] = value
	return nil
}

// writePythonDistFile writes a fixture file under dir, creating parent
// directories as needed.
func writePythonDistFile(t *testing.T, dir, relPath, content string) {
	t.Helper()
	full := filepath.Join(dir, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
}

// TestPythonDepTypeResolver_StubReturnAnnotation (12.1, row 14,
// python-parser-parity-2) pins that a top-level function's return
// annotation in a .pyi stub fills FunctionDecl.ReturnType when currently
// empty.
func TestPythonDepTypeResolver_StubReturnAnnotation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePythonDistFile(t, dir, "kdf.pyi", "def make(x: int) -> Cipher: ...\n")

	graph := &CallGraph{Functions: map[string]*FunctionDecl{}}
	fn := &FunctionDecl{ID: FunctionID{Package: "dep.kdf", Name: "make"}, Parameters: []FunctionParameter{{}}}
	graph.Functions[fn.ID.String()] = fn

	resolver := NewPythonDependencyTypeResolver(newFakePythonSignatureCache())
	if err := resolver.ResolveTypes(graph, []PackageDir{{Dir: dir, ImportPath: "dep", Version: "1.0.0"}}); err != nil {
		t.Fatalf("ResolveTypes() error = %v, want nil", err)
	}
	if fn.ReturnType != "Cipher" {
		t.Fatalf("ReturnType = %q, want %q", fn.ReturnType, "Cipher")
	}
}

// TestPythonDepTypeResolver_SourceAnnotation (12.1) pins the same behavior
// for an annotated .py source file (not just .pyi stubs) — row 14 reads
// both, per design.md.
func TestPythonDepTypeResolver_SourceAnnotation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePythonDistFile(t, dir, "kdf.py", "def make(x: int) -> Cipher:\n    return Cipher(x)\n")

	graph := &CallGraph{Functions: map[string]*FunctionDecl{}}
	fn := &FunctionDecl{ID: FunctionID{Package: "dep.kdf", Name: "make"}, Parameters: []FunctionParameter{{}}}
	graph.Functions[fn.ID.String()] = fn

	resolver := NewPythonDependencyTypeResolver(newFakePythonSignatureCache())
	if err := resolver.ResolveTypes(graph, []PackageDir{{Dir: dir, ImportPath: "dep", Version: "1.0.0"}}); err != nil {
		t.Fatalf("ResolveTypes() error = %v, want nil", err)
	}
	if fn.ReturnType != "Cipher" {
		t.Fatalf("ReturnType = %q, want %q", fn.ReturnType, "Cipher")
	}
}

// TestPythonDepTypeResolver_ClassBases (12.1) pins that a class_definition's
// superclasses field populates graph.TypeHierarchy, keyed by the class's
// fully qualified name.
func TestPythonDepTypeResolver_ClassBases(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePythonDistFile(t, dir, "keys.pyi", "class RSAKey(PKey):\n    def export(self) -> bytes: ...\n")

	graph := &CallGraph{Functions: map[string]*FunctionDecl{}}
	resolver := NewPythonDependencyTypeResolver(newFakePythonSignatureCache())
	if err := resolver.ResolveTypes(graph, []PackageDir{{Dir: dir, ImportPath: "dep", Version: "2.0.0"}}); err != nil {
		t.Fatalf("ResolveTypes() error = %v, want nil", err)
	}
	bases := graph.TypeHierarchy["dep.keys.RSAKey"]
	if len(bases) != 1 || bases[0] != "PKey" {
		t.Fatalf("TypeHierarchy[%q] = %v, want [PKey]", "dep.keys.RSAKey", bases)
	}
}

// TestPythonDepTypeResolver_CachePerDistribution (12.1) pins that a second
// ResolveTypes call for the SAME distribution key (ImportPath@Version)
// reuses the cached index instead of re-reading the filesystem: the fake
// cache's Put is called exactly once (first run), and Get returns a hit on
// the second run.
func TestPythonDepTypeResolver_CachePerDistribution(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePythonDistFile(t, dir, "kdf.pyi", "def make(x: int) -> Cipher: ...\n")

	cache := newFakePythonSignatureCache()
	resolver := NewPythonDependencyTypeResolver(cache)
	roots := []PackageDir{{Dir: dir, ImportPath: "dep", Version: "1.0.0"}}

	graph1 := &CallGraph{Functions: map[string]*FunctionDecl{}}
	fn1 := &FunctionDecl{ID: FunctionID{Package: "dep.kdf", Name: "make"}, Parameters: []FunctionParameter{{}}}
	graph1.Functions[fn1.ID.String()] = fn1
	if err := resolver.ResolveTypes(graph1, roots); err != nil {
		t.Fatalf("first ResolveTypes() error = %v", err)
	}
	if cache.puts != 1 {
		t.Fatalf("cache.puts after first run = %d, want 1", cache.puts)
	}

	// Remove the source file entirely — a second run must still resolve via
	// the cache, proving the filesystem is not re-read.
	if err := os.Remove(filepath.Join(dir, "kdf.pyi")); err != nil {
		t.Fatalf("remove fixture: %v", err)
	}

	graph2 := &CallGraph{Functions: map[string]*FunctionDecl{}}
	fn2 := &FunctionDecl{ID: FunctionID{Package: "dep.kdf", Name: "make"}, Parameters: []FunctionParameter{{}}}
	graph2.Functions[fn2.ID.String()] = fn2
	if err := resolver.ResolveTypes(graph2, roots); err != nil {
		t.Fatalf("second ResolveTypes() error = %v", err)
	}
	if fn2.ReturnType != "Cipher" {
		t.Fatalf("second run ReturnType = %q, want %q (cache hit expected)", fn2.ReturnType, "Cipher")
	}
	if cache.puts != 1 {
		t.Fatalf("cache.puts after second run = %d, want 1 (no re-index on cache hit)", cache.puts)
	}
}

// TestPythonDepTypeResolver_NoAnnotationsDegrades (12.1) pins that an
// unannotated function leaves ReturnType empty and never fabricates a type,
// and that the resolver still returns nil error (degradation, not failure).
func TestPythonDepTypeResolver_NoAnnotationsDegrades(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePythonDistFile(t, dir, "kdf.py", "def make(x):\n    return x\n")

	graph := &CallGraph{Functions: map[string]*FunctionDecl{}}
	fn := &FunctionDecl{ID: FunctionID{Package: "dep.kdf", Name: "make"}, Parameters: []FunctionParameter{{}}}
	graph.Functions[fn.ID.String()] = fn

	resolver := NewPythonDependencyTypeResolver(newFakePythonSignatureCache())
	if err := resolver.ResolveTypes(graph, []PackageDir{{Dir: dir, ImportPath: "dep", Version: "1.0.0"}}); err != nil {
		t.Fatalf("ResolveTypes() error = %v, want nil", err)
	}
	if fn.ReturnType != "" {
		t.Fatalf("ReturnType = %q, want empty (no fabrication)", fn.ReturnType)
	}
}

// TestPythonDepTypeResolver_NoAnnotationsDegrades_UnreadableDir (12.6)
// pins that an unreadable/nonexistent distribution directory degrades to a
// no-op rather than an error.
func TestPythonDepTypeResolver_NoAnnotationsDegrades_UnreadableDir(t *testing.T) {
	t.Parallel()

	graph := &CallGraph{Functions: map[string]*FunctionDecl{}}
	resolver := NewPythonDependencyTypeResolver(newFakePythonSignatureCache())
	roots := []PackageDir{{Dir: filepath.Join(t.TempDir(), "does-not-exist"), ImportPath: "dep", Version: "1.0.0"}}
	if err := resolver.ResolveTypes(graph, roots); err != nil {
		t.Fatalf("ResolveTypes() error = %v, want nil (graceful degradation)", err)
	}
}

// TestPythonDepTypeResolver_ProjectLocalUnaffected (12.1, D8) pins that a
// project-local source root (Version == "") is never read by this resolver
// — even when it contains a same-FQN function with a DIFFERENT annotation
// that would otherwise overwrite the graph's own, already-parser-derived
// ReturnType.
func TestPythonDepTypeResolver_ProjectLocalUnaffected(t *testing.T) {
	t.Parallel()

	projectDir := t.TempDir()
	writePythonDistFile(t, projectDir, "kdf.py", "def make(x: int) -> WrongType:\n    return x\n")

	graph := &CallGraph{Functions: map[string]*FunctionDecl{}}
	fn := &FunctionDecl{
		ID:         FunctionID{Package: "proj.kdf", Name: "make"},
		ReturnType: "AlreadySet",
		Parameters: []FunctionParameter{{}},
	}
	graph.Functions[fn.ID.String()] = fn

	resolver := NewPythonDependencyTypeResolver(newFakePythonSignatureCache())
	roots := []PackageDir{{Dir: projectDir, ImportPath: "proj", Version: ""}}
	if err := resolver.ResolveTypes(graph, roots); err != nil {
		t.Fatalf("ResolveTypes() error = %v, want nil", err)
	}
	if fn.ReturnType != "AlreadySet" {
		t.Fatalf("ReturnType = %q, want unchanged %q (project-local root must be skipped)", fn.ReturnType, "AlreadySet")
	}
}

// TestPythonDepTypeResolver_Integration (12.7) exercises the resolver
// against a REAL pip-resolved package when one is available in this
// environment (the installed `cryptography` distribution, per
// apply-progress.md); otherwise skips explicitly with a logged reason —
// never a fabricated pass.
func TestPythonDepTypeResolver_Integration(t *testing.T) {
	dir := findInstalledCryptographyPackageDir(t)
	if dir == "" {
		t.Skip("no locally installed `cryptography` package found — skipping dependency-mode integration test")
	}

	graph := &CallGraph{Functions: map[string]*FunctionDecl{}}
	fn := &FunctionDecl{
		ID:         FunctionID{Package: "cryptography.hazmat.primitives.kdf.pbkdf2", Type: "PBKDF2HMAC", Name: "derive"},
		Parameters: []FunctionParameter{{}},
	}
	graph.Functions[fn.ID.String()] = fn

	resolver := NewPythonDependencyTypeResolver(newFakePythonSignatureCache())
	roots := []PackageDir{{Dir: dir, ImportPath: "cryptography", Version: "50.0.1"}}
	if err := resolver.ResolveTypes(graph, roots); err != nil {
		t.Fatalf("ResolveTypes() error = %v, want nil", err)
	}
	if len(graph.TypeHierarchy) == 0 && len(graph.ExternalMethodSignatures) == 0 && fn.ReturnType == "" {
		t.Fatalf("resolver produced no signature/hierarchy evidence at all from a real installed package")
	}
	t.Logf("dependency-mode integration: TypeHierarchy=%d ExternalMethodSignatures=%d fn.ReturnType=%q",
		len(graph.TypeHierarchy), len(graph.ExternalMethodSignatures), fn.ReturnType)
}
