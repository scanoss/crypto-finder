package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/python"
)

func TestPythonParser_PackageSeparator(t *testing.T) {
	p := NewPythonParser()
	if got := p.PackageSeparator(); got != "." {
		t.Errorf("PackageSeparator() = %q, want %q", got, ".")
	}
}

func TestPythonParser_SkipDirs(t *testing.T) {
	p := NewPythonParser()
	skip := p.SkipDirs()
	expected := []string{"__pycache__", ".venv", "venv", "test", "tests", ".tox"}
	for _, dir := range expected {
		if !skip[dir] {
			t.Errorf("SkipDirs() missing %q", dir)
		}
	}
}

func TestPythonParser_SubPackagePath(t *testing.T) {
	p := NewPythonParser()
	tests := []struct {
		parent, dir, want string
	}{
		{"cryptography", "hazmat", "cryptography.hazmat"},
		{"", "cryptography", "cryptography"},
		{"cryptography.hazmat", "primitives", "cryptography.hazmat.primitives"},
	}
	for _, tt := range tests {
		got := p.SubPackagePath(tt.parent, tt.dir)
		if got != tt.want {
			t.Errorf("SubPackagePath(%q, %q) = %q, want %q", tt.parent, tt.dir, got, tt.want)
		}
	}
}

func TestPythonParser_ParseFile(t *testing.T) {
	src := `import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from os import urandom

def generate_key(size):
    return urandom(size)

def encrypt(key, data):
    algo = algorithms.AES(key)
    cipher = Cipher(algo, None)
    encryptor = cipher.encryptor()
    return encryptor.update(data)

class CryptoHelper:
    def __init__(self, key):
        self.key = key

    def hash_data(self, data):
        return hashlib.sha256(data).hexdigest()

    def encrypt_data(self, data):
        return encrypt(self.key, data)
`
	dir := t.TempDir()
	filePath := filepath.Join(dir, "crypto_utils.py")
	if err := os.WriteFile(filePath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	p := NewPythonParser()
	analyses, err := p.ParseDirectory(dir, "myproject")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis, got %d", len(analyses))
	}

	analysis := analyses[0]

	// Check imports
	expectedImports := map[string]string{
		"hashlib":    "hashlib",
		"Cipher":     "cryptography.hazmat.primitives.ciphers",
		"algorithms": "cryptography.hazmat.primitives.ciphers",
		"urandom":    "os",
	}
	for name, pkg := range expectedImports {
		if analysis.Imports[name] != pkg {
			t.Errorf("import %q = %q, want %q", name, analysis.Imports[name], pkg)
		}
	}
	if !analysis.ImportedTypes["Cipher"] {
		t.Error("expected Cipher import to be classified as a type")
	}
	if analysis.ImportedTypes["urandom"] {
		t.Error("expected urandom import to remain classified as a function")
	}

	// Check functions
	funcNames := make(map[string]bool)
	for _, fn := range analysis.Functions {
		key := fn.ID.Type + "." + fn.ID.Name
		funcNames[key] = true
	}

	if !funcNames[".generate_key"] {
		t.Error("missing function 'generate_key'")
	}
	if !funcNames[".encrypt"] {
		t.Error("missing function 'encrypt'")
	}
	if !funcNames["CryptoHelper.<init>"] {
		t.Error("missing method 'CryptoHelper.__init__' (mapped to <init>)")
	}
	if !funcNames["CryptoHelper.hash_data"] {
		t.Error("missing method 'CryptoHelper.hash_data'")
	}
	if !funcNames["CryptoHelper.encrypt_data"] {
		t.Error("missing method 'CryptoHelper.encrypt_data'")
	}

	// Check that encrypt function has calls
	for _, fn := range analysis.Functions {
		if fn.ID.Name != "encrypt" || fn.ID.Type != "" {
			continue
		}
		if len(fn.Calls) == 0 {
			t.Error("encrypt function should have calls")
		}
		// Verify Cipher constructor call resolves through imports
		foundCipherCall := false
		for _, call := range fn.Calls {
			if call.Callee.Type == "Cipher" && call.Callee.Name == "<init>" {
				foundCipherCall = true
				if call.Callee.Package != "cryptography.hazmat.primitives.ciphers" {
					t.Errorf("Cipher call package = %q, want %q", call.Callee.Package, "cryptography.hazmat.primitives.ciphers")
				}
			}
		}
		if !foundCipherCall {
			t.Error("encrypt function should have a Cipher() constructor call")
		}
		break
	}

	// Check that hash_data method resolves hashlib.sha256
	for _, fn := range analysis.Functions {
		if fn.ID.Name == "hash_data" {
			foundHashCall := false
			for _, call := range fn.Calls {
				if call.Callee.Package == "hashlib" && call.Callee.Name == "sha256" {
					foundHashCall = true
				}
			}
			if !foundHashCall {
				t.Error("hash_data should have a hashlib.sha256 call")
			}
			break
		}
	}
}

func TestPythonParser_ImportedFunctionCallIsNotConstructor(t *testing.T) {
	src := `from hashlib import sha256

def digest(data):
    return sha256(data)
`
	dir := t.TempDir()
	filePath := filepath.Join(dir, "digest.py")
	if err := os.WriteFile(filePath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	p := NewPythonParser()
	analyses, err := p.ParseDirectory(dir, "myproject")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis, got %d", len(analyses))
	}

	analysis := analyses[0]
	if analysis.ImportedTypes["sha256"] {
		t.Fatal("expected sha256 import not to be classified as a type")
	}

	for _, fn := range analysis.Functions {
		if fn.ID.Name != "digest" || fn.ID.Type != "" {
			continue
		}
		for _, call := range fn.Calls {
			if call.Callee.Package == "hashlib" && call.Callee.Name == "sha256" {
				if call.Callee.Type != "" {
					t.Fatalf("sha256 call type = %q, want empty", call.Callee.Type)
				}
				return
			}
		}
		t.Fatal("expected digest to contain hashlib.sha256 call")
	}

	t.Fatal("expected digest function analysis")
}

func TestPythonParser_IncludeTestsIncludesTestFilesAndDirs(t *testing.T) {
	p := NewPythonParser(WithIncludeTests(true))
	dir := t.TempDir()

	testDir := filepath.Join(dir, "tests")
	if err := os.MkdirAll(testDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(testDir, "test_crypto.py"), []byte("def test_encrypt():\n    return None\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	analyses, err := p.ParseDirectory(testDir, "myproject.tests")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis (test file included), got %d", len(analyses))
	}
	if p.SkipDirs()["tests"] {
		t.Fatal("expected tests dir not to be skipped when includeTests is enabled")
	}
}

func TestPythonParser_SkipTestFiles(t *testing.T) {
	dir := t.TempDir()

	// Regular file
	os.WriteFile(filepath.Join(dir, "crypto.py"), []byte("def foo(): pass"), 0o644)
	// Test files — should be skipped
	os.WriteFile(filepath.Join(dir, "test_crypto.py"), []byte("def test_foo(): pass"), 0o644)
	os.WriteFile(filepath.Join(dir, "crypto_test.py"), []byte("def test_bar(): pass"), 0o644)

	p := NewPythonParser()
	analyses, err := p.ParseDirectory(dir, "test_pkg")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}

	if len(analyses) != 1 {
		t.Errorf("expected 1 analysis (only crypto.py), got %d", len(analyses))
	}
}

func TestPythonParser_DunderMethodSkip(t *testing.T) {
	src := `class MyClass:
    def __init__(self, x):
        self.x = x

    def __repr__(self):
        return f"MyClass({self.x})"

    def __str__(self):
        return str(self.x)

    def real_method(self):
        return self.x
`
	dir := t.TempDir()
	filePath := filepath.Join(dir, "myclass.py")
	if err := os.WriteFile(filePath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	p := NewPythonParser()
	analyses, err := p.ParseDirectory(dir, "myproject")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) == 0 {
		t.Fatalf("expected at least 1 analysis from ParseDirectory(%q), got 0", dir)
	}

	analysis := analyses[0]

	// Should have __init__ (as <init>) and real_method, but NOT __repr__ or __str__
	funcNames := make(map[string]bool)
	for _, fn := range analysis.Functions {
		funcNames[fn.ID.Name] = true
	}

	if !funcNames["<init>"] {
		t.Error("missing __init__ (mapped to <init>)")
	}
	if !funcNames["real_method"] {
		t.Error("missing real_method")
	}
	if funcNames["__repr__"] {
		t.Error("__repr__ should be skipped")
	}
	if funcNames["__str__"] {
		t.Error("__str__ should be skipped")
	}
}

// TestPythonParser_FunctionCallCarriesNonZeroColumns verifies that FunctionCall
// structs produced by the Python parser populate StartCol and EndCol (parity with
// the Java parser). Zero values indicate the column-aware path was skipped, which
// would cause column-based disambiguation in annotate_supporting.go to fall back
// to line-only matching.
func TestPythonParser_FunctionCallCarriesNonZeroColumns(t *testing.T) {
	src := `import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher

def encrypt(key, data):
    digest = hashlib.sha256(key)
    cipher = Cipher(key, None)
    return cipher.encryptor()
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "col_check.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	p := NewPythonParser()
	analyses, err := p.ParseDirectory(dir, "mypkg")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) == 0 {
		t.Fatal("expected at least one analysis")
	}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				if call.StartCol == 0 || call.EndCol == 0 {
					t.Errorf("call %s.%s at line %d has zero StartCol=%d or EndCol=%d; Python parser must populate column spans",
						call.Callee.Package, call.Callee.Name, call.Line, call.StartCol, call.EndCol)
				}
				if call.StartCol > call.EndCol {
					t.Errorf("call %s.%s at line %d: StartCol=%d > EndCol=%d (invalid span)",
						call.Callee.Package, call.Callee.Name, call.Line, call.StartCol, call.EndCol)
				}
			}
		}
	}
}

// TestPythonParser_ReceiverVar_Parameter verifies that a function/method
// parameter name resolves as ReceiverVar on a call made through it, mirroring
// Java's collectParameterTypes/collectParameterOrigins coverage.
func TestPythonParser_ReceiverVar_Parameter(t *testing.T) {
	src := `def encrypt(cipher):
    cipher.update(data)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "encrypt")
	if fn == nil {
		t.Fatal("encrypt function not found")
	}

	call := findPythonCallByMethod(fn, "update")
	if call == nil {
		t.Fatal("update call not found")
	}
	if call.ReceiverVar != "cipher" {
		t.Errorf("update ReceiverVar = %q, want %q", call.ReceiverVar, "cipher")
	}
}

// TestPythonParser_ReceiverVar_WithAs verifies that a `with ... as X` alias
// binds X as a receiver identity.
func TestPythonParser_ReceiverVar_WithAs(t *testing.T) {
	src := `def use_cipher():
    with Cipher() as c:
        c.encrypt(data)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "use_cipher")
	if fn == nil {
		t.Fatal("use_cipher function not found")
	}
	call := findPythonCallByMethod(fn, "encrypt")
	if call == nil {
		t.Fatal("encrypt call not found")
	}
	if call.ReceiverVar != "c" {
		t.Errorf("encrypt ReceiverVar = %q, want %q", call.ReceiverVar, "c")
	}
}

// TestPythonParser_ReceiverVar_AsyncWithAs verifies that `async with ... as X`
// binds X exactly like the synchronous form (async is not a distinct grammar
// node in this tree-sitter grammar).
func TestPythonParser_ReceiverVar_AsyncWithAs(t *testing.T) {
	src := `async def use_cipher():
    async with AsyncCipher() as c:
        await c.encrypt(data)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "use_cipher")
	if fn == nil {
		t.Fatal("use_cipher function not found")
	}
	call := findPythonCallByMethod(fn, "encrypt")
	if call == nil {
		t.Fatal("encrypt call not found")
	}
	if call.ReceiverVar != "c" {
		t.Errorf("encrypt ReceiverVar = %q, want %q", call.ReceiverVar, "c")
	}
}

// TestPythonParser_ReceiverVar_ForIn verifies that `for X in ...:` binds X as
// a receiver identity for calls made through it in the loop body.
func TestPythonParser_ReceiverVar_ForIn(t *testing.T) {
	src := `def derive_all(keys):
    for k in keys:
        k.derive(salt)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "derive_all")
	if fn == nil {
		t.Fatal("derive_all function not found")
	}
	call := findPythonCallByMethod(fn, "derive")
	if call == nil {
		t.Fatal("derive call not found")
	}
	if call.ReceiverVar != "k" {
		t.Errorf("derive ReceiverVar = %q, want %q", call.ReceiverVar, "k")
	}
}

// TestPythonParser_ReceiverVar_AsyncForIn verifies that `async for X in ...:`
// binds X exactly like the synchronous form.
func TestPythonParser_ReceiverVar_AsyncForIn(t *testing.T) {
	src := `async def derive_all(akeys):
    async for k in akeys:
        await k.derive(salt)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "derive_all")
	if fn == nil {
		t.Fatal("derive_all function not found")
	}
	call := findPythonCallByMethod(fn, "derive")
	if call == nil {
		t.Fatal("derive call not found")
	}
	if call.ReceiverVar != "k" {
		t.Errorf("derive ReceiverVar = %q, want %q", call.ReceiverVar, "k")
	}
}

// TestPythonParser_ReceiverVar_ExceptAs verifies that `except ... as X` binds
// X as a receiver identity for calls made through it in the handler body,
// mirroring the with...as binder (both use the same as_pattern grammar node).
func TestPythonParser_ReceiverVar_ExceptAs(t *testing.T) {
	src := `def handle():
    try:
        risky()
    except CryptoError as e:
        e.close()
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "handle")
	if fn == nil {
		t.Fatal("handle function not found")
	}
	call := findPythonCallByMethod(fn, "close")
	if call == nil {
		t.Fatal("close call not found")
	}
	if call.ReceiverVar != "e" {
		t.Errorf("close ReceiverVar = %q, want %q (except...as must resolve as a known local)", call.ReceiverVar, "e")
	}
}

// TestPythonParser_ReceiverVar_Walrus verifies that a walrus (`:=`) binding
// resolves as a receiver identity for calls made in the enclosing scope.
func TestPythonParser_ReceiverVar_Walrus(t *testing.T) {
	src := `def maybe_encrypt(data):
    if (c := Cipher()) is not None:
        c.encrypt(data)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "maybe_encrypt")
	if fn == nil {
		t.Fatal("maybe_encrypt function not found")
	}
	call := findPythonCallByMethod(fn, "encrypt")
	if call == nil {
		t.Fatal("encrypt call not found")
	}
	if call.ReceiverVar != "c" {
		t.Errorf("encrypt ReceiverVar = %q, want %q", call.ReceiverVar, "c")
	}
}

// TestPythonParser_ReceiverVar_TupleUnpacking verifies that every target of a
// tuple/star-unpacking assignment (`a, *rest = ...`) is registered as a known
// local, so a call made through any of them resolves ReceiverVar.
func TestPythonParser_ReceiverVar_TupleUnpacking(t *testing.T) {
	src := `def make_first(rest_count):
    a, *rest = make_ciphers()
    a.encrypt(data)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "make_first")
	if fn == nil {
		t.Fatal("make_first function not found")
	}
	call := findPythonCallByMethod(fn, "encrypt")
	if call == nil {
		t.Fatal("encrypt call not found")
	}
	if call.ReceiverVar != "a" {
		t.Errorf("encrypt ReceiverVar = %q, want %q", call.ReceiverVar, "a")
	}
}

// TestPythonParser_ReceiverVar_ComprehensionTarget verifies that a
// comprehension's `for X in ...` target resolves as a receiver identity for
// calls made INSIDE the comprehension body, but does NOT leak outside the
// comprehension's scope: a same-named bare call elsewhere in the function
// (with no other binder for that name) must not be attributed to it.
func TestPythonParser_ReceiverVar_ComprehensionTarget(t *testing.T) {
	src := `def encrypt_all(ciphers):
    results = [c.encrypt(x) for c in ciphers]
    c.unrelated()
    return results
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "encrypt_all")
	if fn == nil {
		t.Fatal("encrypt_all function not found")
	}

	inside := findPythonCallByMethod(fn, "encrypt")
	if inside == nil {
		t.Fatal("encrypt call (inside comprehension) not found")
	}
	if inside.ReceiverVar != "c" {
		t.Errorf("encrypt ReceiverVar = %q, want %q (comprehension target must resolve inside its own scope)", inside.ReceiverVar, "c")
	}

	outside := findPythonCallByMethod(fn, "unrelated")
	if outside == nil {
		t.Fatal("unrelated call (outside comprehension) not found")
	}
	if outside.ReceiverVar != "" {
		t.Errorf("unrelated ReceiverVar = %q, want empty (comprehension target must not leak outside its scope)", outside.ReceiverVar)
	}
}

// TestPythonParser_SelfAttr_CrossMethodProvenance verifies that a
// `self.attr = ...` assignment in one method and a `self.attr.method()` call
// in a sibling method resolve to the same stable receiver identity.
func TestPythonParser_SelfAttr_CrossMethodProvenance(t *testing.T) {
	src := `from crypto import Cipher

class Worker:
    def __init__(self):
        self.cipher = Cipher()

    def run(self, data):
        self.cipher.encrypt(data)
`
	fns := parsePythonInline(t, src)

	initFn := findPythonFuncByName(fns, constructorMethodName)
	if initFn == nil {
		t.Fatal("<init> method not found")
	}
	ctorCall := findPythonCallByMethod(initFn, constructorMethodName)
	if ctorCall == nil {
		t.Fatal("Cipher constructor call not found in <init>")
	}
	if ctorCall.AssignedVar != "self.cipher" {
		t.Errorf("Cipher() AssignedVar = %q, want %q", ctorCall.AssignedVar, "self.cipher")
	}

	runFn := findPythonFuncByName(fns, "run")
	if runFn == nil {
		t.Fatal("run method not found")
	}
	encryptCall := findPythonCallByMethod(runFn, "encrypt")
	if encryptCall == nil {
		t.Fatal("encrypt call not found in run")
	}
	if encryptCall.ReceiverVar != "self.cipher" {
		t.Errorf("encrypt ReceiverVar = %q, want %q (must share identity with <init>'s assignment)", encryptCall.ReceiverVar, "self.cipher")
	}
}

// TestPythonParser_ClsAttr_ClassmethodProvenance verifies that a
// `cls.attr = ...` assignment made in a classmethod resolves using the SAME
// class-scoped identity as a `self.attr` binding would (cls canonicalizes to
// self).
func TestPythonParser_ClsAttr_ClassmethodProvenance(t *testing.T) {
	src := `from crypto import Cipher

class Worker:
    @classmethod
    def setup(cls):
        cls.cipher = Cipher()

    def run(self, data):
        self.cipher.encrypt(data)
`
	fns := parsePythonInline(t, src)

	setupFn := findPythonFuncByName(fns, "setup")
	if setupFn == nil {
		t.Fatal("setup classmethod not found")
	}
	ctorCall := findPythonCallByMethod(setupFn, constructorMethodName)
	if ctorCall == nil {
		t.Fatal("Cipher constructor call not found in setup")
	}
	if ctorCall.AssignedVar != "self.cipher" {
		t.Errorf("Cipher() AssignedVar = %q, want %q (cls.cipher canonicalizes to self.cipher)", ctorCall.AssignedVar, "self.cipher")
	}

	runFn := findPythonFuncByName(fns, "run")
	if runFn == nil {
		t.Fatal("run method not found")
	}
	encryptCall := findPythonCallByMethod(runFn, "encrypt")
	if encryptCall == nil {
		t.Fatal("encrypt call not found in run")
	}
	if encryptCall.ReceiverVar != "self.cipher" {
		t.Errorf("encrypt ReceiverVar = %q, want %q (must share identity with setup's cls.cipher assignment)", encryptCall.ReceiverVar, "self.cipher")
	}
}

// TestPythonParser_SelfAttr_NoInheritance verifies that a subclass method
// referencing `self.attr` does NOT resolve to a base class's assignment of
// that attribute — inheritance is not followed (only the literal class body
// being parsed is scanned for attribute assignments).
func TestPythonParser_SelfAttr_NoInheritance(t *testing.T) {
	src := `from crypto import Cipher

class Base:
    def __init__(self):
        self.cipher = Cipher()

class Sub(Base):
    def run(self, data):
        self.cipher.encrypt(data)
`
	fns := parsePythonInline(t, src)

	var runFn *FunctionDecl
	for i := range fns {
		if fns[i].ID.Name == "run" && fns[i].ID.Type == "Sub" {
			runFn = &fns[i]
			break
		}
	}
	if runFn == nil {
		t.Fatal("Sub.run method not found")
	}
	encryptCall := findPythonCallByMethod(runFn, "encrypt")
	if encryptCall == nil {
		t.Fatal("encrypt call not found in Sub.run")
	}
	if encryptCall.ReceiverVar == "self.cipher" {
		t.Errorf("encrypt ReceiverVar = %q; must NOT resolve to the base class's self.cipher assignment (inheritance is not followed)", encryptCall.ReceiverVar)
	}
}

// TestPythonParser_SyntheticEntryPoint_ModuleLevel verifies that a
// module-level crypto call (outside any function/class) gets a synthetic
// `<module>` FunctionDecl, keyed by the module's own dotted path so sibling
// files in one package never collide on the `<module>` key.
func TestPythonParser_SyntheticEntryPoint_ModuleLevel(t *testing.T) {
	src := `from crypto import Cipher

cipher = Cipher()
`
	fns := parsePythonInline(t, src)

	var module *FunctionDecl
	for i := range fns {
		if fns[i].ID.Name == moduleInitMethodName {
			module = &fns[i]
			break
		}
	}
	if module == nil {
		t.Fatal("<module> synthetic decl not found")
	}
	if module.ID.Type != "" {
		t.Errorf("<module> ID.Type = %q, want empty", module.ID.Type)
	}
	const wantPackage = "mypkg.src" // parsePythonInline writes to dir/src.py under packagePath "mypkg"
	if module.ID.Package != wantPackage {
		t.Errorf("<module> ID.Package = %q, want %q (module dotted path, not bare package path)", module.ID.Package, wantPackage)
	}
	ctorCall := findPythonCallByMethod(module, constructorMethodName)
	if ctorCall == nil {
		t.Fatal("Cipher() constructor call not found under <module>")
	}
}

// TestPythonParser_SyntheticEntryPoint_ClassBody verifies that a class-body
// statement crypto call (outside any method) gets a synthetic `<clinit>`
// FunctionDecl, reusing Java's synthetic name for cross-language consistency.
func TestPythonParser_SyntheticEntryPoint_ClassBody(t *testing.T) {
	src := `from crypto import Cipher

class Foo:
    default_cipher = Cipher()
`
	fns := parsePythonInline(t, src)

	var clinit *FunctionDecl
	for i := range fns {
		if fns[i].ID.Name == clinitMethodName && fns[i].ID.Type == "Foo" {
			clinit = &fns[i]
			break
		}
	}
	if clinit == nil {
		t.Fatal("<clinit> synthetic decl not found for class Foo")
	}
	ctorCall := findPythonCallByMethod(clinit, constructorMethodName)
	if ctorCall == nil {
		t.Fatal("Cipher() constructor call not found under <clinit>")
	}
}

// TestPythonParser_SyntheticEntryPoint_EmptyBodyOmitted verifies that a
// module/class with no direct-body calls gets NO synthetic decl at all —
// the empty-body guard that keeps TestPythonE2E_Bcrypt_ConsumerScan_NoSynthesis
// at zero.
func TestPythonParser_SyntheticEntryPoint_EmptyBodyOmitted(t *testing.T) {
	src := `import os

X = 5

class Foo:
    x: int
`
	fns := parsePythonInline(t, src)

	for i := range fns {
		if fns[i].ID.Name == moduleInitMethodName {
			t.Errorf("unexpected <module> decl for a call-free module body: %+v", fns[i].ID)
		}
		if fns[i].ID.Name == clinitMethodName {
			t.Errorf("unexpected <clinit> decl for a call-free class body: %+v", fns[i].ID)
		}
	}
}

// TestPythonParser_SyntheticEntryPoint_NoNestedScopeLeak verifies that the
// module-level <module> entry point's receiver-identity table does NOT
// include a name bound only inside a nested function, and that a class's
// <clinit> entry point's receiver-identity table does NOT include a name
// bound only inside one of that class's methods (F3). Before this fix, both
// synthetic decls' locals were built via an UNPRUNED walk of the ENTIRE
// module/class body (including every nested function/method), so `c` (bound
// only inside `def f()`) and `m` (bound only inside `Foo.method()`) leaked
// into the enclosing synthetic entry point's locals table, making a
// same-named module-level/class-body-level bare identifier incorrectly
// resolve as a receiver.
func TestPythonParser_SyntheticEntryPoint_NoNestedScopeLeak(t *testing.T) {
	t.Run("module level", func(t *testing.T) {
		src := `def f():
    c = Cipher()
    c.encrypt(b"y")

c.encrypt(b"x")
`
		fns := parsePythonInline(t, src)
		fn := findPythonFuncByName(fns, moduleInitMethodName)
		if fn == nil {
			t.Fatal("<module> synthetic entry point not found")
		}
		call := findPythonCallByMethod(fn, "encrypt")
		if call == nil {
			t.Fatal("module-level encrypt call not found")
		}
		if call.ReceiverVar != "" {
			t.Errorf("module-level c.encrypt ReceiverVar = %q, want empty (c is bound only inside def f(), not at module level)", call.ReceiverVar)
		}
	})

	t.Run("class body level", func(t *testing.T) {
		src := `class Foo:
    def method(self):
        m = Cipher()
        m.encrypt(b"y")

    m.encrypt(b"x")
`
		fns := parsePythonInline(t, src)
		fn := findPythonFuncByName(fns, clinitMethodName)
		if fn == nil {
			t.Fatal("<clinit> synthetic entry point not found")
		}
		call := findPythonCallByMethod(fn, "encrypt")
		if call == nil {
			t.Fatal("class-body-level encrypt call not found")
		}
		if call.ReceiverVar != "" {
			t.Errorf("class-body m.encrypt ReceiverVar = %q, want empty (m is bound only inside Foo.method(), not directly in the class body)", call.ReceiverVar)
		}
	})
}

// TestPythonParser_Import_TryExcept verifies that an `import` statement
// nested inside a `try`/`except ImportError` block is discovered (the parser
// recurses into nested blocks, not only direct file-root children), and that
// when both branches bind the same name, the FIRST binding in document order
// wins — the later `import crypto` must not overwrite the earlier
// `import fastcrypto as crypto`.
func TestPythonParser_Import_TryExcept(t *testing.T) {
	src := `try:
    import fastcrypto as crypto
except ImportError:
    import crypto
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mod.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	p := NewPythonParser()
	analyses, err := p.ParseDirectory(dir, "mypkg")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis, got %d", len(analyses))
	}
	if got := analyses[0].Imports["crypto"]; got != "fastcrypto" {
		t.Errorf(`Imports["crypto"] = %q, want %q (first binding in document order wins)`, got, "fastcrypto")
	}
}

// TestPythonParser_Import_TypeChecking verifies that an import nested inside
// an `if TYPE_CHECKING:` block is discovered.
func TestPythonParser_Import_TypeChecking(t *testing.T) {
	src := `if TYPE_CHECKING:
    from mypkg import Cipher
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mod.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	p := NewPythonParser()
	analyses, err := p.ParseDirectory(dir, "consumer")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis, got %d", len(analyses))
	}
	if got := analyses[0].Imports["Cipher"]; got != "mypkg" {
		t.Errorf(`Imports["Cipher"] = %q, want %q`, got, "mypkg")
	}
}

// TestPythonParser_Import_FunctionLocal verifies that an import nested inside
// a function body is discovered.
func TestPythonParser_Import_FunctionLocal(t *testing.T) {
	src := `def f():
    import hashlib
    hashlib.sha256()
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mod.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	p := NewPythonParser()
	analyses, err := p.ParseDirectory(dir, "mypkg")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis, got %d", len(analyses))
	}
	if got := analyses[0].Imports["hashlib"]; got != "hashlib" {
		t.Errorf(`Imports["hashlib"] = %q, want %q`, got, "hashlib")
	}
}

// TestPythonParser_Import_RelativeSingleDot verifies that `from . import x`
// in a file at pkg/mod.py resolves x's module path to "pkg" (the current
// package), not an empty/absolute path.
func TestPythonParser_Import_RelativeSingleDot(t *testing.T) {
	dir := t.TempDir()
	pkgDir := filepath.Join(dir, "pkg")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := "from . import helper\n"
	if err := os.WriteFile(filepath.Join(pkgDir, "mod.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	p := NewPythonParser()
	analyses, err := p.ParseDirectory(pkgDir, "pkg")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis, got %d", len(analyses))
	}
	if got := analyses[0].Imports["helper"]; got != "pkg" {
		t.Errorf(`Imports["helper"] = %q, want %q (relative to current package)`, got, "pkg")
	}
}

// TestPythonParser_Import_RelativeDoubleDot verifies that
// `from ..other import Bar` in a file at pkg/sub/mod.py resolves Bar's module
// path to "pkg.other" (one level above pkg.sub), not "other" as an absolute
// top-level module.
func TestPythonParser_Import_RelativeDoubleDot(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "pkg", "sub")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := "from ..other import Bar\n"
	if err := os.WriteFile(filepath.Join(subDir, "mod.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	p := NewPythonParser()
	analyses, err := p.ParseDirectory(subDir, "pkg.sub")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis, got %d", len(analyses))
	}
	if got := analyses[0].Imports["Bar"]; got != "pkg.other" {
		t.Errorf(`Imports["Bar"] = %q, want %q (one level above pkg.sub)`, got, "pkg.other")
	}
}

func TestPythonParser_ParseDirectoryIncludesPyiStubs(t *testing.T) {
	dir := t.TempDir()
	stub := `def gensalt(rounds: int = 12, prefix: bytes = b"2b") -> bytes: ...
def hashpw(password: bytes, salt: bytes) -> bytes: ...
def checkpw(password: bytes, hashed_password: bytes) -> bool: ...
`
	if err := os.WriteFile(filepath.Join(dir, "__init__.pyi"), []byte(stub), 0o600); err != nil {
		t.Fatalf("write stub: %v", err)
	}

	parser := NewPythonParser()
	analyses, err := parser.ParseDirectory(dir, "bcrypt")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}

	seen := map[string]bool{}
	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			seen[fn.ID.String()] = true
		}
	}
	for _, want := range []string{"bcrypt.hashpw", "bcrypt.checkpw", "bcrypt.gensalt"} {
		if !seen[want] {
			t.Fatalf("missing stub function %s; saw %#v", want, seen)
		}
	}
}

// TestPythonParser_ReceiverVar_UpperCaseLocal verifies that a module-level
// UPPER_CASE local (a constant-style name that also happens to satisfy the
// CapitalCase-type-name heuristic) still resolves as a receiver when it is a
// known local binding. receiverIdentity's locals check must run before the
// CapitalCase heuristic disqualifies it, since `looksLikePythonTypeName` only
// inspects the first rune and cannot distinguish `HASHER` (a local instance)
// from `Cipher` (a class reference) by spelling alone.
func TestPythonParser_ReceiverVar_UpperCaseLocal(t *testing.T) {
	src := `HASHER = Cipher()
HASHER.update(b"x")
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, moduleInitMethodName)
	if fn == nil {
		t.Fatal("<module> synthetic entry point not found")
	}
	call := findPythonCallByMethod(fn, "update")
	if call == nil {
		t.Fatal("update call not found")
	}
	if call.ReceiverVar != "HASHER" {
		t.Errorf("module-level HASHER.update ReceiverVar = %q, want %q", call.ReceiverVar, "HASHER")
	}
}

// TestPythonParser_ReceiverVar_UpperCaseLocal_InFunction is the in-function
// variant of the module-level case above: an UPPER_CASE local assigned and
// used inside a function body must still resolve as a receiver.
func TestPythonParser_ReceiverVar_UpperCaseLocal_InFunction(t *testing.T) {
	src := `def run():
    HASHER = Cipher()
    HASHER.update(b"x")
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "run")
	if fn == nil {
		t.Fatal("run function not found")
	}
	call := findPythonCallByMethod(fn, "update")
	if call == nil {
		t.Fatal("update call not found")
	}
	if call.ReceiverVar != "HASHER" {
		t.Errorf("HASHER.update ReceiverVar = %q, want %q", call.ReceiverVar, "HASHER")
	}
}

// TestPythonParser_Import_DottedPlainImport verifies that `import a.b.c`
// binds Imports["a"] = "a" (the top-level module name, not the full dotted
// path), so a chained-attribute call `a.b.c.foo()` resolves through
// resolveImportedCall's chained-attribute path to the full "a.b.c.foo" FQN
// instead of double-appending the dotted suffix ("a.b.c.b.c.foo"). It also
// verifies a later `import a.d` does not get hidden by first-wins, since it
// binds a distinct top-level name ("a" is shared, but resolution now depends
// on the chained-attribute path rather than a single flattened key).
func TestPythonParser_Import_DottedPlainImport(t *testing.T) {
	src := `import a.b.c

def run():
    a.b.c.foo()
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "run")
	if fn == nil {
		t.Fatal("run function not found")
	}
	call := findPythonCallByMethod(fn, "foo")
	if call == nil {
		t.Fatal("foo call not found")
	}
	want := FunctionID{Package: "a.b.c", Name: "foo"}
	if call.Callee != want {
		t.Errorf("a.b.c.foo() callee = %+v, want %+v", call.Callee, want)
	}
}

// TestPythonParser_Import_DottedPlainImport_MultipleTopLevelSiblings
// verifies that `import a.b.c` followed by `import a.d` records BOTH dotted
// imports under distinct import-map behavior: `a.b.c.foo()` still resolves
// via a.b.c (not truncated to "a"), demonstrating first-wins on the "a" key
// does not silently discard the second, differently-rooted dotted import's
// own resolution path.
func TestPythonParser_Import_DottedPlainImport_MultipleTopLevelSiblings(t *testing.T) {
	src := `import a.b.c
import a.d

def run():
    a.b.c.foo()
    a.d.bar()
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "run")
	if fn == nil {
		t.Fatal("run function not found")
	}
	fooCall := findPythonCallByMethod(fn, "foo")
	if fooCall == nil {
		t.Fatal("foo call not found")
	}
	if want := (FunctionID{Package: "a.b.c", Name: "foo"}); fooCall.Callee != want {
		t.Errorf("a.b.c.foo() callee = %+v, want %+v", fooCall.Callee, want)
	}
	barCall := findPythonCallByMethod(fn, "bar")
	if barCall == nil {
		t.Fatal("bar call not found")
	}
	if want := (FunctionID{Package: "a.d", Name: "bar"}); barCall.Callee != want {
		t.Errorf("a.d.bar() callee = %+v, want %+v", barCall.Callee, want)
	}
}

// TestPythonModuleDottedPath pins pythonModuleDottedPath's behavior across
// two edge cases: (1) a root-level module (empty packagePath) must yield its
// bare stem, not a leading-dot-prefixed path; (2) a .pyi type-stub module
// must get its own distinct stem, not collapse to the bare package path
// (which would collide with a sibling __init__.py's <module> key).
func TestPythonModuleDottedPath(t *testing.T) {
	tests := []struct {
		name        string
		filePath    string
		packagePath string
		want        string
	}{
		{"regular module with package", "pkg/a.py", "pkg", "pkg.a"},
		{"__init__.py yields bare package path", "pkg/__init__.py", "pkg", "pkg"},
		{"root-level module, empty package path", "a.py", "", "a"},
		{"root-level __init__.py, empty package path", "__init__.py", "", ""},
		{"pyi stub gets a distinct stem from __init__.py", "pkg/foo.pyi", "pkg", "pkg.foo"},
		{"__init__.pyi yields bare package path", "pkg/__init__.pyi", "pkg", "pkg"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pythonModuleDottedPath(tt.filePath, tt.packagePath)
			if got != tt.want {
				t.Errorf("pythonModuleDottedPath(%q, %q) = %q, want %q", tt.filePath, tt.packagePath, got, tt.want)
			}
		})
	}
}

// TestPythonParser_ReceiverVar_ParameterShadowsImport pins current
// precedence (F9): a parameter that shares its name with an imported symbol
// does NOT resolve as a receiver. receiverIdentity checks Imports before
// locals (see TestPythonParser_ModuleCall_NoReceiverVar for the module-level
// case), so the import wins even when the SAME name is ALSO a declared
// parameter — the call still resolves through the import (Callee reflects
// "x.cipher", not a plain same-package call), and ReceiverVar stays empty.
func TestPythonParser_ReceiverVar_ParameterShadowsImport(t *testing.T) {
	src := `from x import cipher

def f(cipher):
    cipher.update(data)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "f")
	if fn == nil {
		t.Fatal("f function not found")
	}
	call := findPythonCallByMethod(fn, "update")
	if call == nil {
		t.Fatal("update call not found")
	}
	if call.ReceiverVar != "" {
		t.Errorf("cipher.update ReceiverVar = %q, want empty (import must outrank the same-named parameter)", call.ReceiverVar)
	}
	want := FunctionID{Package: "x.cipher", Name: "update"}
	if call.Callee != want {
		t.Errorf("cipher.update callee = %+v, want %+v (resolved through the import, not treated as a local receiver call)", call.Callee, want)
	}
}

// TestPythonParser_ReceiverVar_SplatAndDefaultParameters verifies that
// *args/**kwargs splat parameters and a default-valued parameter all
// register as receivers, matching pythonParameterNames' documented coverage
// (F9).
func TestPythonParser_ReceiverVar_SplatAndDefaultParameters(t *testing.T) {
	src := `def f(cipher=None, *args, **kwargs):
    cipher.update(a)
    args.update(b)
    kwargs.update(c)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "f")
	if fn == nil {
		t.Fatal("f function not found")
	}

	byReceiver := make(map[string]bool, len(fn.Calls))
	for i := range fn.Calls {
		if fn.Calls[i].Callee.Name == "update" {
			byReceiver[fn.Calls[i].ReceiverVar] = true
		}
	}

	for _, tt := range []struct {
		name string
		want string
	}{
		{"cipher (default-valued parameter)", "cipher"},
		{"args (*args splat)", "args"},
		{"kwargs (**kwargs splat)", "kwargs"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if !byReceiver[tt.want] {
				t.Fatalf("no update call found with ReceiverVar %q; saw %v", tt.want, byReceiver)
			}
		})
	}
}

// TestPythonParser_ReceiverVar_SelfAttributeChain pins current behavior
// (F9) for a MULTI-LEVEL self attribute chain (`self.a.b.encrypt(...)`,
// as opposed to the single-level `self.attr` this parser resolves via
// pythonSelfOrClsAttr). pythonSelfOrClsAttr explicitly rejects any object
// text containing a further "." after the self/cls prefix, so ReceiverVar
// stays empty for a chain this deep — no receiver identity is fabricated
// for it, and the callee falls back to Type="self.a.b" (the raw object
// text), Package=analysis.PackagePath.
func TestPythonParser_ReceiverVar_SelfAttributeChain(t *testing.T) {
	src := `class Foo:
    def run(self):
        self.a.b.encrypt(data)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "run")
	if fn == nil {
		t.Fatal("run function not found")
	}
	call := findPythonCallByMethod(fn, "encrypt")
	if call == nil {
		t.Fatal("encrypt call not found")
	}
	if call.ReceiverVar != "" {
		t.Errorf("self.a.b.encrypt ReceiverVar = %q, want empty (multi-level self chains are not resolved as a receiver identity)", call.ReceiverVar)
	}
	want := FunctionID{Package: "mypkg", Type: "self.a.b", Name: "encrypt"}
	if call.Callee != want {
		t.Errorf("self.a.b.encrypt callee = %+v, want %+v", call.Callee, want)
	}
}

// TestPythonParser_SelfNamedReceiver_FreeFunction verifies that a
// FREE-function parameter literally named "self" (unusual, but syntactically
// valid Python outside a class) is NOT treated as an instance attribute
// access. `object == pythonSelfObjectName` is checked unconditionally in
// parseAttributeCall (not gated on "are we inside a class"), so
// `self.encrypt(data)` here resolves as a bare same-module call
// (Type == "", Package == analysis.PackagePath) — exactly like a real
// method's `self.foo()` call — never as a class-scoped attribute access or
// a receiver-var call on the "self" parameter (F9).
func TestPythonParser_SelfNamedReceiver_FreeFunction(t *testing.T) {
	src := `def process(self):
    self.encrypt(data)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "process")
	if fn == nil {
		t.Fatal("process function not found")
	}
	call := findPythonCallByMethod(fn, "encrypt")
	if call == nil {
		t.Fatal("encrypt call not found")
	}
	if call.ReceiverVar != "" {
		t.Errorf("self.encrypt ReceiverVar = %q, want empty (self is never a receiver identity, even as a free-function parameter)", call.ReceiverVar)
	}
	if call.Callee.Type != "" {
		t.Errorf("self.encrypt callee.Type = %q, want empty (must not be treated as an instance attribute access)", call.Callee.Type)
	}
	want := FunctionID{Package: "mypkg", Name: "encrypt"}
	if call.Callee != want {
		t.Errorf("self.encrypt callee = %+v, want %+v", call.Callee, want)
	}
}

// TestPythonParser_Parameters_NameAndTypeFromFieldNodes (A2,
// python-parser-parity-2) pins that FunctionDecl.Parameters is populated
// from field nodes for every parameter shape — plain, typed, defaulted,
// typed+defaulted, and splat — with BOTH Name (previously Java-only) and
// Type set, and that anonymous "/"/"*" separator tokens never produce a
// spurious entry.
func TestPythonParser_Parameters_NameAndTypeFromFieldNodes(t *testing.T) {
	src := `def f(a, b: int, c=1, d: int = 2, /, e=3, *args, **kwargs):
    pass
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "f")
	if fn == nil {
		t.Fatal("f function not found")
	}
	want := []FunctionParameter{
		{Name: "a"},
		{Name: "b", Type: "int"},
		{Name: "c"},
		{Name: "d", Type: "int"},
		{Name: "e"},
		{Name: "args"},
		{Name: "kwargs"},
	}
	if len(fn.Parameters) != len(want) {
		t.Fatalf("Parameters = %+v (%d entries), want %d entries: %+v", fn.Parameters, len(fn.Parameters), len(want), want)
	}
	for i := range want {
		got := fn.Parameters[i]
		if got.Name != want[i].Name || got.Type != want[i].Type {
			t.Errorf("Parameters[%d] = {Name:%q Type:%q}, want {Name:%q Type:%q}", i, got.Name, got.Type, want[i].Name, want[i].Type)
		}
	}
}

// TestPythonParser_Visibility_Underscore (row 18, python-parser-parity-2)
// pins that a single-leading-underscore name resolves to VisibilityProtected.
func TestPythonParser_Visibility_Underscore(t *testing.T) {
	src := `def _internal_helper(x):
    return x
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "_internal_helper")
	if fn == nil {
		t.Fatal("_internal_helper function not found")
	}
	if fn.Visibility != VisibilityProtected {
		t.Errorf("Visibility = %q, want %q", fn.Visibility, VisibilityProtected)
	}
}

// TestPythonParser_Visibility_DoubleUnderscore pins that a double-leading-
// underscore, non-dunder name (name-mangled in real Python) resolves to
// VisibilityPrivate.
func TestPythonParser_Visibility_DoubleUnderscore(t *testing.T) {
	src := `class Vault:
    def __mangled_helper(self):
        return self
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "__mangled_helper")
	if fn == nil {
		t.Fatal("__mangled_helper method not found")
	}
	if fn.Visibility != VisibilityPrivate {
		t.Errorf("Visibility = %q, want %q", fn.Visibility, VisibilityPrivate)
	}
}

// TestPythonParser_Visibility_Dunder pins that a dunder name resolves to
// VisibilityPublic. __init__ is the only dunder method parseFunctionDef
// ever turns into a FunctionDecl (every other dunder is skipped outright),
// so it is the only reachable case for this rule; its Visibility is
// computed from the SOURCE name "__init__", before the <init> rename.
func TestPythonParser_Visibility_Dunder(t *testing.T) {
	src := `class Cipher:
    def __init__(self, key):
        self.key = key
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, constructorMethodName)
	if fn == nil {
		t.Fatal("<init> method not found")
	}
	if fn.Visibility != VisibilityPublic {
		t.Errorf("Visibility = %q, want %q", fn.Visibility, VisibilityPublic)
	}
}

// TestPythonParser_Visibility_OwnerVisibility pins that OwnerVisibility is
// derived from the enclosing class's OWN name via the same rule, and stays
// empty for a module-level function (Python has no package-private
// concept, so a module-level function gets Visibility only — matching
// Java's package-private-vs-absent distinction).
func TestPythonParser_Visibility_OwnerVisibility(t *testing.T) {
	src := `class _InternalHelper:
    def run(self):
        return self


def top_level():
    return None
`
	fns := parsePythonInline(t, src)

	method := findPythonFuncByName(fns, "run")
	if method == nil {
		t.Fatal("run method not found")
	}
	if method.OwnerVisibility != VisibilityProtected {
		t.Errorf("run OwnerVisibility = %q, want %q (class _InternalHelper is protected)", method.OwnerVisibility, VisibilityProtected)
	}

	moduleFn := findPythonFuncByName(fns, "top_level")
	if moduleFn == nil {
		t.Fatal("top_level function not found")
	}
	if moduleFn.OwnerVisibility != "" {
		t.Errorf("top_level OwnerVisibility = %q, want empty (module-level function has no owner visibility)", moduleFn.OwnerVisibility)
	}
	if moduleFn.Visibility != VisibilityPublic {
		t.Errorf("top_level Visibility = %q, want %q", moduleFn.Visibility, VisibilityPublic)
	}
}

// TestPythonParser_ArgProvenance_NestedConstructorCalls (row 20,
// python-parser-parity-2) pins the three bounded argument-provenance
// shapes: a nested call (recursive CALL_RESULT, callee resolved through
// the same parseCallExpr path), a bare identifier bound to a module-level
// integer constant (VARIABLE wrapping VALUE), and a literal (VALUE). A
// bare identifier that is NOT a module-level constant emits nothing.
func TestPythonParser_ArgProvenance_NestedConstructorCalls(t *testing.T) {
	src := `from crypto import Cipher

KEY_LEN = 32


def build(password, salt):
    return derive(Cipher(salt), KEY_LEN, 7, "static", salt)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "build")
	if fn == nil {
		t.Fatal("build function not found")
	}
	call := findPythonCallByMethod(fn, "derive")
	if call == nil {
		t.Fatal("derive call not found")
	}
	if len(call.Arguments) != 5 {
		t.Fatalf("Arguments = %v (%d), want 5", call.Arguments, len(call.Arguments))
	}
	if len(call.ArgumentSources) != 5 {
		t.Fatalf("ArgumentSources length = %d, want 5 (index-parallel to Arguments)", len(call.ArgumentSources))
	}

	// Arg 0: Cipher(salt) — nested call, CALL_RESULT with a resolved CallTarget.
	arg0 := call.ArgumentSources[0]
	if len(arg0) != 1 || arg0[0].Type != "CALL_RESULT" {
		t.Fatalf("ArgumentSources[0] = %+v, want single CALL_RESULT node", arg0)
	}
	if arg0[0].CallTarget == nil || arg0[0].CallTarget.Type != "Cipher" || arg0[0].CallTarget.Name != constructorMethodName {
		t.Errorf("ArgumentSources[0].CallTarget = %+v, want Cipher.<init>", arg0[0].CallTarget)
	}
	if arg0[0].Location == nil || arg0[0].Location.Line != call.Line {
		t.Errorf("ArgumentSources[0].Location = %+v, want Line %d", arg0[0].Location, call.Line)
	}

	// Arg 1: KEY_LEN — bare identifier bound to a module-level int constant.
	arg1 := call.ArgumentSources[1]
	if len(arg1) != 1 || arg1[0].Type != "VARIABLE" || arg1[0].Name != "KEY_LEN" {
		t.Fatalf("ArgumentSources[1] = %+v, want single VARIABLE node named KEY_LEN", arg1)
	}
	if len(arg1[0].SourceNodes) != 1 || arg1[0].SourceNodes[0].Type != "VALUE" || arg1[0].SourceNodes[0].Value != "32" {
		t.Errorf("ArgumentSources[1].SourceNodes = %+v, want single VALUE \"32\"", arg1[0].SourceNodes)
	}

	// Arg 2: 7 — integer literal.
	arg2 := call.ArgumentSources[2]
	if len(arg2) != 1 || arg2[0].Type != "VALUE" || arg2[0].Value != "7" {
		t.Errorf("ArgumentSources[2] = %+v, want single VALUE \"7\"", arg2)
	}

	// Arg 3: "static" — string literal (raw text, quotes included).
	arg3 := call.ArgumentSources[3]
	if len(arg3) != 1 || arg3[0].Type != "VALUE" || arg3[0].Value != `"static"` {
		t.Errorf(`ArgumentSources[3] = %+v, want single VALUE "\"static\""`, arg3)
	}

	// Arg 4: salt — bare identifier, NOT a module-level constant: no fabrication.
	arg4 := call.ArgumentSources[4]
	if arg4 != nil {
		t.Errorf("ArgumentSources[4] = %+v, want nil (salt is a parameter, not a module-level constant)", arg4)
	}
}

// TestPythonParser_Decorator_StaticMethodNoReceiver (row 8,
// python-parser-parity-2) pins that a @staticmethod's parameter 0, even
// when literally named "self", is treated as an ordinary local — never an
// implicit instance receiver refusal.
func TestPythonParser_Decorator_StaticMethodNoReceiver(t *testing.T) {
	src := `class KeyStore:
    @staticmethod
    def wrap(self, data):
        return self.encrypt(data)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "wrap")
	if fn == nil {
		t.Fatal("wrap method not found")
	}
	call := findPythonCallByMethod(fn, "encrypt")
	if call == nil {
		t.Fatal("encrypt call not found")
	}
	if call.ReceiverVar != pythonSelfObjectName {
		t.Errorf("ReceiverVar = %q, want %q (staticmethod parameter 0 is an ordinary local, even named \"self\")", call.ReceiverVar, pythonSelfObjectName)
	}
	want := FunctionID{Package: "mypkg", Type: pythonSelfObjectName, Name: "encrypt"}
	if call.Callee != want {
		t.Errorf("Callee = %+v, want %+v", call.Callee, want)
	}
}

// TestPythonParser_Decorator_ClassMethodCls (row 8, python-parser-parity-2)
// pins that a bare "cls.foo()" call resolves as a local method call
// exactly like "self.foo()" (the row's stated precondition), AND that a
// @classmethod whose first parameter is renamed away from "cls" still
// canonicalises the same way.
func TestPythonParser_Decorator_ClassMethodCls(t *testing.T) {
	src := `class KeyStore:
    @classmethod
    def literal(cls, x):
        return cls.build(x)

    @classmethod
    def renamed(klass, x):
        return klass.build(x)
`
	fns := parsePythonInline(t, src)
	want := FunctionID{Package: "mypkg", Name: "build"}

	literal := findPythonFuncByName(fns, "literal")
	if literal == nil {
		t.Fatal("literal method not found")
	}
	literalCall := findPythonCallByMethod(literal, "build")
	if literalCall == nil {
		t.Fatal("cls.build(x) call not found")
	}
	if literalCall.Callee != want {
		t.Errorf("literal cls.build Callee = %+v, want %+v (bare cls resolves like self)", literalCall.Callee, want)
	}
	if literalCall.ReceiverVar != "" {
		t.Errorf("literal cls.build ReceiverVar = %q, want empty (local method call, not a receiver)", literalCall.ReceiverVar)
	}

	renamed := findPythonFuncByName(fns, "renamed")
	if renamed == nil {
		t.Fatal("renamed method not found")
	}
	renamedCall := findPythonCallByMethod(renamed, "build")
	if renamedCall == nil {
		t.Fatal("klass.build(x) call not found")
	}
	if renamedCall.Callee != want {
		t.Errorf("renamed klass.build Callee = %+v, want %+v (renamed classmethod parameter-0 still canonicalises)", renamedCall.Callee, want)
	}
	if renamedCall.ReceiverVar != "" {
		t.Errorf("renamed klass.build ReceiverVar = %q, want empty (local method call, not a receiver)", renamedCall.ReceiverVar)
	}
}

// TestPythonParser_Decorator_PropertyReceiver (row 8,
// python-parser-parity-2) pins that a @property's own name is recorded
// into the enclosing class's attrs, so `self.<property>.method()` resolves
// a bounded self.<property> receiver identity the same way a self.attr
// assignment already does.
func TestPythonParser_Decorator_PropertyReceiver(t *testing.T) {
	src := `class Vault:
    @property
    def cipher(self):
        return self._cipher

    def use(self, data):
        self.cipher.encrypt(data)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "use")
	if fn == nil {
		t.Fatal("use method not found")
	}
	call := findPythonCallByMethod(fn, "encrypt")
	if call == nil {
		t.Fatal("encrypt call not found")
	}
	if call.ReceiverVar != "self.cipher" {
		t.Errorf("ReceiverVar = %q, want %q (property name must be recorded into the class's attrs)", call.ReceiverVar, "self.cipher")
	}
}

// TestPythonParser_Decorator_CustomKeepsIdentity (row 8,
// python-parser-parity-2) pins that a decorator outside the fixed
// staticmethod/classmethod/property set (bare identifier not in the set,
// an attribute, or a call such as @app.route('/x')) leaves the wrapped
// FunctionID unchanged — self.process(...) still resolves as an ordinary
// local method call.
func TestPythonParser_Decorator_CustomKeepsIdentity(t *testing.T) {
	src := `class Handler:
    @app.route('/x')
    def handle(self, request):
        return self.process(request)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "handle")
	if fn == nil {
		t.Fatal("handle method not found")
	}
	call := findPythonCallByMethod(fn, "process")
	if call == nil {
		t.Fatal("process call not found")
	}
	want := FunctionID{Package: "mypkg", Name: "process"}
	if call.Callee != want {
		t.Errorf("Callee = %+v, want %+v (unaffected by a non-fixed-set decorator)", call.Callee, want)
	}
	if call.ReceiverVar != "" {
		t.Errorf("ReceiverVar = %q, want empty", call.ReceiverVar)
	}
}

// TestPythonParser_Super_InitResolvesBase (row 9, python-parser-parity-2)
// pins that super().__init__() resolves against the enclosing class's own
// base, with __init__ mapped to <init> for the callee name.
func TestPythonParser_Super_InitResolvesBase(t *testing.T) {
	src := `class AesCipher(BaseCipher):
    def __init__(self, key):
        super().__init__(key)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, constructorMethodName)
	if fn == nil {
		t.Fatal("<init> method not found")
	}
	// super().__init__(key) is a 2-link fluent chain (super(), matching
	// any other chain root, is ALSO recorded as its own pending call —
	// pre-existing, unrelated to row 9); find the outer .__init__() link.
	call := findPythonCallByMethod(fn, constructorMethodName)
	if call == nil {
		t.Fatalf("super().__init__() call not found among %+v", fn.Calls)
	}
	want := FunctionID{Package: "mypkg", Type: "BaseCipher", Name: constructorMethodName}
	if call.Callee != want {
		t.Errorf("Callee = %+v, want %+v", call.Callee, want)
	}
	if call.ReceiverVar != "" {
		t.Errorf("ReceiverVar = %q, want empty (super() is never a receiver)", call.ReceiverVar)
	}
}

// TestPythonParser_Super_MethodResolvesBase pins that an ordinary
// (non-__init__) super() method call resolves the same way, WITHOUT the
// <init> rename.
func TestPythonParser_Super_MethodResolvesBase(t *testing.T) {
	src := `class AesCipher(BaseCipher):
    def transform(self, data):
        return super().transform(data)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "transform")
	if fn == nil {
		t.Fatal("transform method not found")
	}
	call := findPythonCallByMethod(fn, "transform")
	if call == nil {
		t.Fatal("super().transform(data) call not found")
	}
	want := FunctionID{Package: "mypkg", Type: "BaseCipher", Name: "transform"}
	if call.Callee != want {
		t.Errorf("Callee = %+v, want %+v", call.Callee, want)
	}
}

// TestPythonParser_Super_NeverLocalSuper pins that a class with NO explicit
// base (bases empty) leaves a super() call unresolved — no Type at all,
// never the fabricated literal "super()" text the old fallback path would
// have produced.
func TestPythonParser_Super_NeverLocalSuper(t *testing.T) {
	src := `class Standalone:
    def run(self):
        return super().run()
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "run")
	if fn == nil {
		t.Fatal("run method not found")
	}
	call := findPythonCallByMethod(fn, "run")
	if call == nil {
		t.Fatal("super().run() call not found")
	}
	if call.Callee.Type != "" {
		t.Errorf("Callee.Type = %q, want empty (no base class declared — never fabricated)", call.Callee.Type)
	}
	if call.Callee.Package != "mypkg" || call.Callee.Name != "run" {
		t.Errorf("Callee = %+v, want Package=mypkg Name=run", call.Callee)
	}
	if call.ReceiverVar != "" {
		t.Errorf("ReceiverVar = %q, want empty (super() is never a receiver)", call.ReceiverVar)
	}
}

// TestPythonParser_DynamicDispatch_GetattrLiteral (row 7,
// python-parser-parity-2) pins that `getattr(obj, "encrypt")(data)`, with a
// single-string_content literal method-name argument, rewrites through the
// SAME receiver/callee resolution path as an ordinary `obj.encrypt(data)`
// attribute call.
func TestPythonParser_DynamicDispatch_GetattrLiteral(t *testing.T) {
	src := `def run(obj, data):
    return getattr(obj, "encrypt")(data)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "run")
	if fn == nil {
		t.Fatal("run function not found")
	}
	call := findPythonCallByMethod(fn, "encrypt")
	if call == nil {
		t.Fatalf("getattr(obj, \"encrypt\")(data) call not found among %+v", fn.Calls)
	}
	want := FunctionID{Package: "mypkg", Type: "obj", Name: "encrypt"}
	if call.Callee != want {
		t.Errorf("Callee = %+v, want %+v", call.Callee, want)
	}
	if call.ReceiverVar != "obj" {
		t.Errorf("ReceiverVar = %q, want %q", call.ReceiverVar, "obj")
	}
}

// TestPythonParser_DynamicDispatch_ImportlibLiteral (row 7,
// python-parser-parity-2) pins that a literal-argument
// importlib.import_module(...) registers the import exactly as `import
// hashlib` would, so a LATER bare `hashlib.sha256()` reference resolves.
func TestPythonParser_DynamicDispatch_ImportlibLiteral(t *testing.T) {
	src := `import importlib

def run(data):
    hashlib = importlib.import_module("hashlib")
    return hashlib.sha256(data)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "run")
	if fn == nil {
		t.Fatal("run function not found")
	}
	call := findPythonCallByMethod(fn, "sha256")
	if call == nil {
		t.Fatalf("hashlib.sha256(data) call not found among %+v", fn.Calls)
	}
	want := FunctionID{Package: "hashlib", Name: "sha256"}
	if call.Callee != want {
		t.Errorf("Callee = %+v, want %+v (import_module literal must register the import)", call.Callee, want)
	}
}

// TestPythonParser_DynamicDispatch_NonLiteralNoIdentity (row 7,
// python-parser-parity-2) pins that a non-literal getattr method-name
// argument fabricates NOTHING beyond the pre-existing (row-7-unrelated)
// recording of the inner `getattr(obj, name)` call as its own pending call
// — exactly as before row 7, and unlike the literal case, no additional
// rewritten call is ever added.
func TestPythonParser_DynamicDispatch_NonLiteralNoIdentity(t *testing.T) {
	src := `def run(obj, name, data):
    return getattr(obj, name)(data)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "run")
	if fn == nil {
		t.Fatal("run function not found")
	}
	if len(fn.Calls) != 1 || fn.Calls[0].Callee.Name != "getattr" {
		t.Errorf("Calls = %+v, want exactly one call (the inner getattr(...) itself) and no fabricated identity", fn.Calls)
	}
}

// TestPythonParser_Partial_ResolvesTarget (row 11, python-parser-parity-2)
// pins that `hasher = functools.partial(hashlib.sha256)` followed by
// `hasher(data)` resolves the SECOND call directly to hashlib.sha256 — the
// partial's own resolved target — never to a fabricated "hasher" identity.
func TestPythonParser_Partial_ResolvesTarget(t *testing.T) {
	src := `import functools
import hashlib

def run(data):
    hasher = functools.partial(hashlib.sha256)
    return hasher(data)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "run")
	if fn == nil {
		t.Fatal("run function not found")
	}
	call := findPythonCallByMethod(fn, "sha256")
	if call == nil {
		t.Fatalf("hasher(data) rewritten call not found among %+v", fn.Calls)
	}
	want := FunctionID{Package: "hashlib", Name: "sha256"}
	if call.Callee != want {
		t.Errorf("Callee = %+v, want %+v", call.Callee, want)
	}
}

// TestPythonParser_Call_DunderCall (row 11, python-parser-parity-2) pins
// that `signer = Signer()` followed by `signer(data)` resolves the second
// call to Signer.__call__ when Signer declares its own __call__ method.
func TestPythonParser_Call_DunderCall(t *testing.T) {
	src := `class Signer:
    def __call__(self, data):
        return self.sign(data)

    def sign(self, data):
        return data


def run(data):
    signer = Signer()
    return signer(data)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "run")
	if fn == nil {
		t.Fatal("run function not found")
	}
	call := findPythonCallByMethod(fn, pythonDunderCallMethodName)
	if call == nil {
		t.Fatalf("signer(data) call not found among %+v", fn.Calls)
	}
	want := FunctionID{Package: "mypkg", Type: "Signer", Name: pythonDunderCallMethodName}
	if call.Callee != want {
		t.Errorf("Callee = %+v, want %+v", call.Callee, want)
	}
}

// TestPythonSymbolTable_AllSymbolsResolved (T0.3, python-parser-parity-2)
// pins that every grammar-rule name resolvePythonSymbols maps into
// pythonSymbolTable actually resolves to a non-zero sitter.Symbol against
// the vendored Python grammar. A typo in either the map's key (a rule name
// that does not exist in the grammar) or its target field would otherwise
// silently leave that pythonSyms field at its zero value, matching no real
// node and never firing — invisible until a much harder-to-debug missed
// dispatch bug downstream.
func TestPythonSymbolTable_AllSymbolsResolved(t *testing.T) {
	entries := map[string]sitter.Symbol{
		"assignment":               pythonSyms.assignment,
		"augmented_assignment":     pythonSyms.augmentedAssignment,
		"as_pattern":               pythonSyms.asPattern,
		"for_statement":            pythonSyms.forStatement,
		"named_expression":         pythonSyms.namedExpression,
		"call":                     pythonSyms.call,
		"function_definition":      pythonSyms.functionDefinition,
		"class_definition":         pythonSyms.classDefinition,
		"decorated_definition":     pythonSyms.decoratedDefinition,
		"lambda":                   pythonSyms.lambda,
		"list_comprehension":       pythonSyms.listComprehension,
		"set_comprehension":        pythonSyms.setComprehension,
		"dictionary_comprehension": pythonSyms.dictionaryComprehension,
		"generator_expression":     pythonSyms.generatorExpression,
		"import_statement":         pythonSyms.importStatement,
		"import_from_statement":    pythonSyms.importFromStatement,
		"identifier":               pythonSyms.identifier,
		"for_in_clause":            pythonSyms.forInClause,

		"block":                    pythonSyms.block,
		"parameters":               pythonSyms.parameters,
		"attribute":                pythonSyms.attribute,
		"argument_list":            pythonSyms.argumentList,
		"dotted_name":              pythonSyms.dottedName,
		"aliased_import":           pythonSyms.aliasedImport,
		"wildcard_import":          pythonSyms.wildcardImport,
		"relative_import":          pythonSyms.relativeImport,
		"import_prefix":            pythonSyms.importPrefix,
		"typed_parameter":          pythonSyms.typedParameter,
		"default_parameter":        pythonSyms.defaultParameter,
		"typed_default_parameter":  pythonSyms.typedDefaultParameter,
		"pattern_list":             pythonSyms.patternList,
		"tuple_pattern":            pythonSyms.tuplePattern,
		"list_pattern":             pythonSyms.listPattern,
		"list_splat_pattern":       pythonSyms.listSplatPattern,
		"dictionary_splat_pattern": pythonSyms.dictSplatPattern,
		"expression_statement":     pythonSyms.expressionStatement,
		"keyword_argument":         pythonSyms.keywordArgument,
		"integer":                  pythonSyms.integer,
		"string":                   pythonSyms.string,
		"string_content":           pythonSyms.stringContent,
		"type":                     pythonSyms.typeNode,
		"generic_type":             pythonSyms.genericType,
		"type_parameter":           pythonSyms.typeParameter,
		"binary_operator":          pythonSyms.binaryOperator,
		"none":                     pythonSyms.none,
		"decorator":                pythonSyms.decorator,
		"await":                    pythonSyms.await,
		"lambda_parameters":        pythonSyms.lambdaParameters,
	}

	lang := python.GetLanguage()
	for name, sym := range entries {
		t.Run(name, func(t *testing.T) {
			if sym == 0 {
				t.Fatalf("resolvePythonSymbols did not resolve grammar rule %q (pythonSyms field is at its zero value — check for a typo in the rule name)", name)
			}
			if got := lang.SymbolName(sym); got != name {
				t.Fatalf("pythonSyms entry for %q resolved to grammar symbol name %q instead", name, got)
			}
		})
	}
}

// pythonVisitBudgetFixtures returns the .py file names under
// testdata/python_visit_budget, sorted, failing the test if the directory
// is empty or missing.
func pythonVisitBudgetFixtures(t *testing.T) []string {
	t.Helper()
	dir := filepath.Join("testdata", "python_visit_budget")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".py") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		t.Fatalf("no .py fixtures found under %s", dir)
	}
	if len(names) > 40 {
		t.Fatalf("%d fixtures under %s exceeds the committed-corpus state-size bound of 40", len(names), dir)
	}
	return names
}

// countAllTreeNodes counts every NAMED node in the subtree rooted at node
// (inclusive), matching what pythonWalk's full unpruned single descent
// visits exactly once. pythonWalk deliberately traverses NamedChild()/
// NamedChildCount() rather than Child()/ChildCount() — every one of its
// dispatch cases matches only named grammar rules, so skipping anonymous
// literal tokens (punctuation, keywords) changes nothing about its
// behavior while avoiding a go-tree-sitter Node-wrapper allocation
// (Tree.cachedNode) for each one; this helper counts the same named-only
// set so the budget stays meaningful.
func countAllTreeNodes(node *sitter.Node) int {
	if node == nil {
		return 0
	}
	count := 1
	for i := 0; i < int(node.NamedChildCount()); i++ {
		count += countAllTreeNodes(node.NamedChild(i))
	}
	return count
}

// TestPythonParser_NodeVisitBudget (T0.4/A3, python-parser-parity-2) is the
// CI-enforceable, non-skipping performance guard: for every committed
// fixture, the instrumented visit counter (D4) must show the whole tree was
// walked (visits >= nodeCount) without exceeding nodeCount plus a bounded
// per-call allowance for deferred resolution (D1) — pythonVisitBudgetPerCall
// extra visits per call node, never a multiple of the whole file.
func TestPythonParser_NodeVisitBudget(t *testing.T) {
	for _, name := range pythonVisitBudgetFixtures(t) {
		name := name
		t.Run(name, func(t *testing.T) {
			srcBytes, err := os.ReadFile(filepath.Join("testdata", "python_visit_budget", name))
			if err != nil {
				t.Fatal(err)
			}

			root, _ := parsePythonGrammarSnippet(t, string(srcBytes))
			nodeCount := countAllTreeNodes(root)
			callCount := len(findAllNodesOfType(root, pythonNodeCall))

			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, name), srcBytes, 0o644); err != nil {
				t.Fatal(err)
			}
			p := NewPythonParser()
			visits := 0
			p.visits = &visits
			if _, err := p.ParseDirectory(dir, "pkg"); err != nil {
				t.Fatalf("ParseDirectory: %v", err)
			}

			if visits < nodeCount {
				t.Errorf("visits = %d, want >= nodeCount %d (the whole tree must be walked at least once)", visits, nodeCount)
			}
			maxAllowed := nodeCount + pythonVisitBudgetPerCall*callCount
			if visits > maxAllowed {
				t.Errorf("visits = %d exceeds budget %d (nodeCount=%d + %d*callCount=%d) — parse cost has re-inflated past the single-descent target",
					visits, maxAllowed, nodeCount, pythonVisitBudgetPerCall, callCount)
			}
		})
	}
}

// largePythonFunctionBody returns a >= n-line straight-line function body
// (each line a trivial local assignment) for TestPythonParser_ReturnTypeFromFieldNode.
func largePythonFunctionBody(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "    x%d = %d\n", i, i)
	}
	b.WriteString("    return x0\n")
	return b.String()
}

// TestPythonParser_ReturnTypeFromFieldNode (T0.5, python-parser-parity-2)
// proves ReturnType extraction never materializes a large function body as
// a Go string. It isolates pythonReturnTypeOf (the seam parseFunctionDef
// calls) from the rest of the parse pipeline and asserts, via a
// testing.Benchmark AllocedBytesPerOp measurement, that its allocation cost
// stays far below the body's byte length — i.e. it reads only the
// return_type field, never node.Content(src) on the whole function_definition.
func TestPythonParser_ReturnTypeFromFieldNode(t *testing.T) {
	body := largePythonFunctionBody(520)
	src := "def big(x: int) -> Cipher:\n" + body

	root, srcBytes := parsePythonGrammarSnippet(t, src)
	defNode := firstNodeOfType(root, pythonNodeFunctionDefinition)
	if defNode == nil {
		t.Fatal("function_definition not found in fixture")
	}
	if got := pythonReturnTypeOf(defNode, srcBytes); got != "Cipher" {
		t.Fatalf("pythonReturnTypeOf = %q, want %q", got, "Cipher")
	}

	result := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = pythonReturnTypeOf(defNode, srcBytes)
		}
	})
	bodyLen := int64(len(body))
	maxAllowed := bodyLen / 10
	if got := result.AllocedBytesPerOp(); got > maxAllowed {
		t.Errorf("pythonReturnTypeOf allocated %d bytes/op for a %d-byte function body; want <= %d — it must read only the return_type field node, never node.Content(src) on the whole function_definition",
			got, bodyLen, maxAllowed)
	}
}

// TestPythonParser_CallOrderIsDocumentOrder (T0.6/D3, python-parser-parity-2)
// pins that decl.Calls preserves source (visitation) order across a
// comprehension, a with/as binder, a fluent-style attribute call, and
// nested constructor-argument calls — the invariant
// internal/scan/supporting_calls.go's lifecycleSelector.selectDescendants
// depends on for positional self.attr rebinding splits. This invariant MUST
// keep holding once deferred per-scope call resolution (D1) replaces
// today's immediate resolution.
func TestPythonParser_CallOrderIsDocumentOrder(t *testing.T) {
	src := `def process(items):
    results = [transform(x) for x in items]
    with open_resource() as res:
        res.configure(setup())
    outer(inner(nested_call()))
    return finalize(results)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "process")
	if fn == nil {
		t.Fatal("process function not found")
	}

	var order []string
	for _, c := range fn.Calls {
		order = append(order, c.Callee.Name)
	}
	want := []string{"transform", "open_resource", "configure", "setup", "outer", "inner", "nested_call", "finalize"}
	if len(order) != len(want) {
		t.Fatalf("call order = %v (%d calls), want %v (%d calls)", order, len(order), want, len(want))
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("call order = %v, want %v (mismatch at index %d: got %q want %q)", order, want, i, order[i], want[i])
		}
	}
}
