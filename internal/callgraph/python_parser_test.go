package callgraph

import (
	"os"
	"path/filepath"
	"testing"
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
