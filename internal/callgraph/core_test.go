package callgraph

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type stubParser struct {
	analyses map[string][]*FileAnalysis
	errs     map[string]error
	skip     map[string]bool
	sep      string
	seenDirs []string
}

func (p *stubParser) ParseDirectory(dir, _ string) ([]*FileAnalysis, error) {
	p.seenDirs = append(p.seenDirs, dir)
	if err, ok := p.errs[dir]; ok {
		return nil, err
	}
	if a, ok := p.analyses[dir]; ok {
		return a, nil
	}
	return nil, nil
}

func (p *stubParser) SkipDirs() map[string]bool {
	return p.skip
}

func (p *stubParser) SubPackagePath(parentPath, dirName string) string {
	if parentPath == "" {
		return dirName
	}
	return parentPath + p.sep + dirName
}

func (p *stubParser) PackageSeparator() string {
	return p.sep
}

func TestBuilder_BuildFromDirectories(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	skip := filepath.Join(root, "vendor")
	hidden := filepath.Join(root, ".git")
	for _, dir := range []string{sub, skip, hidden} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	parser := &stubParser{
		sep:  "/",
		skip: map[string]bool{"vendor": true},
		analyses: map[string][]*FileAnalysis{
			root: {
				{Functions: []FunctionDecl{{
					ID:        FunctionID{Package: "app", Name: "main"},
					FilePath:  filepath.Join(root, "main.go"),
					StartLine: 1,
					EndLine:   20,
					Calls: []FunctionCall{{
						Callee:   FunctionID{Package: "app/sub", Name: "helper"},
						FilePath: filepath.Join(root, "main.go"),
						Line:     7,
					}},
				}}},
			},
			sub: {
				{Functions: []FunctionDecl{{
					ID:        FunctionID{Package: "app/sub", Name: "helper"},
					FilePath:  filepath.Join(sub, "helper.go"),
					StartLine: 3,
					EndLine:   10,
				}}},
			},
		},
	}

	builder := NewBuilder(parser)
	graph, err := builder.BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	if builder.PackageSeparator() != "/" {
		t.Fatalf("PackageSeparator = %q, want /", builder.PackageSeparator())
	}

	if len(graph.Functions) != 2 {
		t.Fatalf("Functions len = %d, want 2", len(graph.Functions))
	}
	callers := graph.Callers["app/sub.helper"]
	if len(callers) != 1 || callers[0] != "app.main" {
		t.Fatalf("unexpected callers index: %#v", graph.Callers)
	}

	sort.Strings(parser.seenDirs)
	if strings.Contains(strings.Join(parser.seenDirs, ","), "vendor") {
		t.Fatalf("expected vendor to be skipped, seen dirs: %#v", parser.seenDirs)
	}
	if strings.Contains(strings.Join(parser.seenDirs, ","), ".git") {
		t.Fatalf("expected hidden dir to be skipped, seen dirs: %#v", parser.seenDirs)
	}
}

func TestBuilder_AnalyzePackageErrorContinues(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	parser := &stubParser{
		sep:  "/",
		errs: map[string]error{dir1: errors.New("parse failed")},
		analyses: map[string][]*FileAnalysis{
			dir2: {{Functions: []FunctionDecl{{
				ID:        FunctionID{Package: "ok", Name: "f"},
				FilePath:  filepath.Join(dir2, "f.go"),
				StartLine: 1,
				EndLine:   2,
			}}}},
		},
	}

	builder := NewBuilder(parser)
	graph, err := builder.BuildFromDirectories([]PackageDir{{Dir: dir1, ImportPath: "bad"}, {Dir: dir2, ImportPath: "ok"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	if len(graph.Functions) != 1 {
		t.Fatalf("Functions len = %d, want 1", len(graph.Functions))
	}
}

func TestTracerAndHelpers(t *testing.T) {
	userEntry := FunctionDecl{
		ID:        FunctionID{Package: "app", Name: "Entry"},
		FilePath:  "/repo/main.go",
		StartLine: 1,
		EndLine:   20,
		Calls: []FunctionCall{{
			Callee:   FunctionID{Package: "app", Name: "Helper"},
			FilePath: "/repo/main.go",
			Line:     5,
		}},
	}
	userHelper := FunctionDecl{
		ID:        FunctionID{Package: "app", Name: "Helper"},
		FilePath:  "/repo/main.go",
		StartLine: 21,
		EndLine:   60,
		Calls: []FunctionCall{{
			Callee:   FunctionID{Package: "dep", Name: "Crypto"},
			FilePath: "/repo/main.go",
			Line:     30,
		}},
	}
	depCrypto := FunctionDecl{
		ID:        FunctionID{Package: "dep", Name: "Crypto"},
		FilePath:  "/dep/lib.go",
		StartLine: 1,
		EndLine:   40,
	}

	graph := &CallGraph{
		Functions: map[string]*FunctionDecl{
			userEntry.ID.String():  &userEntry,
			userHelper.ID.String(): &userHelper,
			depCrypto.ID.String():  &depCrypto,
		},
		Callers: map[string][]string{
			userHelper.ID.String(): {userEntry.ID.String()},
			depCrypto.ID.String():  {userHelper.ID.String()},
		},
	}

	tracer := NewTracer(graph, "/")
	chains, truncated := tracer.TraceBackLimited(depCrypto.ID, map[string]bool{"app": true}, 0, 0)
	if truncated {
		t.Fatal("TraceBackLimited unexpectedly reported truncation")
	}
	if len(chains) != 1 {
		t.Fatalf("TraceBackLimited chains len = %d, want 1", len(chains))
	}
	if len(chains[0].Steps) != 2 {
		t.Fatalf("expected trace to stop at first user boundary, got %+v", chains[0].Steps)
	}
	lastStep := chains[0].Steps[len(chains[0].Steps)-1]
	if chains[0].Steps[0].Function.Package != "app" || chains[0].Steps[0].Function.Name != "Helper" || lastStep.Function.Package != "dep" {
		t.Fatalf("unexpected chain steps: %+v", chains[0].Steps)
	}

	limited, truncated := tracer.TraceBackLimited(depCrypto.ID, map[string]bool{"app": true}, 2, 0)
	if truncated {
		t.Fatal("TraceBackLimited unexpectedly reported truncation for depth-limited traversal")
	}
	if len(limited) != 1 {
		t.Fatalf("expected one chain with depth=2, got %#v", limited)
	}

	graph.Callers[depCrypto.ID.String()] = []string{userHelper.ID.String(), userEntry.ID.String()}
	chainsLimited, truncated := tracer.TraceBackLimited(depCrypto.ID, map[string]bool{"app": true}, 0, 1)
	if !truncated {
		t.Fatal("expected TraceBackLimited to report truncation")
	}
	if len(chainsLimited) != 1 {
		t.Fatalf("TraceBackLimited chains len = %d, want 1", len(chainsLimited))
	}
	graph.Callers[depCrypto.ID.String()] = []string{userHelper.ID.String()}

	missing, truncated := tracer.TraceBackLimited(FunctionID{Package: "x", Name: "Missing"}, map[string]bool{"app": true}, 0, 0)
	if truncated {
		t.Fatal("TraceBackLimited unexpectedly reported truncation for missing target")
	}
	if len(missing) != 0 {
		t.Fatalf("expected no chains for missing target, got %#v", missing)
	}

	if !isUserPackage("app/sub", map[string]bool{"app": true}, "/") {
		t.Fatal("expected subpackage to be treated as user package")
	}
	if isUserPackage("dep", map[string]bool{"app": true}, "/") {
		t.Fatal("unexpected user package match")
	}
	if !chainReachesUserCode(chains[0].Steps, map[string]bool{"app": true}, "/") {
		t.Fatal("expected chain to reach user code")
	}

	if line := findCallLine(&userEntry, userHelper.ID.String()); line != 5 {
		t.Fatalf("findCallLine = %d, want 5", line)
	}
	if line := findCallLine(&depCrypto, "missing"); line != depCrypto.StartLine {
		t.Fatalf("findCallLine fallback = %d, want %d", line, depCrypto.StartLine)
	}

	overloadedCaller := FunctionDecl{
		ID:        FunctionID{Package: "app", Type: "Controller", Name: "issue#0"},
		FilePath:  "/repo/controller.java",
		StartLine: 1,
		EndLine:   20,
		Calls: []FunctionCall{{
			Callee:   FunctionID{Package: "io.jsonwebtoken.impl", Type: "DefaultJwtBuilder", Name: "signWith#2"},
			FilePath: "/repo/controller.java",
			Line:     12,
		}},
	}
	if line := findCallLine(&overloadedCaller, "io.jsonwebtoken.impl.(DefaultJwtBuilder).signWith#2$SignatureAlgorithm,byte"); line != 12 {
		t.Fatalf("findCallLine overload fallback = %d, want 12", line)
	}
}

func TestTypesAndParserRegistry(t *testing.T) {
	cases := []string{"c", "go", "java", "node", "python", "rust"}
	for _, ecosystem := range cases {
		if p := NewParserForEcosystem(ecosystem); p == nil {
			t.Fatalf("expected parser for ecosystem %s", ecosystem)
		}
	}
	if p := NewParserForEcosystem("unknown"); p != nil {
		t.Fatal("expected nil parser for unknown ecosystem")
	}

	if got := (FunctionID{Package: "crypto/aes", Name: "NewCipher"}).String(); got != "crypto/aes.NewCipher" {
		t.Fatalf("FunctionID.String plain = %q", got)
	}
	if got := (FunctionID{Package: "crypto/aes", Type: "*Block", Name: "Encrypt"}).String(); got != "crypto/aes.(*Block).Encrypt" {
		t.Fatalf("FunctionID.String method = %q", got)
	}

	parsedMethod, err := ParseFunctionID("crypto/aes.(*Block).Encrypt")
	if err != nil {
		t.Fatalf("ParseFunctionID method: %v", err)
	}
	if parsedMethod.Package != "crypto/aes" || parsedMethod.Type != "*Block" || parsedMethod.Name != "Encrypt" {
		t.Fatalf("unexpected parsed method: %#v", parsedMethod)
	}

	parsedFn, err := ParseFunctionID("crypto/aes.NewCipher")
	if err != nil {
		t.Fatalf("ParseFunctionID function: %v", err)
	}
	if parsedFn.Package != "crypto/aes" || parsedFn.Name != "NewCipher" {
		t.Fatalf("unexpected parsed function: %#v", parsedFn)
	}

	if _, err := ParseFunctionID("invalid"); err == nil {
		t.Fatal("expected parse error for invalid function id")
	}
	if _, err := ParseFunctionID("crypto/aes.(*Block"); err == nil {
		t.Fatal("expected parse error for unmatched method syntax")
	}
	for _, malformed := range []string{".(Cipher).getInstance", "pkg.().m", "pkg.(Type)."} {
		if _, err := ParseFunctionID(malformed); err == nil {
			t.Fatalf("expected parse error for malformed method id %q", malformed)
		}
	}
}

func TestBuilder_ExpandsInterfaceDispatchAndFluentFallback(t *testing.T) {
	root := t.TempDir()

	callerFn := FunctionDecl{
		ID:        FunctionID{Package: "app", Type: "Controller", Name: "issue"},
		FilePath:  filepath.Join(root, "controller.java"),
		StartLine: 1,
		EndLine:   20,
		Calls: []FunctionCall{
			{
				Callee:    FunctionID{Package: "io.jsonwebtoken", Type: "JwtBuilder", Name: "signWith"},
				Raw:       "builder.signWith",
				FilePath:  filepath.Join(root, "controller.java"),
				Line:      8,
				Arguments: []string{"SignatureAlgorithm.HS256", "secret"},
			},
			{
				Callee:    FunctionID{Package: "app", Type: "Jwts.builder().setId(id)", Name: "signWith"},
				Raw:       "Jwts.builder().setId(id).signWith",
				FilePath:  filepath.Join(root, "controller.java"),
				Line:      9,
				Arguments: []string{"SignatureAlgorithm.HS256", "secret"},
			},
		},
	}

	jwtsBuilder := FunctionDecl{
		ID:         FunctionID{Package: "io.jsonwebtoken", Type: "Jwts", Name: "builder"},
		FilePath:   filepath.Join(root, "Jwts.java"),
		StartLine:  1,
		EndLine:    5,
		OwnerType:  "class",
		OwnerName:  "Jwts",
		Parameters: []FunctionParameter{},
	}

	ifaceSignWith := FunctionDecl{
		ID:         FunctionID{Package: "io.jsonwebtoken", Type: "JwtBuilder", Name: "signWith"},
		FilePath:   filepath.Join(root, "JwtBuilder.java"),
		StartLine:  1,
		EndLine:    5,
		OwnerType:  "interface",
		OwnerName:  "JwtBuilder",
		Parameters: []FunctionParameter{{Type: "SignatureAlgorithm"}, {Type: "byte[]"}},
	}

	implSignWith := FunctionDecl{
		ID:         FunctionID{Package: "io.jsonwebtoken.impl", Type: "DefaultJwtBuilder", Name: "signWith"},
		FilePath:   filepath.Join(root, "DefaultJwtBuilder.java"),
		StartLine:  1,
		EndLine:    8,
		OwnerType:  "class",
		OwnerName:  "DefaultJwtBuilder",
		Parameters: []FunctionParameter{{Type: "SignatureAlgorithm"}, {Type: "byte[]"}},
	}

	parser := &stubParser{
		sep: ".",
		analyses: map[string][]*FileAnalysis{
			root: {
				{
					Functions: []FunctionDecl{
						callerFn,
						jwtsBuilder,
						ifaceSignWith,
						implSignWith,
					},
				},
			},
		},
	}

	builder := NewBuilder(parser)
	graph, err := builder.BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	callerKey := callerFn.ID.String()
	ifaceKey := ifaceSignWith.ID.String()
	implKey := implSignWith.ID.String()

	if callers := graph.Callers[ifaceKey]; len(callers) == 0 || callers[0] != callerKey {
		t.Fatalf("expected interface callsite to be indexed, got %#v", callers)
	}

	foundImplCaller := false
	for _, caller := range graph.Callers[implKey] {
		if caller == callerKey {
			foundImplCaller = true
			break
		}
	}
	if !foundImplCaller {
		t.Fatalf("expected interface/fluent fallback to add caller %q for impl method, got %#v", callerKey, graph.Callers[implKey])
	}
}

func TestBuilder_KeepsPythonImplementationOverPyiStub(t *testing.T) {
	root := t.TempDir()
	impl := `def hashpw(password, salt):
    return helper(password, salt)

def helper(password, salt):
    return password
`
	stub := `def hashpw(password: bytes, salt: bytes) -> bytes: ...
`
	if err := os.WriteFile(filepath.Join(root, "__init__.py"), []byte(impl), 0o600); err != nil {
		t.Fatalf("write impl: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "__init__.pyi"), []byte(stub), 0o600); err != nil {
		t.Fatalf("write stub: %v", err)
	}

	builder := NewBuilderForEcosystem("python", NewPythonParser())
	graph, err := builder.BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "bcrypt"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	fn := graph.Functions["bcrypt.hashpw"]
	if fn == nil {
		t.Fatal("missing bcrypt.hashpw")
	}
	if strings.HasSuffix(fn.FilePath, ".pyi") {
		t.Fatalf("stub overwrote implementation: %s", fn.FilePath)
	}
	if len(fn.Calls) == 0 {
		t.Fatalf("implementation calls were lost: %#v", fn)
	}
}

func TestBuilder_PreservesPythonSiblingModuleFunctionsWithSameName(t *testing.T) {
	root := t.TempDir()
	pwhashDir := filepath.Join(root, "pwhash")
	if err := os.MkdirAll(pwhashDir, 0o755); err != nil {
		t.Fatalf("mkdir pwhash: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pwhashDir, "argon2id.py"), []byte("def kdf(size, password, salt):\n    return password\n"), 0o600); err != nil {
		t.Fatalf("write argon2id: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pwhashDir, "scrypt.py"), []byte("def kdf(size, password, salt):\n    return password\n"), 0o600); err != nil {
		t.Fatalf("write scrypt: %v", err)
	}

	builder := NewBuilderForEcosystem("python", NewPythonParser())
	graph, err := builder.BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "nacl"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	for _, key := range []string{
		"nacl.pwhash.kdf",
		"nacl.pwhash.argon2id.kdf",
		"nacl.pwhash.scrypt.kdf",
	} {
		if graph.Functions[key] == nil {
			t.Fatalf("missing function %s; functions=%v", key, sortedFunctionKeys(graph.Functions))
		}
	}
}

func sortedFunctionKeys(functions map[string]*FunctionDecl) []string {
	keys := make([]string, 0, len(functions))
	for key := range functions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
