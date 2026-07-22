package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJavaParser_Basics(t *testing.T) {
	p := NewJavaParser()

	if got := p.PackageSeparator(); got != "." {
		t.Fatalf("PackageSeparator() = %q, want .", got)
	}
	skip := p.SkipDirs()
	for _, dir := range []string{"test", "tests", "META-INF", "target"} {
		if !skip[dir] {
			t.Fatalf("SkipDirs missing %q", dir)
		}
	}
	if got := p.SubPackagePath("com.example", "crypto"); got != "com.example.crypto" {
		t.Fatalf("SubPackagePath() = %q", got)
	}
	if got := p.SubPackagePath("", "com"); got != "com" {
		t.Fatalf("SubPackagePath() empty parent = %q", got)
	}
}

func TestJavaParser_ParseDirectoryAndResolve(t *testing.T) {
	p := NewJavaParser()
	dir := t.TempDir()

	src := `package com.example.crypto;

import javax.crypto.Cipher;
import java.security.*;
import java.util.ArrayList;
import static java.util.Collections.emptyList;

class CryptoService {
    byte[] encrypt(byte[] data) { return data; }
}

class Outer {
    private final Cipher cipher = null;
    private java.util.Map<String, String> map;
    private CryptoService service;

    Outer() {
        this.service = new CryptoService();
    }

    void encrypt(byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES");
        c.doFinal(data);
        map.put("k", "v");
        service.encrypt(data);
        KeyPairGenerator.getInstance("RSA");
        helper();
        ArrayList<String> list = new ArrayList<String>();
        new javax.crypto.spec.SecretKeySpec(data, "AES");
    }

    void helper() {}

    class Inner {
        void run() {
            encrypt(new byte[0]);
        }
    }
}
`
	if err := os.WriteFile(filepath.Join(dir, "Outer.java"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "OuterTest.java"), []byte("class OuterTest {}"), 0o644); err != nil {
		t.Fatal(err)
	}

	analyses, err := p.ParseDirectory(dir, "fallback.pkg")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis (test file skipped), got %d", len(analyses))
	}

	analysis := analyses[0]
	if analysis.PackageName != "com.example.crypto" || analysis.PackagePath != "com.example.crypto" {
		t.Fatalf("unexpected package name/path: %q / %q", analysis.PackageName, analysis.PackagePath)
	}
	if analysis.Imports["Cipher"] != "javax.crypto" {
		t.Fatalf("Cipher import not resolved correctly: %#v", analysis.Imports)
	}
	if analysis.Imports["ArrayList"] != "java.util" {
		t.Fatalf("ArrayList import not resolved correctly: %#v", analysis.Imports)
	}
	if len(analysis.WildcardImports) == 0 || analysis.WildcardImports[0] != "java.security" {
		t.Fatalf("expected wildcard import java.security, got %#v", analysis.WildcardImports)
	}

	foundCtor := false
	foundInnerMethod := false
	foundStaticCall := false
	foundVarTypeCall := false
	foundScopedGenericVarTypeCall := false
	foundWildcardCall := false
	foundObjectCreation := false
	foundLocalHelperCall := false

	for _, fn := range analysis.Functions {
		if fn.ID.Type == "Outer" && fn.ID.Name == "<init>#0" {
			foundCtor = true
		}
		if fn.ID.Type == "Outer.Inner" && fn.ID.Name == "run#0" {
			foundInnerMethod = true
		}
		if fn.ID.Type != "Outer" || fn.ID.Name != "encrypt#1" {
			continue
		}
		for _, c := range fn.Calls {
			if c.Callee.Package == "javax.crypto" && c.Callee.Type == "Cipher" && c.Callee.Name == "getInstance#1" {
				foundStaticCall = true
			}
			if c.Callee.Package == "com.example.crypto" && c.Callee.Type == "CryptoService" && c.Callee.Name == "encrypt#1" {
				foundVarTypeCall = true
			}
			if c.Callee.Package == "java.util" && c.Callee.Type == "Map<String, String>" && c.Callee.Name == "put#2" {
				foundScopedGenericVarTypeCall = true
			}
			if c.Callee.Package == "java.security" && c.Callee.Name == "getInstance#1" {
				foundWildcardCall = true
			}
			if c.Callee.Package == "com.example.crypto" && c.Callee.Type == "Outer" && c.Callee.Name == "helper#0" {
				foundLocalHelperCall = true
			}
			if BaseFunctionName(c.Callee.Name) == "<init>" {
				foundObjectCreation = true
			}
		}
	}

	if !foundCtor || !foundInnerMethod {
		t.Fatalf("expected constructor and inner class method declarations")
	}
	if !foundStaticCall {
		t.Fatal("expected static imported class call resolution")
	}
	if !foundVarTypeCall {
		t.Fatal("expected variable-type based call resolution")
	}
	if !foundScopedGenericVarTypeCall {
		t.Fatal("expected scoped generic field type call resolution")
	}
	if !foundWildcardCall {
		t.Fatal("expected wildcard import call resolution")
	}
	if !foundLocalHelperCall {
		t.Fatal("expected bare helper call to resolve against current class")
	}
	if !foundObjectCreation {
		t.Fatal("expected constructor/object creation call extraction")
	}

	_, err = p.parseFile(filepath.Join(dir, "missing.java"), "pkg")
	if err == nil {
		t.Fatal("expected parseFile error for missing file")
	}
}

func TestJavaParser_IncludeTestsIncludesTestFilesAndDirs(t *testing.T) {
	p := NewJavaParser(WithIncludeTests(true))
	dir := t.TempDir()

	testDir := filepath.Join(dir, "tests")
	if err := os.MkdirAll(testDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(testDir, "OuterTest.java"), []byte("package com.example.crypto; class OuterTest { void run() {} }"), 0o644); err != nil {
		t.Fatal(err)
	}

	analyses, err := p.ParseDirectory(testDir, "com.example.crypto.tests")
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

func TestJavaParser_TracksVisibilityForTypesMethodsAndConstructors(t *testing.T) {
	p := NewJavaParser()
	dir := t.TempDir()

	src := `package com.example.crypto;

public class PublicApi {
    public PublicApi() {}
    private PublicApi(String mode) {}

    public byte[] encrypt(byte[] data) { return data; }
    protected byte[] protect(byte[] data) { return data; }
    private void secret() {}
    void packageOnly() {}

    public class PublicInner {
        public void run() {}
    }

    class PackageInner {
        public void run() {}
    }

    private class HiddenOuter {
        public void helper() {}

        public class NestedPublic {
            public void leak() {}
        }
    }
}

class InternalApi {
    public void exposedButInternal() {}
}

public interface CryptoOps {
    byte[] derive(byte[] input);
    private void helper() {}
}
`
	if err := os.WriteFile(filepath.Join(dir, "Visibility.java"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	analyses, err := p.ParseDirectory(dir, "com.example.crypto")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis, got %d", len(analyses))
	}

	functions := make(map[string]FunctionDecl)
	for _, fn := range analyses[0].Functions {
		functions[fn.ID.String()] = fn
	}

	assertVisibility := func(key, wantVisibility, wantOwnerVisibility string) {
		t.Helper()
		fn, ok := functions[key]
		if !ok {
			t.Fatalf("missing function %s", key)
		}
		if fn.Visibility != wantVisibility {
			t.Fatalf("%s visibility = %q, want %q", key, fn.Visibility, wantVisibility)
		}
		if fn.OwnerVisibility != wantOwnerVisibility {
			t.Fatalf("%s owner visibility = %q, want %q", key, fn.OwnerVisibility, wantOwnerVisibility)
		}
	}

	assertVisibility("com.example.crypto.(PublicApi).<init>#0", VisibilityPublic, VisibilityPublic)
	assertVisibility("com.example.crypto.(PublicApi).<init>#1", VisibilityPrivate, VisibilityPublic)
	assertVisibility("com.example.crypto.(PublicApi).encrypt#1", VisibilityPublic, VisibilityPublic)
	assertVisibility("com.example.crypto.(PublicApi).protect#1", VisibilityProtected, VisibilityPublic)
	assertVisibility("com.example.crypto.(PublicApi).secret#0", VisibilityPrivate, VisibilityPublic)
	assertVisibility("com.example.crypto.(PublicApi).packageOnly#0", VisibilityPackagePrivate, VisibilityPublic)
	assertVisibility("com.example.crypto.(InternalApi).exposedButInternal#0", VisibilityPublic, VisibilityPackagePrivate)
	assertVisibility("com.example.crypto.(CryptoOps).derive#1", VisibilityPublic, VisibilityPublic)
	assertVisibility("com.example.crypto.(CryptoOps).helper#0", VisibilityPrivate, VisibilityPublic)
	assertVisibility("com.example.crypto.(PublicApi.PublicInner).run#0", VisibilityPublic, VisibilityPublic)
	assertVisibility("com.example.crypto.(PublicApi.PackageInner).run#0", VisibilityPublic, VisibilityPackagePrivate)
	assertVisibility("com.example.crypto.(PublicApi.HiddenOuter).helper#0", VisibilityPublic, VisibilityPrivate)
	assertVisibility("com.example.crypto.(PublicApi.HiddenOuter.NestedPublic).leak#0", VisibilityPublic, VisibilityPrivate)
}

func TestJavaParser_ResolveCalleePaths(t *testing.T) {
	p := NewJavaParser()
	analysis := &FileAnalysis{
		PackagePath: "com.example",
		Imports: map[string]string{
			"Cipher":                "javax.crypto",
			"emptyList":             "java.util.Collections",
			"java.util.Collections": "java.util",
			"CryptoService":         "com.dep",
		},
		WildcardImports: []string{"java.security"},
	}

	callee := p.resolveCallee("", "helper#0", analysis, "Outer", nil)
	if callee.Package != "com.example" || callee.Type != "Outer" || callee.Name != "helper#0" {
		t.Fatalf("unexpected local callee: %#v", callee)
	}

	callee = p.resolveCallee("", "emptyList#0", analysis, "Outer", nil)
	if callee.Package != "java.util" || callee.Type != "Collections" || callee.Name != "emptyList#0" {
		t.Fatalf("unexpected static-import callee: %#v", callee)
	}

	callee = p.resolveCallee("Cipher", "getInstance", analysis, "", nil)
	if callee.Package != "javax.crypto" || callee.Type != "Cipher" {
		t.Fatalf("unexpected explicit import callee: %#v", callee)
	}

	callee = p.resolveCallee("java.util.Collections", "emptyList", analysis, "", nil)
	if callee.Package != "java.util" || callee.Type != "java.util.Collections" {
		t.Fatalf("unexpected full-object import callee: %#v", callee)
	}

	callee = p.resolveCallee("service", "encrypt", analysis, "", map[string]string{"service": "CryptoService"})
	if callee.Package != "com.dep" || callee.Type != "CryptoService" {
		t.Fatalf("unexpected var-type imported callee: %#v", callee)
	}

	callee = p.resolveCallee("alg", "getJcaName#0", analysis, "", map[string]string{"alg": "io.jsonwebtoken.SignatureAlgorithm"})
	if callee.Package != "io.jsonwebtoken" || callee.Type != "SignatureAlgorithm" {
		t.Fatalf("unexpected var-type fully qualified callee: %#v", callee)
	}

	callee = p.resolveCallee("local", "run", analysis, "", map[string]string{"local": "LocalType"})
	if callee.Package != "com.example" || callee.Type != "LocalType" {
		t.Fatalf("unexpected var-type local callee: %#v", callee)
	}

	callee = p.resolveCallee("UnknownClass", "create", analysis, "", map[string]string{})
	if callee.Package != "java.security" || callee.Type != "UnknownClass" {
		t.Fatalf("unexpected wildcard callee: %#v", callee)
	}

	analysis.WildcardImports = nil
	callee = p.resolveCallee("obj", "call", analysis, "", nil)
	if callee.Package != "com.example" || callee.Type != "obj" {
		t.Fatalf("unexpected fallback callee: %#v", callee)
	}

	callee = p.resolveCallee("java.security.MessageDigest", "getInstance#1", analysis, "", nil)
	if callee.Package != "java.security" || callee.Type != "MessageDigest" {
		t.Fatalf("unexpected fully qualified fallback callee: %#v", callee)
	}

	analysis.WildcardImports = []string{"com.nimbusds.jose", "java.security"}
	callee = p.resolveCallee("KeyPairGenerator", "getInstance#1", analysis, "", nil)
	if callee.Package != "java.security" || callee.Type != "KeyPairGenerator" {
		t.Fatalf("unexpected preferred wildcard JCA callee: %#v", callee)
	}

	analysis.WildcardImports = []string{"com.nimbusds.jose.util", "java.security"}
	callee = p.resolveCallee("MessageDigest", "getInstance#1", analysis, "", nil)
	if callee.Package != "java.security" || callee.Type != "MessageDigest" {
		t.Fatalf("unexpected wildcard MessageDigest callee: %#v", callee)
	}

	analysis.WildcardImports = []string{"com.nimbusds.jose.util", "java.security.cert"}
	callee = p.resolveCallee("CertificateFactory", "generateCertificate#1", analysis, "", nil)
	if callee.Package != "java.security.cert" || callee.Type != "CertificateFactory" {
		t.Fatalf("unexpected wildcard CertificateFactory callee: %#v", callee)
	}

	analysis.WildcardImports = []string{"com.nimbusds.jose.util", "java.security.cert"}
	callee = p.resolveCallee("cf", "generateCertificate#1", analysis, "", map[string]string{"cf": "CertificateFactory"})
	if callee.Package != "java.security.cert" || callee.Type != "CertificateFactory" {
		t.Fatalf("unexpected wildcard variable-type CertificateFactory callee: %#v", callee)
	}
}

func TestJavaParser_TraceExpression_MethodCallReceiverProvenance(t *testing.T) {
	p := NewJavaParser()

	analysis := &FileAnalysis{
		PackagePath: "io.jsonwebtoken.impl",
		Imports: map[string]string{
			"SignatureAlgorithm": "io.jsonwebtoken",
		},
	}
	varTypes := map[string]string{
		"alg": "SignatureAlgorithm",
	}
	origins := map[string]varOrigin{
		"alg": {
			typeName:   "SignatureAlgorithm",
			kind:       "parameter",
			filePath:   "DefaultJwtBuilder.java",
			line:       261,
			paramIndex: 0,
		},
	}

	nodes := p.traceExpression("alg.getJcaName()", analysis, "DefaultJwtBuilder", varTypes, origins, 0)
	if len(nodes) != 1 {
		t.Fatalf("traceExpression returned %#v, want single CALL_RESULT node", nodes)
	}
	node := nodes[0]
	if node.Type != "CALL_RESULT" || node.Value != "alg.getJcaName()" {
		t.Fatalf("unexpected call result node: %#v", node)
	}
	if node.CallTarget == nil || node.CallTarget.Package != "io.jsonwebtoken" || node.CallTarget.Type != "SignatureAlgorithm" || node.CallTarget.Name != "getJcaName#0" {
		t.Fatalf("unexpected call target: %#v", node.CallTarget)
	}
	if len(node.SourceNodes) != 1 {
		t.Fatalf("expected receiver provenance under CALL_RESULT, got %#v", node.SourceNodes)
	}
	receiver := node.SourceNodes[0]
	if receiver.Type != "PARAMETER" || receiver.Name != "alg" || receiver.ParameterIndex != 0 {
		t.Fatalf("unexpected receiver provenance node: %#v", receiver)
	}
	if receiver.Location == nil || receiver.Location.FilePath != "DefaultJwtBuilder.java" || receiver.Location.Line != 261 {
		t.Fatalf("unexpected receiver location: %#v", receiver.Location)
	}
}

func TestJavaParser_TraceExpression_ConstructorCallTarget(t *testing.T) {
	p := NewJavaParser()

	analysis := &FileAnalysis{
		PackagePath: "com.nimbusds.jose.util",
		Imports: map[string]string{
			"ByteArrayInputStream": "java.io",
		},
	}

	nodes := p.traceExpression("new ByteArrayInputStream(derEncodedCert)", analysis, "", nil, nil, 0)
	if len(nodes) != 1 {
		t.Fatalf("traceExpression returned %#v, want single CALL_RESULT node", nodes)
	}
	node := nodes[0]
	if node.Type != "CALL_RESULT" || node.Value != "new ByteArrayInputStream(derEncodedCert)" {
		t.Fatalf("unexpected constructor call result node: %#v", node)
	}
	if node.CallTarget == nil {
		t.Fatal("expected constructor call target")
	}
	if node.CallTarget.Package != "java.io" || node.CallTarget.Type != "ByteArrayInputStream" || node.CallTarget.Name != "<init>#1" {
		t.Fatalf("unexpected constructor call target: %#v", node.CallTarget)
	}
}

// TestJavaParser_TraceExpression_ConstructorRecursesIntoArguments verifies that
// nested constructor arguments are broken out into their own provenance nodes —
// the fix for ECDomainParameters/SecureRandom being dropped when used as
// arguments to a non-finding parameter-object constructor.
func TestJavaParser_TraceExpression_ConstructorRecursesIntoArguments(t *testing.T) {
	p := NewJavaParser()

	analysis := &FileAnalysis{
		PackagePath: "com.example",
		Imports: map[string]string{
			"ECKeyGenerationParameters": "org.bouncycastle.crypto.params",
			"ECDomainParameters":        "org.bouncycastle.crypto.params",
			"SecureRandom":              "java.security",
		},
	}
	origins := map[string]varOrigin{
		"domainParams": {
			typeName:    "ECDomainParameters",
			kind:        "local_variable",
			initializer: "new ECDomainParameters(curve, g, n, h)",
			paramIndex:  -1,
		},
	}

	nodes := p.traceExpression(
		"new ECKeyGenerationParameters(domainParams, new SecureRandom())",
		analysis, "com.example", nil, origins, 0,
	)
	if len(nodes) != 1 {
		t.Fatalf("traceExpression returned %#v, want single CALL_RESULT node", nodes)
	}
	top := nodes[0]
	if top.CallTarget == nil || top.CallTarget.Type != "ECKeyGenerationParameters" {
		t.Fatalf("top node call target = %#v, want ECKeyGenerationParameters constructor", top.CallTarget)
	}

	// Both the variable-backed nested constructor (ECDomainParameters, reached via
	// domainParams' initializer) and the inline nested constructor (SecureRandom)
	// must now surface as call_target nodes somewhere in the provenance subtree.
	want := map[string]bool{"ECDomainParameters": false, "SecureRandom": false}
	var walk func(n SourceNode)
	walk = func(n SourceNode) {
		if n.CallTarget != nil {
			if _, ok := want[n.CallTarget.Type]; ok {
				want[n.CallTarget.Type] = true
			}
		}
		for _, child := range n.SourceNodes {
			walk(child)
		}
	}
	walk(top)
	for typ, found := range want {
		if !found {
			t.Fatalf("constructor argument %q was not broken out into a call_target node; provenance = %#v", typ, top)
		}
	}
}

// TestJavaParser_ConstructorArgs_StripInlineComments verifies that an inline
// comment between constructor arguments does not get glued onto the following
// argument's expression — which previously produced a garbage call_target.
func TestJavaParser_ConstructorArgs_StripInlineComments(t *testing.T) {
	p := NewJavaParser()
	analysis := &FileAnalysis{
		PackagePath: "com.example",
		Imports: map[string]string{
			"RSAKeyGenerationParameters": "org.bouncycastle.crypto.params",
			"SecureRandom":               "java.security",
		},
	}
	expr := "new RSAKeyGenerationParameters(\n" +
		"    java.math.BigInteger.valueOf(65537), // public exponent\n" +
		"    new SecureRandom(),\n" +
		"    keySize,\n" +
		"    80 // certainty\n" +
		")"

	nodes := p.traceExpression(expr, analysis, "com.example", nil, nil, 0)
	if len(nodes) != 1 {
		t.Fatalf("traceExpression returned %#v, want single node", nodes)
	}

	var secureRandomClean, garbage bool
	var walk func(n SourceNode)
	walk = func(n SourceNode) {
		if n.CallTarget != nil {
			switch {
			case n.CallTarget.Type == "SecureRandom" && n.CallTarget.Package == "java.security":
				secureRandomClean = true
			case strings.Contains(n.CallTarget.Type, "//") ||
				strings.Contains(n.CallTarget.Type, "exponent") ||
				strings.Contains(n.CallTarget.Type, "certainty"):
				garbage = true
			}
		}
		for _, c := range n.SourceNodes {
			walk(c)
		}
	}
	walk(nodes[0])

	if !secureRandomClean {
		t.Fatalf("expected a clean java.security.SecureRandom call target; provenance = %#v", nodes[0])
	}
	if garbage {
		t.Fatalf("comment text leaked into a call target; provenance = %#v", nodes[0])
	}
}

func TestStripJavaExpressionComments(t *testing.T) {
	cases := []struct{ in, want string }{
		{"a, b", "a, b"},
		{"BigInteger.valueOf(65537), // public exponent\n new SecureRandom()", "BigInteger.valueOf(65537), \n new SecureRandom()"},
		{"a /* block */ b", "a  b"},
		{"\"http://example.com\"", "\"http://example.com\""},
		{"'/' , x", "'/' , x"},
	}
	for _, tc := range cases {
		if got := stripJavaExpressionComments(tc.in); got != tc.want {
			t.Errorf("stripJavaExpressionComments(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestJavaParser_ConstructorOverloadsIncludeArity(t *testing.T) {
	dir := t.TempDir()
	src := `package com.example;

public class Example {
    public Example() {}
    public Example(String value) {}
    public Example(byte[] value) {}
}`
	file := filepath.Join(dir, "Example.java")
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatalf("write Example.java: %v", err)
	}

	p := NewJavaParser()
	analysis, err := p.parseFile(file, "com.example")
	if err != nil {
		t.Fatalf("parseFile failed: %v", err)
	}

	var haveZero bool
	var oneArg []string
	for _, fn := range analysis.Functions {
		if fn.ID.Type != "Example" {
			continue
		}
		if fn.ID.Name == "<init>#0" {
			haveZero = true
		}
		if strings.HasPrefix(fn.ID.Name, "<init>#1") {
			oneArg = append(oneArg, fn.ID.Name)
		}
	}

	if !haveZero || len(oneArg) != 2 {
		t.Fatalf("expected constructor overload ids <init>#0 and <init>#1, got %#v", analysis.Functions)
	}
	if oneArg[0] == oneArg[1] {
		t.Fatalf("expected overloaded one-arg constructors to be uniquely decorated, got %#v", oneArg)
	}
	if !containsString(oneArg, "<init>#1$String") || !containsString(oneArg, "<init>#1$byte[]") {
		t.Fatalf("expected overload decoration to preserve array types, got %#v", oneArg)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestParseJavaParameterList_PreservesOrder(t *testing.T) {
	specs := parseJavaParameterList("(SignatureAlgorithm algorithm, HttpServletRequest request)")
	if len(specs) != 2 {
		t.Fatalf("parseJavaParameterList returned %#v, want 2 params", specs)
	}
	if specs[0].Name != "algorithm" || specs[0].Type != "SignatureAlgorithm" {
		t.Fatalf("unexpected first param: %#v", specs[0])
	}
	if specs[1].Name != "request" || specs[1].Type != "HttpServletRequest" {
		t.Fatalf("unexpected second param: %#v", specs[1])
	}
}

func TestParseJavaParameterList_PreservesQualifiedTypes(t *testing.T) {
	specs := parseJavaParameterList("(io.jsonwebtoken.SignatureAlgorithm alg, byte[] secretKeyBytes)")
	if len(specs) != 2 {
		t.Fatalf("parseJavaParameterList returned %#v, want 2 params", specs)
	}
	if specs[0].Type != "io.jsonwebtoken.SignatureAlgorithm" {
		t.Fatalf("unexpected qualified first param type: %#v", specs[0])
	}
	if specs[1].Type != "byte[]" {
		t.Fatalf("unexpected second param type normalization: %#v", specs[1])
	}
}

func TestJavaParser_InterfaceAndReflectionHandling(t *testing.T) {
	p := NewJavaParser()
	dir := t.TempDir()

	src := `package com.example.crypto;

import io.jsonwebtoken.impl.lang.Classes;

interface Signer {
    byte[] apply(byte[] in);
}

class CryptoFlow {
    byte[] useSigner(Signer signer, byte[] data) {
        Object builder = Classes.newInstance("io.jsonwebtoken.impl.DefaultJwtBuilder");
        return signer.apply(data);
    }
}
`
	if err := os.WriteFile(filepath.Join(dir, "CryptoFlow.java"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	analyses, err := p.ParseDirectory(dir, "fallback.pkg")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis, got %d", len(analyses))
	}

	var foundInterfaceMethod bool
	var foundReflectionCtor bool
	var foundParamTypeResolution bool

	for _, fn := range analyses[0].Functions {
		if fn.ID.Type == "Signer" && fn.ID.Name == "apply#1" && fn.OwnerType == "interface" {
			foundInterfaceMethod = true
		}

		if fn.ID.Type == "CryptoFlow" && fn.ID.Name == "useSigner#2" {
			for _, c := range fn.Calls {
				if c.Callee.Package == "io.jsonwebtoken.impl" &&
					c.Callee.Type == "DefaultJwtBuilder" &&
					c.Callee.Name == "<init>#0" {
					foundReflectionCtor = true
				}
				if c.Callee.Package == "com.example.crypto" &&
					c.Callee.Type == "Signer" &&
					c.Callee.Name == "apply#1" {
					foundParamTypeResolution = true
				}
			}
		}
	}

	if !foundInterfaceMethod {
		t.Fatal("expected interface method declaration to be parsed")
	}
	if !foundReflectionCtor {
		t.Fatal("expected reflective newInstance string literal to resolve to constructor call")
	}
	if !foundParamTypeResolution {
		t.Fatal("expected method parameter type to resolve interface call target")
	}
}

func TestJavaParser_PreservesOverloadedMethods(t *testing.T) {
	p := NewJavaParser()
	dir := t.TempDir()

	src := `package com.example.crypto;

class Overloads {
    String signWith(String value, byte[] secret) {
        return value;
    }

    String signWith(String value, String secret) {
        return value + secret;
    }
}
`
	if err := os.WriteFile(filepath.Join(dir, "Overloads.java"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	analyses, err := p.ParseDirectory(dir, "com.example.crypto")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis, got %d", len(analyses))
	}

	var names []string
	for _, fn := range analyses[0].Functions {
		if fn.ID.Type == "Overloads" {
			names = append(names, fn.ID.Name)
		}
	}

	if len(names) != 2 {
		t.Fatalf("expected 2 overloads, got %d (%v)", len(names), names)
	}
	if names[0] == names[1] {
		t.Fatalf("expected distinct overload identifiers, got %v", names)
	}
}

func TestJavaParser_ResolvesAnonymousCallbackParameterReceiver(t *testing.T) {
	p := NewJavaParser()
	dir := t.TempDir()

	src := `package com.example.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

class Wrapper {
    interface CipherCallback {
        byte[] apply(Cipher cipher) throws Exception;
    }

    byte[] use(final SecretKey kek, final CipherCallback cb) throws Exception {
        return cb.apply(null);
    }

    byte[] wrap(final SecretKey kek) throws Exception {
        return use(kek, new CipherCallback() {
            @Override
            public byte[] apply(Cipher cipher) throws Exception {
                cipher.init(Cipher.WRAP_MODE, kek);
                return null;
            }
        });
    }
}
`
	if err := os.WriteFile(filepath.Join(dir, "Wrapper.java"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	analyses, err := p.ParseDirectory(dir, "com.example.crypto")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis, got %d", len(analyses))
	}

	foundCipherInit := false
	for _, fn := range analyses[0].Functions {
		if fn.ID.Type != "Wrapper" || fn.ID.Name != "wrap#1" {
			continue
		}
		for _, c := range fn.Calls {
			if c.Callee.Package == "javax.crypto" &&
				c.Callee.Type == "Cipher" &&
				c.Callee.Name == "init#2" {
				foundCipherInit = true
			}
		}
	}

	if !foundCipherInit {
		t.Fatal("expected anonymous callback receiver to resolve to javax.crypto.Cipher.init")
	}
}

func TestJavaParser_ParameterOriginsUseSignatureLine(t *testing.T) {
	p := NewJavaParser()
	dir := t.TempDir()

	src := `package com.example.demo;

import org.springframework.web.bind.annotation.GetMapping;

class DemoController {
    @GetMapping("/trace")
    String traceToken(String algorithm) {
        return issueTraceToken(algorithm);
    }

    String issueTraceToken(String algorithm) {
        return algorithm;
    }
}
`
	if err := os.WriteFile(filepath.Join(dir, "DemoController.java"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	analyses, err := p.ParseDirectory(dir, "com.example.demo")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis, got %d", len(analyses))
	}

	var traceToken *FunctionDecl
	for i := range analyses[0].Functions {
		fn := &analyses[0].Functions[i]
		if fn.ID.Type == "DemoController" && fn.ID.Name == "traceToken#1" {
			traceToken = fn
			break
		}
	}
	if traceToken == nil {
		t.Fatal("expected traceToken declaration")
	}
	if len(traceToken.Calls) != 1 {
		t.Fatalf("expected one call from traceToken, got %#v", traceToken.Calls)
	}
	if len(traceToken.Calls[0].ArgumentSources) != 1 || len(traceToken.Calls[0].ArgumentSources[0]) != 1 {
		t.Fatalf("expected one traced parameter source, got %#v", traceToken.Calls[0].ArgumentSources)
	}

	source := traceToken.Calls[0].ArgumentSources[0][0]
	if source.Type != "PARAMETER" {
		t.Fatalf("expected PARAMETER source, got %#v", source)
	}
	if source.Location == nil {
		t.Fatalf("expected parameter source location, got %#v", source)
	}
	if source.Location.Line != 7 {
		t.Fatalf("parameter location line = %d, want signature line 7", source.Location.Line)
	}
}

// ---------------------------------------------------------------------------
// Batch 3: ReturnSources tests (T3.1, T3.3, T3.4, T3.5)
// ---------------------------------------------------------------------------

// parseJavaInline parses an inline Java class string and returns all functions.
func parseJavaInline(t *testing.T, src string) []FunctionDecl {
	t.Helper()
	p := NewJavaParser()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Sample.java"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := p.ParseDirectory(dir, "com.example")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	if len(analyses) == 0 {
		t.Fatal("no analyses returned")
	}
	return analyses[0].Functions
}

// findFunctionByName returns the first FunctionDecl whose base name matches.
func findFunctionByName(fns []FunctionDecl, name string) *FunctionDecl {
	for i := range fns {
		if BaseFunctionName(fns[i].ID.Name) == name {
			return &fns[i]
		}
	}
	return nil
}

// TestJavaParser_ReturnNew_PopulatesReturnSources tests T3.1:
// `return new SecretKeySpec(bytes, "AES")` should populate ReturnSources with a
// CALL_RESULT node whose CallTarget.Name matches <init>#2.
func TestJavaParser_ReturnNew_PopulatesReturnSources(t *testing.T) {
	src := `package com.example;
import javax.crypto.spec.SecretKeySpec;
class Sample {
    public Object wrap(byte[] bytes) {
        return new SecretKeySpec(bytes, "AES");
    }
}
`
	fns := parseJavaInline(t, src)
	fn := findFunctionByName(fns, "wrap")
	if fn == nil {
		t.Fatal("wrap function not found")
	}

	if len(fn.ReturnSources) == 0 {
		t.Fatal("expected ReturnSources to be non-empty for constructor return")
	}

	rs := fn.ReturnSources[0]
	if rs.Type != "CALL_RESULT" {
		t.Fatalf("ReturnSources[0].Type = %q, want CALL_RESULT", rs.Type)
	}
	if rs.CallTarget == nil {
		t.Fatal("ReturnSources[0].CallTarget is nil, expected <init>#2")
	}
	if !strings.Contains(rs.CallTarget.Name, "<init>") {
		t.Fatalf("CallTarget.Name = %q, expected to contain <init>", rs.CallTarget.Name)
	}
}

// TestJavaParser_ReturnCall_PopulatesReturnSources tests T3.3:
// `return KeyGenerator.getInstance("AES").generateKey()` should produce a
// CALL_RESULT node whose CallTarget.Name matches generateKey.
func TestJavaParser_ReturnCall_PopulatesReturnSources(t *testing.T) {
	src := `package com.example;
import javax.crypto.KeyGenerator;
class Sample {
    public Object getKey() throws Exception {
        return KeyGenerator.getInstance("AES").generateKey();
    }
}
`
	fns := parseJavaInline(t, src)
	fn := findFunctionByName(fns, "getKey")
	if fn == nil {
		t.Fatal("getKey function not found")
	}

	if len(fn.ReturnSources) == 0 {
		t.Fatal("expected ReturnSources for method-invocation return")
	}

	rs := fn.ReturnSources[0]
	if rs.Type != "CALL_RESULT" {
		t.Fatalf("ReturnSources[0].Type = %q, want CALL_RESULT", rs.Type)
	}
	if rs.CallTarget == nil {
		t.Fatal("ReturnSources[0].CallTarget is nil, expected generateKey")
	}
	if !strings.Contains(rs.CallTarget.Name, "generateKey") {
		t.Fatalf("CallTarget.Name = %q, expected to contain generateKey", rs.CallTarget.Name)
	}
}

// TestJavaParser_ReturnLiteral_EmitsValueSourceNode tests T3.4:
// `return null` / `return "str"` should emit a VALUE SourceNode.
func TestJavaParser_ReturnLiteral_EmitsValueSourceNode(t *testing.T) {
	src := `package com.example;
class Sample {
    public Object getNull() { return null; }
    public String getString() { return "hello"; }
}
`
	fns := parseJavaInline(t, src)

	for _, name := range []string{"getNull", "getString"} {
		fn := findFunctionByName(fns, name)
		if fn == nil {
			t.Fatalf("%s function not found", name)
		}
		if len(fn.ReturnSources) == 0 {
			t.Fatalf("%s: expected ReturnSources for literal return", name)
		}
		if fn.ReturnSources[0].Type != "VALUE" {
			t.Fatalf("%s: ReturnSources[0].Type = %q, want VALUE", name, fn.ReturnSources[0].Type)
		}
	}
}

// TestJavaParser_BareReturn_NoReturnSources tests T3.5:
// `public void doWork() { return; }` should produce empty ReturnSources.
func TestJavaParser_BareReturn_NoReturnSources(t *testing.T) {
	src := `package com.example;
class Sample {
    public void doWork() { return; }
}
`
	fns := parseJavaInline(t, src)
	fn := findFunctionByName(fns, "doWork")
	if fn == nil {
		t.Fatal("doWork function not found")
	}
	if len(fn.ReturnSources) != 0 {
		t.Fatalf("expected empty ReturnSources for bare return, got %d entries", len(fn.ReturnSources))
	}
}

func TestJavaParser_ReturnSwitch_PreservesSelectorGuards(t *testing.T) {
	t.Parallel()

	source := `package example;
class DigestSelector {
    String name(int algorithm) {
        return switch (algorithm) {
            case 1 -> "MD5";
            case 2, 3 -> "SHA-256";
            default -> "SHA-512";
        };
    }
}`

	fns := parseJavaInline(t, source)
	fn := findFunctionByName(fns, "name")
	if fn == nil {
		t.Fatal("name function not found")
	}
	if len(fn.ReturnSources) != 4 {
		t.Fatalf("ReturnSources = %#v, want one guarded value per switch label", fn.ReturnSources)
	}
	wants := []struct {
		value      string
		guardValue string
		isDefault  bool
	}{
		{value: `"MD5"`, guardValue: "1"},
		{value: `"SHA-256"`, guardValue: "2"},
		{value: `"SHA-256"`, guardValue: "3"},
		{value: `"SHA-512"`, isDefault: true},
	}
	for i, want := range wants {
		got := fn.ReturnSources[i]
		if got.Type != "VALUE" || got.Value != want.value || got.Flow == nil || got.Flow.Guard == nil {
			t.Fatalf("ReturnSources[%d] = %#v, want guarded %q", i, got, want.value)
		}
		if got.Flow.Guard.ParameterIndex != 0 || got.Flow.Guard.Value != want.guardValue || got.Flow.Guard.Default != want.isDefault {
			t.Fatalf("ReturnSources[%d].Guard = %#v, want index=0 value=%q default=%v", i, got.Flow.Guard, want.guardValue, want.isDefault)
		}
	}
}

func TestJavaParser_ReturnTernary_PreservesSelectorGuards(t *testing.T) {
	t.Parallel()

	source := `package example;
class DigestSelector {
    String name(int algorithm) {
        return algorithm == 1 ? "SHA-256" : "SHA-512";
    }
}`

	fn := findFunctionByName(parseJavaInline(t, source), "name")
	if fn == nil || len(fn.ReturnSources) != 2 {
		t.Fatalf("ReturnSources = %#v, want two guarded ternary values", fn)
	}
	if got := fn.ReturnSources[0]; got.Value != `"SHA-256"` || got.Flow == nil || got.Flow.Guard == nil || got.Flow.Guard.ParameterIndex != 0 || got.Flow.Guard.Value != "1" || got.Flow.Guard.Default {
		t.Fatalf("true branch = %#v, want algorithm == 1 guard", got)
	}
	if got := fn.ReturnSources[1]; got.Value != `"SHA-512"` || got.Flow == nil || got.Flow.Guard == nil || got.Flow.Guard.ParameterIndex != 0 || !got.Flow.Guard.Default {
		t.Fatalf("false branch = %#v, want default guard", got)
	}
}

// ---------------------------------------------------------------------------
// Batch 6: Argument provenance in traceMethodInvocationNode (T6.1, T6.2)
// ---------------------------------------------------------------------------

// TestJavaParser_MethodInvocation_PopulatesSourceNodesWithArgProvenance tests T6.1:
// A 3-argument method invocation returned from a function should produce a CALL_RESULT
// SourceNode whose SourceNodes slice has 3 entries, one per argument, each with the
// correct ParameterIndex and resolved Type/Value.
//
// Java source: `return cipher.unwrap(wrapped, "AES", Cipher.SECRET_KEY);`
// Expected:
//   - ReturnSources[0].Type  = "CALL_RESULT"
//   - ReturnSources[0].SourceNodes has len == 3
//   - SourceNodes[0].ParameterIndex == 0  (the `wrapped` variable)
//   - SourceNodes[1].ParameterIndex == 1  (the "AES" string literal → VALUE)
//   - SourceNodes[2].ParameterIndex == 2  (Cipher.SECRET_KEY → VALUE)
//   - SourceNodes[2].Value == "Cipher.SECRET_KEY"
func TestJavaParser_MethodInvocation_PopulatesSourceNodesWithArgProvenance(t *testing.T) {
	src := `package com.example;
import javax.crypto.Cipher;
class Sample {
    private Cipher cipher;
    public Object unwrapKey(byte[] wrapped, String alg) throws Exception {
        return cipher.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
    }
}
`
	fns := parseJavaInline(t, src)
	fn := findFunctionByName(fns, "unwrapKey")
	if fn == nil {
		t.Fatal("unwrapKey function not found")
	}
	if len(fn.ReturnSources) == 0 {
		t.Fatal("expected ReturnSources for method-invocation return, got none")
	}

	rs := fn.ReturnSources[0]
	if rs.Type != "CALL_RESULT" {
		t.Fatalf("ReturnSources[0].Type = %q, want CALL_RESULT", rs.Type)
	}
	if rs.CallTarget == nil {
		t.Fatal("ReturnSources[0].CallTarget is nil, expected unwrap")
	}
	if !strings.Contains(rs.CallTarget.Name, "unwrap") {
		t.Fatalf("CallTarget.Name = %q, expected to contain unwrap", rs.CallTarget.Name)
	}

	// T6.1: SourceNodes must have 3 entries, one per argument.
	if len(rs.SourceNodes) != 3 {
		t.Fatalf("SourceNodes has %d entries, want 3 (one per argument); nodes: %#v", len(rs.SourceNodes), rs.SourceNodes)
	}

	// Arg 0: wrapped variable — PARAMETER or VARIABLE node
	arg0 := rs.SourceNodes[0]
	if arg0.ParameterIndex != 0 {
		t.Errorf("SourceNodes[0].ParameterIndex = %d, want 0", arg0.ParameterIndex)
	}

	// Arg 1: "AES" string literal — VALUE node
	arg1 := rs.SourceNodes[1]
	if arg1.ParameterIndex != 1 {
		t.Errorf("SourceNodes[1].ParameterIndex = %d, want 1", arg1.ParameterIndex)
	}
	if arg1.Type != "VALUE" {
		t.Errorf("SourceNodes[1].Type = %q, want VALUE", arg1.Type)
	}
	if arg1.Value != `"AES"` {
		t.Errorf("SourceNodes[1].Value = %q, want %q", arg1.Value, `"AES"`)
	}

	// Arg 2: Cipher.SECRET_KEY field access — VALUE node with the right value.
	arg2 := rs.SourceNodes[2]
	if arg2.ParameterIndex != 2 {
		t.Errorf("SourceNodes[2].ParameterIndex = %d, want 2", arg2.ParameterIndex)
	}
	if arg2.Value != "Cipher.SECRET_KEY" {
		t.Errorf("SourceNodes[2].Value = %q, want %q", arg2.Value, "Cipher.SECRET_KEY")
	}
}

// ---------------------------------------------------------------------------
// Issue 3 — array_creation_expression must NOT produce a malformed CONSTRUCTOR_CALL
// ---------------------------------------------------------------------------

// TestParseArrayCreationExpression_DoesNotProduceMalformedType verifies that
// `new byte[digest.getDigestSize()]` (Java array allocation) does NOT produce
// a CALL_RESULT SourceNode with a truncated/malformed type string like
// "byte[digest.getDigestSize".
//
// The bug manifests in the text-based parseJavaConstructorExpression:
// `new byte[digest.getDigestSize()]` matches the "new " prefix and has "(" in
// it, so the function extracts everything before the first "(" as the type
// name, yielding the malformed string "byte[digest.getDigestSize".
//
// The fix: parseJavaConstructorExpression must reject expressions where the
// candidate type name contains "[" — those are array allocations, not object
// construction.
func TestParseArrayCreationExpression_DoesNotProduceMalformedType(t *testing.T) {
	t.Parallel()

	// Direct unit test of parseJavaConstructorExpression for array allocations.
	arrayExprs := []string{
		"new byte[digest.getDigestSize()]",
		"new byte[size]",
		"new int[10]",
		"new char[buf.length()]",
	}
	for _, expr := range arrayExprs {
		typeName, _, ok := parseJavaConstructorExpression(expr)
		if ok && strings.Contains(typeName, "[") {
			t.Errorf("parseJavaConstructorExpression(%q): returned malformed typeName=%q (want ok=false for array creation)", expr, typeName)
		}
	}

	// True constructors must still work.
	goodExprs := []struct {
		expr    string
		wantTyp string
	}{
		{"new SecretKeySpec(bytes, \"AES\")", "SecretKeySpec"},
		{"new javax.crypto.spec.SecretKeySpec(bytes, \"AES\")", "javax.crypto.spec.SecretKeySpec"},
	}
	for _, tc := range goodExprs {
		typeName, _, ok := parseJavaConstructorExpression(tc.expr)
		if !ok {
			t.Errorf("parseJavaConstructorExpression(%q): got ok=false, want true", tc.expr)
		} else if typeName != tc.wantTyp {
			t.Errorf("parseJavaConstructorExpression(%q): typeName=%q, want %q", tc.expr, typeName, tc.wantTyp)
		}
	}

	// Integration: a method that uses a local byte array must NOT produce
	// malformed CALL_RESULT nodes in any SourceNode tree in the callgraph.
	src := `package com.example;
public class DigestWrapper {
    private org.bouncycastle.crypto.Digest digest;
    public Object computeDigest(byte[] input) {
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return new javax.crypto.spec.SecretKeySpec(hash, "AES");
    }
}
`
	graph := parseInlineJava(t, "DigestWrapper", src)
	fn := findFunctionBySimpleName(t, graph, "computeDigest")
	for _, sn := range fn.ReturnSources {
		checkNoMalformedArrayType(t, sn)
	}
}

// ---------------------------------------------------------------------------
// Batch 8 — Field/variable assignment provenance for wrapper-case visibility
// ---------------------------------------------------------------------------

// TestJavaParser_LocalVariableReturn_PopulatesSourceNodesFromAssignment (Batch 8 pair 1).
//
// When a method assigns a local variable from a call and then returns the variable,
// the parser must populate the VARIABLE SourceNode's SourceNodes slice with
// the call's provenance. This allows the engine to propagate the inferred return
// type through wrapper functions.
//
// Shape:
//
//	SecretKey unwrap() {
//	    SecretKey result = KeyGenerator.getInstance("AES").generateKey();
//	    return result;
//	}
//
// Expected: ReturnSources contains a VARIABLE node for "result" whose SourceNodes
// contains a CALL_RESULT for generateKey.
func TestJavaParser_LocalVariableReturn_PopulatesSourceNodesFromAssignment(t *testing.T) {
	t.Parallel()

	src := `package com.example;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
public class WrapperA {
    public Object unwrap() throws Exception {
        SecretKey result = KeyGenerator.getInstance("AES").generateKey();
        return result;
    }
}
`
	graph := parseInlineJava(t, "WrapperA", src)

	fn := findFunctionBySimpleName(t, graph, "unwrap")
	if len(fn.ReturnSources) == 0 {
		t.Fatal("expected ReturnSources to be non-empty")
	}

	// Find the VARIABLE or FIELD source node for "result".
	var resultNode *SourceNode
	for i := range fn.ReturnSources {
		sn := &fn.ReturnSources[i]
		if (sn.Type == "VARIABLE" || sn.Type == "FIELD") && sn.Name == "result" {
			resultNode = sn
			break
		}
	}
	if resultNode == nil {
		t.Fatalf("expected a VARIABLE/FIELD SourceNode named 'result'; got: %+v", fn.ReturnSources)
	}
	if len(resultNode.SourceNodes) == 0 {
		t.Errorf("expected SourceNodes on 'result' variable node to be populated from assignment; got empty. "+
			"Full ReturnSources: %+v", fn.ReturnSources)
	}
}

// TestJavaParser_FieldReturn_PopulatesSourceNodesFromInMethodAssignment (Batch 8 pair 2).
//
// When a field is assigned inside a method body and then returned, the FIELD SourceNode
// must carry the assignment's RHS in its SourceNodes slice. This is the canonical shape
// of FieldLevelEncryptionParams.getSecretKey().
//
// Shape:
//
//	class Foo {
//	    Key secretKey;
//	    Key get() {
//	        secretKey = RSA.unwrap(...);
//	        return secretKey;
//	    }
//	}
func TestJavaParser_FieldReturn_PopulatesSourceNodesFromInMethodAssignment(t *testing.T) {
	t.Parallel()

	src := `package com.example;
import java.security.Key;
public class WrapperB {
    private Key secretKey;
    public Object get(Key decryptionKey, byte[] data) throws Exception {
        secretKey = com.example.RSA.unwrap(decryptionKey, data);
        return secretKey;
    }
}
`
	graph := parseInlineJava(t, "WrapperB", src)

	fn := findFunctionBySimpleName(t, graph, "get")
	if len(fn.ReturnSources) == 0 {
		t.Fatal("expected ReturnSources to be non-empty")
	}

	// The return is `secretKey` — a field. The FIELD SourceNode must have SourceNodes.
	var secretKeyNode *SourceNode
	for i := range fn.ReturnSources {
		sn := &fn.ReturnSources[i]
		if (sn.Type == "FIELD" || sn.Type == "VARIABLE") && sn.Name == "secretKey" {
			secretKeyNode = sn
			break
		}
	}
	if secretKeyNode == nil {
		t.Fatalf("expected a FIELD/VARIABLE SourceNode named 'secretKey'; got: %+v", fn.ReturnSources)
	}
	if len(secretKeyNode.SourceNodes) == 0 {
		t.Errorf("expected SourceNodes on 'secretKey' field node to be populated from in-method assignment; got empty. "+
			"Full ReturnSources: %+v", fn.ReturnSources)
	}
}

// TestJavaParser_FieldReturn_NoAssignment_LeavesSourceNodesEmpty (Batch 8 pair 3).
//
// When a field is returned without any in-method assignment, its SourceNodes must
// remain empty (no cross-method data flow in v1). This ensures no regressions on
// existing tests that previously relied on empty SourceNodes for VARIABLE/FIELD nodes.
func TestJavaParser_FieldReturn_NoAssignment_LeavesSourceNodesEmpty(t *testing.T) {
	t.Parallel()

	src := `package com.example;
import java.security.Key;
public class WrapperC {
    private Key secretKey;
    public Object get() {
        return secretKey;
    }
}
`
	graph := parseInlineJava(t, "WrapperC", src)

	fn := findFunctionBySimpleName(t, graph, "get")
	if len(fn.ReturnSources) == 0 {
		t.Fatal("expected ReturnSources to be non-empty")
	}

	// Find the FIELD SourceNode for "secretKey".
	var secretKeyNode *SourceNode
	for i := range fn.ReturnSources {
		sn := &fn.ReturnSources[i]
		if (sn.Type == "FIELD" || sn.Type == "VARIABLE") && sn.Name == "secretKey" {
			secretKeyNode = sn
			break
		}
	}
	if secretKeyNode == nil {
		t.Fatalf("expected a FIELD/VARIABLE SourceNode named 'secretKey'; got: %+v", fn.ReturnSources)
	}
	if len(secretKeyNode.SourceNodes) != 0 {
		t.Errorf("expected SourceNodes to be empty when no in-method assignment; got: %+v", secretKeyNode.SourceNodes)
	}
}

// TestJavaParser_FieldReturn_MultipleAssignments_PopulatesAllSourceNodes (Batch 8 pair 4).
//
// When a field has multiple in-method assignments (e.g., in different branches),
// all of them must be represented in the SourceNodes slice. The engine's lattice
// join handles the multi-candidate case.
func TestJavaParser_FieldReturn_MultipleAssignments_PopulatesAllSourceNodes(t *testing.T) {
	t.Parallel()

	src := `package com.example;
import java.security.Key;
public class WrapperD {
    private Key key;
    public Object get(boolean cond, Key decryptionKey, byte[] data) throws Exception {
        if (cond) {
            key = com.example.Crypto.getX(decryptionKey, data);
        } else {
            key = com.example.Crypto.getY(decryptionKey, data);
        }
        return key;
    }
}
`
	graph := parseInlineJava(t, "WrapperD", src)

	fn := findFunctionBySimpleName(t, graph, "get")
	if len(fn.ReturnSources) == 0 {
		t.Fatal("expected ReturnSources to be non-empty")
	}

	var keyNode *SourceNode
	for i := range fn.ReturnSources {
		sn := &fn.ReturnSources[i]
		if (sn.Type == "FIELD" || sn.Type == "VARIABLE") && sn.Name == "key" {
			keyNode = sn
			break
		}
	}
	if keyNode == nil {
		t.Fatalf("expected a FIELD/VARIABLE SourceNode named 'key'; got: %+v", fn.ReturnSources)
	}
	if len(keyNode.SourceNodes) < 2 {
		t.Errorf("expected at least 2 SourceNodes (one per branch assignment), got %d: %+v",
			len(keyNode.SourceNodes), keyNode.SourceNodes)
	}
}

// checkNoMalformedArrayType recursively checks that no SourceNode carries a
// malformed array-creation type like "byte[digest.getDigestSize".
func checkNoMalformedArrayType(t *testing.T, sn SourceNode) {
	t.Helper()
	if sn.Type == "CALL_RESULT" || sn.DeclaredType != "" {
		typ := sn.DeclaredType
		if sn.CallTarget != nil && sn.CallTarget.Type != "" {
			typ = sn.CallTarget.Type
		}
		// A malformed array type has "[" in it but does NOT end with "[]".
		if strings.Contains(typ, "[") && !strings.HasSuffix(typ, "[]") {
			t.Errorf("malformed array type string in SourceNode: Type=%q DeclaredType=%q CallTarget=%v",
				sn.Type, sn.DeclaredType, sn.CallTarget)
		}
	}
	for _, child := range sn.SourceNodes {
		checkNoMalformedArrayType(t, child)
	}
}

// TestJavaParser_FluentConstructorChain_ResolvesReceiverType covers the
// fluent/constructor-chain resolution gap: a method invoked on a builder created
// inline — `new X().setProvider("BC").method(...)` — must resolve to the
// CONSTRUCTOR type X (so the callee key is the canonical `pkg.(X).method#arity`),
// not leak the raw source expression into FunctionID.Type. Without the fix the
// receiver is read as raw text and the edge dangles (unresolvable in the
// graph-fragment stitch). Only chains ROOTED at `new X()` are resolved — the
// builder/fluent assumption that intermediate calls return the builder — so no
// false edges are introduced for variable- or static-rooted chains.
func TestJavaParser_FluentConstructorChain_ResolvesReceiverType(t *testing.T) {
	src := `package com.example;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
class Sample {
    public void run(Object certHolder, Object provider) {
        new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
        new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC").build(provider);
    }
}
`
	fns := parseJavaInline(t, src)
	fn := findFunctionByName(fns, "run")
	if fn == nil {
		t.Fatal("run function not found")
	}

	var gotCert, gotBuild bool
	for _, c := range fn.Calls {
		// No call's resolved receiver type may carry raw source text.
		if strings.Contains(c.Callee.Type, "new ") || strings.Contains(c.Callee.Type, "(") || strings.Contains(c.Callee.Type, "\n") {
			t.Errorf("raw expression leaked into Callee.Type: %q (name=%q)", c.Callee.Type, c.Callee.Name)
		}
		if c.Callee.Type == "JcaX509CertificateConverter" && c.Callee.Name == "getCertificate#1" {
			gotCert = true
			if c.Callee.Package != "org.bouncycastle.cert.jcajce" {
				t.Errorf("getCertificate package = %q, want org.bouncycastle.cert.jcajce", c.Callee.Package)
			}
		}
		if c.Callee.Type == "JceOpenSSLPKCS8DecryptorProviderBuilder" && c.Callee.Name == "build#1" {
			gotBuild = true
			if c.Callee.Package != "org.bouncycastle.openssl.jcajce" {
				t.Errorf("build package = %q, want org.bouncycastle.openssl.jcajce", c.Callee.Package)
			}
		}
	}
	if !gotCert {
		t.Errorf("did not resolve new JcaX509CertificateConverter().setProvider(...).getCertificate(...) to (JcaX509CertificateConverter).getCertificate#1; calls=%+v", calleeSummaries(fn.Calls))
	}
	if !gotBuild {
		t.Errorf("did not resolve new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider(...).build(...) to (JceOpenSSLPKCS8DecryptorProviderBuilder).build#1; calls=%+v", calleeSummaries(fn.Calls))
	}
}

func calleeSummaries(calls []FunctionCall) []string {
	out := make([]string, 0, len(calls))
	for i := range calls {
		out = append(out, calls[i].Callee.String())
	}
	return out
}

// TestJavaParser_FunctionCallColumnPopulation verifies that the Java parser
// populates StartCol and EndCol on FunctionCall entries, converting from
// tree-sitter 0-based columns to the internal 1-based convention by adding 1.
//
// Task 2.1 (Strict TDD RED test): must fail until Task 2.2 adds the fields.
func TestJavaParser_FunctionCallColumnPopulation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		src         string
		wantMethod  string // base method name to look for
		wantStartGt int    // StartCol must be > 0 (1-based, inclusive)
		wantEndGt   int    // EndCol must be > StartCol (1-based, exclusive)
	}{
		{
			name: "method_invocation columns populated",
			// "SHA3Digest digest = new SHA3Digest(256);" is on line 5,
			// "digest.update(data, 0, data.length);" is on line 6.
			// We only care that update() has StartCol>0 and EndCol>StartCol.
			src: `package com.example;
class Service {
    void run() {
        org.bouncycastle.crypto.digests.SHA3Digest digest = new org.bouncycastle.crypto.digests.SHA3Digest(256);
        digest.update(data, 0, data.length);
    }
}
`,
			wantMethod:  "update",
			wantStartGt: 0,
			wantEndGt:   0,
		},
		{
			name: "object_creation columns populated",
			// new SHA3Digest(256) is an object creation; StartCol and EndCol
			// must be non-zero and EndCol > StartCol.
			src: `package com.example;
class Service {
    void run() {
        org.bouncycastle.crypto.digests.SHA3Digest digest = new org.bouncycastle.crypto.digests.SHA3Digest(256);
    }
}
`,
			wantMethod:  "<init>",
			wantStartGt: 0,
			wantEndGt:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "Service.java"), []byte(tt.src), 0o644); err != nil {
				t.Fatal(err)
			}

			p := NewJavaParser()
			analyses, err := p.ParseDirectory(dir, "com.example")
			if err != nil {
				t.Fatalf("ParseDirectory error: %v", err)
			}
			if len(analyses) == 0 {
				t.Fatal("no analyses returned")
			}

			var found *FunctionCall
			for i := range analyses[0].Functions {
				fn := &analyses[0].Functions[i]
				for j := range fn.Calls {
					c := &fn.Calls[j]
					if BaseFunctionName(c.Callee.Name) == tt.wantMethod {
						found = c
						break
					}
				}
				if found != nil {
					break
				}
			}
			if found == nil {
				t.Fatalf("did not find call to %q in parsed output", tt.wantMethod)
			}

			if found.StartCol <= tt.wantStartGt {
				t.Errorf("StartCol = %d, want > %d (1-based, tree-sitter col+1)", found.StartCol, tt.wantStartGt)
			}
			if found.EndCol <= found.StartCol {
				t.Errorf("EndCol(%d) must be > StartCol(%d)", found.EndCol, found.StartCol)
			}
		})
	}
}
