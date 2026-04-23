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
