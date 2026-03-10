package callgraph

import (
	"os"
	"path/filepath"
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
	foundWildcardCall := false
	foundObjectCreation := false

	for _, fn := range analysis.Functions {
		if fn.ID.Type == "Outer" && fn.ID.Name == "<init>" {
			foundCtor = true
		}
		if fn.ID.Type == "Outer.Inner" && fn.ID.Name == "run#0" {
			foundInnerMethod = true
		}
		if fn.ID.Type == "Outer" && fn.ID.Name == "encrypt#1" {
			for _, c := range fn.Calls {
				if c.Callee.Package == "javax.crypto" && c.Callee.Type == "Cipher" && c.Callee.Name == "getInstance#1" {
					foundStaticCall = true
				}
				if c.Callee.Package == "com.example.crypto" && c.Callee.Type == "CryptoService" && c.Callee.Name == "encrypt#1" {
					foundVarTypeCall = true
				}
				if c.Callee.Package == "java.security" && c.Callee.Name == "getInstance#1" {
					foundWildcardCall = true
				}
				if c.Callee.Name == "<init>" {
					foundObjectCreation = true
				}
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
	if !foundWildcardCall {
		t.Fatal("expected wildcard import call resolution")
	}
	if !foundObjectCreation {
		t.Fatal("expected constructor/object creation call extraction")
	}

	_, err = p.parseFile(filepath.Join(dir, "missing.java"), "pkg")
	if err == nil {
		t.Fatal("expected parseFile error for missing file")
	}
}

func TestJavaParser_ResolveCalleePaths(t *testing.T) {
	p := NewJavaParser()
	analysis := &FileAnalysis{
		PackagePath: "com.example",
		Imports: map[string]string{
			"Cipher":                "javax.crypto",
			"java.util.Collections": "java.util",
			"CryptoService":         "com.dep",
		},
		WildcardImports: []string{"java.security"},
	}

	callee := p.resolveCallee("", "helper", analysis, nil)
	if callee.Package != "com.example" || callee.Name != "helper" {
		t.Fatalf("unexpected local callee: %#v", callee)
	}

	callee = p.resolveCallee("Cipher", "getInstance", analysis, nil)
	if callee.Package != "javax.crypto" || callee.Type != "Cipher" {
		t.Fatalf("unexpected explicit import callee: %#v", callee)
	}

	callee = p.resolveCallee("java.util.Collections", "emptyList", analysis, nil)
	if callee.Package != "java.util" || callee.Type != "java.util.Collections" {
		t.Fatalf("unexpected full-object import callee: %#v", callee)
	}

	callee = p.resolveCallee("service", "encrypt", analysis, map[string]string{"service": "CryptoService"})
	if callee.Package != "com.dep" || callee.Type != "CryptoService" {
		t.Fatalf("unexpected var-type imported callee: %#v", callee)
	}

	callee = p.resolveCallee("local", "run", analysis, map[string]string{"local": "LocalType"})
	if callee.Package != "com.example" || callee.Type != "LocalType" {
		t.Fatalf("unexpected var-type local callee: %#v", callee)
	}

	callee = p.resolveCallee("UnknownClass", "create", analysis, map[string]string{})
	if callee.Package != "java.security" || callee.Type != "UnknownClass" {
		t.Fatalf("unexpected wildcard callee: %#v", callee)
	}

	analysis.WildcardImports = nil
	callee = p.resolveCallee("obj", "call", analysis, nil)
	if callee.Package != "com.example" || callee.Type != "obj" {
		t.Fatalf("unexpected fallback callee: %#v", callee)
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
					c.Callee.Name == "<init>" {
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
