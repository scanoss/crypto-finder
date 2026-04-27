package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

func TestJavaParser_ResolveCallee_StaticWildcardImport(t *testing.T) {
	p := NewJavaParser()
	analysis := &FileAnalysis{
		PackagePath:           "com.example",
		StaticWildcardImports: []string{"java.util.Collections"},
	}

	callee := p.resolveCallee("", "emptyList#0", analysis, "LocalType", nil)
	if callee.Package != "java.util" || callee.Type != "Collections" || callee.Name != "emptyList#0" {
		t.Fatalf("unexpected static wildcard callee: %#v", callee)
	}
}

func TestJavaParser_ResolveCallee_StaticWildcardImportDoesNotBehaveLikePackageWildcard(t *testing.T) {
	p := NewJavaParser()
	analysis := &FileAnalysis{
		PackagePath:           "com.example",
		StaticWildcardImports: []string{"java.util.Collections"},
	}

	callee := p.resolveCallee("UnknownClass", "create", analysis, "", nil)
	if callee.Package != "com.example" || callee.Type != "UnknownClass" || callee.Name != "create" {
		t.Fatalf("static wildcard import should not resolve object call as package wildcard: %#v", callee)
	}
}

func TestJavaParser_ParseDirectory_PreservesStaticWildcardImportKind(t *testing.T) {
	p := NewJavaParser()
	dir := t.TempDir()

	src := `package com.example;

import java.security.*;
import static java.util.Collections.*;

class Sample {
    void run() {
        emptyList();
    }
}
`
	if err := os.WriteFile(filepath.Join(dir, "Sample.java"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	analyses, err := p.ParseDirectory(dir, "fallback.pkg")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis, got %d", len(analyses))
	}

	analysis := analyses[0]
	if len(analysis.WildcardImports) != 1 || analysis.WildcardImports[0] != "java.security" {
		t.Fatalf("expected package wildcard import java.security, got %#v", analysis.WildcardImports)
	}
	if len(analysis.StaticWildcardImports) != 1 || analysis.StaticWildcardImports[0] != "java.util.Collections" {
		t.Fatalf("expected static wildcard import java.util.Collections, got %#v", analysis.StaticWildcardImports)
	}
}

func TestDecorateJavaOverloadName_PreservesPackageQualifiers(t *testing.T) {
	gotA := decorateJavaOverloadName("encrypt", []FunctionParameter{{Type: "com.a.Key"}})
	gotB := decorateJavaOverloadName("encrypt", []FunctionParameter{{Type: "com.b.Key"}})

	if gotA == gotB {
		t.Fatalf("decorateJavaOverloadName collapsed distinct overloads: %q", gotA)
	}
	if gotA != "encrypt$com_a_Key" {
		t.Fatalf("decorateJavaOverloadName(com.a.Key) = %q, want %q", gotA, "encrypt$com_a_Key")
	}
	if gotB != "encrypt$com_b_Key" {
		t.Fatalf("decorateJavaOverloadName(com.b.Key) = %q, want %q", gotB, "encrypt$com_b_Key")
	}
}
