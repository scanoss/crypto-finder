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

// ---------------------------------------------------------------------------
// Batch 3: ReturnSources extra tests (T3.6, T3.7, T3.8)
// ---------------------------------------------------------------------------

// TestJavaParser_MultipleReturnBranches tests T3.6:
// if-else with two different return expressions → ReturnSources has 2 entries.
func TestJavaParser_MultipleReturnBranches(t *testing.T) {
	src := `package com.example;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
class Sample {
    public Object choose(boolean flag, byte[] bytes) {
        if (flag) {
            return new SecretKeySpec(bytes, "AES");
        } else {
            return new IvParameterSpec(bytes);
        }
    }
}
`
	fns := parseJavaInline(t, src)
	fn := findFunctionByName(fns, "choose")
	if fn == nil {
		t.Fatal("choose function not found")
	}
	if len(fn.ReturnSources) < 2 {
		t.Fatalf("expected at least 2 ReturnSources for if-else returns, got %d", len(fn.ReturnSources))
	}
}

// TestJavaParser_ReturnTernary_PopulatesReturnSources tests T3.7:
// ternary `return flag ? new SecretKeySpec(...) : existingKey` produces
// at least one ReturnSources entry.
func TestJavaParser_ReturnTernary_PopulatesReturnSources(t *testing.T) {
	src := `package com.example;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
class Sample {
    public Object ternary(boolean flag, byte[] bytes, Key existingKey) {
        return flag ? new SecretKeySpec(bytes, "AES") : existingKey;
    }
}
`
	fns := parseJavaInline(t, src)
	fn := findFunctionByName(fns, "ternary")
	if fn == nil {
		t.Fatal("ternary function not found")
	}
	if len(fn.ReturnSources) == 0 {
		t.Fatal("expected ReturnSources for ternary return expression")
	}
}

// TestJavaParser_LambdaReturn_IsNotPopulated tests T3.8 (explicit TODO/deferred):
// A lambda body's return statement MUST NOT be attributed to the outer function's
// ReturnSources in v1. Lambda inference is deferred to v2.
func TestJavaParser_LambdaReturn_IsNotPopulated(t *testing.T) {
	t.Log("TODO: lambda inference deferred to v2 — outer fn must not absorb lambda return sources")
	src := `package com.example;
import java.util.function.Supplier;
import javax.crypto.spec.SecretKeySpec;
class Sample {
    public Supplier<Object> makeSupplier(byte[] bytes) {
        // TODO(callgraph-inferred-types v2): walk lambda return statements
        return () -> new SecretKeySpec(bytes, "AES");
    }
}
`
	fns := parseJavaInline(t, src)
	fn := findFunctionByName(fns, "makeSupplier")
	if fn == nil {
		t.Fatal("makeSupplier function not found")
	}
	// The outer function's ReturnSources MUST be empty or non-constructor
	// (the lambda itself is returned as a CALL_RESULT or EXPRESSION, not the constructor inside it).
	for _, rs := range fn.ReturnSources {
		if rs.CallTarget != nil && rs.CallTarget.Type == "SecretKeySpec" {
			t.Errorf("outer fn ReturnSources should not contain SecretKeySpec constructor from lambda body (lambda inference is deferred to v2); got %#v", rs)
		}
	}
}
