package callgraph

import "testing"

func TestJavaParser_ResolveCallee_StaticWildcardImport(t *testing.T) {
	p := NewJavaParser()
	analysis := &FileAnalysis{
		PackagePath:     "com.example",
		WildcardImports: []string{"java.util.Collections"},
	}

	callee := p.resolveCallee("", "emptyList#0", analysis, "LocalType", nil)
	if callee.Package != "java.util" || callee.Type != "Collections" || callee.Name != "emptyList#0" {
		t.Fatalf("unexpected static wildcard callee: %#v", callee)
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
