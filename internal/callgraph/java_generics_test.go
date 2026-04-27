package callgraph

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestJavaParser_ExtractsStructuredGenericsFromSourceAST asserts that for a
// Java source method declared with parameterized types, the parser populates
// the structured TypeRef fields (Name + GenericParameters) and erases the
// flat Type string to the raw type name. This drives the schema unification
// between source-derived and JAR-derived signatures.
func TestJavaParser_ExtractsStructuredGenericsFromSourceAST(t *testing.T) {
	p := NewJavaParser()
	dir := t.TempDir()
	src := `package com.example;
import java.util.Map;
import java.util.List;

class Provider {
    public Map<String, Integer> createTable(List<String> tokens, java.util.Set<Long> ids) {
        return null;
    }

    public Map<String, List<Foo>> nested() {
        return null;
    }
}
`
	if err := os.WriteFile(filepath.Join(dir, "Provider.java"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := p.ParseDirectory(dir, "fallback.pkg")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("got %d analyses, want 1", len(analyses))
	}

	createTable := findProviderMethod(t, analyses[0].Functions, "createTable")
	nested := findProviderMethod(t, analyses[0].Functions, "nested")

	if createTable.ReturnType != "Map" {
		t.Fatalf("createTable.ReturnType = %q, want erased %q", createTable.ReturnType, "Map")
	}
	wantReturnRef := TypeRef{
		Name: "Map",
		GenericParameters: []TypeRef{
			{Name: "String"},
			{Name: "Integer"},
		},
	}
	if !reflect.DeepEqual(createTable.ReturnTypeRef, wantReturnRef) {
		t.Fatalf("createTable.ReturnTypeRef = %#v, want %#v", createTable.ReturnTypeRef, wantReturnRef)
	}

	if len(createTable.Parameters) != 2 {
		t.Fatalf("createTable has %d parameters, want 2", len(createTable.Parameters))
	}
	if createTable.Parameters[0].Type != "List" {
		t.Fatalf("createTable.Parameters[0].Type = %q, want erased %q", createTable.Parameters[0].Type, "List")
	}
	wantP0 := TypeRef{Name: "List", GenericParameters: []TypeRef{{Name: "String"}}}
	if !reflect.DeepEqual(createTable.Parameters[0].TypeRef, wantP0) {
		t.Fatalf("createTable.Parameters[0].TypeRef = %#v, want %#v", createTable.Parameters[0].TypeRef, wantP0)
	}
	if createTable.Parameters[1].Type != "Set" {
		t.Fatalf("createTable.Parameters[1].Type = %q, want erased %q (scoped types must be erased to last segment)", createTable.Parameters[1].Type, "Set")
	}
	wantP1 := TypeRef{Name: "Set", GenericParameters: []TypeRef{{Name: "Long"}}}
	if !reflect.DeepEqual(createTable.Parameters[1].TypeRef, wantP1) {
		t.Fatalf("createTable.Parameters[1].TypeRef = %#v, want %#v", createTable.Parameters[1].TypeRef, wantP1)
	}

	wantNestedRef := TypeRef{
		Name: "Map",
		GenericParameters: []TypeRef{
			{Name: "String"},
			{Name: "List", GenericParameters: []TypeRef{{Name: "Foo"}}},
		},
	}
	if !reflect.DeepEqual(nested.ReturnTypeRef, wantNestedRef) {
		t.Fatalf("nested.ReturnTypeRef = %#v, want %#v", nested.ReturnTypeRef, wantNestedRef)
	}
}

// findProviderMethod returns a copy of the FunctionDecl in the slice whose
// owner is "Provider" and whose name starts with the given prefix. The test
// is failed via t.Fatal when no match exists, so callers can dereference the
// result unconditionally.
func findProviderMethod(t *testing.T, fns []FunctionDecl, namePrefix string) FunctionDecl {
	t.Helper()
	for i := range fns {
		fn := fns[i]
		if fn.ID.Type == "Provider" && strings.HasPrefix(fn.ID.Name, namePrefix) {
			return fn
		}
	}
	t.Fatalf("method %q not found", namePrefix)
	return FunctionDecl{}
}

// TestParseClassSignatureAttribute_DecodesGenericMethodSignature asserts that
// the JLS §4.7.9.1 method signature parser decodes a parametrized return type
// and parameter list into structured TypeRef values. This is the parser used
// when a classfile method carries a Signature attribute alongside its erased
// descriptor.
func TestParseClassSignatureAttribute_DecodesGenericMethodSignature(t *testing.T) {
	signature := "(Ljava/util/List<Ljava/lang/String;>;)Ljava/util/Map<Ljava/lang/String;Ljava/util/List<Lcom/example/Foo;>;>;"

	params, ret, err := parseClassMethodSignature(signature)
	if err != nil {
		t.Fatalf("parseClassMethodSignature error: %v", err)
	}

	wantParams := []TypeRef{
		{Name: "List", GenericParameters: []TypeRef{{Name: "String"}}},
	}
	if !reflect.DeepEqual(params, wantParams) {
		t.Fatalf("params = %#v, want %#v", params, wantParams)
	}

	wantReturn := TypeRef{
		Name: "Map",
		GenericParameters: []TypeRef{
			{Name: "String"},
			{Name: "List", GenericParameters: []TypeRef{{Name: "Foo"}}},
		},
	}
	if !reflect.DeepEqual(ret, wantReturn) {
		t.Fatalf("ret = %#v, want %#v", ret, wantReturn)
	}
}

// TestParseClassSignatureAttribute_HandlesPrimitiveAndArrayBounds asserts the
// signature parser handles primitives, arrays, and methods with no generic
// parameters at all (where the Signature attribute may still appear with
// just type-variable scope but no parametrized inputs).
func TestParseClassSignatureAttribute_HandlesPrimitiveAndArrayBounds(t *testing.T) {
	cases := []struct {
		name       string
		signature  string
		wantParams []TypeRef
		wantReturn TypeRef
	}{
		{
			name:      "primitive_and_array",
			signature: "(I[B)Ljava/lang/String;",
			wantParams: []TypeRef{
				{Name: "int"},
				{Name: "byte[]"},
			},
			wantReturn: TypeRef{Name: "String"},
		},
		{
			name:      "void_return_with_object",
			signature: "(Ljava/lang/Object;)V",
			wantParams: []TypeRef{
				{Name: "Object"},
			},
			wantReturn: TypeRef{Name: "void"},
		},
		{
			name:      "array_of_generic",
			signature: "()[Ljava/util/List<Ljava/lang/String;>;",
			wantReturn: TypeRef{
				Name:              "List[]",
				GenericParameters: []TypeRef{{Name: "String"}},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			params, ret, err := parseClassMethodSignature(tc.signature)
			if err != nil {
				t.Fatalf("parseClassMethodSignature(%q) error: %v", tc.signature, err)
			}
			if !reflect.DeepEqual(params, tc.wantParams) {
				t.Fatalf("params = %#v, want %#v", params, tc.wantParams)
			}
			if !reflect.DeepEqual(ret, tc.wantReturn) {
				t.Fatalf("ret = %#v, want %#v", ret, tc.wantReturn)
			}
		})
	}
}

// TestExternalMethodSignaturePropagatesGenericParametersFromBytecode asserts
// the bytecode pipeline reads the Signature attribute when present and
// surfaces structured generic information through methodSignature.
//
// The fixture is compiled at test time with javac so we exercise a real
// classfile shape rather than a synthetic byte buffer. The test is skipped
// when javac is not on PATH so it remains green on minimal CI images that
// lack a JDK.
func TestExternalMethodSignaturePropagatesGenericParametersFromBytecode(t *testing.T) {
	javac, err := exec.LookPath("javac")
	if err != nil {
		t.Skip("javac not available on PATH; skipping bytecode-level generics test")
	}

	dir := t.TempDir()
	src := `package com.example;
import java.util.Map;
import java.util.List;

public class Provider {
    public Map<String, Foo> createTable(List<String> tokens) { return null; }
}

class Foo { }
`
	srcPath := filepath.Join(dir, "Provider.java")
	if writeErr := os.WriteFile(srcPath, []byte(src), 0o644); writeErr != nil {
		t.Fatal(writeErr)
	}
	cmd := exec.CommandContext(context.Background(), javac, "-d", dir, srcPath)
	if out, runErr := cmd.CombinedOutput(); runErr != nil {
		t.Fatalf("javac failed: %v: %s", runErr, out)
	}
	classPath := filepath.Join(dir, "com", "example", "Provider.class")
	classBytes, readErr := os.ReadFile(classPath)
	if readErr != nil {
		t.Fatalf("read compiled class: %v", readErr)
	}

	info := requireParsedClass(t, classBytes, "com.example.Provider")
	method := requireMethodSignature(t, info, "createTable")

	if method.returnType != "java.util.Map" {
		t.Fatalf("returnType = %q, want java.util.Map", method.returnType)
	}
	wantReturnRef := TypeRef{
		Name: "Map",
		GenericParameters: []TypeRef{
			{Name: "String"},
			{Name: "Foo"},
		},
	}
	if !reflect.DeepEqual(method.returnTypeRef, wantReturnRef) {
		t.Fatalf("returnTypeRef = %#v, want %#v", method.returnTypeRef, wantReturnRef)
	}

	if len(method.paramTypeRefs) != 1 {
		t.Fatalf("paramTypeRefs = %#v, want 1 entry", method.paramTypeRefs)
	}
	wantParamRef := TypeRef{Name: "List", GenericParameters: []TypeRef{{Name: "String"}}}
	if !reflect.DeepEqual(method.paramTypeRefs[0], wantParamRef) {
		t.Fatalf("paramTypeRefs[0] = %#v, want %#v", method.paramTypeRefs[0], wantParamRef)
	}
}

// requireParsedClass parses a classfile fixture and asserts both the parser
// success and that the class identity matches the expected fully-qualified
// name. Returns the dereferenced classFileInfo so callers can access fields
// without re-checking for nil.
func requireParsedClass(t *testing.T, data []byte, wantFullClassName string) classFileInfo {
	t.Helper()
	info, err := parseClassFile(data, wantFullClassName+".class")
	if err != nil {
		t.Fatalf("parseClassFile: %v", err)
	}
	if info == nil {
		t.Fatal("parseClassFile returned nil info")
		return classFileInfo{}
	}
	if info.fullClassName != wantFullClassName {
		t.Fatalf("fullClassName = %q, want %q", info.fullClassName, wantFullClassName)
	}
	return *info
}

// requireMethodSignature returns the method whose name matches, or fails the
// test if none does.
func requireMethodSignature(t *testing.T, info classFileInfo, methodName string) methodSignature {
	t.Helper()
	for i := range info.methods {
		if info.methods[i].methodName == methodName {
			return info.methods[i]
		}
	}
	t.Fatalf("method %q not parsed; got methods=%v", methodName, methodNames(info.methods))
	return methodSignature{}
}

func methodNames(sigs []methodSignature) []string {
	out := make([]string, 0, len(sigs))
	for i := range sigs {
		out = append(out, sigs[i].methodName)
	}
	return out
}
