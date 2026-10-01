// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// parseInlineJavaFiles writes each relative path -> source pair under one
// temp root and builds the graph over all of them, so a constant can live in a
// different file, directory and package than its use.
func parseInlineJavaFiles(t *testing.T, files map[string]string) *CallGraph {
	t.Helper()
	dir := t.TempDir()
	for rel, src := range files {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := NewBuilder(NewJavaParser()).BuildFromDirectories([]PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

const javaDigestCallerTemplate = `package app;
%s
import java.security.MessageDigest;
public class Caller {
    void digest() throws Exception {
        MessageDigest.getInstance(%s);
    }
}
`

func digestArgumentSource(t *testing.T, graph *CallGraph) SourceNode {
	t.Helper()
	sources := javaArgumentSourcesOfCall(t, graph, "digest", "getInstance")
	if len(sources) != 1 || len(sources[0]) != 1 {
		t.Fatalf("argument sources = %+v, want one node", sources)
	}
	return sources[0][0]
}

func assertFoldedConstant(t *testing.T, node SourceNode, name, file string, line int, value string) {
	t.Helper()
	if node.Type != sourceNodeField || node.Name != name {
		t.Fatalf("argument source = %+v, want FIELD %s", node, name)
	}
	if node.Location == nil || filepath.Base(node.Location.FilePath) != file || node.Location.Line != line {
		t.Errorf("FIELD location = %+v, want %s:%d", node.Location, file, line)
	}
	if len(node.SourceNodes) != 1 || node.SourceNodes[0].Type != sourceNodeValue || node.SourceNodes[0].Value != value {
		t.Errorf("FIELD source nodes = %+v, want one VALUE %s", node.SourceNodes, value)
	}
}

func assertUnfolded(t *testing.T, node SourceNode, expr string) {
	t.Helper()
	if node.Type != sourceNodeValue || node.Value != expr || len(node.SourceNodes) != 0 {
		t.Fatalf("argument source = %+v, want unchanged VALUE %s", node, expr)
	}
}

const javaAlgorithmsSrc = `package lib.digest;
public class Algorithms {
    private Algorithms() {}
    public static final String SHA_1 = "SHA-1";
    public static final String DEFAULT = SHA_1;
    public static String mutable = "MD5";
    public static final int BITS = 2048;
    public static class Legacy {
        public static final String MD5 = "MD5";
    }
}
`

func callerSrc(imports, arg string) string {
	return fmt.Sprintf(javaDigestCallerTemplate, imports, arg)
}

func TestJavaStringConstant_ImportedFromAnotherPackage(t *testing.T) {
	t.Parallel()
	graph := parseInlineJavaFiles(t, map[string]string{
		"lib/digest/Algorithms.java": javaAlgorithmsSrc,
		"app/Caller.java":            callerSrc("import lib.digest.Algorithms;", "Algorithms.SHA_1"),
	})
	assertFoldedConstant(t, digestArgumentSource(t, graph), "Algorithms.SHA_1", "Algorithms.java", 4, `"SHA-1"`)
}

func TestJavaStringConstant_SamePackageWithoutImport(t *testing.T) {
	t.Parallel()
	graph := parseInlineJavaFiles(t, map[string]string{
		"app/Names.java":  "package app;\nclass Names {\n    static final String ALG = \"SHA-256\";\n}\n",
		"app/Caller.java": callerSrc("", "Names.ALG"),
	})
	assertFoldedConstant(t, digestArgumentSource(t, graph), "Names.ALG", "Names.java", 3, `"SHA-256"`)
}

func TestJavaStringConstant_WildcardImport(t *testing.T) {
	t.Parallel()
	graph := parseInlineJavaFiles(t, map[string]string{
		"lib/digest/Algorithms.java": javaAlgorithmsSrc,
		"app/Caller.java":            callerSrc("import lib.digest.*;", "Algorithms.SHA_1"),
	})
	assertFoldedConstant(t, digestArgumentSource(t, graph), "Algorithms.SHA_1", "Algorithms.java", 4, `"SHA-1"`)
}

func TestJavaStringConstant_InterfaceField(t *testing.T) {
	t.Parallel()
	graph := parseInlineJavaFiles(t, map[string]string{
		"lib/Tags.java":   "package lib;\npublic interface Tags {\n    String HASH = \"SHA-512\";\n}\n",
		"app/Caller.java": callerSrc("import lib.Tags;", "Tags.HASH"),
	})
	assertFoldedConstant(t, digestArgumentSource(t, graph), "Tags.HASH", "Tags.java", 3, `"SHA-512"`)
}

func TestJavaStringConstant_NestedClass(t *testing.T) {
	t.Parallel()
	graph := parseInlineJavaFiles(t, map[string]string{
		"lib/digest/Algorithms.java": javaAlgorithmsSrc,
		"app/Caller.java":            callerSrc("import lib.digest.Algorithms;", "Algorithms.Legacy.MD5"),
	})
	assertFoldedConstant(t, digestArgumentSource(t, graph), "Algorithms.Legacy.MD5", "Algorithms.java", 9, `"MD5"`)
}

func TestJavaStringConstant_FullyQualifiedReference(t *testing.T) {
	t.Parallel()
	graph := parseInlineJavaFiles(t, map[string]string{
		"lib/digest/Algorithms.java": javaAlgorithmsSrc,
		"app/Caller.java":            callerSrc("", "lib.digest.Algorithms.SHA_1"),
	})
	assertFoldedConstant(t, digestArgumentSource(t, graph), "lib.digest.Algorithms.SHA_1", "Algorithms.java", 4, `"SHA-1"`)
}

func TestJavaStringConstant_StaticImport(t *testing.T) {
	t.Parallel()
	graph := parseInlineJavaFiles(t, map[string]string{
		"lib/digest/Algorithms.java": javaAlgorithmsSrc,
		"app/Caller.java":            callerSrc("import static lib.digest.Algorithms.SHA_1;", "SHA_1"),
	})
	assertFoldedConstant(t, digestArgumentSource(t, graph), "SHA_1", "Algorithms.java", 4, `"SHA-1"`)
}

func TestJavaStringConstant_InitializedFromAnotherConstant(t *testing.T) {
	t.Parallel()
	graph := parseInlineJavaFiles(t, map[string]string{
		"lib/digest/Algorithms.java": javaAlgorithmsSrc,
		"app/Caller.java":            callerSrc("import lib.digest.Algorithms;", "Algorithms.DEFAULT"),
	})
	assertFoldedConstant(t, digestArgumentSource(t, graph), "Algorithms.DEFAULT", "Algorithms.java", 5, `"SHA-1"`)
}

func TestJavaStringConstant_CyclicInitializersStayUnresolved(t *testing.T) {
	t.Parallel()
	graph := parseInlineJavaFiles(t, map[string]string{
		"lib/Loop.java":   "package lib;\npublic class Loop {\n    public static final String A = Loop.B;\n    public static final String B = A;\n}\n",
		"app/Caller.java": callerSrc("import lib.Loop;", "Loop.A"),
	})
	assertUnfolded(t, digestArgumentSource(t, graph), "Loop.A")
}

func TestJavaStringConstant_NonFinalStaticStaysUnresolved(t *testing.T) {
	t.Parallel()
	graph := parseInlineJavaFiles(t, map[string]string{
		"lib/digest/Algorithms.java": javaAlgorithmsSrc,
		"app/Caller.java":            callerSrc("import lib.digest.Algorithms;", "Algorithms.mutable"),
	})
	assertUnfolded(t, digestArgumentSource(t, graph), "Algorithms.mutable")
}

func TestJavaStringConstant_IntConstantStaysName(t *testing.T) {
	t.Parallel()
	graph := parseInlineJavaFiles(t, map[string]string{
		"lib/digest/Algorithms.java": javaAlgorithmsSrc,
		"app/Caller.java":            callerSrc("import lib.digest.Algorithms;", "Algorithms.BITS"),
	})
	assertUnfolded(t, digestArgumentSource(t, graph), "Algorithms.BITS")
}

func TestJavaStringConstant_UnknownClassStaysUnchanged(t *testing.T) {
	t.Parallel()
	graph := parseInlineJavaFiles(t, map[string]string{
		"lib/digest/Algorithms.java": javaAlgorithmsSrc,
		"app/Caller.java":            callerSrc("import other.Missing;", "Missing.SHA_1"),
	})
	assertUnfolded(t, digestArgumentSource(t, graph), "Missing.SHA_1")
}

func TestJavaStringConstant_AmbiguousWildcardsStayUnchanged(t *testing.T) {
	t.Parallel()
	graph := parseInlineJavaFiles(t, map[string]string{
		"one/Algs.java":   "package one;\npublic class Algs {\n    public static final String H = \"SHA-1\";\n}\n",
		"two/Algs.java":   "package two;\npublic class Algs {\n    public static final String H = \"MD5\";\n}\n",
		"app/Caller.java": callerSrc("import one.*;\nimport two.*;", "Algs.H"),
	})
	assertUnfolded(t, digestArgumentSource(t, graph), "Algs.H")
}

func TestJavaStringConstant_LocalVariableShadowsType(t *testing.T) {
	t.Parallel()
	graph := parseInlineJavaFiles(t, map[string]string{
		"app/Names.java": "package app;\nclass Names {\n    static final String ALG = \"SHA-256\";\n}\n",
		"app/Caller.java": `package app;
import java.security.MessageDigest;
public class Caller {
    void digest(Holder Names) throws Exception {
        MessageDigest.getInstance(Names.ALG);
    }
}
`,
	})
	assertUnfolded(t, digestArgumentSource(t, graph), "Names.ALG")
}
