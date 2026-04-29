package callgraph

import (
	"os"
	"strings"
	"testing"
)

// TestInferenceEngineHasNoJavaSpecificImports asserts that inference.go does
// not import any Java-specific or tree-sitter-java packages. The inference
// engine must remain language-agnostic; it operates only on the generic
// CallGraph + contracts.KnowledgeBase types defined in this package.
func TestInferenceEngineHasNoJavaSpecificImports(t *testing.T) {
	src, err := os.ReadFile("inference.go")
	if err != nil {
		t.Fatalf("cannot open inference.go: %v", err)
	}

	forbidden := []string{
		"java_parser",
		"javaruntime",
		"tree-sitter-java",
		"sitter/java",
	}
	content := string(src)
	for _, f := range forbidden {
		if strings.Contains(content, f) {
			t.Errorf("inference.go imports forbidden Java-specific symbol %q", f)
		}
	}
}
