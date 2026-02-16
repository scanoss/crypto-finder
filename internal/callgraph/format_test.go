package callgraph

import (
	"encoding/json"
	"strings"
	"testing"
)

// testGraph builds a small call graph for testing formatters.
func testGraph() *CallGraph {
	graph := &CallGraph{
		Functions: map[string]*FunctionDecl{
			"github.com/myorg/myproject.main": {
				ID:        FunctionID{Package: "github.com/myorg/myproject", Name: "main"},
				FilePath:  "main.go",
				StartLine: 10,
				EndLine:   25,
				Calls: []FunctionCall{
					{
						Callee:   FunctionID{Package: "github.com/myorg/myproject/pkg", Name: "Encrypt"},
						Raw:      "pkg.Encrypt",
						FilePath: "main.go",
						Line:     15,
					},
				},
			},
			"github.com/myorg/myproject/pkg.Encrypt": {
				ID:        FunctionID{Package: "github.com/myorg/myproject/pkg", Name: "Encrypt"},
				FilePath:  "pkg/crypto.go",
				StartLine: 42,
				EndLine:   60,
				Calls: []FunctionCall{
					{
						Callee:   FunctionID{Package: "crypto/aes", Name: "NewCipher"},
						Raw:      "aes.NewCipher",
						FilePath: "pkg/crypto.go",
						Line:     45,
					},
				},
			},
		},
		Callers: map[string][]string{
			"github.com/myorg/myproject/pkg.Encrypt": {"github.com/myorg/myproject.main"},
			"crypto/aes.NewCipher":                   {"github.com/myorg/myproject/pkg.Encrypt"},
		},
	}
	return graph
}

func TestParseFunctionID_Plain(t *testing.T) {
	id, err := ParseFunctionID("crypto/aes.NewCipher", "/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.Package != "crypto/aes" {
		t.Errorf("package = %q, want %q", id.Package, "crypto/aes")
	}
	if id.Type != "" {
		t.Errorf("type = %q, want empty", id.Type)
	}
	if id.Name != "NewCipher" {
		t.Errorf("name = %q, want %q", id.Name, "NewCipher")
	}
}

func TestParseFunctionID_Method(t *testing.T) {
	id, err := ParseFunctionID("crypto/aes.(*Block).Encrypt", "/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.Package != "crypto/aes" {
		t.Errorf("package = %q, want %q", id.Package, "crypto/aes")
	}
	if id.Type != "*Block" {
		t.Errorf("type = %q, want %q", id.Type, "*Block")
	}
	if id.Name != "Encrypt" {
		t.Errorf("name = %q, want %q", id.Name, "Encrypt")
	}
}

func TestParseFunctionID_Java(t *testing.T) {
	id, err := ParseFunctionID("javax.crypto.Cipher.getInstance", ".")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.Package != "javax.crypto.Cipher" {
		t.Errorf("package = %q, want %q", id.Package, "javax.crypto.Cipher")
	}
	if id.Name != "getInstance" {
		t.Errorf("name = %q, want %q", id.Name, "getInstance")
	}
}

func TestParseFunctionID_Invalid(t *testing.T) {
	tests := []string{
		"nopackage",
		"",
		".name",
		"pkg.",
	}
	for _, s := range tests {
		_, err := ParseFunctionID(s, "/")
		if err == nil {
			t.Errorf("ParseFunctionID(%q) should return error", s)
		}
	}
}

func TestParseFunctionID_Roundtrip(t *testing.T) {
	ids := []FunctionID{
		{Package: "crypto/aes", Name: "NewCipher"},
		{Package: "crypto/aes", Type: "*Block", Name: "Encrypt"},
		{Package: "github.com/myorg/pkg", Name: "Foo"},
	}
	for _, orig := range ids {
		s := orig.String()
		parsed, err := ParseFunctionID(s, "/")
		if err != nil {
			t.Errorf("ParseFunctionID(%q) error: %v", s, err)
			continue
		}
		if parsed != orig {
			t.Errorf("roundtrip failed: %v != %v", parsed, orig)
		}
	}
}

func TestFormatJSON(t *testing.T) {
	graph := testGraph()
	meta := GraphMetadata{
		Ecosystem:     "go",
		RootModule:    "github.com/myorg/myproject",
		FunctionCount: len(graph.Functions),
		EdgeCount:     2,
	}

	data, err := FormatJSON(graph, meta)
	if err != nil {
		t.Fatalf("FormatJSON error: %v", err)
	}

	// Verify it's valid JSON
	var out jsonOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if out.Metadata.Ecosystem != "go" {
		t.Errorf("metadata.ecosystem = %q, want %q", out.Metadata.Ecosystem, "go")
	}
	if out.Metadata.FunctionCount != 2 {
		t.Errorf("metadata.function_count = %d, want 2", out.Metadata.FunctionCount)
	}
	if len(out.Functions) != 2 {
		t.Errorf("functions count = %d, want 2", len(out.Functions))
	}
	if len(out.Callers) != 2 {
		t.Errorf("callers count = %d, want 2", len(out.Callers))
	}
}

func TestFormatDOT(t *testing.T) {
	graph := testGraph()
	data, err := FormatDOT(graph)
	if err != nil {
		t.Fatalf("FormatDOT error: %v", err)
	}

	output := string(data)

	// Check basic DOT structure
	if !strings.Contains(output, "digraph callgraph {") {
		t.Error("missing digraph header")
	}
	if !strings.Contains(output, "rankdir=LR") {
		t.Error("missing rankdir")
	}
	if !strings.Contains(output, "cluster_") {
		t.Error("missing subgraph clusters")
	}
	if !strings.Contains(output, "->") {
		t.Error("missing edges")
	}
}

func TestFormatText(t *testing.T) {
	graph := testGraph()
	data, err := FormatText(graph)
	if err != nil {
		t.Fatalf("FormatText error: %v", err)
	}

	output := string(data)

	if !strings.Contains(output, "Call Graph: 2 functions, 2 edges") {
		t.Errorf("missing or incorrect header, got:\n%s", output)
	}
	if !strings.Contains(output, "→") {
		t.Error("missing call arrows")
	}
	if !strings.Contains(output, "main.go:10-25") {
		t.Error("missing function location")
	}
}

func TestFormatTraceText(t *testing.T) {
	chains := []CallChain{
		{
			Steps: []CallChainStep{
				{Function: FunctionID{Package: "main", Name: "main"}, FilePath: "main.go", Line: 15},
				{Function: FunctionID{Package: "pkg", Name: "Encrypt"}, FilePath: "crypto.go", Line: 42},
				{Function: FunctionID{Package: "crypto/aes", Name: "NewCipher"}, FilePath: "aes.go", Line: 28},
			},
		},
	}

	output := FormatTraceText(chains, "crypto/aes.NewCipher")

	if !strings.Contains(output, "Callers of crypto/aes.NewCipher:") {
		t.Error("missing header")
	}
	if !strings.Contains(output, "main.main") {
		t.Error("missing entry point")
	}
	if !strings.Contains(output, "→ pkg.Encrypt") {
		t.Error("missing intermediate step")
	}
}

func TestFormatTraceText_NoCallers(t *testing.T) {
	output := FormatTraceText(nil, "crypto/aes.NewCipher")
	if !strings.Contains(output, "No callers found") {
		t.Error("expected 'No callers found' message")
	}
}
