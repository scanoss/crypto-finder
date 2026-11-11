package callgraph

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func parseInlinePythonFiles(t *testing.T, files map[string]string) *CallGraph {
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
	graph, err := NewBuilder(NewPythonParser()).BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

func stripSourceLocations(nodes []SourceNode) []SourceNode {
	for i := range nodes {
		nodes[i].Location = nil
		nodes[i].SourceNodes = stripSourceLocations(nodes[i].SourceNodes)
	}
	return nodes
}

const pythonAlgorithmSourcesModule = `import hashlib

ALG = "sha256"
TWICE = "sha256"
TWICE = "md5"

def by_param(data, alg):
    return hashlib.new(alg, data)

def by_local(data):
    a = "sha1"
    return hashlib.new(a, data)

def by_module_constant(data):
    return hashlib.new(ALG, data)

def by_rebound_param(alg, data):
    alg = alg.lower()
    return hashlib.new(alg, data)

def by_augmented_param(alg, data):
    alg += "-x"
    return hashlib.new(alg, data)

def by_poisoned_local(data, flag):
    a = "sha1"
    if flag:
        a = "md5"
    return hashlib.new(a, data)

def by_rebound_module_constant(data):
    return hashlib.new(TWICE, data)

def by_fstring_local(data, n):
    a = f"sha{n}"
    return hashlib.new(a, data)

def by_bytes_local(data):
    a = b"sha1"
    return hashlib.new(a, data)

def by_keyword_only(*parts, alg):
    return hashlib.new(alg)

def by_keyword_only_after_typed_splat(*parts: str, alg: str = "sha256"):
    return hashlib.new(alg)

def by_keyword_only_after_typed_kwargs(data, **kw: str):
    return hashlib.new(data)

class Hasher:
    def by_method_param(self, alg):
        return hashlib.new(alg)
`

func TestPythonParser_AlgorithmArgumentSources(t *testing.T) {
	graph := parseInlinePythonFiles(t, map[string]string{"app/hasher.py": pythonAlgorithmSourcesModule})

	value := func(text string) []SourceNode {
		return []SourceNode{{Type: "VALUE", Value: text}}
	}
	tests := []struct {
		function string
		want     []SourceNode
	}{
		{"by_param", []SourceNode{{Type: "PARAMETER", Name: "alg", ParameterIndex: 1}}},
		{"by_local", []SourceNode{{Type: "VARIABLE", Name: "a", SourceNodes: value(`"sha1"`)}}},
		{"by_module_constant", []SourceNode{{Type: "VARIABLE", Name: "ALG", SourceNodes: value(`"sha256"`)}}},
		{"by_rebound_param", nil},
		{"by_augmented_param", nil},
		{"by_poisoned_local", nil},
		{"by_rebound_module_constant", nil},
		{"by_fstring_local", nil},
		{"by_bytes_local", nil},
		{"by_keyword_only", nil},
		{"by_keyword_only_after_typed_splat", nil},
		{"by_keyword_only_after_typed_kwargs", []SourceNode{{Type: "PARAMETER", Name: "data", ParameterIndex: 0}}},
		{"by_method_param", nil},
	}
	for _, tt := range tests {
		t.Run(tt.function, func(t *testing.T) {
			var call *FunctionCall
			for _, fn := range graph.Functions {
				if fn.ID.Name == tt.function {
					call = findPythonCallByMethod(fn, "new")
				}
			}
			if call == nil {
				t.Fatalf("hashlib.new call in %s not found", tt.function)
			}
			if len(call.ArgumentSources) == 0 {
				t.Fatalf("ArgumentSources = nil, want one entry per argument")
			}
			if got := stripSourceLocations(call.ArgumentSources[0]); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ArgumentSources[0] = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestPythonParser_ParameterSourceLocation(t *testing.T) {
	graph := parseInlinePythonFiles(t, map[string]string{"app/hasher.py": pythonAlgorithmSourcesModule})
	for _, fn := range graph.Functions {
		if fn.ID.Name != "by_param" {
			continue
		}
		node := findPythonCallByMethod(fn, "new").ArgumentSources[0][0]
		if node.Location == nil || filepath.Base(node.Location.FilePath) != "hasher.py" || node.Location.Line != 8 {
			t.Fatalf("PARAMETER location = %+v, want hasher.py:8", node.Location)
		}
		return
	}
	t.Fatal("by_param not found")
}
