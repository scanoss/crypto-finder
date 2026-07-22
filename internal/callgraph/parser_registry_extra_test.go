package callgraph

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/javaruntime"
)

func TestNewParserForEcosystem_IncludeTestsOption(t *testing.T) {
	tests := []struct {
		ecosystem string
		check     func(t *testing.T, parser Parser)
	}{
		{
			ecosystem: "c",
			check: func(t *testing.T, parser Parser) {
				p, ok := parser.(*CParser)
				if !ok || !p.includeTests {
					t.Fatalf("expected CParser with includeTests, got %#v", parser)
				}
			},
		},
		{
			ecosystem: "cpp",
			check: func(t *testing.T, parser Parser) {
				p, ok := parser.(*CPPParser)
				if !ok || !p.includeTests {
					t.Fatalf("expected CPPParser with includeTests, got %#v", parser)
				}
			},
		},
		{
			ecosystem: "go",
			check: func(t *testing.T, parser Parser) {
				p, ok := parser.(*GoParser)
				if !ok || !p.includeTests {
					t.Fatalf("expected GoParser with includeTests, got %#v", parser)
				}
			},
		},
		{
			ecosystem: "java",
			check: func(t *testing.T, parser Parser) {
				p, ok := parser.(*JavaParser)
				if !ok || !p.includeTests {
					t.Fatalf("expected JavaParser with includeTests, got %#v", parser)
				}
			},
		},
		{
			ecosystem: "node",
			check: func(t *testing.T, parser Parser) {
				p, ok := parser.(*NodeParser)
				if !ok || !p.includeTests {
					t.Fatalf("expected NodeParser with includeTests, got %#v", parser)
				}
			},
		},
		{
			ecosystem: "python",
			check: func(t *testing.T, parser Parser) {
				p, ok := parser.(*PythonParser)
				if !ok || !p.includeTests {
					t.Fatalf("expected PythonParser with includeTests, got %#v", parser)
				}
			},
		},
		{
			ecosystem: "rust",
			check: func(t *testing.T, parser Parser) {
				p, ok := parser.(*RustParser)
				if !ok || !p.includeTests {
					t.Fatalf("expected RustParser with includeTests, got %#v", parser)
				}
			},
		},
	}

	for _, tt := range tests {
		parser := NewParserForEcosystem(tt.ecosystem, WithIncludeTests(true))
		if parser == nil {
			t.Fatalf("expected parser for ecosystem %q", tt.ecosystem)
		}
		tt.check(t, parser)
	}

	if parser := NewParserForEcosystem("unknown", WithIncludeTests(true)); parser != nil {
		t.Fatalf("expected nil parser for unknown ecosystem, got %#v", parser)
	}
}

func TestNewTypeResolverForEcosystem(t *testing.T) {
	if _, ok := NewTypeResolverForEcosystem("c", javaruntime.Config{}).(*CContractTypeResolver); !ok {
		t.Fatal("expected CContractTypeResolver")
	}
	for _, ecosystem := range []string{"cpp", "c++"} {
		if _, ok := NewTypeResolverForEcosystem(ecosystem, javaruntime.Config{}).(*CPPContractTypeResolver); !ok {
			t.Fatalf("expected CPPContractTypeResolver for %q", ecosystem)
		}
	}
	if resolver := NewTypeResolverForEcosystem("java", javaruntime.Config{}); resolver == nil {
		t.Fatal("expected Java type resolver")
	}
	if _, ok := NewTypeResolverForEcosystem("go", javaruntime.Config{}).(*GoContractTypeResolver); !ok {
		t.Fatal("expected GoContractTypeResolver")
	}
	for _, ecosystem := range []string{"node", "javascript", "typescript"} {
		if _, ok := NewTypeResolverForEcosystem(ecosystem, javaruntime.Config{}).(*NodeContractTypeResolver); !ok {
			t.Fatalf("expected NodeContractTypeResolver for %q", ecosystem)
		}
	}
}
