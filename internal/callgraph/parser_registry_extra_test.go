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
	if resolver := NewTypeResolverForEcosystem("java", javaruntime.Config{}); resolver == nil {
		t.Fatal("expected Java type resolver")
	}
	if resolver := NewTypeResolverForEcosystem("go", javaruntime.Config{}); resolver != nil {
		t.Fatalf("expected nil type resolver for go, got %#v", resolver)
	}
}
