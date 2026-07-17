package callgraph

import "github.com/scanoss/crypto-finder/internal/javaruntime"

// NewParserForEcosystem returns the call graph parser for the given ecosystem.
// Returns nil if no parser is available for the ecosystem.
func NewParserForEcosystem(ecosystem string, opts ...ParserOption) Parser {
	switch ecosystem {
	case "c":
		return NewCParser(opts...)
	case "go":
		return NewGoParser(opts...)
	case "java":
		return NewJavaParser(opts...)
	case "python":
		return NewPythonParser(opts...)
	case "rust":
		return NewRustParser(opts...)
	default:
		return nil
	}
}

// NewTypeResolverForEcosystem returns the type resolver for the given ecosystem.
// Returns nil if no type resolver is available (tree-sitter-only resolution).
func NewTypeResolverForEcosystem(ecosystem string, javaRuntime javaruntime.Config) TypeResolver {
	switch ecosystem {
	case "java":
		return NewJavaBytecodeTypeResolver(javaRuntime)
	case "python":
		return NewPythonContractTypeResolverFromEmbedded()
	default:
		return nil
	}
}
