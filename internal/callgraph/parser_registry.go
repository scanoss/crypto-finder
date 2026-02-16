package callgraph

// NewParserForEcosystem returns the call graph parser for the given ecosystem.
// Returns nil if no parser is available for the ecosystem.
func NewParserForEcosystem(ecosystem string) Parser {
	switch ecosystem {
	case "go":
		return NewGoParser()
	case "java":
		return NewJavaParser()
	case "python":
		return NewPythonParser()
	case "rust":
		return NewRustParser()
	default:
		return nil
	}
}
