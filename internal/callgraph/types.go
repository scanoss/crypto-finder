// Package callgraph provides function-level call graph construction and
// backward tracing for linking cryptographic findings in dependencies
// back to user code entry points.
package callgraph

import (
	"fmt"
	"strconv"
	"strings"
)

const constructorMethodName = "<init>"

// TypeResolver provides language-specific type resolution capabilities.
// Each language implements this using its best-fit approach (bytecode analysis,
// go/types, type stubs, LSP, etc.). The builder calls it after tree-sitter
// parsing to enrich the call graph with full type information.
type TypeResolver interface {
	// ResolveTypes enriches function declarations and calls in the graph with
	// type information that tree-sitter alone cannot provide. It receives the
	// full graph and the source/artifact directories, and modifies calls in-place.
	ResolveTypes(graph *CallGraph, sourceRoots []PackageDir) error
}

// BaseFunctionName strips the #N arity suffix from a function name.
// For example, "encrypt#1" returns "encrypt", "refreshSecrets#0" returns "refreshSecrets".
func BaseFunctionName(name string) string {
	idx := strings.LastIndex(name, "#")
	if idx <= 0 || idx >= len(name)-1 {
		return name
	}
	if _, err := strconv.Atoi(name[idx+1:]); err != nil {
		return name
	}
	return name[:idx]
}

// FunctionID uniquely identifies a function or method across packages.
type FunctionID struct {
	// Package is the full package/module path (e.g., "crypto/aes" or "javax.crypto")
	Package string
	// Type is the owning type for methods (Go: receiver like "*Block", Java: class like "Cipher").
	// Empty for plain functions.
	Type string
	// Name is the function/method name (e.g., "NewCipher")
	Name string
}

// String returns a human-readable representation of the function ID.
// This includes the arity suffix (e.g., "javax.crypto.(Cipher).getInstance#1").
func (f FunctionID) String() string {
	if f.Type != "" {
		return fmt.Sprintf("%s.(%s).%s", f.Package, f.Type, f.Name)
	}
	return fmt.Sprintf("%s.%s", f.Package, f.Name)
}

// CanonicalSymbol returns a clean, human-readable symbol without arity suffix.
// For example, "javax.crypto.Cipher.getInstance" instead of "javax.crypto.(Cipher).getInstance#1".
func (f FunctionID) CanonicalSymbol() string {
	base := BaseFunctionName(f.Name)
	if f.Type != "" {
		return f.Package + "." + f.Type + "." + base
	}
	return f.Package + "." + base
}

// FunctionDecl represents a function or method declaration with its location and outgoing calls.
type FunctionDecl struct {
	ID           FunctionID
	FilePath     string
	StartLine    int
	EndLine      int
	OwnerType    string
	OwnerName    string
	FunctionType string
	ReturnType   string
	Parameters   []FunctionParameter
	Calls        []FunctionCall
}

// FunctionParameter describes a declared function parameter.
type FunctionParameter struct {
	Type string
}

// FunctionCall represents a call expression within a function body.
type FunctionCall struct {
	// Callee is the resolved target function
	Callee FunctionID
	// Raw is the raw call expression text (e.g., "aes.NewCipher")
	Raw string
	// FilePath is the file containing this call
	FilePath string
	// Line is the line number of the call
	Line int
	// Arguments are the raw argument expressions passed in this invocation.
	Arguments []string
	// ArgumentSources traces where each argument value comes from.
	// Parallel to Arguments — same indices. Populated by the parser's data flow analysis.
	ArgumentSources [][]SourceNode
}

// SourceNode describes where a value comes from in the data flow.
// Nodes are recursive: each node can have its own SourceNodes showing deeper origins.
type SourceNode struct {
	// Type classifies the origin: VALUE, VARIABLE, FIELD, PARAMETER, CALL_RESULT, EXPRESSION
	Type string
	// Name is the variable/field/parameter name (e.g., "secret", "algorithm")
	Name string
	// DeclaredType is the type if known (e.g., "byte[]", "io.jsonwebtoken.SignatureAlgorithm")
	DeclaredType string
	// Value is the actual value for VALUE nodes (e.g., "\"AES\"", "256")
	Value string
	// ParameterIndex is set for PARAMETER nodes — which param (0-based)
	ParameterIndex int
	// CallTarget is set for CALL_RESULT nodes — the function that produced this value
	CallTarget *FunctionID
	// Location is where this source is defined
	Location *SourceLocation
	// SourceNodes traces where THIS node's value came from (recursive)
	SourceNodes []SourceNode
}

// SourceLocation identifies a position in source code.
type SourceLocation struct {
	FilePath string
	Line     int
}

// FileAnalysis contains all extracted information from a single source file.
type FileAnalysis struct {
	FilePath        string
	PackageName     string
	PackagePath     string
	Imports         map[string]string // alias (or last path segment) -> full import path
	WildcardImports []string          // wildcard import prefixes (e.g., "java.security")
	Functions       []FunctionDecl
}

// CallGraph is the complete call graph across all analyzed packages.
type CallGraph struct {
	// Functions maps FunctionID.String() to its declaration
	Functions map[string]*FunctionDecl
	// Callers maps callee FunctionID.String() to list of caller FunctionID.String()
	// This is the reverse index for walking backwards from a crypto finding.
	Callers map[string][]string
	// TypeHierarchy maps a type name to its parent interfaces/superclasses.
	// E.g., "JwtBuilder" → ["ClaimsMutator"]. Populated by TypeResolver from bytecode.
	TypeHierarchy map[string][]string
}

// CallChain represents a traced path from user code to a crypto finding.
type CallChain struct {
	// Steps is ordered from user entry point to crypto call site
	Steps []CallChainStep
}

// CallChainStep represents a single step in a call chain.
type CallChainStep struct {
	Function FunctionID
	FilePath string
	Line     int
}

// ParseFunctionID parses a fully-qualified function string back into a FunctionID.
// It handles both plain functions ("crypto/aes.NewCipher") and methods with
// a type receiver ("crypto/aes.(*Block).Encrypt").
//
// The sep parameter is the package path separator ("/" for Go, "." for Java).
// For Go, the last "." before the name splits package from function.
// For Java, the last "." splits the fully-qualified class path from the method name.
func ParseFunctionID(s, _ string) (FunctionID, error) {
	// Check for method pattern: "package.(Type).Name"
	if parenStart := strings.Index(s, ".("); parenStart != -1 {
		pkg := s[:parenStart]
		rest := s[parenStart+2:] // skip ".("

		parenEnd := strings.Index(rest, ").")
		if parenEnd == -1 {
			return FunctionID{}, fmt.Errorf("invalid function ID: unmatched parentheses in %q", s)
		}
		typ := rest[:parenEnd]
		name := rest[parenEnd+2:] // skip ")."

		return FunctionID{Package: pkg, Type: typ, Name: name}, nil
	}

	// Plain function: "package<sep>Name" — find the last separator-appropriate dot
	lastDot := strings.LastIndex(s, ".")
	if lastDot == -1 || lastDot == 0 || lastDot == len(s)-1 {
		return FunctionID{}, fmt.Errorf("invalid function ID: no package separator in %q", s)
	}

	return FunctionID{
		Package: s[:lastDot],
		Name:    s[lastDot+1:],
	}, nil
}

