// Package callgraph provides function-level call graph construction and
// backward tracing for linking cryptographic findings in dependencies
// back to user code entry points.
package callgraph

import (
	"fmt"
	"strings"
)

const constructorMethodName = "<init>"

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
func (f FunctionID) String() string {
	if f.Type != "" {
		return fmt.Sprintf("%s.(%s).%s", f.Package, f.Type, f.Name)
	}
	return fmt.Sprintf("%s.%s", f.Package, f.Name)
}

// FunctionDecl represents a function or method declaration with its location and outgoing calls.
type FunctionDecl struct {
	ID        FunctionID
	FilePath  string
	StartLine int
	EndLine   int
	Calls     []FunctionCall
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

// CallChainEntry is a JSON-serializable representation of a single call chain step.
// Unlike CallChainStep (which carries a FunctionID), this type uses a flat function
// string suitable for structured output in reports.
type CallChainEntry struct {
	Function string `json:"function"`
	FilePath string `json:"file"`
	Line     int    `json:"line"`
}

// Entries converts the call chain steps into JSON-serializable CallChainEntry values.
func (cc CallChain) Entries() []CallChainEntry {
	entries := make([]CallChainEntry, len(cc.Steps))
	for i, step := range cc.Steps {
		entries[i] = CallChainEntry{
			Function: step.Function.String(),
			FilePath: step.FilePath,
			Line:     step.Line,
		}
	}
	return entries
}

// String returns a human-readable representation of the call chain.
// Example: "main.Encrypt() -> chacha20poly1305.New() -> cipher.NewGCM()".
func (cc CallChain) String() string {
	parts := make([]string, len(cc.Steps))
	for i, step := range cc.Steps {
		parts[i] = step.Function.String() + "()"
	}
	return strings.Join(parts, " -> ")
}
