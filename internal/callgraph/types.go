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
// It exposes split symbol fields and optional parameter/argument bindings suitable
// for downstream ingestion.
type CallChainEntry struct {
	FunctionName string               `json:"function_name"`
	Namespace    string               `json:"namespace,omitempty"`
	FilePath     string               `json:"file"`
	Line         int                  `json:"line"`
	OwnerType    string               `json:"owner_type,omitempty"`
	OwnerName    string               `json:"owner_name,omitempty"`
	FunctionType string               `json:"function_type,omitempty"`
	ReturnType   string               `json:"return_type,omitempty"`
	Parameters   []CallChainParameter `json:"parameters,omitempty"`
}

// CallChainParameter represents a parameter in a call chain node.
type CallChainParameter struct {
	Type          string `json:"type,omitempty"`
	ArgumentValue string `json:"argument_value,omitempty"`
}

// Entries converts the call chain steps into JSON-serializable CallChainEntry values.
func (cc CallChain) Entries(graph *CallGraph) []CallChainEntry {
	entries := make([]CallChainEntry, len(cc.Steps))
	for i, step := range cc.Steps {
		entry := CallChainEntry{
			FunctionName: step.Function.Name,
			Namespace:    step.Function.Package,
			FilePath:     step.FilePath,
			Line:         step.Line,
		}

		if graph != nil {
			if fn, ok := graph.Functions[step.Function.String()]; ok {
				entry.OwnerType = fn.OwnerType
				entry.OwnerName = fn.OwnerName
				if entry.OwnerName == "" {
					entry.OwnerName = fn.ID.Type
				}
				entry.FunctionType = fn.FunctionType
				entry.ReturnType = fn.ReturnType
				entry.Parameters = mergeDeclAndCallParameters(fn.Parameters, nil)
			}
		}

		// Fallback owner metadata when declaration data isn't available.
		if entry.OwnerName == "" && step.Function.Type != "" {
			entry.OwnerName = step.Function.Type
		}

		if i > 0 {
			args := cc.findInvocationArgs(graph, i)
			entry.Parameters = mergeDeclAndCallParameters(toDeclaredParameters(entry.Parameters), args)
		}

		entry.Parameters = compactParameters(entry.Parameters)
		entries[i] = CallChainEntry{
			FunctionName: entry.FunctionName,
			Namespace:    entry.Namespace,
			FilePath:     entry.FilePath,
			Line:         entry.Line,
			OwnerType:    entry.OwnerType,
			OwnerName:    entry.OwnerName,
			FunctionType: entry.FunctionType,
			ReturnType:   entry.ReturnType,
			Parameters:   entry.Parameters,
		}
	}
	return entries
}

func (cc CallChain) findInvocationArgs(graph *CallGraph, index int) []string {
	if graph == nil || index <= 0 || index >= len(cc.Steps) {
		return nil
	}

	prevStep := cc.Steps[index-1]
	currStep := cc.Steps[index]

	prevFn, ok := graph.Functions[prevStep.Function.String()]
	if !ok {
		return nil
	}

	calleeKey := currStep.Function.String()
	var fallback []string
	for _, call := range prevFn.Calls {
		if call.Callee.String() != calleeKey {
			continue
		}
		if call.Line == prevStep.Line {
			return call.Arguments
		}
		if fallback == nil {
			fallback = call.Arguments
		}
	}

	return fallback
}

func mergeDeclAndCallParameters(declared []FunctionParameter, args []string) []CallChainParameter {
	size := len(declared)
	if len(args) > size {
		size = len(args)
	}
	if size == 0 {
		return nil
	}

	result := make([]CallChainParameter, size)
	for i := range declared {
		result[i].Type = strings.TrimSpace(declared[i].Type)
	}
	for i := range args {
		arg := strings.TrimSpace(args[i])
		if arg == "" {
			continue
		}
		result[i].ArgumentValue = arg
	}
	return result
}

func toDeclaredParameters(params []CallChainParameter) []FunctionParameter {
	if len(params) == 0 {
		return nil
	}
	declared := make([]FunctionParameter, len(params))
	for i, p := range params {
		declared[i] = FunctionParameter{Type: p.Type}
	}
	return declared
}

func compactParameters(params []CallChainParameter) []CallChainParameter {
	if len(params) == 0 {
		return nil
	}
	compacted := make([]CallChainParameter, 0, len(params))
	for _, p := range params {
		if strings.TrimSpace(p.Type) == "" && strings.TrimSpace(p.ArgumentValue) == "" {
			continue
		}
		compacted = append(compacted, p)
	}
	if len(compacted) == 0 {
		return nil
	}
	return compacted
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
