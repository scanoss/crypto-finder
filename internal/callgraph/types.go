// Package callgraph provides function-level call graph construction and
// backward tracing for linking cryptographic findings in dependencies
// back to user code entry points.
package callgraph

import (
	"fmt"
	"strings"
)

const constructorMethodName = "<init>"

// Java visibility values exported in call graph metadata.
const (
	VisibilityPublic         = "public"
	VisibilityProtected      = "protected"
	VisibilityPrivate        = "private"
	VisibilityPackagePrivate = "package-private"
)

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

// StrictResolver reports whether resolver failures should fail the graph build
// instead of being downgraded to a warning.
type StrictResolver interface {
	StrictFailure() bool
}

// TypeRef describes a type reference, optionally carrying nested generic
// parameters. Name holds the erased type name (e.g. "Map", "byte[]"), while
// GenericParameters captures parametrized type arguments recursively (e.g.
// Map<String, List<Foo>> → Name="Map", GenericParameters=[
//
//	{Name:"String"},
//	{Name:"List", GenericParameters:[{Name:"Foo"}]}]).
type TypeRef struct {
	Name              string
	GenericParameters []TypeRef
}

// HasGenerics reports whether the TypeRef carries any generic parameters.
func (t TypeRef) HasGenerics() bool {
	return len(t.GenericParameters) > 0
}

func cloneTypeRef(t TypeRef) TypeRef {
	return TypeRef{
		Name:              t.Name,
		GenericParameters: cloneTypeRefs(t.GenericParameters),
	}
}

func cloneTypeRefs(refs []TypeRef) []TypeRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]TypeRef, len(refs))
	for i, r := range refs {
		out[i] = cloneTypeRef(r)
	}
	return out
}

// ExternalMethodSignature stores resolver-derived signature data for methods that
// may not have a source-backed FunctionDecl in the graph.
type ExternalMethodSignature struct {
	ParameterTypes    []string
	ReturnType        string
	ParameterTypeRefs []TypeRef
	ReturnTypeRef     TypeRef
}

// JavaPlatformSignatureMetadata records whether Java platform signatures from a
// pinned runtime were available and used during type enrichment.
type JavaPlatformSignatureMetadata struct {
	RequestedMajor    string
	RuntimeVersion    string
	SignaturesUsed    bool
	SignatureSource   string
	UnavailableReason string
}

// BaseFunctionName strips the Java/Go arity suffix and any overload decoration
// from a function name.
// For example, "encrypt#1" returns "encrypt", and
// "signWith#2$SignatureAlgorithm,byte[]" returns "signWith".
func BaseFunctionName(name string) string {
	arityKey := methodArityKey(name)
	idx := strings.Index(arityKey, "#")
	if idx <= 0 {
		return name
	}
	return arityKey[:idx]
}

// methodArityKey extracts the stable "<name>#<arity>" prefix from a decorated
// function name. If the name is not arity-qualified, it returns the original
// input unchanged.
func methodArityKey(name string) string {
	idx := strings.Index(name, "#")
	if idx <= 0 || idx >= len(name)-1 {
		return name
	}

	j := idx + 1
	for j < len(name) && name[j] >= '0' && name[j] <= '9' {
		j++
	}
	if j == idx+1 {
		return name
	}
	return name[:j]
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

// FunctionDecl represents a function or method declaration with its location and outgoing calls.
type FunctionDecl struct {
	ID              FunctionID
	FilePath        string
	StartLine       int
	EndLine         int
	OwnerType       string
	OwnerName       string
	FunctionType    string
	ReturnType      string
	ReturnTypeRef   TypeRef
	Visibility      string
	OwnerVisibility string
	Parameters      []FunctionParameter
	Calls           []FunctionCall
}

// FunctionParameter describes a declared function parameter.
type FunctionParameter struct {
	Type    string
	TypeRef TypeRef
}

// FunctionCall represents a call expression within a function body.
type FunctionCall struct {
	// Callee is the resolved target function
	Callee FunctionID
	// ReceiverVar preserves the original receiver variable name for selector calls
	// like `cipher.Encrypt()` when static type information is incomplete.
	ReceiverVar string
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
	FilePath              string
	PackageName           string
	PackagePath           string
	Imports               map[string]string // alias (or last path segment) -> full import path
	ImportedTypes         map[string]bool   // imported symbol alias -> inferred class/type
	WildcardImports       []string          // wildcard import prefixes (e.g., "java.security")
	StaticWildcardImports []string          // static wildcard owner types (e.g., "java.util.Collections")
	Functions             []FunctionDecl
}

// CallGraph is the complete call graph across all analyzed packages.
type CallGraph struct {
	// Functions maps FunctionID.String() to its declaration
	Functions map[string]*FunctionDecl
	// Callers maps callee FunctionID.String() to list of caller FunctionID.String()
	// This is the reverse index for walking backwards from a crypto finding.
	Callers map[string][]string
	// TypeHierarchy maps a fully qualified type name to its fully qualified parent
	// interfaces/superclasses. E.g., "io.jsonwebtoken.JwtBuilder" →
	// ["io.jsonwebtoken.ClaimsMutator"]. Populated by TypeResolver from bytecode.
	TypeHierarchy map[string][]string
	// ExternalMethodSignatures stores resolver-derived signatures for methods that
	// are known to the graph by symbol but do not have a source declaration.
	// Keyed by fully qualified method + arity via ExternalMethodSignatureKey.
	ExternalMethodSignatures map[string][]ExternalMethodSignature
	// JavaPlatformSignatures records whether Java platform signatures from the
	// pinned runtime were available and used for this graph build.
	JavaPlatformSignatures *JavaPlatformSignatureMetadata
}

// ExternalMethodSignatureKey returns the stable graph key for resolver-provided
// method signatures. The key normalizes overload decoration down to name+arity.
func ExternalMethodSignatureKey(id FunctionID) string {
	return qualifiedMethodArityKey(id.Package, id.Type, id.Name)
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
// ParseFunctionID splits plain function identifiers at the last "." in the input,
// treating everything before that point as the package or fully-qualified class
// name and everything after it as the function name. Go package paths may contain
// "/" before that final ".", while Java package and class names use "." throughout.
func ParseFunctionID(s string) (FunctionID, error) {
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
		if pkg == "" || typ == "" || name == "" {
			return FunctionID{}, fmt.Errorf("invalid function ID: malformed method components in %q", s)
		}

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
