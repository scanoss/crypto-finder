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

// clinitMethodName names the synthetic function that represents a Java class's
// static initialization context — its `static { ... }` blocks and its
// initialized static `field_declaration` values. Mirrors the JVM `<clinit>`
// method.
const clinitMethodName = "<clinit>"

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
		return f.Package + ".(" + f.Type + ")." + f.Name
	}
	return f.Package + "." + f.Name
}

// InferredReturn carries the result of static return-type inference for a function.
// Fields mirror what the export layer surfaces, plus the internal-only join-failed origin.
// The join-failed origin is never emitted in exported output; when a join fails the
// entire field is omitted.
type InferredReturn struct {
	// Type is the inferred fully-qualified return type name, e.g. "javax.crypto.SecretKey".
	Type string
	// TypeRef is the structured generic form when applicable; zero value when none.
	TypeRef TypeRef
	// Confidence is the inference confidence level: "high", "medium", or "low".
	Confidence string
	// Origin is one of: "constructor", "kb-direct", "kb-conditional", "propagated",
	// or the internal-only "join-failed" (never exported).
	Origin string
	// Provenance is the recursive provenance chain (subset of ReturnSources, normalised).
	Provenance []SourceNode
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
	// ReturnSources traces where return values originate when the parser supports it.
	ReturnSources []SourceNode
	// InferredReturn is the result of the post-build inference pass; nil when no inference fires.
	InferredReturn *InferredReturn
	// OwnerBases holds the direct base class names as declared in the source
	// (e.g. ["PKey"] for "class RSAKey(PKey):"). Populated by the Python parser;
	// always nil for Java/Go/Rust declarations. Used by expandPythonSubclassDispatch
	// to expand a base-class call site to its concrete subclass overrides.
	OwnerBases []string
}

// FunctionParameter describes a declared function parameter.
type FunctionParameter struct {
	Type    string
	TypeRef TypeRef
	// Name is the declared parameter name (e.g. "hashingFunction"), when the
	// parser captures it (1.6+ / Java only as of introduction). Empty for
	// ecosystems whose parser does not populate it — callers that key off Name
	// (e.g. parameter pass-through dispatch resolution) simply find no match and
	// degrade to the prior behavior.
	Name string
}

// FunctionCall represents a call expression within a function body.
type FunctionCall struct {
	// Callee is the resolved target function
	Callee FunctionID
	// ReceiverVar preserves the original receiver variable name for selector calls
	// like `cipher.Encrypt()` when static type information is incomplete.
	ReceiverVar string
	// AssignedVar is the local variable this call's result is bound to, e.g.
	// "digest" in `SHA3Digest digest = new SHA3Digest(256)`. Empty when the call
	// result is not assigned to a variable. For fluent chains only the chain root
	// (the outermost call) carries AssignedVar. Used to resolve the identity of a
	// crypto object when deriving its lifecycle/supporting calls.
	AssignedVar string
	// ChainID groups the links of a single fluent method chain such as
	// `Password.hash(p).addRandomSalt().withBcrypt()`. All invocations belonging
	// to the same chain share a non-empty ChainID; standalone calls leave it
	// empty. Used to enumerate the supporting links of a chain-rooted finding.
	ChainID string
	// Raw is the raw call expression text (e.g., "aes.NewCipher")
	Raw string
	// FilePath is the file containing this call
	FilePath string
	// Line is the line number of the call
	Line int
	// StartCol is the 1-based start column (inclusive) of this call expression.
	// 0 when the parser is not column-aware — triggers line-only fallback.
	// Converted from tree-sitter 0-based columns at the parser boundary by +1.
	StartCol int
	// EndCol is the 1-based end column (exclusive) of this call expression.
	// 0 when unknown. Mirrors the opengrep/semgrep convention: exclusive end.
	EndCol int
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
	FromImports           map[string]bool   // symbols introduced via `from X import Y` (Python only)
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
	// EdgeResolutions records how each caller->callee call-site/dispatch variant
	// was resolved. Keyed by EdgeResolutionKey(callerKey, calleeKey, resolution).
	// An edge with no entry is an exact, directly-resolved source call. Consumers
	// use this to refuse to present over-broad name/arity dispatch guesses as
	// typed reachability proof. Values carry their caller/callee endpoints
	// (EdgeResolutionEndpoints), so per-pair views are one O(E) pass away —
	// see internal/scan's indexFragmentEdgeResolutions.
	EdgeResolutions map[string]EdgeResolution
}

// EdgeKind classifies how confidently a caller->callee edge was resolved.
type EdgeKind string

const (
	// EdgeKindExact means the receiver's static type was known and the method
	// resolved to a unique declared target (or an overload on that exact type).
	EdgeKindExact EdgeKind = "exact"
	// EdgeKindInterfaceDispatch is a synthesized edge from an interface/abstract
	// method call site to a concrete implementation matched by name+arity within
	// a namespace root.
	EdgeKindInterfaceDispatch EdgeKind = "interface_dispatch"
	// EdgeKindNameOnly is a fluent-fallback edge matched by method name+arity (and
	// namespace heuristics) with no receiver type anchor.
	EdgeKindNameOnly EdgeKind = "name_only"
	// EdgeKindPythonSubclassDispatch is a synthesized edge from a base-class method
	// call site to a concrete subclass override. Populated by expandPythonSubclassDispatch
	// using OwnerBases declared in the Python source. Python-only; Java dispatch uses
	// EdgeKindInterfaceDispatch instead.
	EdgeKindPythonSubclassDispatch EdgeKind = "python_subclass_dispatch"
)

// edgeKindRank orders kinds by trust so a stronger classification is never
// downgraded when the same edge is reached via multiple resolution paths.
func edgeKindRank(k EdgeKind) int {
	switch k {
	case EdgeKindExact:
		return 3
	case EdgeKindInterfaceDispatch:
		return 2
	case EdgeKindPythonSubclassDispatch:
		return 2
	case EdgeKindNameOnly:
		return 1
	default:
		return 0
	}
}

// EdgeResolution describes how one caller->callee edge was resolved, plus the
// call-site identity needed to group ambiguous dispatch siblings downstream.
type EdgeResolution struct {
	Kind         EdgeKind
	DeclaredType string // interface/static type for dispatch edges (e.g. "dep.Sink")
	MethodName   string // base method name (no arity decoration)
	Arity        int
	CallSite     int // source line of the call expression
	StartCol     int // 1-based, inclusive; 0 when the parser is not column-aware
	EndCol       int // 1-based, exclusive; 0 when unknown
	callerKey    string
	calleeKey    string

	// ResolvedReceiverType is the concrete receiver type resolveParameterPassthroughDispatch
	// determined for THIS specific dispatch edge, when the call site is a
	// single-use pass-through parameter and the calling context supplied a
	// statically concrete argument (e.g. password4j's
	// `with(AlgorithmFinder.getPBKDF2Instance())` calling into
	// `with(HashingFunction h) { h.hash(...) }`). Empty when no such resolution
	// applies. Exported verbatim as graph-fragment resolved_receiver_type so the
	// stitcher can disambiguate a dispatch group at serve time.
	ResolvedReceiverType string
}

// EdgeResolutionKey is the stable map key for one resolved caller->callee
// call-site/dispatch variant.
func EdgeResolutionKey(callerKey, calleeKey string, resolution EdgeResolution) string {
	return EdgeResolutionKeyPrefix(callerKey, calleeKey) +
		strconv.Itoa(resolution.CallSite) + "\x00" +
		strconv.Itoa(resolution.StartCol) + "\x00" +
		strconv.Itoa(resolution.EndCol) + "\x00" +
		resolution.DeclaredType + "\x00" +
		resolution.MethodName + "\x00" +
		strconv.Itoa(resolution.Arity)
}

// EdgeResolutionKeyPrefix returns the stable prefix shared by all resolution
// variants for one caller->callee pair.
func EdgeResolutionKeyPrefix(callerKey, calleeKey string) string {
	return callerKey + "\x00" + calleeKey + "\x00"
}

// EdgeResolutionEndpoints returns the caller/callee pair for a stored edge
// resolution. Values recorded by this package carry endpoints directly so
// large export paths do not need to repeatedly split the map key; hand-built
// tests or older in-memory fixtures still fall back to parsing the key.
func EdgeResolutionEndpoints(key string, resolution EdgeResolution) (callerKey, calleeKey string, ok bool) {
	if resolution.callerKey != "" && resolution.calleeKey != "" {
		return resolution.callerKey, resolution.calleeKey, true
	}
	parts := strings.SplitN(key, "\x00", 3)
	if len(parts) < 3 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// functionArity parses the "#<n>" arity suffix from a decorated function name.
// Returns 0 when the name carries no arity suffix.
func functionArity(name string) int {
	idx := strings.Index(name, "#")
	if idx < 0 || idx >= len(name)-1 {
		return 0
	}
	n := 0
	for j := idx + 1; j < len(name) && name[j] >= '0' && name[j] <= '9'; j++ {
		n = n*10 + int(name[j]-'0')
	}
	return n
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
