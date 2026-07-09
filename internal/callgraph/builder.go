package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

const (
	ownerTypeInterface = "interface"
	ownerTypeClass     = "class"
	javaStringType     = "String"
	// ecosystemPython is the ecosystem identifier for Python callgraphs.
	// Used to gate Python-specific dispatch (e.g. expandPythonSubclassDispatch).
	ecosystemPython = "python"
)

// Parser extracts function declarations, calls, and imports from source files
// in a language-specific way. Each supported language implements this interface.
type Parser interface {
	// ParseDirectory parses all relevant source files in dir.
	// packagePath is the canonical namespace (Go import path, Java package, etc.).
	ParseDirectory(dir string, packagePath string) ([]*FileAnalysis, error)
	// SkipDirs returns directory names to skip during recursive traversal.
	SkipDirs() map[string]bool
	// SubPackagePath constructs a child package path from parent + directory name.
	SubPackagePath(parentPath, dirName string) string
	// PackageSeparator returns the separator used in package paths ("/" for Go, "." for Java).
	PackageSeparator() string
}

// PackageDir associates a filesystem directory with its package/module path.
type PackageDir struct {
	Dir                  string // Absolute filesystem path
	ImportPath           string // Package/module path (e.g., "crypto/aes" or "javax.crypto")
	Version              string // Dependency version when applicable (e.g., "1.2.3")
	CompiledArtifactPath string // Absolute path to a compiled artifact for type-only resolution
}

// Builder constructs a CallGraph from multiple packages using a language-specific parser.
type Builder struct {
	parser       Parser
	typeResolver TypeResolver
	// ecosystem identifies which embedded contract KB to load during BuildFromDirectories.
	// Defaults to "java" for backward compatibility with NewBuilder.
	ecosystem string
}

// NewBuilder creates a new call graph builder with the given parser.
// Uses the "java" ecosystem KB for backward compatibility.
// An optional TypeResolver can be set via SetTypeResolver for language-native
// type resolution (bytecode analysis, go/types, etc.).
func NewBuilder(parser Parser) *Builder {
	return NewBuilderForEcosystem("java", parser)
}

// NewBuilderForEcosystem creates a new call graph builder for the given ecosystem.
// The ecosystem string controls which embedded contract KB is loaded during
// BuildFromDirectories (e.g. "java", "python"). An empty or unknown ecosystem
// results in an empty KB (no contracts), which is valid and does not produce an error.
func NewBuilderForEcosystem(ecosystem string, parser Parser) *Builder {
	return &Builder{
		parser:    parser,
		ecosystem: ecosystem,
	}
}

// SetTypeResolver configures the builder to use a language-specific type resolver
// after tree-sitter parsing. This enriches the call graph with full type information.
func (b *Builder) SetTypeResolver(resolver TypeResolver) {
	b.typeResolver = resolver
}

// PackageSeparator exposes the parser's package separator for use by the tracer.
func (b *Builder) PackageSeparator() string {
	return b.parser.PackageSeparator()
}

// BuildFromDirectories analyzes source files and builds a call graph.
//
// Two-phase approach for performance:
//   - packages: get full source parsing (user code + deps with findings)
//   - typeOnlyPackages: used only for bytecode type indexing (no source parsing),
//     preserving type resolution accuracy for fluent chains across dependency boundaries
func (b *Builder) BuildFromDirectories(packages, typeOnlyPackages []PackageDir) (*CallGraph, error) {
	buildStart := time.Now()
	graph := &CallGraph{
		Functions:             make(map[string]*FunctionDecl),
		Callers:               make(map[string][]string),
		EdgeResolutions:       make(map[string]EdgeResolution),
		EdgeResolutionsByPair: make(map[string][]EdgeResolution),
	}

	// Phase 1: Parse source files only for packages that need full analysis
	sourceParseStart := time.Now()
	log.Info().Int("packages", len(packages)).Msg("Parsing source files for call graph")
	for _, pkg := range packages {
		if err := b.analyzePackage(pkg, graph); err != nil {
			log.Debug().Err(err).Str("package", pkg.ImportPath).Msg("Failed to analyze package")
			continue
		}
	}
	sourceParseDuration := time.Since(sourceParseStart)

	log.Info().Int("functions", len(graph.Functions)).Msg("Source parsing complete, building caller index")

	// Build the reverse caller index (includes interface dispatch and fluent fallback)
	callerIndexStart := time.Now()
	b.buildCallerIndex(graph)
	callerIndexDuration := time.Since(callerIndexStart)

	// Phase 2: Type resolution from bytecode — index ALL packages (including type-only)
	// so that fluent chain resolution has complete type information across all deps.
	var typeResolutionDuration time.Duration
	if b.typeResolver != nil {
		allPackages := make([]PackageDir, 0, len(packages)+len(typeOnlyPackages))
		allPackages = append(allPackages, packages...)
		allPackages = append(allPackages, typeOnlyPackages...)
		log.Info().Int("typePackages", len(allPackages)).Msg("Resolving types from bytecode")
		typeResolutionStart := time.Now()
		if err := b.typeResolver.ResolveTypes(graph, allPackages); err != nil {
			if strictResolver, ok := b.typeResolver.(StrictResolver); ok && strictResolver.StrictFailure() {
				return nil, fmt.Errorf("type resolver failed: %w", err)
			}
			log.Warn().Err(err).Msg("Type resolver encountered errors (continuing with partial resolution)")
		}
		typeResolutionDuration = time.Since(typeResolutionStart)
	}

	// Resolve fluent chain calls using return type propagation (benefits from type resolver enrichment)
	fluentResolutionStart := time.Now()
	resolveFluentChainsByReturnType(graph)
	fluentResolutionDuration := time.Since(fluentResolutionStart)

	// Post-build pass: infer semantic return types using the embedded JCA/JCE KB.
	// This is language-agnostic — it operates on ReturnSources populated by parsers.
	// In v1, only the Java parser populates ReturnSources; for other ecosystems the
	// pass is a no-op since no function will have ReturnSources set.
	inferenceStart := time.Now()
	kb, err := contracts.LoadEmbedded(b.ecosystem)
	if err != nil {
		return nil, fmt.Errorf("callgraph: load embedded %s KB: %w", b.ecosystem, err)
	}
	if err := InferReturnTypes(graph, kb); err != nil {
		return nil, fmt.Errorf("callgraph: infer return types: %w", err)
	}
	// Correct fluent-chain link callees using KB return-type propagation. Runs
	// after the KB is loaded so chains rooted at a library call (e.g.
	// Password.hash(p).addRandomSalt().withBcrypt()) resolve their intermediate
	// links through the contract KB instead of mis-guessing against wildcard
	// imports. resolveFluentChainsByReturnType (above) only propagates in-graph
	// return types and runs before the KB is available.
	resolveFluentChainCalleesByContract(graph, kb)

	// Resolve single-argument pass-through dispatch: a call site whose
	// interface-typed parameter is used, unmodified, as the sole receiver of an
	// otherwise-ambiguous interface-dispatch call inside the callee's body.
	// When a caller of that callee passes a statically concrete argument (a
	// constructor call, or a call whose declared/inferred return type is
	// concrete), the ambiguity is resolvable FOR THAT CALLER even though the
	// dispatch call site itself is shared by every caller of the callee. Runs
	// after inference so both declared and KB-inferred return types are
	// available. See resolveParameterPassthroughDispatch for the full contract.
	resolveParameterPassthroughDispatch(graph)
	inferenceDuration := time.Since(inferenceStart)

	log.Info().
		Int("functions", len(graph.Functions)).
		Int("callees", len(graph.Callers)).
		Dur("source_parse_duration", sourceParseDuration).
		Dur("caller_index_duration", callerIndexDuration).
		Dur("type_resolution_duration", typeResolutionDuration).
		Dur("fluent_resolution_duration", fluentResolutionDuration).
		Dur("inference_duration", inferenceDuration).
		Dur("total_duration", time.Since(buildStart)).
		Msg("Built call graph")

	return graph, nil
}

// analyzePackage parses all source files in a package directory,
// recursing into subdirectories to handle sub-packages.
func (b *Builder) analyzePackage(pkg PackageDir, graph *CallGraph) error {
	return b.analyzeDir(pkg.Dir, pkg.ImportPath, graph)
}

func (b *Builder) analyzeDir(dir, importPath string, graph *CallGraph) error {
	analyses, err := b.parser.ParseDirectory(dir, importPath)
	if err != nil {
		return err
	}

	b.addAnalyses(graph, analyses)
	b.analyzeSubdirs(dir, importPath, graph)
	return nil
}

func (b *Builder) addAnalyses(graph *CallGraph, analyses []*FileAnalysis) {
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			fn := &analysis.Functions[i]
			key := fn.ID.String()
			if existing, ok := graph.Functions[key]; ok {
				if keepExistingDecl(existing, fn) {
					continue
				}
				if b.preservePythonModuleCollision(graph, existing, fn) {
					continue
				}
			}
			graph.Functions[key] = fn
		}
	}
}

func (b *Builder) analyzeSubdirs(dir, importPath string, graph *CallGraph) {
	// Recurse into subdirectories
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		log.Debug().Err(readErr).Str("dir", dir).Msg("Failed to read directory during call graph traversal")
	}

	skipDirs := b.parser.SkipDirs()

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") || skipDirs[name] {
			continue
		}
		subDir := filepath.Join(dir, name)
		subImportPath := b.parser.SubPackagePath(importPath, name)
		if err := b.analyzeDir(subDir, subImportPath, graph); err != nil {
			log.Debug().Err(err).Str("dir", subDir).Msg("Failed to analyze subdirectory")
		}
	}
}

func keepExistingDecl(existing, candidate *FunctionDecl) bool {
	return isPythonStubPath(candidate.FilePath) && !isPythonStubPath(existing.FilePath)
}

func isPythonStubPath(path string) bool {
	return strings.HasSuffix(path, ".pyi")
}

func (b *Builder) preservePythonModuleCollision(graph *CallGraph, existing, candidate *FunctionDecl) bool {
	if b.ecosystem != ecosystemPython {
		return false
	}
	if isPythonStubPath(existing.FilePath) || isPythonStubPath(candidate.FilePath) {
		return false
	}

	existingStem := pythonModuleFileStem(existing.FilePath)
	candidateStem := pythonModuleFileStem(candidate.FilePath)
	if existingStem == "" || candidateStem == "" || existingStem == candidateStem {
		return false
	}

	addPythonModuleAlias(graph, existing, existingStem)
	addPythonModuleAlias(graph, candidate, candidateStem)
	return true
}

func addPythonModuleAlias(graph *CallGraph, fn *FunctionDecl, stem string) {
	alias := *fn
	if !strings.HasSuffix(alias.ID.Package, "."+stem) {
		alias.ID.Package = alias.ID.Package + "." + stem
	}
	graph.Functions[alias.ID.String()] = &alias
}

func pythonModuleFileStem(path string) string {
	ext := filepath.Ext(path)
	if ext != ".py" {
		return ""
	}
	stem := strings.TrimSuffix(filepath.Base(path), ext)
	if stem == "" || stem == "__init__" {
		return ""
	}
	return stem
}

// buildCallerIndex builds the reverse index: for each callee, which functions call it.
func (b *Builder) buildCallerIndex(graph *CallGraph) {
	idx := dispatchIndexes{
		methodsByName:           indexMethodsByName(graph),
		methodsByQualifiedArity: indexMethodsByQualifiedArity(graph),
		subclassByTypeName:      indexSubclassByTypeName(graph),
		knownClassTypes:         indexKnownClassTypes(graph),
		interfaceDispatchMemo:   make(map[string][]interfaceDispatchAlias),
		abstractDispatchMemo:    make(map[string][]interfaceDispatchAlias),
		callerSeen:              make(map[string]map[string]struct{}),
	}

	for callerKey, fn := range graph.Functions {
		for i := range fn.Calls {
			b.indexCallDispatch(graph, callerKey, fn.Calls[i], idx)
		}
	}
}

// dispatchIndexes bundles the lookup tables buildCallerIndex needs to expand
// one call site into all of its dispatch aliases (overloads, interface/abstract
// virtual dispatch, Python subclass dispatch, fluent fallback).
//
// interfaceDispatchMemo/abstractDispatchMemo cache expansion results per callee
// target: both expansions depend only on the target and the (immutable during
// buildCallerIndex) graph/index state, while popular targets are re-expanded
// once per call site — on dispatch-heavy corpora such as bcprov the same
// interface method is expanded thousands of times. A nil slice is a valid
// cached value, so presence is tracked with the two-value map lookup.
//
// callerSeen mirrors graph.Callers as callee → set-of-callers so the hot path
// can dedup in O(1) instead of addCaller's linear scan over fan-in slices.
// Only buildCallerIndex uses it; later passes call addCaller at low volume.
type dispatchIndexes struct {
	methodsByName           map[string][]*FunctionDecl
	methodsByQualifiedArity map[string][]string
	subclassByTypeName      map[string][]*FunctionDecl
	knownClassTypes         map[string]bool
	interfaceDispatchMemo   map[string][]interfaceDispatchAlias
	abstractDispatchMemo    map[string][]interfaceDispatchAlias
	callerSeen              map[string]map[string]struct{}
}

// addCallerIndexed is addCaller's O(1) equivalent for the buildCallerIndex hot
// path, backed by the dispatchIndexes.callerSeen set. Semantics are identical:
// append callerKey to callers[calleeKey] unless already present.
func (idx dispatchIndexes) addCallerIndexed(callers map[string][]string, calleeKey, callerKey string) {
	set := idx.callerSeen[calleeKey]
	if set == nil {
		set = make(map[string]struct{}, 4)
		idx.callerSeen[calleeKey] = set
	}
	if _, dup := set[callerKey]; dup {
		return
	}
	set[callerKey] = struct{}{}
	callers[calleeKey] = append(callers[calleeKey], callerKey)
}

func (idx dispatchIndexes) expandInterfaceDispatchMemoized(b *Builder, calleeKey string, graph *CallGraph) []interfaceDispatchAlias {
	if aliases, ok := idx.interfaceDispatchMemo[calleeKey]; ok {
		return aliases
	}
	aliases := b.expandInterfaceDispatch(calleeKey, graph, idx.methodsByName)
	idx.interfaceDispatchMemo[calleeKey] = aliases
	return aliases
}

func (idx dispatchIndexes) expandAbstractClassDispatchMemoized(b *Builder, callee FunctionID, calleeKey string, graph *CallGraph) []interfaceDispatchAlias {
	if aliases, ok := idx.abstractDispatchMemo[calleeKey]; ok {
		return aliases
	}
	aliases := b.expandAbstractClassDispatch(callee, graph, idx.methodsByName, idx.knownClassTypes)
	idx.abstractDispatchMemo[calleeKey] = aliases
	return aliases
}

// indexCallDispatch records the direct edge for one call site plus every
// synthesized dispatch alias (overloads, interface/abstract virtual dispatch,
// Python subclass dispatch, fluent fallback), each with its own edge
// classification.
func (b *Builder) indexCallDispatch(graph *CallGraph, callerKey string, call FunctionCall, idx dispatchIndexes) {
	calleeKey := call.Callee.String()
	idx.addCallerIndexed(graph.Callers, calleeKey, callerKey)
	recordEdgeResolution(graph, callerKey, calleeKey, EdgeKindExact, "", call.Line)

	overloadTargets := b.expandOverloadCandidates(call.Callee, idx.methodsByQualifiedArity)
	resolvedTargets := make([]string, 1, 1+len(overloadTargets))
	resolvedTargets[0] = calleeKey
	for _, target := range overloadTargets {
		idx.addCallerIndexed(graph.Callers, target, callerKey)
		recordEdgeResolution(graph, callerKey, target, EdgeKindExact, "", call.Line)
		resolvedTargets = append(resolvedTargets, target)
	}

	for _, target := range resolvedTargets {
		for _, alias := range idx.expandInterfaceDispatchMemoized(b, target, graph) {
			idx.addCallerIndexed(graph.Callers, alias.CalleeKey, callerKey)
			recordEdgeResolution(graph, callerKey, alias.CalleeKey, EdgeKindInterfaceDispatch, alias.DeclaredType, call.Line)
		}
		for _, alias := range b.expandPythonSubclassDispatch(target, graph, idx.subclassByTypeName) {
			idx.addCallerIndexed(graph.Callers, alias.CalleeKey, callerKey)
			recordEdgeResolution(graph, callerKey, alias.CalleeKey, EdgeKindPythonSubclassDispatch, alias.DeclaredType, call.Line)
		}
	}

	for _, alias := range idx.expandAbstractClassDispatchMemoized(b, call.Callee, calleeKey, graph) {
		idx.addCallerIndexed(graph.Callers, alias.CalleeKey, callerKey)
		recordEdgeResolution(graph, callerKey, alias.CalleeKey, EdgeKindInterfaceDispatch, alias.DeclaredType, call.Line)
	}

	for _, alias := range b.expandFluentFallback(call, graph, idx.methodsByName) {
		idx.addCallerIndexed(graph.Callers, alias, callerKey)
		recordEdgeResolution(graph, callerKey, alias, EdgeKindNameOnly, "", call.Line)
	}
}

// recordEdgeResolution stores how a caller->callee edge was resolved, keeping
// the highest-trust classification when the same edge is reached via multiple
// paths (a direct exact call must never be downgraded to a dispatch guess).
// MethodName and Arity are derived from the callee key so dispatch siblings of
// one call site share a stable grouping identity downstream.
func recordEdgeResolution(graph *CallGraph, callerKey, calleeKey string, kind EdgeKind, declaredType string, callSite int) {
	if graph.EdgeResolutions == nil {
		graph.EdgeResolutions = make(map[string]EdgeResolution)
	}
	method, arity := "", 0
	if calleeID, err := ParseFunctionID(calleeKey); err == nil {
		method = BaseFunctionName(calleeID.Name)
		arity = functionArity(calleeID.Name)
	}
	resolution := EdgeResolution{
		Kind:         kind,
		DeclaredType: declaredType,
		MethodName:   method,
		Arity:        arity,
		CallSite:     callSite,
		callerKey:    callerKey,
		calleeKey:    calleeKey,
	}
	key := EdgeResolutionKey(callerKey, calleeKey, resolution)
	if existing, ok := graph.EdgeResolutions[key]; ok {
		if edgeKindRank(existing.Kind) >= edgeKindRank(kind) {
			return
		}
		graph.EdgeResolutions[key] = resolution
		upsertEdgeResolutionByPair(graph, callerKey, calleeKey, resolution)
		return
	}
	graph.EdgeResolutions[key] = resolution
	upsertEdgeResolutionByPair(graph, callerKey, calleeKey, resolution)
}

func upsertEdgeResolutionByPair(graph *CallGraph, callerKey, calleeKey string, resolution EdgeResolution) {
	if graph.EdgeResolutionsByPair == nil {
		graph.EdgeResolutionsByPair = make(map[string][]EdgeResolution)
	}
	pairKey := EdgeResolutionPairKey(callerKey, calleeKey)
	values := graph.EdgeResolutionsByPair[pairKey]
	for i := range values {
		if sameEdgeResolutionVariant(values[i], resolution) {
			values[i] = resolution
			graph.EdgeResolutionsByPair[pairKey] = values
			return
		}
	}
	graph.EdgeResolutionsByPair[pairKey] = append(values, resolution)
}

func sameEdgeResolutionVariant(a, b EdgeResolution) bool {
	return a.CallSite == b.CallSite &&
		a.DeclaredType == b.DeclaredType &&
		a.MethodName == b.MethodName &&
		a.Arity == b.Arity
}

func indexMethodsByName(graph *CallGraph) map[string][]*FunctionDecl {
	index := make(map[string][]*FunctionDecl)
	for _, fn := range graph.Functions {
		baseName := methodLookupName(fn.ID.Name)
		index[baseName] = append(index[baseName], fn)
	}
	return index
}

func indexMethodsByQualifiedArity(graph *CallGraph) map[string][]string {
	index := make(map[string][]string)
	keys := make([]string, 0, len(graph.Functions))
	for key := range graph.Functions {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		fn := graph.Functions[key]
		index[qualifiedMethodArityKey(fn.ID.Package, fn.ID.Type, fn.ID.Name)] = append(
			index[qualifiedMethodArityKey(fn.ID.Package, fn.ID.Type, fn.ID.Name)],
			key,
		)
	}
	return index
}

// indexKnownClassTypes builds the set of "Package|Type" pairs for every
// class-owned declaration in the graph. Used by expandAbstractClassDispatch to
// tell apart "this Type is a real parsed class, just missing a body for this
// particular method+arity" (an abstract method left undefined on an
// intermediate class) from "this Type is unknown to the graph entirely"
// (an unresolved/external callee, where no dispatch inference is safe).
func indexKnownClassTypes(graph *CallGraph) map[string]bool {
	index := make(map[string]bool)
	for _, fn := range graph.Functions {
		if fn.OwnerType != ownerTypeClass || fn.ID.Type == "" {
			continue
		}
		index[fn.ID.Package+"|"+fn.ID.Type] = true
	}
	return index
}

// indexSubclassByTypeName builds a map from base-class simple name → list of
// FunctionDecl pointers belonging to subclass methods that declare that base.
// Used exclusively by expandPythonSubclassDispatch. Only class-typed decls with
// non-empty OwnerBases are indexed.
func indexSubclassByTypeName(graph *CallGraph) map[string][]*FunctionDecl {
	index := make(map[string][]*FunctionDecl)
	for _, fn := range graph.Functions {
		if fn.OwnerType != ownerTypeClass || len(fn.OwnerBases) == 0 {
			continue
		}
		for _, base := range fn.OwnerBases {
			base = strings.TrimSpace(base)
			if base == "" {
				continue
			}
			index[base] = append(index[base], fn)
		}
	}
	return index
}

// pythonSubclassDispatchAlias is one synthesized Python subclass dispatch edge
// target plus the base class type that was expanded.
type pythonSubclassDispatchAlias struct {
	CalleeKey    string
	DeclaredType string
}

// expandPythonSubclassDispatch links a base-class method call to concrete
// subclass overrides. It fires ONLY when:
//   - The resolved callee belongs to a "class"-typed decl (not module, not interface).
//   - The ecosystem is "python" (Python-only; Java uses expandInterfaceDispatch).
//   - At least one other class in the graph declares the callee's OwnerName (or Type)
//     as a base via OwnerBases and defines the same method name+arity.
//
// Java interface dispatch is unchanged — it still uses OwnerType == "interface".
func (b *Builder) expandPythonSubclassDispatch(
	calleeKey string,
	graph *CallGraph,
	subclassByTypeName map[string][]*FunctionDecl,
) []pythonSubclassDispatchAlias {
	if b.ecosystem != ecosystemPython {
		return nil
	}

	calleeDecl, ok := graph.Functions[calleeKey]
	if !ok || calleeDecl.OwnerType != ownerTypeClass || calleeDecl.ID.Type == "" {
		return nil
	}

	// Look for subclass methods whose OwnerBases list includes this callee's Type.
	candidates := subclassByTypeName[calleeDecl.ID.Type]
	if len(candidates) == 0 {
		return nil
	}

	baseName := methodLookupName(calleeDecl.ID.Name)
	baseArity := len(calleeDecl.Parameters)
	declaredType := interfaceDeclaredType(calleeDecl.ID)

	var keys []string
	for _, candidate := range candidates {
		// Must be a class method (not module) and match name+arity.
		if candidate.OwnerType != ownerTypeClass {
			continue
		}
		if methodLookupName(candidate.ID.Name) != baseName {
			continue
		}
		if len(candidate.Parameters) != baseArity {
			continue
		}
		// Do not self-alias.
		if candidate.ID.String() == calleeKey {
			continue
		}
		keys = append(keys, candidate.ID.String())
	}

	sort.Strings(keys)
	results := make([]pythonSubclassDispatchAlias, 0, len(keys))
	for _, k := range keys {
		results = append(results, pythonSubclassDispatchAlias{CalleeKey: k, DeclaredType: declaredType})
	}
	return results
}

func addCaller(callers map[string][]string, calleeKey, callerKey string, oldCalleeKeys ...string) {
	for _, oldCalleeKey := range oldCalleeKeys {
		if oldCalleeKey == "" || oldCalleeKey == calleeKey {
			continue
		}
		removeCaller(callers, oldCalleeKey, callerKey)
	}

	existing := callers[calleeKey]
	for _, candidate := range existing {
		if candidate == callerKey {
			return
		}
	}
	callers[calleeKey] = append(existing, callerKey)
}

func removeCaller(callers map[string][]string, calleeKey, callerKey string) {
	existing := callers[calleeKey]
	if len(existing) == 0 {
		return
	}

	filtered := existing[:0]
	for _, candidate := range existing {
		if candidate != callerKey {
			filtered = append(filtered, candidate)
		}
	}

	if len(filtered) == 0 {
		delete(callers, calleeKey)
		return
	}
	callers[calleeKey] = filtered
}

func qualifiedMethodArityKey(pkg, typ, name string) string {
	return pkg + "|" + typ + "|" + methodArityKey(name)
}

func (b *Builder) expandOverloadCandidates(callee FunctionID, methodsByQualifiedArity map[string][]string) []string {
	return methodsByQualifiedArity[qualifiedMethodArityKey(callee.Package, callee.Type, callee.Name)]
}

// interfaceDispatchAlias is one synthesized interface-dispatch edge target plus
// the interface type that was expanded, so the edge can be classified and
// grouped with its siblings downstream.
type interfaceDispatchAlias struct {
	CalleeKey    string
	DeclaredType string
}

// expandInterfaceDispatch links interface method call-sites to concrete implementations
// with matching method name/arity in the same namespace root.
func (b *Builder) expandInterfaceDispatch(
	calleeKey string,
	graph *CallGraph,
	methodsByName map[string][]*FunctionDecl,
) []interfaceDispatchAlias {
	calleeDecl, ok := graph.Functions[calleeKey]
	if !ok || calleeDecl.OwnerType != ownerTypeInterface {
		return nil
	}

	targets := methodsByName[methodLookupName(calleeDecl.ID.Name)]
	if len(targets) == 0 {
		return nil
	}

	declaredType := interfaceDeclaredType(calleeDecl.ID)
	baseRoot := namespaceRoot(calleeDecl.ID.Package)
	keys := make([]string, 0, len(targets))
	for _, candidate := range targets {
		if candidate.OwnerType == ownerTypeInterface {
			continue
		}
		if len(candidate.Parameters) != len(calleeDecl.Parameters) {
			continue
		}
		if namespaceRoot(candidate.ID.Package) != baseRoot {
			continue
		}
		keys = append(keys, candidate.ID.String())
	}

	sort.Strings(keys)
	results := make([]interfaceDispatchAlias, 0, len(keys))
	for _, k := range keys {
		results = append(results, interfaceDispatchAlias{CalleeKey: k, DeclaredType: declaredType})
	}
	return results
}

// interfaceDeclaredType renders the fully-qualified interface type for a method
// ID (e.g. {Package: "dep", Type: "Sink"} -> "dep.Sink").
func interfaceDeclaredType(id FunctionID) string {
	if id.Type == "" {
		return id.Package
	}
	if id.Package == "" {
		return id.Type
	}
	return id.Package + "." + id.Type
}

// expandAbstractClassDispatch links a call site to concrete overrides when the
// resolved callee is an unqualified/this-call to a method that its own class
// never defines a body for — the Java shape of an abstract intermediate class
// declaring (but not implementing) a method that only its concrete subclasses
// override. Mirrors expandInterfaceDispatch's policy (same-name+arity, same
// namespace root) but keys off "callee class is known yet the exact method
// has no declaration" rather than "callee owner is an interface", so it also
// covers the case where the interface's only concrete body sits on an
// abstract class that itself calls other not-yet-overridden interface methods
// via `this`.
//
// It intentionally does NOT fire when the callee's Type is unknown to the
// graph at all (e.g. an external/unresolved receiver) — knownClassTypes gates
// that, so this stays a narrow "missing override" inference instead of a
// generic name+arity fallback.
func (b *Builder) expandAbstractClassDispatch(
	callee FunctionID,
	graph *CallGraph,
	methodsByName map[string][]*FunctionDecl,
	knownClassTypes map[string]bool,
) []interfaceDispatchAlias {
	if callee.Type == "" {
		return nil
	}
	calleeKey := callee.String()
	if _, declared := graph.Functions[calleeKey]; declared {
		return nil
	}
	if !knownClassTypes[callee.Package+"|"+callee.Type] {
		return nil
	}

	targets := methodsByName[methodLookupName(callee.Name)]
	if len(targets) == 0 {
		return nil
	}

	declaredType := interfaceDeclaredType(callee)
	baseRoot := namespaceRoot(callee.Package)
	calleeArity := functionArity(callee.Name)
	keys := make([]string, 0, len(targets))
	for _, candidate := range targets {
		if candidate.OwnerType != ownerTypeClass {
			continue
		}
		if candidate.ID.Type == callee.Type && candidate.ID.Package == callee.Package {
			continue
		}
		if functionArity(candidate.ID.Name) != calleeArity {
			continue
		}
		if namespaceRoot(candidate.ID.Package) != baseRoot {
			continue
		}
		keys = append(keys, candidate.ID.String())
	}

	sort.Strings(keys)
	results := make([]interfaceDispatchAlias, 0, len(keys))
	for _, k := range keys {
		results = append(results, interfaceDispatchAlias{CalleeKey: k, DeclaredType: declaredType})
	}
	return results
}

// expandFluentFallback links unresolved fluent-chain calls (foo().bar().baz()) to
// candidate methods by deriving namespace root from the chain's root static call.
func (b *Builder) expandFluentFallback(
	call FunctionCall,
	graph *CallGraph,
	methodsByName map[string][]*FunctionDecl,
) []string {
	rootPkg, targets := b.fluentFallbackContext(call, graph, methodsByName)
	if rootPkg == "" || len(targets) == 0 {
		return nil
	}

	scoredTargets := scoreFluentFallbackTargets(call, rootPkg, targets)
	if len(scoredTargets) == 0 {
		return nil
	}
	sort.SliceStable(scoredTargets, func(i, j int) bool {
		if scoredTargets[i].score == scoredTargets[j].score {
			return scoredTargets[i].key < scoredTargets[j].key
		}
		return scoredTargets[i].score > scoredTargets[j].score
	})

	limit := min(6, len(scoredTargets))
	results := make([]string, 0, limit)
	for i := 0; i < limit; i++ {
		results = append(results, scoredTargets[i].key)
	}
	return results
}

func (b *Builder) fluentFallbackContext(
	call FunctionCall,
	graph *CallGraph,
	methodsByName map[string][]*FunctionDecl,
) (string, []*FunctionDecl) {
	calleeKey := call.Callee.String()
	if _, ok := graph.Functions[calleeKey]; ok || !strings.Contains(call.Raw, ").") {
		return "", nil
	}

	rootType, rootMethod, ok := parseFluentRoot(call.Raw)
	if !ok {
		return "", nil
	}
	rootPkg := resolveRootPackage(rootType, rootMethod, methodsByName)
	if rootPkg == "" {
		return "", nil
	}

	targets := methodsByName[methodLookupName(call.Callee.Name)]
	if len(targets) == 0 {
		return "", nil
	}
	return rootPkg, targets
}

type scoredFluentTarget struct {
	key   string
	score int
}

func scoreFluentFallbackTargets(call FunctionCall, rootPkg string, targets []*FunctionDecl) []scoredFluentTarget {
	rootNS := namespaceRoot(rootPkg)
	scoredTargets := make([]scoredFluentTarget, 0, len(targets))
	for _, candidate := range targets {
		if !matchesFluentFallbackCandidate(call, rootNS, candidate) {
			continue
		}
		scoredTargets = append(scoredTargets, scoredFluentTarget{
			key:   candidate.ID.String(),
			score: fluentFallbackScore(call, rootPkg, candidate),
		})
	}
	return scoredTargets
}

func matchesFluentFallbackCandidate(call FunctionCall, rootNS string, candidate *FunctionDecl) bool {
	if len(call.Arguments) > 0 && len(candidate.Parameters) != len(call.Arguments) {
		return false
	}
	return namespaceRoot(candidate.ID.Package) == rootNS
}

func fluentFallbackScore(call FunctionCall, rootPkg string, candidate *FunctionDecl) int {
	score := 1
	if candidate.ID.Package == rootPkg {
		score += 2
	}
	if strings.HasSuffix(candidate.ID.Type, "Builder") {
		score++
	}
	if strings.Contains(call.Raw, "SignatureAlgorithm.") && strings.Contains(candidate.ID.Package, "io.jsonwebtoken") {
		score += 2
	}
	return score
}

func parseFluentRoot(raw string) (rootType, rootMethod string, ok bool) {
	firstDot := strings.Index(raw, ".")
	if firstDot <= 0 || firstDot >= len(raw)-1 {
		return "", "", false
	}
	rootType = strings.TrimSpace(raw[:firstDot])
	rest := raw[firstDot+1:]
	openParen := strings.Index(rest, "(")
	if openParen <= 0 {
		return "", "", false
	}
	rootMethod = strings.TrimSpace(rest[:openParen])
	if rootType == "" || rootMethod == "" || strings.Contains(rootType, "(") {
		return "", "", false
	}
	return rootType, rootMethod, true
}

func resolveRootPackage(rootType, rootMethod string, methodsByName map[string][]*FunctionDecl) string {
	candidates := methodsByName[rootMethod]
	if len(candidates) == 0 {
		return ""
	}

	var pkg string
	for _, fn := range candidates {
		if methodLookupName(fn.ID.Name) != rootMethod || fn.ID.Type != rootType {
			continue
		}
		if pkg == "" {
			pkg = fn.ID.Package
			continue
		}
		if pkg != fn.ID.Package {
			// Ambiguous root package, skip fallback.
			return ""
		}
	}
	return pkg
}

func namespaceRoot(pkg string) string {
	sep := "."
	if strings.Contains(pkg, "/") && !strings.Contains(pkg, ".") {
		sep = "/"
	}

	parts := strings.Split(pkg, sep)
	if len(parts) >= 2 {
		return parts[0] + sep + parts[1]
	}
	return pkg
}

// resolveFluentChainsByReturnType improves call resolution for fluent chains
// by propagating return types through chained calls.
//
// For a chain like Jwts.builder().setId(id).signWith(algo, key):
//   - Jwts.builder() is resolved → its ReturnType is "JwtBuilder"
//   - .setId(id) was unresolved → now we look for JwtBuilder.setId in the graph
//   - .signWith(algo, key) was unresolved → JwtBuilder.signWith in the graph
//
// This rewrites FunctionCall.Callee for matched calls, making them resolvable
// for parameter type extraction and caller index linking.
func resolveFluentChainsByReturnType(graph *CallGraph) {
	totalResolved := 0
	for pass := range 10 { // max 10 iterations to prevent infinite loops
		typePackages := buildTypePackageIndex(graph)
		methodsByQualifiedArity := indexMethodsByQualifiedArity(graph)
		resolved := 0
		for _, fn := range graph.Functions {
			resolved += resolveFluentCallsInFunction(fn, graph, typePackages, methodsByQualifiedArity)
		}
		totalResolved += resolved
		if resolved == 0 {
			break // fixed point reached
		}
		_ = pass
	}

	if totalResolved > 0 {
		log.Info().Int("resolved", totalResolved).Msg("Resolved fluent chain calls via return types")
	}
}

// resolveFluentChainCalleesByContract corrects the callees of fluent method-chain
// links using the contract KB. The parser resolves constructor-rooted chains and
// typed-variable receivers, but a chain rooted at a static/library call such as
// `Password.hash(p).addRandomSalt().withBcrypt()` leaves its intermediate links
// untyped — resolveCallee then mis-guesses them against wildcard imports.
//
// Using the ChainID grouping recorded by the parser, this pass walks each chain
// innermost-first, seeds the receiver type from the root link's KB return type,
// and rewrites each subsequent link to <receiverType>.method when the KB knows
// that method, propagating the contract return type to the next link. It is
// conservative: a link is only rewritten when the KB confirms the method exists
// on the propagated receiver type, so chains the KB does not describe are left
// untouched.
func resolveFluentChainCalleesByContract(graph *CallGraph, kb *contracts.KnowledgeBase) {
	if kb == nil {
		return
	}
	// The reconciliation below writes resolved edges into the caller index.
	// BuildFromDirectories always initializes it, but callers that invoke this
	// pass on a hand-built graph (unit tests) may not — guard against a nil map.
	if graph.Callers == nil {
		graph.Callers = make(map[string][]string)
	}
	resolved := 0
	for callerKey, fn := range graph.Functions {
		resolved += resolveChainCalleesInFunction(graph, callerKey, fn, kb)
	}
	if resolved > 0 {
		log.Info().Int("resolved", resolved).Msg("Resolved fluent chain link callees via contract KB")
	}
}

func resolveChainCalleesInFunction(graph *CallGraph, callerKey string, fn *FunctionDecl, kb *contracts.KnowledgeBase) int {
	chains := make(map[string][]int)
	order := make([]string, 0)
	for i := range fn.Calls {
		cid := fn.Calls[i].ChainID
		if cid == "" {
			continue
		}
		if _, seen := chains[cid]; !seen {
			order = append(order, cid)
		}
		chains[cid] = append(chains[cid], i)
	}

	resolved := 0
	for _, cid := range order {
		idxs := chains[cid]
		if len(idxs) < 2 {
			continue
		}
		// Order links innermost-first: an outer link's Raw strictly contains the
		// inner link's Raw as a prefix, so Raw length is monotonic with depth.
		sort.SliceStable(idxs, func(a, b int) bool {
			return len(fn.Calls[idxs[a]].Raw) < len(fn.Calls[idxs[b]].Raw)
		})
		resolved += resolveChainLinkCallees(graph, callerKey, fn, idxs, kb)
	}
	return resolved
}

func resolveChainLinkCallees(graph *CallGraph, callerKey string, fn *FunctionDecl, idxs []int, kb *contracts.KnowledgeBase) int {
	// Seed the receiver type from the root (innermost) link's KB return type.
	rootFQN, rootArity := splitMethodArity(&fn.Calls[idxs[0]].Callee)
	currentType := unconditionalContractReturn(kb.ContractsForTolerant(rootFQN, rootArity))

	resolved := 0
	for pos := 1; pos < len(idxs); pos++ {
		if currentType == "" {
			break
		}
		call := &fn.Calls[idxs[pos]]
		base, arity := methodBaseArity(call.Callee.Name)
		ctrs := kb.ContractsForTolerant(currentType+"."+base, arity)
		if len(ctrs) == 0 {
			break // not a known method of the propagated type; stop, do not guess
		}
		pkg, typ := splitQualifiedTypeName(currentType)
		rewritten := FunctionID{Package: pkg, Type: typ, Name: fmt.Sprintf("%s#%d", base, arity)}
		oldKey := call.Callee.String()
		if newKey := rewritten.String(); newKey != oldKey {
			call.Callee = rewritten
			// Reconcile the caller index with the rewrite. buildCallerIndex ran in
			// Phase 1 with the pre-resolution (messy, name-only fallback) key; move
			// this caller to the resolved key and record it as an exact edge so the
			// fragment export and the stitcher see the clean KB-resolved target
			// instead of the stale fallback. Without this the index and the
			// FunctionCall.Callee diverge and the exported edge carries a synthesized
			// key with no object identity.
			addCaller(graph.Callers, newKey, callerKey, oldKey)
			recordEdgeResolution(graph, callerKey, newKey, EdgeKindExact, "", call.Line)
			resolved++
		}
		currentType = unconditionalContractReturn(ctrs)
	}
	return resolved
}

// methodBaseArity splits a decorated method name ("withBcrypt#0") into its base
// name and arity. Arity is -1 when the name is not arity-qualified.
func methodBaseArity(name string) (string, int) {
	idx := strings.LastIndex(name, "#")
	if idx < 0 {
		return name, -1
	}
	arity := 0
	for _, ch := range name[idx+1:] {
		if ch < '0' || ch > '9' {
			return name, -1
		}
		arity = arity*10 + int(ch-'0')
	}
	return name[:idx], arity
}

// splitQualifiedTypeName splits a fully-qualified type name into package and
// simple type (e.g. "com.password4j.HashBuilder" -> "com.password4j",
// "HashBuilder").
func splitQualifiedTypeName(fqn string) (pkg, typ string) {
	if idx := strings.LastIndex(fqn, "."); idx >= 0 {
		return fqn[:idx], fqn[idx+1:]
	}
	return "", fqn
}

// unconditionalContractReturn returns the return type of the first unconditional
// contract in the set, or "" when none applies.
func unconditionalContractReturn(ctrs []contracts.Contract) string {
	for i := range ctrs {
		if ctrs[i].When == nil {
			return ctrs[i].Return.Type
		}
	}
	return ""
}

// dispatchAmbiguousGroupKey groups EdgeResolutions the same way the stitcher's
// dispatchGroupKey does: one interface-dispatch call site (caller + call site +
// method + arity), independent of which of the N candidate targets a given
// EdgeResolution entry names.
type dispatchAmbiguousGroupKey struct {
	Caller     string
	CallSite   int
	MethodName string
	Arity      int
}

// resolveParameterPassthroughDispatch resolves a narrow, sound special case the
// generic count-of-candidates ambiguity check cannot: a callee function whose
// interface-typed parameter is used, directly and exclusively, as the receiver
// of the ONE ambiguous interface-dispatch call in its body (a "pass-through"
// receiver, e.g. password4j's `with(HashingFunction h) { return h.hash(...); }`).
// That call site is genuinely ambiguous when judged in isolation — `with`'s
// several callers each pass a DIFFERENT concrete HashingFunction implementation
// (withPBKDF2 passes PBKDF2Function, withBcrypt passes BcryptFunction, ...) — so
// stamping a single resolved type on the shared edge would be unsound: correct
// for one caller, wrong for the rest.
//
// Instead, for each caller of the pass-through callee whose argument at the
// parameter's position resolves to ONE concrete type (constructor call, or a
// call whose declared/inferred return type is concrete) that matches EXACTLY
// ONE candidate in the dispatch group, a new direct edge is added from that
// SPECIFIC caller straight to the concrete target — bypassing the shared
// ambiguous node for that caller's reachability only. The original
// caller->passthrough->[ambiguous group] edges are left untouched, so any
// caller this pass cannot resolve keeps failing closed exactly as before.
// passthroughMaxIterations caps the fixpoint loop in resolveParameterPassthroughDispatch.
// Each iteration only adds NEW bypass edges (existing ones are never revisited
// as new sources — addCaller/recordEdgeResolution are idempotent), and a real
// password4j-shaped chain is at most a few hops deep, so this is a generous
// safety valve rather than a realistic limit.
const passthroughMaxIterations = 10

// resolveParameterPassthroughDispatch resolves a narrow, sound special case the
// generic count-of-candidates ambiguity check cannot: a callee function whose
// interface-typed parameter (or, for the SAME-context case, its own implicit
// "this" receiver) is used, directly and exclusively, as the receiver of the
// ONE ambiguous interface-dispatch call in its body (a "pass-through"
// receiver, e.g. password4j's `with(HashingFunction h) { return h.hash(...); }`,
// or an inherited method's `this.hash(...)` self-call). That call site is
// genuinely ambiguous when judged in isolation — `with`'s several callers each
// pass a DIFFERENT concrete HashingFunction implementation (withPBKDF2 passes
// PBKDF2Function, withBcrypt passes BcryptFunction, ...) — so stamping a single
// resolved type on the shared edge would be unsound: correct for one caller,
// wrong for the rest.
//
// Instead, for each caller of the pass-through callee whose argument (or, for
// a "this" receiver, whose own already-resolved bypass context) resolves to
// ONE concrete type that matches EXACTLY ONE candidate in the dispatch group,
// a new direct edge is added from that SPECIFIC caller straight to the
// concrete target — bypassing the shared ambiguous node for that caller's
// reachability only. The original caller->passthrough->[ambiguous group] edges
// are left untouched, so any caller this pass cannot resolve keeps failing
// closed exactly as before.
//
// Runs to a fixpoint (bounded by passthroughMaxIterations) because resolving
// one hop (e.g. withPBKDF2 -> AbstractHashingFunction.hash#3, in a
// PBKDF2Function context) can unlock the NEXT hop inside that same target's
// body (hash#3's own "this.hash(...)" self-call, which the first pass alone
// cannot see since it has no explicit receiver argument to resolve).
func resolveParameterPassthroughDispatch(graph *CallGraph) int {
	// receiverIdx mirrors every ResolvedReceiverType stamped onto
	// graph.EdgeResolutions, keyed by "callerKey\x00calleeKey" so
	// resolvePassthroughForThisReceiver can look up an already-resolved bypass
	// edge in O(1) instead of linearly scanning the (potentially huge, after
	// dispatch fan-out) EdgeResolutions map on every call — see
	// lookupResolvedReceiverType's doc comment for the full contract this
	// index mirrors. Built once and kept in sync by stampResolvedReceiverType
	// for the lifetime of this pass (including across fixpoint iterations,
	// since a later group can depend on an edge a same-iteration earlier group
	// just stamped).
	receiverIdx := newResolvedReceiverIndex(graph)

	// The ambiguous-group membership (groupAmbiguousDispatchEdges) and each
	// group's qualification (passthroughParameterIndex, candidateOwners) are
	// invariant across fixpoint iterations: this pass only ever adds
	// EdgeKindExact bypass edges targeting a CONCRETE candidate — never an
	// EdgeKindInterfaceDispatch edge — so groupAmbiguousDispatchEdges's
	// filtered set never changes. Computing that (and each group's
	// qualification) once instead of on every iteration turns what used to be
	// up to passthroughMaxIterations full rescans of graph.EdgeResolutions
	// (millions of entries on large graphs such as bcprov) into a single
	// rescan.
	//
	// graph.Callers[gk.Caller] is NOT invariant, though: gk.Caller can itself
	// be a bypass TARGET for a different group (a multi-hop chain — e.g.
	// password4j's HashBuilder.withBcrypt() -> BcryptFunction.hash, where
	// BcryptFunction.hash's own inherited AbstractHashingFunction.hash body
	// is a second, deeper ambiguous group). Resolving that outer group adds
	// gk.Caller as a NEW caller of the inner group via addCaller, so the
	// caller list must be re-read from graph.Callers every iteration — see
	// resolveQualifiedPassthroughGroup.
	qualified := qualifyPassthroughGroups(graph)

	totalResolved := 0
	for iter := 0; iter < passthroughMaxIterations; iter++ {
		resolved := 0
		for i := range qualified {
			resolved += resolveQualifiedPassthroughGroup(graph, &qualified[i], receiverIdx)
		}
		totalResolved += resolved
		if resolved == 0 {
			break
		}
	}
	if totalResolved > 0 {
		log.Info().Int("resolved", totalResolved).Msg("Resolved parameter pass-through interface dispatch")
	}
	return totalResolved
}

// qualifiedPassthroughGroup caches one ambiguous dispatch group's
// iteration-invariant qualification (see resolveParameterPassthroughDispatch's
// doc comment): everything passthroughParameterIndex and
// resolveOverloadPerOwner/candidateOwnersByType compute from gk and entries
// alone, plus the group's outer caller list, none of which changes across
// fixpoint iterations.
type qualifiedPassthroughGroup struct {
	gk              dispatchAmbiguousGroupKey
	calleeFn        *FunctionDecl
	paramIdx        int
	candidateOwners map[string]string
}

// qualifyPassthroughGroups computes groupAmbiguousDispatchEdges once and
// resolves each group's iteration-invariant qualification up front, so the
// fixpoint loop in resolveParameterPassthroughDispatch only repeats the part
// that can actually change between iterations: per-caller resolution.
//
// Qualification for one group (gk.Caller is the function whose body issues
// the ambiguous call — the "pass-through candidate"; conservative by design —
// every condition narrows toward "do nothing" on doubt, matching the
// fail-closed default), delegated to passthroughParameterIndex:
//  1. The ambiguous call site must be uniquely identifiable in gk.Caller's
//     body by (line, method, arity) — see findCallAtSite.
//  2. Its receiver is either (a) one of gk.Caller's OWN parameters
//     (positionally matched via FunctionParameter.Name) — a pass-through of an
//     argument — in which case gk.Caller must have EXACTLY ONE call in its
//     body (a parameter could otherwise be reassigned or escape into a branch
//     this pass cannot see); or (b) gk.Caller's own implicit "this" — in which
//     case a multi-call, branching body is tolerated (this's type is fixed for
//     the whole method regardless of branch).
//  3. Each entry in the group names a distinct candidate; each candidate's
//     owner type is derived from its FunctionID.Type (simple name).
func qualifyPassthroughGroups(graph *CallGraph) []qualifiedPassthroughGroup {
	groups := groupAmbiguousDispatchEdges(graph)
	keys := sortedAmbiguousGroupKeys(groups)
	qualified := make([]qualifiedPassthroughGroup, 0, len(keys))
	for _, gk := range keys {
		calleeFn, ambiguousCall, paramIdx, ok := passthroughParameterIndex(graph, gk)
		if !ok {
			continue
		}
		candidateOwners := resolveOverloadPerOwner(graph, ambiguousCall, candidateOwnersByType(groups[gk]))
		if len(candidateOwners) == 0 {
			continue
		}
		qualified = append(qualified, qualifiedPassthroughGroup{
			gk:              gk,
			calleeFn:        calleeFn,
			paramIdx:        paramIdx,
			candidateOwners: candidateOwners,
		})
	}
	return qualified
}

// resolveQualifiedPassthroughGroup runs one fixpoint iteration's worth of
// per-caller resolution for a pre-qualified group. Returns the number of
// caller-specific bypass edges added this call.
func resolveQualifiedPassthroughGroup(graph *CallGraph, qg *qualifiedPassthroughGroup, receiverIdx resolvedReceiverIndex) int {
	// graph.Callers[gk.Caller] is re-read (and snapshotted before iterating,
	// since resolvePassthroughForCaller mutates graph.Callers via addCaller)
	// on every call rather than cached in qg: unlike the rest of a group's
	// qualification, the caller list is NOT invariant across fixpoint
	// iterations — gk.Caller can itself be resolved as another group's bypass
	// TARGET, which appends a new entry to graph.Callers[gk.Caller] via
	// addCaller (see resolveParameterPassthroughDispatch's doc comment for the
	// password4j multi-hop example this covers). This lookup is O(callers of
	// one function), not a rescan of the whole graph, so it stays cheap.
	callerKeys := append([]string(nil), graph.Callers[qg.gk.Caller]...)
	resolved := 0
	for _, callerKey := range callerKeys {
		outerFn := graph.Functions[callerKey]
		if outerFn == nil {
			continue
		}
		resolved += resolvePassthroughForCaller(graph, outerFn, callerKey, qg.calleeFn, qg.gk, qg.paramIdx, qg.candidateOwners, receiverIdx)
	}
	return resolved
}

// groupAmbiguousDispatchEdges collects every recorded interface_dispatch
// EdgeResolution keyed by call site, mirroring the stitcher's dispatch-group
// identity so a group here has >1 entries exactly when the stitcher would judge
// that call site ambiguous.
func groupAmbiguousDispatchEdges(graph *CallGraph) map[dispatchAmbiguousGroupKey][]edgeResolutionEntry {
	candidateSites, callersByID := passthroughCandidateCallSites(graph)
	if len(candidateSites) == 0 {
		return nil
	}

	edgesByCaller := interfaceDispatchEdgesByCaller(graph)
	compactGroups := make(map[compactDispatchGroupKey][]edgeResolutionEntry)
	for callerKey, candidate := range candidateSites {
		entries := edgesByCaller[callerKey]
		if len(entries) < 2 {
			continue
		}
		for i := range entries {
			entry := entries[i]
			res := entry.resolution
			if !containsDispatchCallSite(candidate.sites, res.CallSite, res.MethodName, res.Arity) {
				continue
			}
			gk := compactDispatchGroupKey{CallerID: candidate.id, CallSite: res.CallSite, MethodName: res.MethodName, Arity: res.Arity}
			compactGroups[gk] = append(compactGroups[gk], entry)
		}
	}

	groups := make(map[dispatchAmbiguousGroupKey][]edgeResolutionEntry, len(compactGroups))
	for gk, entries := range compactGroups {
		if len(entries) < 2 {
			continue
		}
		groups[dispatchAmbiguousGroupKey{
			Caller:     callersByID[gk.CallerID],
			CallSite:   gk.CallSite,
			MethodName: gk.MethodName,
			Arity:      gk.Arity,
		}] = entries
	}
	return groups
}

func interfaceDispatchEdgesByCaller(graph *CallGraph) map[string][]edgeResolutionEntry {
	edgesByCaller := make(map[string][]edgeResolutionEntry)
	for key, res := range graph.EdgeResolutions {
		if res.Kind != EdgeKindInterfaceDispatch {
			continue
		}
		callerKey, calleeKey := res.callerKey, res.calleeKey
		if callerKey == "" || calleeKey == "" {
			var ok bool
			callerKey, calleeKey, ok = splitEdgeResolutionKey(key)
			if !ok {
				continue
			}
		}
		edgesByCaller[callerKey] = append(edgesByCaller[callerKey], edgeResolutionEntry{calleeKey: calleeKey, resolution: res})
	}
	return edgesByCaller
}

type dispatchCallSiteKey struct {
	CallSite   int
	MethodName string
	Arity      int
}

type compactDispatchGroupKey struct {
	CallerID   int
	CallSite   int
	MethodName string
	Arity      int
}

type passthroughCandidateCaller struct {
	id    int
	sites []dispatchCallSiteKey
}

func passthroughCandidateCallSites(graph *CallGraph) (map[string]passthroughCandidateCaller, []string) {
	candidates := make(map[string]passthroughCandidateCaller)
	callersByID := make([]string, 0)
	for callerKey, fn := range graph.Functions {
		sites := passthroughCandidateSites(fn)
		if len(sites) == 0 {
			continue
		}
		candidates[callerKey] = passthroughCandidateCaller{id: len(callersByID), sites: sites}
		callersByID = append(callersByID, callerKey)
	}
	return candidates, callersByID
}

func passthroughCandidateSites(fn *FunctionDecl) []dispatchCallSiteKey {
	if fn == nil {
		return nil
	}
	sites := make([]dispatchCallSiteKey, 0, len(fn.Calls))
	for i := range fn.Calls {
		call := &fn.Calls[i]
		if !canPassthroughReceiver(fn, call) {
			continue
		}
		method, arity := methodBaseArity(call.Callee.Name)
		site := dispatchCallSiteKey{CallSite: call.Line, MethodName: method, Arity: arity}
		if !containsDispatchCallSite(sites, site.CallSite, site.MethodName, site.Arity) {
			sites = append(sites, site)
		}
	}
	return sites
}

func containsDispatchCallSite(sites []dispatchCallSiteKey, callSite int, methodName string, arity int) bool {
	for i := range sites {
		if sites[i].CallSite == callSite && sites[i].MethodName == methodName && sites[i].Arity == arity {
			return true
		}
	}
	return false
}

func canPassthroughReceiver(fn *FunctionDecl, call *FunctionCall) bool {
	if call.ReceiverVar == "" {
		return true
	}
	if len(fn.Calls) != 1 {
		return false
	}
	for i := range fn.Parameters {
		if fn.Parameters[i].Name != "" && fn.Parameters[i].Name == call.ReceiverVar {
			return true
		}
	}
	return false
}

// edgeResolutionEntry pairs one EdgeResolutions map entry with its parsed
// callee key so grouping code does not re-split the composite key.
type edgeResolutionEntry struct {
	calleeKey  string
	resolution EdgeResolution
}

// splitEdgeResolutionKey recovers the callerKey/calleeKey from an
// EdgeResolutionKey string. EdgeResolutionKeyPrefix builds the key as
// "<callerKey>\x00<calleeKey>\x00<callSite>\x00<declaredType>\x00<method>\x00<arity>";
// callerKey and calleeKey are FunctionID.String() values, which never contain
// \x00, so the first two \x00-delimited fields are exactly callerKey and
// calleeKey. Returns ok=false if the key has fewer than 2 fields (defensive;
// should not happen for well-formed keys produced by EdgeResolutionKey).
func splitEdgeResolutionKey(key string) (callerKey, calleeKey string, ok bool) {
	parts := strings.SplitN(key, "\x00", 3)
	if len(parts) < 3 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func sortedAmbiguousGroupKeys(groups map[dispatchAmbiguousGroupKey][]edgeResolutionEntry) []dispatchAmbiguousGroupKey {
	keys := make([]dispatchAmbiguousGroupKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.Caller != b.Caller {
			return a.Caller < b.Caller
		}
		if a.CallSite != b.CallSite {
			return a.CallSite < b.CallSite
		}
		if a.MethodName != b.MethodName {
			return a.MethodName < b.MethodName
		}
		return a.Arity < b.Arity
	})
	return keys
}

// resolveOverloadPerOwner collapses candidateOwnersByType's owner->[]calleeKey
// map to owner->calleeKey by picking the best-scoring overload for each owner
// with more than one candidate, using the ambiguous call's OWN argument types
// (call is the pass-through function's single internal call, e.g.
// `hashingFunction.hash(plainTextPassword, salt, pepper)` — its argument types
// are fixed regardless of which outer caller reaches it, since they come from
// the pass-through function's own fields/locals, not the outer caller). Reuses
// scoreOverloadCandidate, the same scoring inferJavaArgumentType-based overload
// resolution uses elsewhere in this file. An owner whose best score is 0 (no
// argument matched any parameter) is dropped rather than guessed.
func resolveOverloadPerOwner(graph *CallGraph, call FunctionCall, ownerCandidates map[string][]string) map[string]string {
	resolved := make(map[string]string, len(ownerCandidates))
	for owner, keys := range ownerCandidates {
		if len(keys) == 1 {
			resolved[owner] = keys[0]
			continue
		}
		best, bestScore := "", -1
		for _, key := range keys {
			fn := graph.Functions[key]
			if fn == nil {
				continue
			}
			if score := scoreOverloadCandidate(fn, &call); score > bestScore {
				best, bestScore = key, score
			}
		}
		if best != "" && bestScore > 0 {
			resolved[owner] = best
		}
	}
	return resolved
}

// thisReceiverParamIndex is the sentinel passthroughParameterIndex returns
// when the ambiguous call's receiver is the function's own implicit "this"
// (ReceiverVar == "") rather than a named parameter — e.g.
// AbstractHashingFunction.hash#3's own `hash(peppered, salt)` self-call. In
// that case resolvePassthroughForCaller resolves the concrete type from the
// OUTER caller's own already-resolved bypass context (ResolvedReceiverType on
// the edge that reached gk.Caller) instead of from an argument.
const thisReceiverParamIndex = -1

// passthroughParameterIndex locates the ambiguous call site inside
// gk.Caller's body and classifies its receiver as either a pass-through of one
// of the function's own parameters (returns that parameter's index) or the
// function's own implicit "this" (returns thisReceiverParamIndex). Also
// returns the specific matching FunctionCall (there may be several calls in
// the body; only the one at gk.CallSite/method/arity is relevant). ok=false
// disqualifies the whole group (see resolvePassthroughGroup).
//
// The "this" case tolerates a multi-call, branching body (e.g.
// `if (salt == null) { hash(x) } else { hash(x, salt) }`): this's concrete
// type is fixed for the whole method regardless of which branch runs, so extra
// calls/branches around it do not introduce the ambiguity the parameter case
// guards against. The named-parameter case keeps the stricter "exactly one
// call total" gate: a parameter COULD be reassigned or escape into a branch
// this pass cannot see, so it stays conservative.
func passthroughParameterIndex(graph *CallGraph, gk dispatchAmbiguousGroupKey) (*FunctionDecl, FunctionCall, int, bool) {
	fn := graph.Functions[gk.Caller]
	if fn == nil {
		return nil, FunctionCall{}, 0, false
	}
	call, ok := findCallAtSite(fn, gk)
	if !ok {
		return nil, FunctionCall{}, 0, false
	}
	if call.ReceiverVar == "" {
		return fn, call, thisReceiverParamIndex, true
	}
	if len(fn.Calls) != 1 {
		return nil, FunctionCall{}, 0, false
	}
	for i := range fn.Parameters {
		if fn.Parameters[i].Name != "" && fn.Parameters[i].Name == call.ReceiverVar {
			return fn, call, i, true
		}
	}
	return nil, FunctionCall{}, 0, false
}

// findCallAtSite finds the single call in fn matching gk's call site identity
// (line, method name, arity). Returns ok=false if zero or more than one call
// matches (an unexpected shape this pass should not guess about).
func findCallAtSite(fn *FunctionDecl, gk dispatchAmbiguousGroupKey) (FunctionCall, bool) {
	var found *FunctionCall
	for i := range fn.Calls {
		c := &fn.Calls[i]
		if c.Line != gk.CallSite {
			continue
		}
		method, arity := methodBaseArity(c.Callee.Name)
		if method != gk.MethodName || arity != gk.Arity {
			continue
		}
		if found != nil {
			return FunctionCall{}, false
		}
		found = c
	}
	if found == nil {
		return FunctionCall{}, false
	}
	return *found, true
}

// candidateOwnersByType maps each candidate's declaring type SIMPLE name
// (FunctionID.Type, e.g. "AbstractHashingFunction") to its callee key(s), for
// candidates with a non-empty owner type. The simple name — not the
// fully-qualified one — is used because resolveArgumentConcreteType's sources
// (FunctionDecl.ReturnType, InferredReturn.Type, and constructor DeclaredType)
// are erased/simple names throughout this codebase (see erasedTypeName), so
// matching on simple name is what actually lines up; a real cross-package name
// collision would require qualifying by package too, which this pass does not
// attempt (out of scope: erased-name provenance does not carry package here).
//
// An owner can map to more than one candidate when the dispatch group's
// method+arity covers multiple overloads declared on the SAME type (e.g.
// AbstractHashingFunction.hash(CharSequence,String,CharSequence) and
// .hash(byte[],byte[],CharSequence) are both arity-3 "hash" methods) — that
// ambiguity is resolved by resolveOverloadPerOwner using the ambiguous call's
// own argument types (the same signal scoreOverloadCandidate uses elsewhere).
func candidateOwnersByType(entries []edgeResolutionEntry) map[string][]string {
	owners := make(map[string][]string, len(entries))
	seen := make(map[string]bool, len(entries))
	for i := range entries {
		calleeKey := entries[i].calleeKey
		id, err := ParseFunctionID(calleeKey)
		if err != nil || id.Type == "" || seen[calleeKey] {
			continue
		}
		seen[calleeKey] = true
		owners[id.Type] = append(owners[id.Type], calleeKey)
	}
	return owners
}

// resolvePassthroughForCaller resolves ONE outer caller's context to a
// concrete receiver type and, if it matches exactly one candidate owner, adds
// a direct bypass edge from callerKey straight to that candidate. Returns 1 if
// an edge was added, else 0.
//
// Two receiver shapes (see passthroughParameterIndex):
//   - paramIdx >= 0: the ambiguous call's receiver is calleeFn's own paramIdx-th
//     parameter. The concrete type comes from resolving outerFn's OWN call to
//     calleeFn at that argument position (a constructor call, or a call whose
//     declared/inferred return type is concrete).
//   - paramIdx == thisReceiverParamIndex: the ambiguous call's receiver is
//     calleeFn's own implicit "this" (calleeFn.ID IS gk.Caller). The concrete
//     type comes from the ResolvedReceiverType this pass already stamped on
//     the edge callerKey->gk.Caller in an earlier iteration — i.e. this
//     extends an existing resolved bypass one hop further into the target's
//     own body, rather than resolving a fresh argument.
func resolvePassthroughForCaller(
	graph *CallGraph,
	outerFn *FunctionDecl,
	callerKey string,
	calleeFn *FunctionDecl,
	gk dispatchAmbiguousGroupKey,
	paramIdx int,
	candidateOwners map[string]string,
	receiverIdx resolvedReceiverIndex,
) int {
	if paramIdx == thisReceiverParamIndex {
		return resolvePassthroughForThisReceiver(graph, callerKey, gk, candidateOwners, receiverIdx)
	}

	call := findCallToCallee(outerFn, calleeFn.ID, len(calleeFn.Parameters))
	if call == nil || paramIdx >= len(call.Arguments) {
		return 0
	}
	argType := resolveArgumentConcreteType(graph, call, paramIdx)
	if argType == "" {
		return 0
	}
	targetKey, ok := resolveCandidateOwner(graph, argType, candidateOwners)
	if !ok {
		return 0
	}
	// Already resolved in a prior iteration: adding the same bypass edge again
	// is a no-op (addCaller dedupes, the resolution map overwrites), but
	// counting it as progress keeps the fixpoint spinning to
	// passthroughMaxIterations instead of terminating.
	if _, _, exists := lookupResolvedReceiverType(receiverIdx, callerKey, targetKey); exists {
		return 0
	}
	addCaller(graph.Callers, targetKey, callerKey)
	recordEdgeResolution(graph, callerKey, targetKey, EdgeKindExact, "", call.Line)
	stampResolvedReceiverType(graph, callerKey, targetKey, call.Line, argType, receiverIdx)
	return 1
}

// resolvePassthroughForThisReceiver extends an already-resolved bypass edge
// callerKey->gk.Caller (which carries a ResolvedReceiverType stamped by an
// earlier resolveParameterPassthroughDispatch iteration) one hop further: if
// gk.Caller's own ambiguous "this" call resolves, via that SAME concrete type,
// to exactly one candidate, a new bypass edge callerKey->candidate is added.
// Returns 1 if an edge was added, else 0.
func resolvePassthroughForThisReceiver(
	graph *CallGraph,
	callerKey string,
	gk dispatchAmbiguousGroupKey,
	candidateOwners map[string]string,
	receiverIdx resolvedReceiverIndex,
) int {
	resolvedType, line, ok := lookupResolvedReceiverType(receiverIdx, callerKey, gk.Caller)
	if !ok {
		return 0
	}
	targetKey, ok := resolveCandidateOwner(graph, resolvedType, candidateOwners)
	if !ok {
		return 0
	}
	// Same no-progress gate as resolvePassthroughForCaller: a bypass edge
	// stamped in a prior iteration must not count as fixpoint progress.
	if _, _, exists := lookupResolvedReceiverType(receiverIdx, callerKey, targetKey); exists {
		return 0
	}
	addCaller(graph.Callers, targetKey, callerKey)
	recordEdgeResolution(graph, callerKey, targetKey, EdgeKindExact, "", line)
	stampResolvedReceiverType(graph, callerKey, targetKey, line, resolvedType, receiverIdx)
	return 1
}

// resolvedReceiverIndex mirrors every ResolvedReceiverType stamped onto
// graph.EdgeResolutions by resolveParameterPassthroughDispatch, keyed by
// "callerKey\x00calleeKey" (the same pairing lookupResolvedReceiverType used
// to search for via a full EdgeResolutions scan). Kept in sync incrementally
// by stampResolvedReceiverType so lookupResolvedReceiverType is O(1) instead
// of O(len(graph.EdgeResolutions)) — on large graphs (e.g. bcprov, with heavy
// interface-dispatch fan-out) EdgeResolutions can hold hundreds of thousands
// of entries, and the old scan ran once per caller per ambiguous group per
// fixpoint iteration.
type resolvedReceiverIndex map[string]resolvedReceiverEntry

// resolvedReceiverEntry is one indexed ResolvedReceiverType plus the
// call-site line it should be attributed to when extended one hop further.
type resolvedReceiverEntry struct {
	resolvedType string
	line         int
}

// resolvedReceiverIndexKey builds the lookup key shared by
// lookupResolvedReceiverType and stampResolvedReceiverType's index update.
func resolvedReceiverIndexKey(callerKey, calleeKey string) string {
	return callerKey + "\x00" + calleeKey
}

// newResolvedReceiverIndex seeds a resolvedReceiverIndex from any
// ResolvedReceiverType entries already present in graph.EdgeResolutions.
// In practice resolveParameterPassthroughDispatch is the sole writer of
// ResolvedReceiverType and runs once per build, so this is normally empty at
// call time — seeding defensively keeps the index correct if that ever
// changes.
func newResolvedReceiverIndex(graph *CallGraph) resolvedReceiverIndex {
	idx := make(resolvedReceiverIndex, len(graph.EdgeResolutions))
	for key, res := range graph.EdgeResolutions {
		if res.ResolvedReceiverType == "" {
			continue
		}
		callerKey, calleeKey, ok := splitEdgeResolutionKey(key)
		if !ok {
			continue
		}
		idx[resolvedReceiverIndexKey(callerKey, calleeKey)] = resolvedReceiverEntry{
			resolvedType: res.ResolvedReceiverType,
			line:         res.CallSite,
		}
	}
	return idx
}

// lookupResolvedReceiverType looks up callerKey->calleeKey's ResolvedReceiverType
// (stamped by a previous resolveParameterPassthroughDispatch iteration) in the
// index instead of scanning graph.EdgeResolutions. Returns the resolved type
// and the call-site line to attribute the extended bypass edge to.
func lookupResolvedReceiverType(receiverIdx resolvedReceiverIndex, callerKey, calleeKey string) (resolvedType string, line int, ok bool) {
	entry, found := receiverIdx[resolvedReceiverIndexKey(callerKey, calleeKey)]
	if !found {
		return "", 0, false
	}
	return entry.resolvedType, entry.line, true
}

// resolveCandidateOwner matches a resolved concrete argument type against the
// dispatch group's candidate owners (keyed by simple type name — see
// candidateOwnersByType), first by exact match, then by walking the concrete
// type's OwnerBases (populated for Java classes from their extends/implements
// clauses) up to inheritanceMaxDepth levels — this is what lets password4j's
// PBKDF2Function (which inherits hash#3 from AbstractHashingFunction without
// overriding it) resolve to the AbstractHashingFunction candidate.
//
// argType may be a simple name (the common case: FunctionDecl.ReturnType /
// InferredReturn.Type are erased/simple names) or occasionally
// fully-qualified (a constructor's DeclaredType); simpleTypeName normalizes
// either shape to its trailing segment before matching/walking.
func resolveCandidateOwner(graph *CallGraph, argType string, candidateOwners map[string]string) (string, bool) {
	simpleName := simpleTypeName(argType)
	if targetKey, ok := candidateOwners[simpleName]; ok {
		return targetKey, true
	}

	seen := map[string]bool{simpleName: true}
	queue := []string{simpleName}
	for depth := 0; depth < inheritanceMaxDepth && len(queue) > 0; depth++ {
		next := queue[0]
		queue = queue[1:]
		decl := findClassDeclByType(graph, next)
		if decl == nil {
			continue
		}
		for _, base := range decl.OwnerBases {
			base = simpleTypeName(strings.TrimSpace(base))
			if base == "" || seen[base] {
				continue
			}
			seen[base] = true
			if targetKey, ok := candidateOwners[base]; ok {
				return targetKey, true
			}
			queue = append(queue, base)
		}
	}
	return "", false
}

// simpleTypeName returns the trailing, unqualified segment of a (possibly
// fully-qualified) type name.
func simpleTypeName(typeName string) string {
	if idx := strings.LastIndex(typeName, "."); idx >= 0 {
		return typeName[idx+1:]
	}
	return typeName
}

// inheritanceMaxDepth caps the OwnerBases ancestor walk in resolveCandidateOwner.
// Java inheritance chains this pass needs to bridge are shallow in practice
// (one or two hops); the cap is a safety valve against a malformed/cyclic
// OwnerBases graph, not a realistic limit.
const inheritanceMaxDepth = 8

// findClassDeclByType finds any FunctionDecl declared on the given
// simple-type-name class, used only to read its OwnerBases (every
// method/constructor of a class carries the same OwnerBases, so the first hit
// is sufficient). Matches by simple name only (see candidateOwnersByType).
func findClassDeclByType(graph *CallGraph, typeName string) *FunctionDecl {
	for _, fn := range graph.Functions {
		if fn.OwnerType == ownerTypeClass && fn.ID.Type == typeName {
			return fn
		}
	}
	return nil
}

// findCallToCallee finds the first call in fn whose resolved callee matches id
// and whose argument count equals wantArity (the pass-through function's own
// parameter count, since the outer call must supply the same arity to reach it).
func findCallToCallee(fn *FunctionDecl, id FunctionID, wantArity int) *FunctionCall {
	for i := range fn.Calls {
		c := &fn.Calls[i]
		if c.Callee.String() == id.String() && len(c.Arguments) == wantArity {
			return c
		}
	}
	return nil
}

// resolveArgumentConcreteType resolves a call argument to a concrete
// (non-interface, non-generic) type using its recorded SourceNodes: a
// constructor call yields its constructed type; a CALL_RESULT yields the
// target function's InferredReturn.Type when set, else its declared
// ReturnType. Returns "" when no concrete type can be determined — the caller
// then leaves the ambiguity exactly as before (fail-closed).
func resolveArgumentConcreteType(graph *CallGraph, call *FunctionCall, argIdx int) string {
	if argIdx >= len(call.ArgumentSources) {
		return ""
	}
	for _, src := range call.ArgumentSources[argIdx] {
		if typ := concreteTypeFromSourceNode(graph, src); typ != "" {
			return typ
		}
	}
	return ""
}

func concreteTypeFromSourceNode(graph *CallGraph, src SourceNode) string {
	if src.Type != sourceNodeCallResult || src.CallTarget == nil {
		return ""
	}
	target := src.CallTarget
	if strings.Contains(target.Name, constructorMethodName) {
		if src.DeclaredType != "" {
			return src.DeclaredType
		}
		return qualifiedType(target.Package, target.Type)
	}
	callee := graph.Functions[target.String()]
	if callee == nil {
		return ""
	}
	if callee.InferredReturn != nil && callee.InferredReturn.Origin != OriginJoinFailed && callee.InferredReturn.Type != "" {
		return callee.InferredReturn.Type
	}
	return callee.ReturnType
}

// stampResolvedReceiverType writes ResolvedReceiverType onto the just-recorded
// exact EdgeResolution for callerKey->targetKey at line, so the fragment
// exporter can carry it through as graph-fragment resolved_receiver_type.
func stampResolvedReceiverType(graph *CallGraph, callerKey, targetKey string, line int, resolvedType string, receiverIdx resolvedReceiverIndex) {
	// Mirror recordEdgeResolution's method/arity derivation exactly so the key
	// matches the entry it just wrote (EdgeResolutionKey folds MethodName/Arity
	// into the map key, so an approximate key would silently miss).
	method, arity := "", 0
	if calleeID, err := ParseFunctionID(targetKey); err == nil {
		method = BaseFunctionName(calleeID.Name)
		arity = functionArity(calleeID.Name)
	}
	key := EdgeResolutionKey(callerKey, targetKey, EdgeResolution{MethodName: method, Arity: arity, CallSite: line})
	res, ok := graph.EdgeResolutions[key]
	if !ok {
		return
	}
	res.ResolvedReceiverType = resolvedType
	graph.EdgeResolutions[key] = res
	upsertEdgeResolutionByPair(graph, callerKey, targetKey, res)
	receiverIdx[resolvedReceiverIndexKey(callerKey, targetKey)] = resolvedReceiverEntry{resolvedType: resolvedType, line: line}
}

// buildTypePackageIndex maps simple type names to their packages.
// When a type appears in multiple packages, the first one wins (deterministic via sort).
func buildTypePackageIndex(graph *CallGraph) map[string]string {
	index := make(map[string]string)
	// Sort keys for deterministic output
	keys := make([]string, 0, len(graph.Functions))
	for k := range graph.Functions {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		fn := graph.Functions[k]
		if fn.ID.Type == "" {
			continue
		}
		if _, exists := index[fn.ID.Type]; !exists {
			index[fn.ID.Type] = fn.ID.Package
		}
	}
	return index
}

// resolveFluentCallsInFunction processes calls within a single function,
// propagating return types through fluent chains to resolve unresolved calls.
func resolveFluentCallsInFunction(
	fn *FunctionDecl,
	graph *CallGraph,
	typePackages map[string]string,
	methodsByQualifiedArity map[string][]string,
) int {
	resolved := 0
	sortedIndices := sortedFluentCallIndices(fn, graph)

	// Track return type from the last resolved call on each line (fluent chains share a line)
	lastReturnType := ""
	lastLine := -1

	for _, idx := range sortedIndices {
		call := &fn.Calls[idx]
		lastReturnType, lastLine = resetFluentLineState(call, lastReturnType, lastLine)

		if updateFluentReturnTypeFromResolvedCall(call, graph, &lastReturnType) {
			continue
		}
		if resolveFluentCall(call, fn, graph, typePackages, methodsByQualifiedArity, &lastReturnType) {
			resolved++
		}
	}

	return resolved
}

func sortedFluentCallIndices(fn *FunctionDecl, graph *CallGraph) []int {
	sortedIndices := make([]int, len(fn.Calls))
	for i := range sortedIndices {
		sortedIndices[i] = i
	}
	sort.SliceStable(sortedIndices, func(a, b int) bool {
		lineA := fn.Calls[sortedIndices[a]].Line
		lineB := fn.Calls[sortedIndices[b]].Line
		if lineA != lineB {
			return lineA < lineB
		}
		_, aResolved := graph.Functions[fn.Calls[sortedIndices[a]].Callee.String()]
		_, bResolved := graph.Functions[fn.Calls[sortedIndices[b]].Callee.String()]
		if aResolved != bResolved {
			return aResolved
		}
		return false
	})
	return sortedIndices
}

func resetFluentLineState(call *FunctionCall, lastReturnType string, lastLine int) (string, int) {
	if call.Line != lastLine {
		return "", call.Line
	}
	return lastReturnType, lastLine
}

func updateFluentReturnTypeFromResolvedCall(call *FunctionCall, graph *CallGraph, lastReturnType *string) bool {
	callee, ok := graph.Functions[call.Callee.String()]
	if !ok {
		return false
	}
	if callee.ReturnType != "" {
		*lastReturnType = normalizeLookupTypeName(callee.ReturnType)
	}
	return true
}

func resolveFluentCall(
	call *FunctionCall,
	fn *FunctionDecl,
	graph *CallGraph,
	typePackages map[string]string,
	methodsByQualifiedArity map[string][]string,
	lastReturnType *string,
) bool {
	if *lastReturnType == "" || !strings.Contains(call.Raw, ").") {
		return false
	}
	pkg, ok := typePackages[*lastReturnType]
	if !ok {
		return false
	}

	candidateID, candidateFn := findMethodOnTypeOrParents(
		graph, *lastReturnType, pkg, call, typePackages, methodsByQualifiedArity,
	)
	if candidateFn == nil {
		return false
	}

	oldCalleeKey := call.Callee.String()
	call.Callee = candidateID
	addCaller(graph.Callers, candidateID.String(), fn.ID.String(), oldCalleeKey)
	if candidateFn.ReturnType != "" {
		*lastReturnType = normalizeLookupTypeName(candidateFn.ReturnType)
	}
	return true
}

// findMethodOnTypeOrParents looks for a method on the given type, falling back to
// parent interfaces from the TypeHierarchy if not found directly.
func findMethodOnTypeOrParents(
	graph *CallGraph,
	typeName,
	pkg string,
	call *FunctionCall,
	typePackages map[string]string,
	methodsByQualifiedArity map[string][]string,
) (FunctionID, *FunctionDecl) {
	if candidateID, candidateFn := findBestQualifiedMethodCandidate(
		graph,
		pkg,
		typeName,
		call,
		methodsByQualifiedArity,
	); candidateFn != nil {
		return candidateID, candidateFn
	}

	// Try parent interfaces
	if graph.TypeHierarchy != nil {
		hierarchyKey := qualifiedJavaTypeName(pkg, typeName)
		parents := graph.TypeHierarchy[hierarchyKey]
		if len(parents) == 0 {
			parents = graph.TypeHierarchy[typeName]
		}
		for _, parent := range parents {
			parentPkg := pkg
			parentType := parent
			if pkgName, typeName, ok := splitQualifiedJavaType(parent); ok {
				parentPkg = pkgName
				parentType = typeName
			} else if resolvedPkg, ok := typePackages[parent]; ok {
				parentPkg = resolvedPkg
			}
			if candidateID, candidateFn := findBestQualifiedMethodCandidate(
				graph,
				parentPkg,
				parentType,
				call,
				methodsByQualifiedArity,
			); candidateFn != nil {
				return candidateID, candidateFn
			}
		}
	}

	return FunctionID{}, nil
}

func findBestQualifiedMethodCandidate(
	graph *CallGraph,
	pkg string,
	typeName string,
	call *FunctionCall,
	methodsByQualifiedArity map[string][]string,
) (FunctionID, *FunctionDecl) {
	keys := methodsByQualifiedArity[qualifiedMethodArityKey(pkg, typeName, call.Callee.Name)]
	if len(keys) == 0 {
		return FunctionID{}, nil
	}

	type scoredCandidate struct {
		key   string
		fn    *FunctionDecl
		score int
	}

	scored := make([]scoredCandidate, 0, len(keys))
	for _, key := range keys {
		fn := graph.Functions[key]
		if fn == nil {
			continue
		}
		scored = append(scored, scoredCandidate{
			key:   key,
			fn:    fn,
			score: scoreOverloadCandidate(fn, call),
		})
	}
	if len(scored) == 0 {
		return FunctionID{}, nil
	}

	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].score == scored[j].score {
			return scored[i].key < scored[j].key
		}
		return scored[i].score > scored[j].score
	})

	return scored[0].fn.ID, scored[0].fn
}

func scoreOverloadCandidate(fn *FunctionDecl, call *FunctionCall) int {
	score := 0
	for i, param := range fn.Parameters {
		inferred := inferJavaArgumentType(call, i)
		if inferred == "" {
			continue
		}

		paramType := normalizeJavaTypeName(param.Type)
		if paramType == inferred {
			score += 4
			continue
		}
		if stripGenericSuffix(paramType) == stripGenericSuffix(inferred) {
			score += 3
			continue
		}
		if strings.HasSuffix(paramType, "[]") && strings.TrimSuffix(paramType, "[]") == inferred {
			score += 2
		}
	}
	return score
}

func inferJavaArgumentType(call *FunctionCall, idx int) string {
	if idx < len(call.ArgumentSources) {
		if inferred := inferTypeFromSourceNodes(call.ArgumentSources[idx]); inferred != "" {
			return inferred
		}
	}
	if idx >= len(call.Arguments) {
		return ""
	}

	expr := strings.TrimSpace(call.Arguments[idx])
	switch {
	case expr == "":
		return ""
	case strings.HasPrefix(expr, "\"") && strings.HasSuffix(expr, "\""):
		return javaStringType
	case expr == "true" || expr == "false":
		return "boolean"
	case strings.HasPrefix(expr, "new "):
		body := strings.TrimSpace(strings.TrimPrefix(expr, "new "))
		if open := strings.Index(body, "("); open > 0 {
			return normalizeJavaTypeName(body[:open])
		}
	case looksLikeJavaEnumConstant(expr):
		if dot := strings.LastIndex(expr, "."); dot > 0 {
			return normalizeJavaTypeName(expr[:dot])
		}
	case looksLikeIntegerLiteral(expr):
		return "int"
	}

	return ""
}

func inferTypeFromSourceNodes(nodes []SourceNode) string {
	for _, node := range nodes {
		if node.DeclaredType != "" {
			return normalizeJavaTypeName(node.DeclaredType)
		}
		if inferred := inferTypeFromSourceNodes(node.SourceNodes); inferred != "" {
			return inferred
		}
	}
	return ""
}

func looksLikeJavaEnumConstant(expr string) bool {
	if dot := strings.LastIndex(expr, "."); dot > 0 && dot < len(expr)-1 {
		suffix := expr[dot+1:]
		for i, r := range suffix {
			if (r >= 'A' && r <= 'Z') || r == '_' || (i > 0 && r >= '0' && r <= '9') {
				continue
			}
			return false
		}
		return true
	}
	return false
}

func looksLikeIntegerLiteral(expr string) bool {
	expr = strings.TrimSuffix(expr, "L")
	if expr == "" {
		return false
	}
	for i, r := range expr {
		if i == 0 && (r == '+' || r == '-') {
			continue
		}
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// stripGenericSuffix removes generic type parameters from a type name.
// E.g., "Map<String, String>" → "Map", "ClaimsMutator<JwtBuilder>" → "ClaimsMutator".
func stripGenericSuffix(typeName string) string {
	if idx := strings.Index(typeName, "<"); idx > 0 {
		return typeName[:idx]
	}
	return typeName
}

func normalizeLookupTypeName(typeName string) string {
	normalized := strings.TrimSpace(stripGenericSuffix(typeName))
	if normalized == "" {
		return ""
	}

	pointerPrefix := ""
	for strings.HasPrefix(normalized, "*") {
		pointerPrefix += "*"
		normalized = strings.TrimPrefix(normalized, "*")
	}

	arraySuffix := ""
	for strings.HasSuffix(normalized, "[]") {
		arraySuffix = "[]" + arraySuffix
		normalized = strings.TrimSpace(strings.TrimSuffix(normalized, "[]"))
	}

	if stripped := stripQualifiedTypePrefix(normalized); stripped != "" {
		normalized = stripped
	}

	return pointerPrefix + normalized + arraySuffix
}

func stripQualifiedTypePrefix(typeName string) string {
	for _, sep := range []string{"::", "/", "."} {
		if stripped, ok := stripQualifiedTypePrefixBySeparator(typeName, sep); ok {
			return stripped
		}
	}
	return typeName
}

func stripQualifiedTypePrefixBySeparator(typeName, sep string) (string, bool) {
	if !strings.Contains(typeName, sep) {
		return "", false
	}

	parts := strings.Split(typeName, sep)
	for idx, part := range parts {
		if looksLikeQualifiedTypeSegment(part) {
			return strings.Join(parts[idx:], sep), true
		}
	}

	return parts[len(parts)-1], true
}

func looksLikeQualifiedTypeSegment(part string) bool {
	part = strings.TrimLeft(part, "*")
	if part == "" {
		return false
	}

	for _, r := range part {
		return r >= 'A' && r <= 'Z'
	}
	return false
}

func methodLookupName(name string) string {
	return BaseFunctionName(name)
}
