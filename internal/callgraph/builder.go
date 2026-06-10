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
		Functions:       make(map[string]*FunctionDecl),
		Callers:         make(map[string][]string),
		EdgeResolutions: make(map[string]EdgeResolution),
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

	for _, analysis := range analyses {
		for i := range analysis.Functions {
			fn := &analysis.Functions[i]
			key := fn.ID.String()
			graph.Functions[key] = fn
		}
	}

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

	return nil
}

// buildCallerIndex builds the reverse index: for each callee, which functions call it.
func (b *Builder) buildCallerIndex(graph *CallGraph) {
	methodsByName := indexMethodsByName(graph)
	methodsByQualifiedArity := indexMethodsByQualifiedArity(graph)
	subclassByTypeName := indexSubclassByTypeName(graph)

	for callerKey, fn := range graph.Functions {
		for i := range fn.Calls {
			call := fn.Calls[i]
			calleeKey := call.Callee.String()
			addCaller(graph.Callers, calleeKey, callerKey)
			recordEdgeResolution(graph, callerKey, calleeKey, EdgeKindExact, "", call.Line)

			overloadTargets := b.expandOverloadCandidates(call.Callee, methodsByQualifiedArity)
			resolvedTargets := make([]string, 1, 1+len(overloadTargets))
			resolvedTargets[0] = calleeKey
			for _, target := range overloadTargets {
				addCaller(graph.Callers, target, callerKey)
				recordEdgeResolution(graph, callerKey, target, EdgeKindExact, "", call.Line)
				resolvedTargets = append(resolvedTargets, target)
			}

			for _, target := range resolvedTargets {
				for _, alias := range b.expandInterfaceDispatch(target, graph, methodsByName) {
					addCaller(graph.Callers, alias.CalleeKey, callerKey)
					recordEdgeResolution(graph, callerKey, alias.CalleeKey, EdgeKindInterfaceDispatch, alias.DeclaredType, call.Line)
				}
				for _, alias := range b.expandPythonSubclassDispatch(target, graph, subclassByTypeName) {
					addCaller(graph.Callers, alias.CalleeKey, callerKey)
					recordEdgeResolution(graph, callerKey, alias.CalleeKey, EdgeKindPythonSubclassDispatch, alias.DeclaredType, call.Line)
				}
			}

			for _, alias := range b.expandFluentFallback(call, graph, methodsByName) {
				addCaller(graph.Callers, alias, callerKey)
				recordEdgeResolution(graph, callerKey, alias, EdgeKindNameOnly, "", call.Line)
			}
		}
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
	}
	key := EdgeResolutionKey(callerKey, calleeKey, resolution)
	if existing, ok := graph.EdgeResolutions[key]; ok && edgeKindRank(existing.Kind) >= edgeKindRank(kind) {
		return
	}
	graph.EdgeResolutions[key] = resolution
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

// indexSubclassByTypeName builds a map from base-class simple name → list of
// FunctionDecl pointers belonging to subclass methods that declare that base.
// Used exclusively by expandPythonSubclassDispatch. Only class-typed decls with
// non-empty OwnerBases are indexed.
func indexSubclassByTypeName(graph *CallGraph) map[string][]*FunctionDecl {
	index := make(map[string][]*FunctionDecl)
	for _, fn := range graph.Functions {
		if fn.OwnerType != "class" || len(fn.OwnerBases) == 0 {
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
	if !ok || calleeDecl.OwnerType != "class" || calleeDecl.ID.Type == "" {
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
		if candidate.OwnerType != "class" {
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
