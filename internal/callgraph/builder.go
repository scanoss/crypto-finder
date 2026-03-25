package callgraph

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
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
	Dir        string // Absolute filesystem path
	ImportPath string // Package/module path (e.g., "crypto/aes" or "javax.crypto")
}

// Builder constructs a CallGraph from multiple packages using a language-specific parser.
type Builder struct {
	parser       Parser
	typeResolver TypeResolver
}

// NewBuilder creates a new call graph builder with the given parser.
// An optional TypeResolver can be set via SetTypeResolver for language-native
// type resolution (bytecode analysis, go/types, etc.).
func NewBuilder(parser Parser) *Builder {
	return &Builder{
		parser: parser,
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
func (b *Builder) BuildFromDirectories(packages []PackageDir, typeOnlyPackages []PackageDir) (*CallGraph, error) {
	graph := &CallGraph{
		Functions: make(map[string]*FunctionDecl),
		Callers:   make(map[string][]string),
	}

	// Phase 1: Parse source files only for packages that need full analysis
	log.Info().Int("packages", len(packages)).Msg("Parsing source files for call graph")
	for _, pkg := range packages {
		if err := b.analyzePackage(pkg, graph); err != nil {
			log.Debug().Err(err).Str("package", pkg.ImportPath).Msg("Failed to analyze package")
			continue
		}
	}

	log.Info().Int("functions", len(graph.Functions)).Msg("Source parsing complete, building caller index")

	// Build the reverse caller index (includes interface dispatch and fluent fallback)
	b.buildCallerIndex(graph)

	// Phase 2: Type resolution from bytecode — index ALL packages (including type-only)
	// so that fluent chain resolution has complete type information across all deps.
	if b.typeResolver != nil {
		allPackages := make([]PackageDir, 0, len(packages)+len(typeOnlyPackages))
		allPackages = append(allPackages, packages...)
		allPackages = append(allPackages, typeOnlyPackages...)
		log.Info().Int("typePackages", len(allPackages)).Msg("Resolving types from bytecode")
		if err := b.typeResolver.ResolveTypes(graph, allPackages); err != nil {
			log.Warn().Err(err).Msg("Type resolver encountered errors (continuing with partial resolution)")
		}
	}

	// Resolve fluent chain calls using return type propagation (benefits from type resolver enrichment)
	resolveFluentChainsByReturnType(graph)

	log.Info().
		Int("functions", len(graph.Functions)).
		Int("callees", len(graph.Callers)).
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

	for callerKey, fn := range graph.Functions {
		for _, call := range fn.Calls {
			calleeKey := call.Callee.String()
			addCaller(graph.Callers, calleeKey, callerKey)

			for _, alias := range b.expandInterfaceDispatch(calleeKey, graph, methodsByName) {
				addCaller(graph.Callers, alias, callerKey)
			}

			for _, alias := range b.expandFluentFallback(call, graph, methodsByName) {
				addCaller(graph.Callers, alias, callerKey)
			}
		}
	}
}

func indexMethodsByName(graph *CallGraph) map[string][]*FunctionDecl {
	index := make(map[string][]*FunctionDecl)
	for _, fn := range graph.Functions {
		baseName := methodLookupName(fn.ID.Name)
		index[baseName] = append(index[baseName], fn)
	}
	return index
}

func addCaller(callers map[string][]string, calleeKey, callerKey string) {
	existing := callers[calleeKey]
	for _, candidate := range existing {
		if candidate == callerKey {
			return
		}
	}
	callers[calleeKey] = append(existing, callerKey)
}

// expandInterfaceDispatch links interface method call-sites to concrete implementations
// with matching method name/arity in the same namespace root.
func (b *Builder) expandInterfaceDispatch(
	calleeKey string,
	graph *CallGraph,
	methodsByName map[string][]*FunctionDecl,
) []string {
	calleeDecl, ok := graph.Functions[calleeKey]
	if !ok || calleeDecl.OwnerType != "interface" {
		return nil
	}

	targets := methodsByName[methodLookupName(calleeDecl.ID.Name)]
	if len(targets) == 0 {
		return nil
	}

	baseRoot := namespaceRoot(calleeDecl.ID.Package)
	results := make([]string, 0, len(targets))
	for _, candidate := range targets {
		if candidate.OwnerType == "interface" {
			continue
		}
		if len(candidate.Parameters) != len(calleeDecl.Parameters) {
			continue
		}
		if namespaceRoot(candidate.ID.Package) != baseRoot {
			continue
		}
		results = append(results, candidate.ID.String())
	}

	sort.Strings(results)
	if len(results) > 8 {
		return results[:8]
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
	calleeKey := call.Callee.String()
	if _, ok := graph.Functions[calleeKey]; ok {
		return nil
	}
	if !strings.Contains(call.Raw, ").") {
		return nil
	}

	rootType, rootMethod, ok := parseFluentRoot(call.Raw)
	if !ok {
		return nil
	}
	rootPkg := resolveRootPackage(rootType, rootMethod, methodsByName)
	if rootPkg == "" {
		return nil
	}

	targets := methodsByName[methodLookupName(call.Callee.Name)]
	if len(targets) == 0 {
		return nil
	}

	rootNS := namespaceRoot(rootPkg)
	type scored struct {
		key   string
		score int
	}
	scoredTargets := make([]scored, 0, len(targets))
	for _, candidate := range targets {
		if len(call.Arguments) > 0 && len(candidate.Parameters) != len(call.Arguments) {
			continue
		}
		candidateNS := namespaceRoot(candidate.ID.Package)
		if candidateNS != rootNS {
			continue
		}

		score := 1
		if candidate.ID.Package == rootPkg {
			score += 2
		}
		if strings.HasSuffix(candidate.ID.Type, "Builder") {
			score += 1
		}
		if strings.Contains(call.Raw, "SignatureAlgorithm.") && strings.Contains(candidate.ID.Package, "io.jsonwebtoken") {
			score += 2
		}
		scoredTargets = append(scoredTargets, scored{
			key:   candidate.ID.String(),
			score: score,
		})
	}

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
		resolved := 0
		for _, fn := range graph.Functions {
			resolved += resolveFluentCallsInFunction(fn, graph, typePackages)
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
func resolveFluentCallsInFunction(fn *FunctionDecl, graph *CallGraph, typePackages map[string]string) int {
	resolved := 0

	// Sort calls by line, then resolved-before-unresolved within the same line.
	// This ensures innermost calls in fluent chains (which are resolved, e.g., builder())
	// are processed first, setting lastReturnType for unresolved chained calls.
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
			return aResolved // resolved before unresolved
		}
		return false
	})

	// Track return type from the last resolved call on each line (fluent chains share a line)
	lastReturnType := ""
	lastLine := -1

	for _, idx := range sortedIndices {
		call := &fn.Calls[idx]
		calleeKey := call.Callee.String()

		// If this call is on a different line, reset the chain tracking
		if call.Line != lastLine {
			lastReturnType = ""
			lastLine = call.Line
		}

		// Check if this call is already resolved
		if callee, ok := graph.Functions[calleeKey]; ok {
			if callee.ReturnType != "" {
				lastReturnType = stripGenericSuffix(callee.ReturnType)
			}
			continue
		}

		// Unresolved call — try to resolve via the last return type
		if lastReturnType == "" || !strings.Contains(call.Raw, ").") {
			continue
		}

		// Look up the return type's package
		pkg, ok := typePackages[lastReturnType]
		if !ok {
			continue
		}

		// Try to find the method on this type (or its parent interfaces)
		candidateID, candidateFn := findMethodOnTypeOrParents(
			graph, lastReturnType, pkg, call.Callee.Name, typePackages,
		)
		if candidateFn == nil {
			continue
		}
		candidateKey := candidateID.String()

		// Rewrite the call's callee to the resolved function
		call.Callee = candidateID

		// Add to caller index
		addCaller(graph.Callers, candidateKey, fn.ID.String())

		// Propagate this callee's return type for the next chain link
		if candidateFn.ReturnType != "" {
			lastReturnType = stripGenericSuffix(candidateFn.ReturnType)
		}

		resolved++
	}

	return resolved
}

// findMethodOnTypeOrParents looks for a method on the given type, falling back to
// parent interfaces from the TypeHierarchy if not found directly.
func findMethodOnTypeOrParents(
	graph *CallGraph, typeName, pkg, methodName string, typePackages map[string]string,
) (FunctionID, *FunctionDecl) {
	// Try direct match first
	id := FunctionID{Package: pkg, Type: typeName, Name: methodName}
	if fn, ok := graph.Functions[id.String()]; ok {
		return id, fn
	}

	// Try parent interfaces
	if graph.TypeHierarchy != nil {
		for _, parent := range graph.TypeHierarchy[typeName] {
			parentPkg, ok := typePackages[parent]
			if !ok {
				parentPkg = pkg // assume same package
			}
			parentID := FunctionID{Package: parentPkg, Type: parent, Name: methodName}
			if fn, ok := graph.Functions[parentID.String()]; ok {
				return parentID, fn
			}
		}
	}

	return FunctionID{}, nil
}

// stripGenericSuffix removes generic type parameters from a type name.
// E.g., "Map<String, String>" → "Map", "ClaimsMutator<JwtBuilder>" → "ClaimsMutator"
func stripGenericSuffix(typeName string) string {
	if idx := strings.Index(typeName, "<"); idx > 0 {
		return typeName[:idx]
	}
	return typeName
}

func methodLookupName(name string) string {
	idx := strings.LastIndex(name, "#")
	if idx <= 0 || idx >= len(name)-1 {
		return name
	}
	if _, err := strconv.Atoi(name[idx+1:]); err != nil {
		return name
	}
	return name[:idx]
}
