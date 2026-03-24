package callgraph

import (
	"archive/zip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/javaruntime"
)

const maxJavaJARWorkers = 8

const javaResolverProgressInterval = 5000

// JavaBytecodeTypeResolver reads compiled .class files from Maven-cached JARs
// to extract method signatures with full type information. This provides
// accurate parameter and return types without requiring a JDK or compilation.
type JavaBytecodeTypeResolver struct {
	// mavenRepoPath is the root of the Maven local repository (e.g., ~/.m2/repository).
	mavenRepoPath         string
	resolveJARPath        func(PackageDir) string
	resolvePlatformSource func() (*javaPlatformIndexSource, error)
	extractClassInfo      func(string) ([]*classFileInfo, error)
	bytecodeCache         BytecodeIndexCache
	runtimeConfig         javaruntime.Config
	getenv                func(string) string
}

// NewJavaBytecodeTypeResolver creates a resolver that reads bytecode from Maven JARs.
func NewJavaBytecodeTypeResolver(runtimeConfig javaruntime.Config) *JavaBytecodeTypeResolver {
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	return &JavaBytecodeTypeResolver{
		mavenRepoPath: filepath.Join(home, ".m2", "repository"),
		runtimeConfig: runtimeConfig,
		getenv:        os.Getenv,
	}
}

// StrictFailure reports whether Java runtime selection failures should fail the build.
func (r *JavaBytecodeTypeResolver) StrictFailure() bool {
	return r.runtimeConfig.IsExplicitMajor()
}

// SetBytecodeIndexCache configures an optional per-artifact bytecode cache.
func (r *JavaBytecodeTypeResolver) SetBytecodeIndexCache(cache BytecodeIndexCache) {
	r.bytecodeCache = cache
}

// methodSignature holds parsed method type information from bytecode.
type methodSignature struct {
	className  string   // e.g., "JwtBuilder"
	methodName string   // e.g., "signWith"
	paramTypes []string // e.g., ["SignatureAlgorithm", "byte[]"]
	returnType string   // e.g., "JwtBuilder"
	fullClass  string   // e.g., "io.jsonwebtoken.JwtBuilder"
}

type jarTask struct {
	order       int
	jarPath     string
	artifactKey string
}

type jarIndexChunk struct {
	order     int
	index     map[string][]methodSignature
	hierarchy map[string][]string
	err       error
	jarPath   string
	stats     jarProcessingStats
}

type jarProcessingStats struct {
	cacheGets          int
	cacheHits          int
	cacheMisses        int
	cachePuts          int
	cacheGetDuration   time.Duration
	cachePutDuration   time.Duration
	parseCount         int
	parseDuration      time.Duration
	buildIndexCount    int
	buildIndexDuration time.Duration
}

type javaPlatformIndexSource struct {
	RuntimeVersion    string
	SignatureSource   string
	ArchivePaths      []string
	ArtifactKey       string
	UnavailableReason string
}

type javaBytecodeIndexStats struct {
	jars               int
	cacheGets          int
	cacheHits          int
	cacheMisses        int
	cachePuts          int
	cacheGetDuration   time.Duration
	cachePutDuration   time.Duration
	parseCount         int
	parseDuration      time.Duration
	buildIndexCount    int
	buildIndexDuration time.Duration
	mergeDuration      time.Duration
	totalDuration      time.Duration
}

type javaMethodLookup struct {
	qualified      map[string][]methodSignature
	simple         map[string][]methodSignature
	qualifiedArity map[string][]methodSignature
	simpleArity    map[string][]methodSignature
}

type javaResolverProgress struct {
	phase     string
	total     int
	processed int
	resolved  int
	nextLogAt int
	start     time.Time
}

// ResolveTypes enriches the call graph with type information from Java bytecode.
func (r *JavaBytecodeTypeResolver) ResolveTypes(graph *CallGraph, sourceRoots []PackageDir) error {
	resolveStart := time.Now()
	tasks := r.collectJARTasks(sourceRoots)

	platformSource, platformSourceErr := r.discoverPlatformSource()
	platformMeta := r.platformSignatureMetadata(platformSource, platformSourceErr)

	workers := min(max(runtime.NumCPU()/2, 1), maxJavaJARWorkers)
	index, hierarchy, indexStats := r.buildIndexes(tasks, workers)
	if err := r.handlePlatformDiscoveryError(graph, platformMeta, platformSourceErr); err != nil {
		return err
	}
	r.mergePlatformIndex(index, hierarchy, platformSource, platformMeta)

	if graph != nil {
		graph.JavaPlatformSignatures = platformMeta
	}

	if len(index) == 0 {
		return nil
	}

	inheritanceStart := time.Now()
	propagateInheritedMethods(index, hierarchy)
	inheritanceDuration := time.Since(inheritanceStart)

	lookupBuildStart := time.Now()
	lookup := buildJavaMethodLookup(index)
	lookupBuildDuration := time.Since(lookupBuildStart)

	hierarchyStoreStart := time.Now()
	// Store hierarchy on the graph for use by the fluent chain resolver
	if graph.TypeHierarchy == nil {
		graph.TypeHierarchy = make(map[string][]string)
	}
	for k, v := range hierarchy {
		graph.TypeHierarchy[k] = v
	}
	hierarchyStoreDuration := time.Since(hierarchyStoreStart)

	externalSignatureStoreStart := time.Now()
	if graph.ExternalMethodSignatures == nil {
		graph.ExternalMethodSignatures = make(map[string][]ExternalMethodSignature)
	}
	for key, sigs := range buildExternalMethodSignatureIndex(index) {
		graph.ExternalMethodSignatures[key] = sigs
	}
	externalSignatureStoreDuration := time.Since(externalSignatureStoreStart)

	if len(index) == 0 {
		return nil
	}

	declarationEnrichmentStart := time.Now()
	resolved := enrichJavaFunctionDeclarations(graph, lookup)
	declarationEnrichmentDuration := time.Since(declarationEnrichmentStart)

	callRewriteStart := time.Now()
	callsResolved := rewriteJavaCallsFromIndex(graph, lookup)
	callRewriteDuration := time.Since(callRewriteStart)

	log.Info().
		Int("jars", indexStats.jars).
		Int("cache_gets", indexStats.cacheGets).
		Int("cache_hits", indexStats.cacheHits).
		Int("cache_misses", indexStats.cacheMisses).
		Int("cache_puts", indexStats.cachePuts).
		Int("parsed_jars", indexStats.parseCount).
		Int("indexed_jars", indexStats.buildIndexCount).
		Dur("cache_get_duration", indexStats.cacheGetDuration).
		Dur("cache_put_duration", indexStats.cachePutDuration).
		Dur("parse_duration", indexStats.parseDuration).
		Dur("build_index_duration", indexStats.buildIndexDuration).
		Dur("merge_duration", indexStats.mergeDuration).
		Dur("index_duration", indexStats.totalDuration).
		Msg("Java bytecode indexing stats")

	log.Info().
		Int("declarations_enriched", resolved).
		Int("calls_resolved", callsResolved).
		Int("methods_indexed", len(index)).
		Bool("platform_signatures_used", platformMeta.SignaturesUsed).
		Str("platform_signature_source", platformMeta.SignatureSource).
		Str("platform_runtime_version", platformMeta.RuntimeVersion).
		Str("platform_unavailable_reason", platformMeta.UnavailableReason).
		Dur("inheritance_duration", inheritanceDuration).
		Dur("lookup_build_duration", lookupBuildDuration).
		Dur("hierarchy_store_duration", hierarchyStoreDuration).
		Dur("external_signature_store_duration", externalSignatureStoreDuration).
		Dur("declaration_enrichment_duration", declarationEnrichmentDuration).
		Dur("call_rewrite_duration", callRewriteDuration).
		Dur("total_duration", time.Since(resolveStart)).
		Msg("Java bytecode type resolution complete")

	return nil
}

func (r *JavaBytecodeTypeResolver) buildIndexes(tasks []jarTask, workers int) (map[string][]methodSignature, map[string][]string, javaBytecodeIndexStats) {
	index := make(map[string][]methodSignature)
	hierarchy := make(map[string][]string)
	var indexStats javaBytecodeIndexStats
	if len(tasks) == 0 {
		return index, hierarchy, indexStats
	}

	log.Info().
		Int("jars", len(tasks)).
		Int("workers", workers).
		Msg("Starting parallel Java bytecode indexing")
	return r.indexJARTasks(tasks, workers)
}

func (r *JavaBytecodeTypeResolver) handlePlatformDiscoveryError(
	graph *CallGraph,
	platformMeta *JavaPlatformSignatureMetadata,
	platformSourceErr error,
) error {
	if platformSourceErr == nil {
		return nil
	}

	log.Debug().Err(platformSourceErr).Msg("Failed to discover Java platform signature source")
	if !r.StrictFailure() {
		return nil
	}
	if graph != nil {
		graph.JavaPlatformSignatures = platformMeta
	}
	return platformSourceErr
}

func (r *JavaBytecodeTypeResolver) mergePlatformIndex(
	index map[string][]methodSignature,
	hierarchy map[string][]string,
	platformSource *javaPlatformIndexSource,
	platformMeta *JavaPlatformSignatureMetadata,
) {
	if platformSource == nil || len(platformSource.ArchivePaths) == 0 {
		return
	}

	start := time.Now()
	log.Info().
		Str("signature_source", platformSource.SignatureSource).
		Int("archives", len(platformSource.ArchivePaths)).
		Msg("Starting Java platform signature merge")

	platformIndex, platformHierarchy, err := r.indexPlatformSource(platformSource)
	if err != nil {
		if platformMeta.UnavailableReason == "" {
			platformMeta.UnavailableReason = "platform_index_failed"
		}
		log.Debug().Err(err).Str("source", platformSource.SignatureSource).Msg("Failed to index Java platform signatures")
		return
	}

	mergeMethodIndex(index, platformIndex)
	mergeTypeHierarchy(hierarchy, platformHierarchy)
	platformMeta.SignaturesUsed = true

	log.Info().
		Str("signature_source", platformSource.SignatureSource).
		Int("archives", len(platformSource.ArchivePaths)).
		Int("methods", len(platformIndex)).
		Int("types", len(platformHierarchy)).
		Dur("duration", time.Since(start)).
		Msg("Java platform signature merge complete")
}

func enrichJavaFunctionDeclarations(graph *CallGraph, lookup *javaMethodLookup) int {
	resolved := 0
	progress := newJavaResolverProgress("declaration_enrichment", len(graph.Functions))
	for _, fn := range graph.Functions {
		if fn.ID.Type == "" {
			progress.Tick(false)
			continue
		}
		signatures := lookupJavaMethodSignatures(lookup, fn.ID.Package, fn.ID.Type, BaseFunctionName(fn.ID.Name), len(fn.Parameters))
		didResolve := enrichJavaFunctionDeclaration(fn, signatures)
		if didResolve {
			resolved++
		}
		progress.Tick(didResolve)
	}
	progress.Finish()
	return resolved
}

func enrichJavaFunctionDeclaration(fn *FunctionDecl, signatures []methodSignature) bool {
	if len(signatures) == 0 {
		return false
	}

	arity := len(fn.Parameters)
	for _, sig := range signatures {
		if len(sig.paramTypes) != arity {
			continue
		}
		enriched := false
		for i := range fn.Parameters {
			if i < len(sig.paramTypes) && shouldOverrideType(fn.Parameters[i].Type, sig.paramTypes[i]) {
				fn.Parameters[i].Type = sig.paramTypes[i]
				enriched = true
			}
		}
		if fn.ReturnType == "" && sig.returnType != "" {
			fn.ReturnType = sig.returnType
			enriched = true
		}
		return enriched
	}
	return false
}

func rewriteJavaCallsFromIndex(graph *CallGraph, lookup *javaMethodLookup) int {
	callsResolved := 0
	methodsByQualifiedArity := indexMethodsByQualifiedArity(graph)
	progress := newJavaResolverProgress("call_rewrite", countJavaCalls(graph))
	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			didResolve := rewriteJavaCallFromIndex(graph, fn, &fn.Calls[i], lookup, methodsByQualifiedArity)
			if didResolve {
				callsResolved++
			}
			progress.Tick(didResolve)
		}
	}
	progress.Finish()
	return callsResolved
}

func rewriteJavaCallFromIndex(
	graph *CallGraph,
	fn *FunctionDecl,
	call *FunctionCall,
	lookup *javaMethodLookup,
	methodsByQualifiedArity map[string][]string,
) bool {
	if _, ok := graph.Functions[call.Callee.String()]; ok {
		return false
	}
	typeName := call.Callee.Type
	if typeName == "" || strings.Contains(typeName, "(") {
		return false
	}

	signatures := lookupJavaMethodSignatures(lookup, call.Callee.Package, typeName, BaseFunctionName(call.Callee.Name), len(call.Arguments))
	if len(signatures) == 0 {
		return false
	}
	for _, sig := range signatures {
		if applyResolvedJavaCall(graph, fn, call, sig, methodsByQualifiedArity) {
			return true
		}
	}
	return false
}

func applyResolvedJavaCall(
	graph *CallGraph,
	fn *FunctionDecl,
	call *FunctionCall,
	sig methodSignature,
	methodsByQualifiedArity map[string][]string,
) bool {
	pkg := ""
	if idx := strings.LastIndex(sig.fullClass, "."); idx >= 0 {
		pkg = sig.fullClass[:idx]
	}
	newID := FunctionID{
		Package: pkg,
		Type:    sig.className,
		Name:    call.Callee.Name,
	}
	oldCalleeKey := call.Callee.String()
	if _, ok := graph.Functions[newID.String()]; ok {
		call.Callee = newID
		addCaller(graph.Callers, newID.String(), fn.ID.String(), oldCalleeKey)
		return true
	}
	candidateID, candidateFn := findBestQualifiedMethodCandidate(
		graph,
		newID.Package,
		newID.Type,
		call,
		methodsByQualifiedArity,
	)
	if candidateFn == nil {
		return false
	}
	call.Callee = candidateID
	addCaller(graph.Callers, candidateID.String(), fn.ID.String(), oldCalleeKey)
	return true
}

func (r *JavaBytecodeTypeResolver) collectJARTasks(sourceRoots []PackageDir) []jarTask {
	tasks := make([]jarTask, 0, len(sourceRoots))
	seen := make(map[string]struct{}, len(sourceRoots))

	for _, root := range sourceRoots {
		jarPath := r.findCompiledJAR(root)
		if jarPath == "" {
			continue
		}
		if absPath, err := filepath.Abs(jarPath); err == nil {
			jarPath = absPath
		} else {
			jarPath = filepath.Clean(jarPath)
		}
		if _, ok := seen[jarPath]; ok {
			continue
		}
		seen[jarPath] = struct{}{}
		tasks = append(tasks, jarTask{
			order:       len(tasks),
			jarPath:     jarPath,
			artifactKey: buildBytecodeArtifactKey(root),
		})
	}

	return tasks
}

func (r *JavaBytecodeTypeResolver) indexJARTasks(tasks []jarTask, workers int) (map[string][]methodSignature, map[string][]string, javaBytecodeIndexStats) {
	indexStart := time.Now()
	workCh := make(chan jarTask, len(tasks))
	resultCh := make(chan jarIndexChunk, len(tasks))

	for _, task := range tasks {
		workCh <- task
	}
	close(workCh)

	var wg sync.WaitGroup
	for range min(workers, len(tasks)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range workCh {
				resultCh <- r.indexSingleJAR(task)
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	results := make([]jarIndexChunk, 0, len(tasks))
	stats := javaBytecodeIndexStats{jars: len(tasks)}
	for result := range resultCh {
		stats.cacheGets += result.stats.cacheGets
		stats.cacheHits += result.stats.cacheHits
		stats.cacheMisses += result.stats.cacheMisses
		stats.cachePuts += result.stats.cachePuts
		stats.cacheGetDuration += result.stats.cacheGetDuration
		stats.cachePutDuration += result.stats.cachePutDuration
		stats.parseCount += result.stats.parseCount
		stats.parseDuration += result.stats.parseDuration
		stats.buildIndexCount += result.stats.buildIndexCount
		stats.buildIndexDuration += result.stats.buildIndexDuration
		if result.err != nil {
			log.Debug().Err(result.err).Str("jar", result.jarPath).Msg("Failed to read JAR for type resolution")
			continue
		}
		results = append(results, result)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].order < results[j].order
	})

	mergeStart := time.Now()
	index := make(map[string][]methodSignature)
	hierarchy := make(map[string][]string)
	for i := range results {
		result := results[i]
		for key, sigs := range result.index {
			index[key] = append(index[key], sigs...)
		}
		for className, parents := range result.hierarchy {
			hierarchy[className] = parents
		}
	}

	stats.mergeDuration = time.Since(mergeStart)
	stats.totalDuration = time.Since(indexStart)

	return index, hierarchy, stats
}

func (r *JavaBytecodeTypeResolver) indexSingleJAR(task jarTask) jarIndexChunk {
	var stats jarProcessingStats
	cacheKey := bytecodeCacheStorageKey(task.artifactKey)
	if cacheKey != "" && r.bytecodeCache != nil {
		cacheGetStart := time.Now()
		cached, ok, err := r.bytecodeCache.Get(context.Background(), cacheKey)
		stats.cacheGets++
		stats.cacheGetDuration += time.Since(cacheGetStart)
		if err != nil {
			log.Debug().Err(err).Str("artifact", task.artifactKey).Msg("Failed to load bytecode cache entry")
		} else if ok && isValidCachedBytecodeIndex(cached, task.artifactKey) {
			stats.cacheHits++
			return jarIndexChunk{
				order:     task.order,
				index:     cached.MethodsIndex,
				hierarchy: cached.TypeHierarchy,
				jarPath:   task.jarPath,
				stats:     stats,
			}
		}
		stats.cacheMisses++
	}

	parseStart := time.Now()
	classInfos, err := r.readClassInfo(task.jarPath)
	stats.parseCount++
	stats.parseDuration += time.Since(parseStart)
	if err != nil {
		return jarIndexChunk{
			order:   task.order,
			err:     err,
			jarPath: task.jarPath,
			stats:   stats,
		}
	}

	buildIndexStart := time.Now()
	index := make(map[string][]methodSignature)
	hierarchy := make(map[string][]string)
	for _, info := range classInfos {
		for _, sig := range info.methods {
			key := sig.fullClass + "." + sig.methodName
			index[key] = append(index[key], sig)
		}
		if parents := classHierarchyParents(info); len(parents) > 0 {
			hierarchy[info.fullClassName] = parents
		}
	}
	stats.buildIndexCount++
	stats.buildIndexDuration += time.Since(buildIndexStart)

	chunk := jarIndexChunk{
		order:     task.order,
		index:     index,
		hierarchy: hierarchy,
		jarPath:   task.jarPath,
		stats:     stats,
	}

	if cacheKey != "" && r.bytecodeCache != nil {
		entry := &CachedBytecodeIndex{
			SchemaVersion: bytecodeCacheSchemaVersion,
			ArtifactKey:   task.artifactKey,
			MethodsIndex:  index,
			TypeHierarchy: hierarchy,
		}
		cachePutStart := time.Now()
		if err := r.bytecodeCache.Put(context.Background(), cacheKey, entry); err != nil {
			log.Debug().Err(err).Str("artifact", task.artifactKey).Msg("Failed to store bytecode cache entry")
		} else {
			chunk.stats.cachePuts++
		}
		chunk.stats.cachePutDuration += time.Since(cachePutStart)
	}

	return chunk
}

func (r *JavaBytecodeTypeResolver) indexPlatformSource(source *javaPlatformIndexSource) (map[string][]methodSignature, map[string][]string, error) {
	if source == nil || len(source.ArchivePaths) == 0 {
		return nil, nil, nil
	}

	cacheKey := bytecodeCacheStorageKey(source.ArtifactKey)
	if cacheKey != "" && r.bytecodeCache != nil {
		cached, ok, err := r.bytecodeCache.Get(context.Background(), cacheKey)
		if err != nil {
			log.Debug().Err(err).Str("artifact", source.ArtifactKey).Msg("Failed to load Java platform bytecode cache entry")
		} else if ok && isValidCachedBytecodeIndex(cached, source.ArtifactKey) {
			return cached.MethodsIndex, cached.TypeHierarchy, nil
		}
	}

	classInfos := make([]*classFileInfo, 0)
	for _, archivePath := range source.ArchivePaths {
		infos, err := r.readClassInfo(archivePath)
		if err != nil {
			log.Debug().Err(err).Str("archive", archivePath).Msg("Failed to read Java platform archive")
			continue
		}
		classInfos = append(classInfos, infos...)
	}
	if len(classInfos) == 0 {
		return nil, nil, fmt.Errorf("no Java platform classes indexed from %s", source.SignatureSource)
	}

	index, hierarchy := buildMethodIndexFromClassInfos(classInfos)

	if cacheKey != "" && r.bytecodeCache != nil {
		entry := &CachedBytecodeIndex{
			SchemaVersion: bytecodeCacheSchemaVersion,
			ArtifactKey:   source.ArtifactKey,
			MethodsIndex:  index,
			TypeHierarchy: hierarchy,
		}
		if err := r.bytecodeCache.Put(context.Background(), cacheKey, entry); err != nil {
			log.Debug().Err(err).Str("artifact", source.ArtifactKey).Msg("Failed to store Java platform bytecode cache entry")
		}
	}

	return index, hierarchy, nil
}

// findCompiledJAR locates the compiled JAR for a Maven dependency.
// importPath format: "groupId:artifactId" (e.g., "io.jsonwebtoken:jjwt-api").
func (r *JavaBytecodeTypeResolver) findCompiledJAR(root PackageDir) string {
	if r.resolveJARPath != nil {
		return r.resolveJARPath(root)
	}
	if root.Version == "" {
		return ""
	}

	parts := strings.SplitN(root.ImportPath, ":", 2)
	if len(parts) != 2 {
		return ""
	}
	groupID := parts[0]
	artifactID := parts[1]

	// Convert groupId to directory path
	groupDir := strings.ReplaceAll(groupID, ".", string(filepath.Separator))
	jarPath := filepath.Join(r.mavenRepoPath, groupDir, artifactID, root.Version, artifactID+"-"+root.Version+".jar")
	if _, err := os.Stat(jarPath); err == nil {
		return jarPath
	}
	return ""
}

func (r *JavaBytecodeTypeResolver) readClassInfo(path string) ([]*classFileInfo, error) {
	if r.extractClassInfo != nil {
		return r.extractClassInfo(path)
	}
	switch {
	case strings.HasSuffix(path, ".jmod"):
		return r.extractFromJMOD(path)
	case strings.HasSuffix(path, ".jar"):
		return r.extractFromJAR(path)
	default:
		return nil, fmt.Errorf("unsupported Java archive format: %s", path)
	}
}

func buildBytecodeArtifactKey(root PackageDir) string {
	if root.ImportPath == "" || root.Version == "" {
		return ""
	}
	return root.ImportPath + "@" + root.Version
}

func buildJavaPlatformSignatureMetadata(
	source *javaPlatformIndexSource,
	discoveryErr error,
) *JavaPlatformSignatureMetadata {
	meta := &JavaPlatformSignatureMetadata{
		RequestedMajor:  javaruntime.AutoMajor,
		SignatureSource: "unavailable",
	}
	if source != nil {
		meta.RuntimeVersion = source.RuntimeVersion
		if source.SignatureSource != "" {
			meta.SignatureSource = source.SignatureSource
		}
		meta.UnavailableReason = source.UnavailableReason
	}
	if discoveryErr != nil && meta.UnavailableReason == "" {
		meta.UnavailableReason = "platform_source_discovery_failed"
	}
	return meta
}

func (r *JavaBytecodeTypeResolver) platformSignatureMetadata(
	source *javaPlatformIndexSource,
	discoveryErr error,
) *JavaPlatformSignatureMetadata {
	meta := buildJavaPlatformSignatureMetadata(source, discoveryErr)
	meta.RequestedMajor = r.runtimeConfig.RequestedMajorOrAuto()
	return meta
}

func mergeMethodIndex(dst, src map[string][]methodSignature) {
	for key, sigs := range src {
		dst[key] = append(dst[key], sigs...)
	}
}

func mergeTypeHierarchy(dst, src map[string][]string) {
	for className, parents := range src {
		dst[className] = parents
	}
}

func qualifiedJavaTypeName(pkg, typ string) string {
	if pkg == "" {
		return typ
	}
	if typ == "" {
		return pkg
	}
	return pkg + "." + typ
}

func simpleJavaTypeName(fullClassName string) string {
	if pkg, typ, ok := splitQualifiedJavaType(fullClassName); ok && pkg != "" && typ != "" {
		return typ
	}
	return fullClassName
}

func normalizeJavaHierarchyParents(fullClassName string, parents []string) []string {
	if len(parents) == 0 {
		return nil
	}

	qualified := make([]string, 0, len(parents))
	pkg, _, _ := splitQualifiedJavaType(fullClassName)
	for _, parent := range parents {
		parent = strings.TrimSpace(parent)
		if parent == "" {
			continue
		}
		if parentPkg, parentType, ok := splitQualifiedJavaType(parent); ok && parentPkg != "" && parentType != "" {
			qualified = append(qualified, parent)
			continue
		}
		if pkg != "" {
			qualified = append(qualified, qualifiedJavaTypeName(pkg, parent))
			continue
		}
		qualified = append(qualified, parent)
	}
	if len(qualified) == 0 {
		return nil
	}
	return qualified
}

func classHierarchyParents(info *classFileInfo) []string {
	if info == nil {
		return nil
	}
	parents := make([]string, 0, len(info.interfaces)+1)
	parents = append(parents, info.interfaces...)
	if strings.TrimSpace(info.superClass) != "" {
		parents = append(parents, info.superClass)
	}
	return normalizeJavaHierarchyParents(info.fullClassName, parents)
}

func lookupJavaMethodSignatures(lookup *javaMethodLookup, pkg, typeName, methodName string, arity int) []methodSignature {
	if lookup == nil || typeName == "" || methodName == "" {
		return nil
	}

	qualifiedClass := qualifiedJavaTypeName(pkg, typeName)
	if arity >= 0 {
		if sigs := lookup.qualifiedArity[javaLookupArityKey(qualifiedClass, methodName, arity)]; len(sigs) > 0 {
			return sigs
		}
		if sigs := lookup.simpleArity[javaLookupArityKey(typeName, methodName, arity)]; len(sigs) > 0 {
			return sigs
		}
		return nil
	}

	if sigs := lookup.qualified[qualifiedClass+"."+methodName]; len(sigs) > 0 {
		return sigs
	}
	if sigs := lookup.simple[typeName+"."+methodName]; len(sigs) > 0 {
		return sigs
	}
	return nil
}

func buildJavaMethodLookup(index map[string][]methodSignature) *javaMethodLookup {
	lookup := &javaMethodLookup{
		qualified:      index,
		simple:         make(map[string][]methodSignature),
		qualifiedArity: make(map[string][]methodSignature),
		simpleArity:    make(map[string][]methodSignature),
	}

	keys := make([]string, 0, len(index))
	for key := range index {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		sigs := index[key]
		dot := strings.LastIndex(key, ".")
		if dot <= 0 || dot == len(key)-1 {
			continue
		}
		fullClass := key[:dot]
		methodName := key[dot+1:]
		simpleKey := simpleJavaTypeName(fullClass) + "." + methodName
		lookup.simple[simpleKey] = append(lookup.simple[simpleKey], sigs...)

		for _, sig := range sigs {
			qualifiedArityKey := javaLookupArityKey(fullClass, methodName, len(sig.paramTypes))
			simpleArityKey := javaLookupArityKey(simpleJavaTypeName(fullClass), methodName, len(sig.paramTypes))
			lookup.qualifiedArity[qualifiedArityKey] = append(lookup.qualifiedArity[qualifiedArityKey], sig)
			lookup.simpleArity[simpleArityKey] = append(lookup.simpleArity[simpleArityKey], sig)
		}
	}

	return lookup
}

func javaLookupArityKey(typeName, methodName string, arity int) string {
	return fmt.Sprintf("%s.%s#%d", typeName, methodName, arity)
}

func countJavaCalls(graph *CallGraph) int {
	total := 0
	for _, fn := range graph.Functions {
		total += len(fn.Calls)
	}
	return total
}

func newJavaResolverProgress(phase string, total int) *javaResolverProgress {
	progress := &javaResolverProgress{
		phase:     phase,
		total:     total,
		nextLogAt: javaResolverProgressInterval,
		start:     time.Now(),
	}
	log.Info().
		Str("phase", phase).
		Int("total", total).
		Msg("Starting Java resolver phase")
	return progress
}

func (p *javaResolverProgress) Tick(resolved bool) {
	p.processed++
	if resolved {
		p.resolved++
	}

	if p.processed == p.total || p.processed >= p.nextLogAt {
		log.Info().
			Str("phase", p.phase).
			Int("processed", p.processed).
			Int("total", p.total).
			Int("resolved", p.resolved).
			Dur("elapsed", time.Since(p.start)).
			Msg("Java resolver progress")
		p.nextLogAt += javaResolverProgressInterval
	}
}

func (p *javaResolverProgress) Finish() {
	if p.processed == p.total {
		log.Info().
			Str("phase", p.phase).
			Int("processed", p.processed).
			Int("total", p.total).
			Int("resolved", p.resolved).
			Dur("duration", time.Since(p.start)).
			Msg("Java resolver phase complete")
	}
}

func (r *JavaBytecodeTypeResolver) discoverPlatformSource() (*javaPlatformIndexSource, error) {
	if r.resolvePlatformSource != nil {
		return r.resolvePlatformSource()
	}

	if selection, err := javaruntime.ResolveExplicitSelection(r.runtimeConfig); err != nil {
		return &javaPlatformIndexSource{
			SignatureSource:   "unavailable",
			UnavailableReason: "invalid_configured_java_home",
		}, err
	} else if selection != nil {
		return r.discoverPlatformSourceForHome(selection.JavaHome, selection.RuntimeVersion)
	}

	getenv := r.getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	javaHome := strings.TrimSpace(getenv("JAVA_HOME"))
	if javaHome == "" {
		return &javaPlatformIndexSource{
			SignatureSource:   "unavailable",
			UnavailableReason: "java_home_not_set",
		}, nil
	}

	runtimeVersion, err := javaruntime.RuntimeVersion(javaHome)
	if err != nil {
		return &javaPlatformIndexSource{
			SignatureSource:   "unavailable",
			UnavailableReason: "release_file_unreadable",
		}, err
	}

	return r.discoverPlatformSourceForHome(javaHome, runtimeVersion)
}

func (r *JavaBytecodeTypeResolver) discoverPlatformSourceForHome(javaHome, runtimeVersion string) (*javaPlatformIndexSource, error) {
	if runtimeVersion == "" {
		return &javaPlatformIndexSource{
			SignatureSource:   "unavailable",
			UnavailableReason: "java_version_missing",
		}, nil
	}

	if !javaruntime.IsSupportedMajor(javaruntime.MajorFromVersion(runtimeVersion)) {
		return &javaPlatformIndexSource{
			RuntimeVersion:    runtimeVersion,
			SignatureSource:   "unavailable",
			UnavailableReason: "unsupported_java_major_version",
		}, nil
	}

	jmodPaths, err := filepath.Glob(filepath.Join(javaHome, "jmods", "*.jmod"))
	if err == nil && len(jmodPaths) > 0 {
		sort.Strings(jmodPaths)
		return &javaPlatformIndexSource{
			RuntimeVersion:  runtimeVersion,
			SignatureSource: "jmods",
			ArchivePaths:    jmodPaths,
			ArtifactKey:     "jdk-platform@" + runtimeVersion + ":jmods",
		}, nil
	}

	rtCandidates := []string{
		filepath.Join(javaHome, "lib", "rt.jar"),
		filepath.Join(javaHome, "jre", "lib", "rt.jar"),
	}
	for _, candidate := range rtCandidates {
		if _, statErr := os.Stat(candidate); statErr == nil {
			return &javaPlatformIndexSource{
				RuntimeVersion:  runtimeVersion,
				SignatureSource: "rt.jar",
				ArchivePaths:    []string{candidate},
				ArtifactKey:     "jdk-platform@" + runtimeVersion + ":rt.jar",
			}, nil
		}
	}

	return &javaPlatformIndexSource{
		RuntimeVersion:    runtimeVersion,
		SignatureSource:   "unavailable",
		UnavailableReason: "no_platform_archives",
	}, nil
}

func buildExternalMethodSignatureIndex(index map[string][]methodSignature) map[string][]ExternalMethodSignature {
	out := make(map[string][]ExternalMethodSignature)
	seen := make(map[string]map[string]struct{})
	for _, sigs := range index {
		for _, sig := range sigs {
			lastDot := strings.LastIndex(sig.fullClass, ".")
			if lastDot <= 0 {
				continue
			}
			id := FunctionID{
				Package: sig.fullClass[:lastDot],
				Type:    sig.className,
				Name:    fmt.Sprintf("%s#%d", sig.methodName, len(sig.paramTypes)),
			}
			key := ExternalMethodSignatureKey(id)
			fingerprint := strings.Join(sig.paramTypes, "\x00") + "\x01" + sig.returnType
			if seen[key] == nil {
				seen[key] = make(map[string]struct{})
			}
			if _, ok := seen[key][fingerprint]; ok {
				continue
			}
			seen[key][fingerprint] = struct{}{}
			out[key] = append(out[key], ExternalMethodSignature{
				ParameterTypes: append([]string(nil), sig.paramTypes...),
				ReturnType:     sig.returnType,
			})
		}
	}
	return out
}

func buildMethodIndexFromClassInfos(classInfos []*classFileInfo) (map[string][]methodSignature, map[string][]string) {
	index := make(map[string][]methodSignature)
	hierarchy := make(map[string][]string)
	for _, info := range classInfos {
		for _, sig := range info.methods {
			key := sig.fullClass + "." + sig.methodName
			index[key] = append(index[key], sig)
		}
		if parents := classHierarchyParents(info); len(parents) > 0 {
			hierarchy[info.fullClassName] = parents
		}
	}
	return index, hierarchy
}

func propagateInheritedMethods(index map[string][]methodSignature, hierarchy map[string][]string) {
	declaredByType := groupMethodIndexByType(index)
	effectiveByType := make(map[string]map[string][]methodSignature, len(hierarchy))
	visiting := make(map[string]bool, len(hierarchy))

	var expandTypeMethods func(typeName string) map[string][]methodSignature
	expandTypeMethods = func(typeName string) map[string][]methodSignature {
		if methods, ok := effectiveByType[typeName]; ok {
			return methods
		}
		if visiting[typeName] {
			return cloneMethodsByName(declaredByType[typeName])
		}

		visiting[typeName] = true
		methods := cloneMethodsByName(declaredByType[typeName])
		for _, parentType := range hierarchy[typeName] {
			for methodName, parentSigs := range expandTypeMethods(parentType) {
				if _, exists := methods[methodName]; exists {
					continue
				}
				methods[methodName] = inheritMethodSignatures(typeName, parentSigs)
			}
		}
		visiting[typeName] = false
		effectiveByType[typeName] = methods
		return methods
	}

	for childType := range hierarchy {
		for methodName, sigs := range expandTypeMethods(childType) {
			key := childType + "." + methodName
			if _, exists := index[key]; exists {
				continue
			}
			index[key] = sigs
		}
	}
}

func groupMethodIndexByType(index map[string][]methodSignature) map[string]map[string][]methodSignature {
	grouped := make(map[string]map[string][]methodSignature)
	for key, sigs := range index {
		dot := strings.LastIndex(key, ".")
		if dot <= 0 || dot == len(key)-1 {
			continue
		}
		typeName := key[:dot]
		methodName := key[dot+1:]
		methods := grouped[typeName]
		if methods == nil {
			methods = make(map[string][]methodSignature)
			grouped[typeName] = methods
		}
		methods[methodName] = sigs
	}
	return grouped
}

func cloneMethodsByName(methods map[string][]methodSignature) map[string][]methodSignature {
	if len(methods) == 0 {
		return make(map[string][]methodSignature)
	}

	cloned := make(map[string][]methodSignature, len(methods))
	for methodName, sigs := range methods {
		copied := make([]methodSignature, len(sigs))
		copy(copied, sigs)
		cloned[methodName] = copied
	}
	return cloned
}

func inheritMethodSignatures(typeName string, sigs []methodSignature) []methodSignature {
	inherited := make([]methodSignature, len(sigs))
	for i, sig := range sigs {
		inherited[i] = sig
		inherited[i].className = simpleJavaTypeName(typeName)
		inherited[i].fullClass = typeName
	}
	return inherited
}

// extractFromJAR reads all .class files from a JAR and extracts method signatures and type hierarchy.
func (r *JavaBytecodeTypeResolver) extractFromJAR(jarPath string) ([]*classFileInfo, error) {
	return r.extractFromZIPArchive(jarPath, "")
}

// extractFromJMOD reads all exported .class files from a JMOD and extracts
// method signatures and type hierarchy.
func (r *JavaBytecodeTypeResolver) extractFromJMOD(jmodPath string) ([]*classFileInfo, error) {
	return r.extractFromZIPArchive(jmodPath, "classes/")
}

func (r *JavaBytecodeTypeResolver) extractFromZIPArchive(archivePath, classPrefix string) ([]*classFileInfo, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open Java archive %s: %w", archivePath, err)
	}
	defer func() {
		if cerr := reader.Close(); cerr != nil {
			log.Debug().Err(cerr).Str("archive", archivePath).Msg("Failed to close Java archive reader")
		}
	}()

	results := make([]*classFileInfo, 0, len(reader.File))
	for _, f := range reader.File {
		info, entryName, err := readArchiveClassFile(f, classPrefix)
		if err != nil {
			log.Debug().Err(err).Str("class", entryName).Msg("Failed to parse class file")
			continue
		}
		if info != nil {
			results = append(results, info)
		}
	}

	return results, nil
}

func readArchiveClassFile(f *zip.File, classPrefix string) (*classFileInfo, string, error) {
	entryName, ok := normalizeArchiveEntryName(f.Name, classPrefix)
	if !ok {
		return nil, entryName, nil
	}

	data, err := readZIPEntry(f)
	if err != nil {
		return nil, entryName, err
	}

	info, err := parseClassFile(data, entryName)
	if err != nil {
		return nil, entryName, err
	}
	return info, entryName, nil
}

func normalizeArchiveEntryName(entryName, classPrefix string) (string, bool) {
	if classPrefix != "" {
		if !strings.HasPrefix(entryName, classPrefix) {
			return entryName, false
		}
		entryName = strings.TrimPrefix(entryName, classPrefix)
	}
	if !strings.HasSuffix(entryName, ".class") {
		return entryName, false
	}
	if strings.Contains(filepath.Base(entryName), "$") {
		return entryName, false
	}
	return entryName, true
}

func readZIPEntry(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := rc.Close(); cerr != nil {
			err = errors.Join(err, cerr)
		}
	}()

	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}
	return data, err
}

func isValidCachedBytecodeIndex(cached *CachedBytecodeIndex, artifactKey string) bool {
	if cached == nil {
		return false
	}
	if cached.SchemaVersion == bytecodeCacheSchemaVersion {
		return true
	}

	log.Warn().
		Str("artifact", artifactKey).
		Int("cached_schema_version", cached.SchemaVersion).
		Int("expected_schema_version", bytecodeCacheSchemaVersion).
		Msg("Ignoring stale bytecode cache entry")
	return false
}

// shouldOverrideType returns true when a bytecode type should replace a tree-sitter type.
// This handles cases like generic type parameters (K, T, E) that tree-sitter extracts
// from source but bytecode has the erased, fully-qualified type.
func shouldOverrideType(treeSitterType, _ string) bool {
	if treeSitterType == "" {
		return true
	}
	// Single uppercase letter = generic type parameter (K, T, E, V, etc.)
	if len(treeSitterType) == 1 && treeSitterType[0] >= 'A' && treeSitterType[0] <= 'Z' {
		return true
	}
	// Generic with bounds like "? super K" or "K extends Key"
	if strings.Contains(treeSitterType, "?") || strings.Contains(treeSitterType, " extends ") || strings.Contains(treeSitterType, " super ") {
		return true
	}
	return false
}

// --- Java .class file parser (minimal — only reads constant pool + methods) ---

// classFileInfo holds the parsed result from a single .class file.
type classFileInfo struct {
	className     string            // simple name, e.g. "JwtBuilder"
	fullClassName string            // e.g. "io.jsonwebtoken.JwtBuilder"
	interfaces    []string          // fully qualified parent/interface names, e.g. ["io.jsonwebtoken.ClaimsMutator"]
	superClass    string            // fully qualified superclass name, e.g. "io.jsonwebtoken.BaseJwtBuilder"
	methods       []methodSignature // method signatures
}

// parseClassFile extracts method signatures and interface hierarchy from a .class file.
func parseClassFile(data []byte, _ string) (*classFileInfo, error) {
	cp, offset, err := parseClassConstantPool(data)
	if err != nil {
		return nil, err
	}

	className, fullClassName, offset, err := parseClassIdentity(data, cp, offset)
	if err != nil {
		return nil, err
	}
	superClass, offset, err := parseClassSuperClass(data, cp, offset)
	if err != nil {
		return nil, err
	}
	interfaces, offset, err := parseClassInterfaces(data, cp, offset)
	if err != nil {
		return nil, err
	}
	offset, err = skipFieldsOrMethods(data, offset, cp)
	if err != nil {
		return nil, fmt.Errorf("failed to skip fields: %w", err)
	}
	methods, err := parseClassMethods(data, cp, offset, className, fullClassName, superClass, interfaces)
	if err != nil {
		return nil, err
	}
	return methods, nil
}

type cpEntry struct {
	tag      uint8
	strValue string
	intValue int
}

func parseConstantPool(data []byte, offset, count int) ([]cpEntry, int, error) {
	cp := make([]cpEntry, count)
	i := 1 // constant pool indices start at 1
	for i < count {
		entry, newOffset, takesExtraSlot, err := parseConstantPoolEntry(data, offset, i)
		if err != nil {
			return cp, offset, err
		}
		cp[i] = entry
		offset = newOffset
		if takesExtraSlot {
			i++
		}
		i++
	}
	return cp, offset, nil
}

func parseClassConstantPool(data []byte) ([]cpEntry, int, error) {
	if len(data) < 10 {
		return nil, 0, fmt.Errorf("class file too short")
	}
	if magic := binary.BigEndian.Uint32(data[0:4]); magic != 0xCAFEBABE {
		return nil, 0, fmt.Errorf("invalid class file magic: %x", magic)
	}
	offset := 8
	cpCount := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	return parseConstantPool(data, offset, cpCount)
}

func parseClassIdentity(data []byte, cp []cpEntry, offset int) (string, string, int, error) {
	if offset+4 > len(data) {
		return "", "", offset, fmt.Errorf("unexpected end of class file")
	}
	thisClassIdx := int(binary.BigEndian.Uint16(data[offset+2:]))
	offset += 4
	className, fullClassName := classNamesFromConstantPool(cp, thisClassIdx)
	if className == "" {
		return "", "", offset, fmt.Errorf("could not determine class name")
	}
	return className, fullClassName, offset, nil
}

func classNamesFromConstantPool(cp []cpEntry, thisClassIdx int) (string, string) {
	if thisClassIdx <= 0 || thisClassIdx >= len(cp) || cp[thisClassIdx].tag != 7 {
		return "", ""
	}
	nameIdx := cp[thisClassIdx].intValue
	if nameIdx <= 0 || nameIdx >= len(cp) {
		return "", ""
	}
	fullClassName := strings.ReplaceAll(cp[nameIdx].strValue, "/", ".")
	if lastDot := strings.LastIndex(fullClassName, "."); lastDot >= 0 {
		return fullClassName[lastDot+1:], fullClassName
	}
	return fullClassName, fullClassName
}

func parseClassSuperClass(data []byte, cp []cpEntry, offset int) (string, int, error) {
	if offset+2 > len(data) {
		return "", offset, fmt.Errorf("unexpected end reading superclass")
	}
	superClassIdx := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	superClassName := classNameFromConstantPool(cp, superClassIdx)
	if superClassName == "java.lang.Object" {
		return "", offset, nil
	}
	return superClassName, offset, nil
}

func parseClassInterfaces(data []byte, cp []cpEntry, offset int) ([]string, int, error) {
	if offset+2 > len(data) {
		return nil, offset, fmt.Errorf("unexpected end reading interfaces")
	}
	interfacesCount := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	interfaces := make([]string, 0, interfacesCount)
	for range interfacesCount {
		if offset+2 > len(data) {
			break
		}
		ifaceIdx := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		if ifaceName := interfaceNameFromConstantPool(cp, ifaceIdx); ifaceName != "" {
			interfaces = append(interfaces, ifaceName)
		}
	}
	return interfaces, offset, nil
}

func classNameFromConstantPool(cp []cpEntry, classIdx int) string {
	if classIdx <= 0 || classIdx >= len(cp) || cp[classIdx].tag != 7 {
		return ""
	}
	nameIdx := cp[classIdx].intValue
	if nameIdx <= 0 || nameIdx >= len(cp) {
		return ""
	}
	return strings.ReplaceAll(cp[nameIdx].strValue, "/", ".")
}

func interfaceNameFromConstantPool(cp []cpEntry, ifaceIdx int) string {
	return classNameFromConstantPool(cp, ifaceIdx)
}

func parseClassMethods(
	data []byte,
	cp []cpEntry,
	offset int,
	className string,
	fullClassName string,
	superClass string,
	interfaces []string,
) (*classFileInfo, error) {
	if offset+2 > len(data) {
		return nil, fmt.Errorf("unexpected end reading methods count")
	}
	methodsCount := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	sigs := make([]methodSignature, 0, methodsCount)
	for range methodsCount {
		methodSig, newOffset, done := parseClassMethod(data, cp, offset, className, fullClassName, superClass, interfaces, sigs)
		offset = newOffset
		if done != nil {
			return done, nil
		}
		if methodSig.methodName != "" {
			sigs = append(sigs, methodSig)
		}
	}
	return &classFileInfo{
		className:     className,
		fullClassName: fullClassName,
		interfaces:    interfaces,
		superClass:    superClass,
		methods:       sigs,
	}, nil
}

func parseClassMethod(
	data []byte,
	cp []cpEntry,
	offset int,
	className string,
	fullClassName string,
	superClass string,
	interfaces []string,
	sigs []methodSignature,
) (methodSignature, int, *classFileInfo) {
	if offset+8 > len(data) {
		return methodSignature{}, offset, nil
	}
	nameIdx := int(binary.BigEndian.Uint16(data[offset+2:]))
	descIdx := int(binary.BigEndian.Uint16(data[offset+4:]))
	attrCount := int(binary.BigEndian.Uint16(data[offset+6:]))
	offset += 8

	newOffset, truncated := skipMethodAttributes(data, offset, attrCount)
	if truncated {
		return methodSignature{}, newOffset, &classFileInfo{
			className:     className,
			fullClassName: fullClassName,
			interfaces:    interfaces,
			superClass:    superClass,
			methods:       sigs,
		}
	}
	methodName, descriptor := methodSignatureStrings(cp, nameIdx, descIdx)
	if methodName == "" || descriptor == "" || methodName == "<clinit>" {
		return methodSignature{}, newOffset, nil
	}
	params, ret := parseMethodDescriptor(descriptor)
	return methodSignature{
		className:  className,
		methodName: methodName,
		paramTypes: params,
		returnType: ret,
		fullClass:  fullClassName,
	}, newOffset, nil
}

func skipMethodAttributes(data []byte, offset, attrCount int) (int, bool) {
	for range attrCount {
		if offset+6 > len(data) {
			return offset, true
		}
		attrLen := int(binary.BigEndian.Uint32(data[offset+2:]))
		offset += 6 + attrLen
	}
	return offset, false
}

func methodSignatureStrings(cp []cpEntry, nameIdx, descIdx int) (string, string) {
	methodName := ""
	descriptor := ""
	if nameIdx > 0 && nameIdx < len(cp) {
		methodName = cp[nameIdx].strValue
	}
	if descIdx > 0 && descIdx < len(cp) {
		descriptor = cp[descIdx].strValue
	}
	return methodName, descriptor
}

func parseConstantPoolEntry(data []byte, offset, index int) (cpEntry, int, bool, error) {
	if offset >= len(data) {
		return cpEntry{}, offset, false, fmt.Errorf("unexpected end of constant pool at index %d", index)
	}
	tag := data[offset]
	offset++

	switch tag {
	case 1:
		return parseUTF8CPEntry(data, offset, tag, index)
	case 3, 4:
		return parseIntCPEntry(data, offset, tag, index)
	case 5, 6:
		return parseLongCPEntry(data, offset, tag, index)
	case 7, 8, 16, 19, 20:
		return parseShortIndexCPEntry(data, offset, tag, index)
	case 9, 10, 11, 12, 17, 18:
		return parseFixedWidthCPEntry(data, offset, tag, index, 4)
	case 15:
		return parseFixedWidthCPEntry(data, offset, tag, index, 3)
	default:
		return cpEntry{}, offset, false, fmt.Errorf("unknown constant pool tag %d at index %d", tag, index)
	}
}

func parseUTF8CPEntry(data []byte, offset int, tag uint8, index int) (cpEntry, int, bool, error) {
	if offset+2 > len(data) {
		return cpEntry{}, offset, false, fmt.Errorf("truncated utf8 at index %d", index)
	}
	length := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if offset+length > len(data) {
		return cpEntry{}, offset, false, fmt.Errorf("truncated utf8 string at index %d", index)
	}
	return cpEntry{tag: tag, strValue: string(data[offset : offset+length])}, offset + length, false, nil
}

func parseIntCPEntry(data []byte, offset int, tag uint8, index int) (cpEntry, int, bool, error) {
	if offset+4 > len(data) {
		return cpEntry{}, offset, false, fmt.Errorf("truncated int/float at index %d", index)
	}
	return cpEntry{tag: tag, intValue: int(binary.BigEndian.Uint32(data[offset:]))}, offset + 4, false, nil
}

func parseLongCPEntry(data []byte, offset int, tag uint8, index int) (cpEntry, int, bool, error) {
	if offset+8 > len(data) {
		return cpEntry{}, offset, false, fmt.Errorf("truncated long/double at index %d", index)
	}
	return cpEntry{tag: tag}, offset + 8, true, nil
}

func parseShortIndexCPEntry(data []byte, offset int, tag uint8, index int) (cpEntry, int, bool, error) {
	if offset+2 > len(data) {
		return cpEntry{}, offset, false, fmt.Errorf("truncated constant pool entry at index %d", index)
	}
	return cpEntry{tag: tag, intValue: int(binary.BigEndian.Uint16(data[offset:]))}, offset + 2, false, nil
}

func parseFixedWidthCPEntry(data []byte, offset int, tag uint8, index, width int) (cpEntry, int, bool, error) {
	if offset+width > len(data) {
		return cpEntry{}, offset, false, fmt.Errorf("truncated constant pool entry at index %d", index)
	}
	return cpEntry{tag: tag}, offset + width, false, nil
}

func skipFieldsOrMethods(data []byte, offset int, _ []cpEntry) (int, error) {
	if offset+2 > len(data) {
		return offset, fmt.Errorf("unexpected end reading count")
	}
	count := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	for range count {
		if offset+8 > len(data) {
			return offset, fmt.Errorf("unexpected end in field/method")
		}
		attrCount := int(binary.BigEndian.Uint16(data[offset+6:]))
		offset += 8
		for range attrCount {
			if offset+6 > len(data) {
				return offset, fmt.Errorf("unexpected end in attribute")
			}
			attrLen := int(binary.BigEndian.Uint32(data[offset+2:]))
			offset += 6 + attrLen
		}
	}
	return offset, nil
}

// parseMethodDescriptor parses a JVM method descriptor string.
// Example: "(Lio/jsonwebtoken/SignatureAlgorithm;[B)Lio/jsonwebtoken/JwtBuilder;"
// Returns: params=["SignatureAlgorithm", "byte[]"], return="JwtBuilder".
func parseMethodDescriptor(desc string) (params []string, returnType string) {
	if desc == "" || desc[0] != '(' {
		return nil, ""
	}

	i := 1 // skip '('
	for i < len(desc) && desc[i] != ')' {
		typeName, newI := parseJVMType(desc, i)
		if newI <= i {
			break // prevent infinite loop
		}
		params = append(params, typeName)
		i = newI
	}

	// Skip ')'
	if i < len(desc) {
		i++
	}

	// Parse return type
	if i < len(desc) {
		returnType, _ = parseJVMType(desc, i)
	}

	return params, returnType
}

// parseJVMType parses a single JVM type from a descriptor at position i.
// Returns the human-readable type name and the new position.
func parseJVMType(desc string, i int) (string, int) {
	if i >= len(desc) {
		return "", i
	}

	switch desc[i] {
	case 'B':
		return "byte", i + 1
	case 'C':
		return "char", i + 1
	case 'D':
		return "double", i + 1
	case 'F':
		return "float", i + 1
	case 'I':
		return "int", i + 1
	case 'J':
		return "long", i + 1
	case 'S':
		return "short", i + 1
	case 'V':
		return "void", i + 1
	case 'Z':
		return "boolean", i + 1
	case '[':
		elemType, newI := parseJVMType(desc, i+1)
		return elemType + "[]", newI
	case 'L':
		semicolon := strings.Index(desc[i:], ";")
		if semicolon < 0 {
			return "", len(desc)
		}
		fullPath := desc[i+1 : i+semicolon]
		// Convert "io/jsonwebtoken/SignatureAlgorithm" → "io.jsonwebtoken.SignatureAlgorithm"
		return strings.ReplaceAll(fullPath, "/", "."), i + semicolon + 1
	default:
		return "", i + 1
	}
}
