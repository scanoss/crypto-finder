// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

package callgraph

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/python"
)

// maxPythonDistributionWorkers mirrors maxJavaJARWorkers (row 14,
// python-parser-parity-2 design.md §4 row 14): a bounded worker pool
// indexes pip-resolved distributions in parallel.
const maxPythonDistributionWorkers = 8

// maxPythonDependencyFileBytes bounds a single indexed file's size —
// an oversized file is skipped entirely rather than read (threat matrix:
// untrusted file reads).
const maxPythonDependencyFileBytes = 5 * 1024 * 1024

// pythonSourceExt/pythonStubExt name the two extensions this resolver
// indexes, factored into constants (goconst) rather than repeated string
// literals in selectPythonDistFiles.
const (
	pythonSourceExt = ".py"
	pythonStubExt   = ".pyi"
)

// pythonDependencySkipDirs mirrors PythonParser.SkipDirs()'s own skip set
// (computed once from the zero-value parser, whose includeTests defaults
// to false — a dependency signature index has no reason to descend into a
// vendored test suite).
var pythonDependencySkipDirs = (&PythonParser{}).SkipDirs()

// PythonDependencyTypeResolver reads .pyi stubs and annotated .py sources
// from pip-resolved dependency distributions to extract return-type and
// class-hierarchy signatures — filling gaps the tree-sitter source parser's
// own graphPackages pass cannot reach (e.g. a compiled-extension module
// that ships only a .pyi stub with no .py implementation at all) and
// caching the result per distribution so repeated scans do not re-walk
// unchanged, potentially large dependency trees (row 14, design.md §4 row
// 14). Never a general Python type inference engine: no import-chain
// resolution, no cross-distribution inference, no fabricated types.
//
// The resolver always returns nil error — a missing/unreadable
// distribution, an absent annotation, or a cache I/O failure all degrade to
// "resolve nothing for this input", never a fatal build error.
type pythonDependencyParser interface {
	ParseCtx(context.Context, *sitter.Tree, []byte) (*sitter.Tree, error)
	Close()
}

// PythonDependencyTypeResolver enriches Python declarations from dependency
// source and stub annotations.
type PythonDependencyTypeResolver struct {
	cache PythonSignatureIndexCache
	// readDir and newParser are test seams.
	readDir   func(string) ([]os.DirEntry, error)
	newParser func() pythonDependencyParser
}

// NewPythonDependencyTypeResolver creates a resolver backed by the supplied
// cache. A nil cache is a safe no-op cache (every distribution is
// re-indexed every call, never persisted).
func NewPythonDependencyTypeResolver(cache PythonSignatureIndexCache) *PythonDependencyTypeResolver {
	return &PythonDependencyTypeResolver{
		cache:   cache,
		readDir: os.ReadDir,
		newParser: func() pythonDependencyParser {
			return newPythonDependencyParser()
		},
	}
}

// ResolveTypes implements TypeResolver (row 14 algorithm, design.md §4 row
// 14): select sourceRoots with Version != "" (D8 — project-local roots are
// skipped entirely), index each distinct distribution in a bounded worker
// pool (cache-first), merge the combined signatures/hierarchy into
// graph.TypeHierarchy and graph.ExternalMethodSignatures, then fill
// FunctionDecl.ReturnType only when currently empty.
func (r *PythonDependencyTypeResolver) ResolveTypes(graph *CallGraph, sourceRoots []PackageDir) error {
	if graph == nil {
		return nil
	}
	roots := selectPythonDependencyRoots(sourceRoots)
	if len(roots) == 0 {
		return nil
	}

	workers := min(max(runtime.NumCPU()/2, 1), maxPythonDistributionWorkers)
	signatures, hierarchy := r.buildIndexes(roots, workers)
	if len(signatures) == 0 && len(hierarchy) == 0 {
		return nil
	}

	mergePythonHierarchy(graph, hierarchy)
	mergePythonExternalSignatures(graph, signatures)
	fillPythonReturnTypesFromSignatures(graph, signatures)
	return nil
}

// selectPythonDependencyRoots filters sourceRoots to real, non-project-local
// distributions (D8: Version != "") with a resolved source directory, and
// deduplicates by distribution/import-root/version - a dependency graph can
// list the same resolved distribution more than once (e.g. reached via two
// paths), while distinct distributions must never share an index accidentally.
func selectPythonDependencyRoots(sourceRoots []PackageDir) []PackageDir {
	seen := make(map[string]struct{}, len(sourceRoots))
	roots := make([]PackageDir, 0, len(sourceRoots))
	for _, root := range sourceRoots {
		if root.Version == "" || root.Dir == "" {
			continue
		}
		distributionName := root.DistributionName
		if distributionName == "" {
			distributionName = root.ImportPath
		}
		key := distributionName + "@" + root.Version + ":" + root.ImportPath
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		roots = append(roots, root)
	}
	return roots
}

// pythonDistributionIndexResult is one worker's indexed (or cache-hit)
// output for a single distribution.
type pythonDistributionIndexResult struct {
	signatures map[string]pythonSignature
	hierarchy  map[string][]string
}

func (r *PythonDependencyTypeResolver) buildIndexes(roots []PackageDir, workers int) (map[string]pythonSignature, map[string][]string) {
	workCh := make(chan PackageDir, len(roots))
	resultCh := make(chan pythonDistributionIndexResult, len(roots))
	for _, root := range roots {
		workCh <- root
	}
	close(workCh)

	var wg sync.WaitGroup
	for range min(workers, len(roots)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			parser := r.newParser()
			if parser == nil {
				return
			}
			defer parser.Close()
			for root := range workCh {
				sigs, hierarchy := r.indexDistribution(root, parser)
				resultCh <- pythonDistributionIndexResult{signatures: sigs, hierarchy: hierarchy}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	signatures := make(map[string]pythonSignature)
	hierarchy := make(map[string][]string)
	for result := range resultCh {
		for fqn, sig := range result.signatures {
			if _, exists := signatures[fqn]; !exists {
				signatures[fqn] = sig
			}
		}
		for className, bases := range result.hierarchy {
			hierarchy[className] = bases
		}
	}
	return signatures, hierarchy
}

func newPythonDependencyParser() *sitter.Parser {
	p := sitter.NewParser()
	p.SetLanguage(python.GetLanguage())
	return p
}

// indexDistribution returns one distribution's signatures/hierarchy,
// preferring a cached entry over re-walking the filesystem.
func (r *PythonDependencyTypeResolver) indexDistribution(root PackageDir, parser pythonDependencyParser) (map[string]pythonSignature, map[string][]string) {
	identity := pythonSignatureIdentity(root)
	cacheKey := pythonSignatureDistributionKeyForIdentity(root, identity)
	if r.cache != nil {
		if cached, ok, err := r.cache.Get(context.Background(), cacheKey); err != nil {
			log.Debug().Err(err).Str("distribution", cacheKey).Msg("Failed to load Python signature cache entry")
		} else if ok && cached != nil &&
			cached.SchemaVersion == pythonSignatureCacheSchemaVersion &&
			cached.DistributionKey == cacheKey &&
			cached.DistributionName == identity.distributionName &&
			cached.ImportPath == identity.importPath &&
			cached.SourceFingerprint == identity.sourceFingerprint {
			return cached.Signatures, cached.Hierarchy
		}
	}

	signatures := make(map[string]pythonSignature)
	hierarchy := make(map[string][]string)
	r.walkDistribution(root.Dir, root.ImportPath, parser, signatures, hierarchy)

	if r.cache != nil {
		entry := &CachedPythonSignatureIndex{
			SchemaVersion:     pythonSignatureCacheSchemaVersion,
			DistributionKey:   cacheKey,
			DistributionName:  identity.distributionName,
			ImportPath:        identity.importPath,
			SourceFingerprint: identity.sourceFingerprint,
			Signatures:        signatures,
			Hierarchy:         hierarchy,
		}
		if err := r.cache.Put(context.Background(), cacheKey, entry); err != nil {
			log.Debug().Err(err).Str("distribution", cacheKey).Msg("Failed to store Python signature cache entry")
		}
	}
	return signatures, hierarchy
}

// walkDistribution recurses through dir (pre-order, mirroring
// Builder.collectParseDirs' own traversal so module paths line up with
// what the main source-parsing pass would compute for the SAME
// distribution), indexing every selected .py/.pyi file at each level and
// descending into subdirectories under the growing dotted importPath.
// An unreadable directory degrades silently (12.6): the caller simply
// receives whatever was indexed before the failure.
func (r *PythonDependencyTypeResolver) walkDistribution(
	dir, importPath string,
	parser pythonDependencyParser,
	signatures map[string]pythonSignature,
	hierarchy map[string][]string,
) {
	entries, err := r.readDir(dir)
	if err != nil {
		log.Debug().Err(err).Str("dir", dir).Msg("Failed to read Python dependency directory")
		return
	}

	for _, name := range selectPythonDistFiles(entries) {
		r.indexDistributionFile(filepath.Join(dir, name), importPath, parser, signatures, hierarchy)
	}

	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") || pythonDependencySkipDirs[name] {
			continue
		}
		r.walkDistribution(filepath.Join(dir, name), pythonDependencySubPackagePath(importPath, name), parser, signatures, hierarchy)
	}
}

func (r *PythonDependencyTypeResolver) indexDistributionFile(
	path, importPath string,
	parser pythonDependencyParser,
	signatures map[string]pythonSignature,
	hierarchy map[string][]string,
) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&fs.ModeSymlink != 0 || info.Size() > maxPythonDependencyFileBytes {
		return
	}
	src, err := os.ReadFile(path)
	if err != nil {
		return
	}
	tree, err := parser.ParseCtx(context.Background(), nil, src)
	if err != nil {
		return
	}
	defer tree.Close()

	modulePath := pythonModuleDottedPath(path, importPath)
	root := tree.RootNode()
	count := int(root.NamedChildCount())
	for i := 0; i < count; i++ {
		pythonIndexTopLevelNode(root.NamedChild(i), src, FunctionID{Package: modulePath}, signatures, hierarchy)
	}
}

// pythonDependencySubPackagePath mirrors PythonParser.SubPackagePath.
func pythonDependencySubPackagePath(parentPath, dirName string) string {
	if parentPath == "" {
		return dirName
	}
	return parentPath + "." + dirName
}

// selectPythonDistFiles lists dir's .py/.pyi files (skipping test files,
// matching PythonParser.ParseDirectory's own filter), preferring a .pyi
// stub over a same-stem .py source (design.md §4 row 14: ".pyi preferred
// over a same-stem .py, matching the existing stub-precedence rule") —
// deliberately the opposite precedence from the main declaration-merge
// path (builder.go's keepExistingDecl prefers a real .py over an
// incoming .pyi there); this resolver is a TYPE-STUB indexer specifically,
// so a hand-authored .pyi's annotations are the more reliable source of
// truth for it. Returns names in deterministic (sorted) order.
func selectPythonDistFiles(entries []os.DirEntry) []string {
	chosen := make(map[string]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := filepath.Ext(name)
		if ext != pythonSourceExt && ext != pythonStubExt {
			continue
		}
		if strings.HasPrefix(name, "test_") || strings.HasSuffix(name, "_test.py") || strings.HasSuffix(name, "_test.pyi") {
			continue
		}
		stem := strings.TrimSuffix(name, ext)
		existing, ok := chosen[stem]
		if !ok || (ext == pythonStubExt && filepath.Ext(existing) == pythonSourceExt) {
			chosen[stem] = name
		}
	}
	names := make([]string, 0, len(chosen))
	for _, name := range chosen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// pythonIndexTopLevelNode records a signature for a top-level
// function_definition or class_definition node (unwrapping a
// decorated_definition wrapper first). Anything else — an assignment, an
// if-guard, an import — is pruned: this indexer never descends into a
// function body (design.md §4 row 14, step 3: "Never reads a function
// body").
func pythonIndexTopLevelNode(node *sitter.Node, src []byte, owner FunctionID, signatures map[string]pythonSignature, hierarchy map[string][]string) {
	def := node
	if node.Symbol() == pythonSyms.decoratedDefinition {
		inner := node.ChildByFieldName("definition")
		if inner == nil {
			return
		}
		def = inner
	}
	switch def.Symbol() {
	case pythonSyms.functionDefinition:
		recordPythonFunctionSignature(def, src, owner, signatures, false)
	case pythonSyms.classDefinition:
		recordPythonClassSignature(def, src, owner, signatures, hierarchy)
	}
}

// recordPythonFunctionSignature records one function/method's signature —
// return annotation via pythonNormalizeAnnotation (reused from row 13,
// python-parser-parity-2) and per-parameter annotations, index-aligned
// with the declared parameter list. `__init__` renames to constructorMethodName,
// matching the main parser's own convention (parseFunctionDef). The FIRST
// distribution to declare a given FQN wins — later distributions never
// overwrite an already-recorded signature within the same indexing pass.
func recordPythonFunctionSignature(node *sitter.Node, src []byte, owner FunctionID, signatures map[string]pythonSignature, implicitReceiver bool) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	name := nameNode.Content(src)
	if name == "" {
		return
	}
	if name == pythonInitMethodName {
		name = constructorMethodName
	}
	id := FunctionID{Package: owner.Package, Type: owner.Type, Name: name}
	fqn := pythonFunctionIDFQN(id)
	if _, exists := signatures[fqn]; exists {
		return
	}
	signatures[fqn] = pythonSignature{
		ID:         id,
		ReturnType: pythonNormalizeAnnotation(node.ChildByFieldName("return_type"), src),
		ParamTypes: pythonDependencyParamTypes(node.ChildByFieldName("parameters"), src, implicitReceiver),
	}
}

// recordPythonClassSignature records a class's declared base names (its
// superclasses field, verbatim bare identifiers — never import-qualified,
// matching row 9's OwnerBases convention) into hierarchy, then descends
// ONE level into the class body to record each method's own signature.
// Never descends into a nested class's methods' bodies or any other
// nested statement.
func recordPythonClassSignature(node *sitter.Node, src []byte, owner FunctionID, signatures map[string]pythonSignature, hierarchy map[string][]string) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	className := nameNode.Content(src)
	if className == "" {
		return
	}
	classFQN := className
	if owner.Package != "" {
		classFQN = owner.Package + "." + className
	}

	if superclasses := node.ChildByFieldName("superclasses"); superclasses != nil {
		if bases := extractPythonBaseClassNames(superclasses, src); len(bases) > 0 {
			hierarchy[classFQN] = bases
		}
	}

	body := node.ChildByFieldName("body")
	if body == nil {
		return
	}
	methodOwner := FunctionID{Package: owner.Package, Type: className}
	count := int(body.NamedChildCount())
	for i := 0; i < count; i++ {
		child := body.NamedChild(i)
		def := child
		implicitReceiver := true
		if child.Symbol() == pythonSyms.decoratedDefinition {
			info := classifyPythonDecorators(child, src)
			implicitReceiver = !info.static
			inner := child.ChildByFieldName("definition")
			if inner == nil {
				continue
			}
			def = inner
		}
		if def.Symbol() == pythonSyms.functionDefinition {
			recordPythonFunctionSignature(def, src, methodOwner, signatures, implicitReceiver)
		}
	}
}

// pythonDependencyParamTypes reads a parameters node's typed_parameter /
// typed_default_parameter annotations, index-aligned with the declared
// parameter list ("" for an unannotated parameter). nil when the node is
// nil or declares no parameters.
func pythonDependencyParamTypes(params *sitter.Node, src []byte, implicitReceiver bool) []string {
	if params == nil {
		return nil
	}
	count := int(params.NamedChildCount())
	if count == 0 {
		return nil
	}
	types := make([]string, count)
	for i := 0; i < count; i++ {
		child := params.NamedChild(i)
		var typeField *sitter.Node
		switch child.Symbol() {
		case pythonSyms.typedParameter, pythonSyms.typedDefaultParameter:
			typeField = child.ChildByFieldName("type")
		}
		types[i] = pythonNormalizeAnnotation(typeField, src)
	}
	if implicitReceiver && len(types) > 0 {
		return types[1:]
	}
	return types
}

// pythonFunctionIDFQN builds the dotted FQN for a FunctionID exactly as
// pythonFunctionFQN builds it for a *FunctionDecl (row 13,
// python_type_resolver.go) — kept as a separate small helper here rather
// than reusing pythonFunctionFQN directly, since that helper takes a
// *FunctionDecl rather than a bare FunctionID.
func pythonFunctionIDFQN(id FunctionID) string {
	if id.Type != "" {
		return id.Package + "." + id.Type + "." + id.Name
	}
	return id.Package + "." + id.Name
}

// mergePythonHierarchy merges a distribution index's class hierarchy into
// the graph, overwriting any prior entry for the same class FQN (mirrors
// mergeTypeHierarchy's own last-writer-wins behavior for the Java
// resolver).
func mergePythonHierarchy(graph *CallGraph, hierarchy map[string][]string) {
	if len(hierarchy) == 0 {
		return
	}
	if graph.TypeHierarchy == nil {
		graph.TypeHierarchy = make(map[string][]string)
	}
	for className, bases := range hierarchy {
		graph.TypeHierarchy[className] = bases
	}
}

// mergePythonExternalSignatures merges every indexed signature into
// graph.ExternalMethodSignatures, keyed by ExternalMethodSignatureKey — the
// same external-signature surface the Java bytecode resolver populates,
// consumed by internal/scan/export.go for a callee with no in-graph
// FunctionDecl of its own.
func mergePythonExternalSignatures(graph *CallGraph, signatures map[string]pythonSignature) {
	if len(signatures) == 0 {
		return
	}
	if graph.ExternalMethodSignatures == nil {
		graph.ExternalMethodSignatures = make(map[string][]ExternalMethodSignature)
	}
	for _, sig := range signatures {
		key := ExternalMethodSignatureKey(sig.ID)
		entry := ExternalMethodSignature{
			ParameterTypes: append([]string(nil), sig.ParamTypes...),
			ReturnType:     sig.ReturnType,
		}
		graph.ExternalMethodSignatures[key] = append(graph.ExternalMethodSignatures[key], entry)
	}
}

// fillPythonReturnTypesFromSignatures sets FunctionDecl.ReturnType from the
// indexed signature ONLY when currently empty (never overwrites a value
// the parser or the contract KB resolver already set — KB always wins,
// design.md D7/point 5).
func fillPythonReturnTypesFromSignatures(graph *CallGraph, signatures map[string]pythonSignature) {
	for _, fn := range graph.Functions {
		if fn == nil || fn.ReturnType != "" {
			continue
		}
		sig, ok := signatures[pythonFunctionIDFQN(fn.ID)]
		if !ok || sig.ReturnType == "" {
			continue
		}
		fn.ReturnType = sig.ReturnType
	}
}
