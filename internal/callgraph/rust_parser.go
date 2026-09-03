package callgraph

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/rust"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

const (
	rustNodeCallExpression      = "call_expression"
	rustNodeExpressionStatement = "expression_statement"
	rustNodeFieldExpression     = "field_expression"
	rustNodeFunctionItem        = "function_item"
	rustNodeGenericFunction     = "generic_function"
	rustNodeUseAsClause         = "use_as_clause"
	rustNodeTypeItem            = "type_item"
	rustNodeSelf                = "self"
	rustNodeModItem             = "mod_item"
	rustNodeImplItem            = "impl_item"
	rustNodeTraitItem           = "trait_item"
	rustNodeLetDeclaration      = "let_declaration"
	rustNodeCrate               = "crate"
	rustNodeSuper               = "super"
	rustNodeMatchPattern        = "match_pattern"
	rustNodeTokenTree           = "token_tree"
	rustNodeAttributeItem       = "attribute_item"
	rustNodeAttribute           = "attribute"
	rustNodeDocComment          = "doc_comment"
	rustNodeClosureExpression   = "closure_expression"
	rustNodeExternCrate         = "extern_crate_declaration"
	rustNodeUseDeclaration      = "use_declaration"
	rustNodeUseWildcard         = "use_wildcard"
	// rustSelfType is the `Self` type keyword, which stands for the type of
	// the enclosing impl block and is substituted for it.
	rustSelfType = "Self"
)

// RustParser extracts function declarations, calls, and imports from Rust source files
// using tree-sitter for fast, accurate parsing.
type RustParser struct {
	parser       *sitter.Parser
	includeTests bool
	// crateAliasCache memoizes each crate root's `extern crate X as Y`
	// renames, keyed by the root source file. Those aliases are crate-scoped
	// but the import model is per file, so every file has to be able to see
	// them; parsing the root once per parser instance is what makes that
	// affordable.
	crateAliasCache map[string]map[string]string
	// manifestRenameCache memoizes each crate manifest's `package = `
	// dependency renames, keyed by the manifest path.
	manifestRenameCache map[string]map[string]string
	// dependencyCache memoizes the dependency names each crate manifest
	// declares, which is what tells a module apart from a crate.
	dependencyCache map[string]map[string]bool
	// editionCache memoizes each crate manifest's declared Rust edition, which
	// decides whether a `use` path's first segment names a crate.
	editionCache map[string]string
	// globReExportCache memoizes each directory's glob re-exported child
	// modules, keyed by directory. Reading and tree-sitter-parsing the
	// directory's mod.rs/lib.rs on every call made it O(N^2) in the number of
	// `mod` declarations at a crate root: ParseDirectory asks once per
	// directory, but rustIndexPackagePath asks once per FILE inside
	// indexCrateSources. Isolated, with the same N trivial files, `lib.rs` with
	// versus without the `pub mod` lines: 400 files 0.165s vs 0.919s, 800 0.266s
	// vs 3.181s, 1600 0.367s vs 12.324s.
	globReExportCache map[string]map[string]bool
	// crateIndex is shared with every clone of this parser, so a crate's
	// declarations are indexed once per build rather than once per worker.
	crateIndex *rustCrateIndex
	// kb is the embedded Rust contracts KB, used to resolve a generic's
	// associated type (`C::KeySize`) past its trait bound. Loaded once per
	// process (see rustEmbeddedContractsKB) and shared across every parser
	// instance and clone, the same way crateIndex is: the KB does not depend
	// on which worker asked for it.
	kb *contracts.KnowledgeBase
}

// NewRustParser creates a new Rust source parser backed by tree-sitter.
func NewRustParser(opts ...ParserOption) *RustParser {
	cfg := newParserConfig(opts)
	p := sitter.NewParser()
	p.SetLanguage(rust.GetLanguage())
	return &RustParser{parser: p, includeTests: cfg.includeTests, crateIndex: newRustCrateIndex(), kb: rustEmbeddedContractsKB()}
}

var (
	rustEmbeddedContractsKBOnce   sync.Once
	rustEmbeddedContractsKBCached *contracts.KnowledgeBase
)

// rustEmbeddedContractsKB loads the embedded Rust contracts KB once per
// process. A load failure degrades to a nil KB (no associated-type
// resolution), never a startup error.
func rustEmbeddedContractsKB() *contracts.KnowledgeBase {
	rustEmbeddedContractsKBOnce.Do(func() {
		kb, err := contracts.LoadEmbedded("rust")
		if err == nil {
			rustEmbeddedContractsKBCached = kb
		}
	})
	return rustEmbeddedContractsKBCached
}

// CloneParser returns an independent RustParser with the same configuration,
// for concurrent use (tree-sitter parsers are not reentrant).
func (p *RustParser) CloneParser() Parser {
	clone := NewRustParser(WithIncludeTests(p.includeTests))
	// The crate index is shared, not copied: it is keyed by crate root and its
	// contents do not depend on which worker asked for them.
	clone.crateIndex = p.crateIndex
	return clone
}

// SubPackagePath constructs a child module path using "::" separator.
// In Rust, src/ is the crate root directory and does not correspond to a module —
// it is transparent in the module path. e.g., ring/src/aead/ maps to "ring::aead",
// not "ring::src::aead".
func (p *RustParser) SubPackagePath(parentPath, dirName string) string {
	if dirName == "src" {
		return parentPath
	}
	if parentPath == "" {
		return dirName
	}
	return parentPath + "::" + dirName
}

// PackageSeparator returns "::" — Rust uses double colons in module paths.
func (p *RustParser) PackageSeparator() string {
	return "::"
}

// ParseDirectory parses all .rs files in a directory.
func (p *RustParser) ParseDirectory(dir, packagePath string) ([]*FileAnalysis, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory %s: %w", dir, err)
	}

	// A module whose parent glob-re-exports it has the PARENT's public path.
	reExported := p.rustGlobReExportedModules(dir)

	analyses := make([]*FileAnalysis, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".rs") {
			continue
		}
		if !p.includeTests && (strings.HasSuffix(name, "_test.rs") || name == "tests.rs") {
			continue
		}

		fullPath := filepath.Join(dir, name)
		analysis, err := p.parseFile(fullPath, rustFileModulePath(packagePath, name, reExported))
		if err != nil {
			continue
		}
		analyses = append(analyses, analysis)
	}

	return analyses, nil
}

// rustFileModulePath extends a directory's module path with the file's own
// module name.
//
// A `src/rsa.rs` is the module `rsa`, exactly as `src/rsa/mod.rs` would be, and
// the contract KB keys it that way: `openssl::rsa::Rsa.generate`. Leaving the
// segment off made a call inside rsa.rs emit `openssl.(Rsa).generate` while the
// identical call from pkcs12.rs emitted `openssl::rsa.(Rsa).generate` — one
// matched its contract and the other did not. It also collapsed two sibling
// files' same-named functions onto one key, dropping one file's declarations
// entirely.
//
// lib.rs, main.rs and mod.rs name no module of their own: they ARE the module
// their directory stands for.
func rustFileModulePath(packagePath, fileName string, reExported map[string]bool) string {
	stem := strings.TrimSuffix(fileName, ".rs")
	switch stem {
	case "lib", "main", "mod", "":
		return packagePath
	}
	// A parent that writes `pub use self::inner::*;` makes the child's items
	// public at ITS path, and that is the identity a contract keys on:
	// sodiumoxide's `sign/mod.rs` re-exports `ed25519`, and its contract reads
	// `sodiumoxide::crypto::sign.sign_detached`, not the declaring file's
	// `...::sign::ed25519`. Extending the path here without checking cost four
	// contract hits on that crate's own source.
	if reExported[stem] {
		return packagePath
	}
	if packagePath == "" {
		return stem
	}
	return packagePath + "::" + stem
}

// rustGlobReExportedModules returns the child modules a directory's own module
// file glob-re-exports, so their declarations carry the public path rather than
// the declaring file's.
func (p *RustParser) rustGlobReExportedModules(dir string) map[string]bool {
	if cached, ok := p.globReExportCache[dir]; ok {
		return cached
	}
	found := p.readRustGlobReExportedModules(dir)
	if p.globReExportCache == nil {
		p.globReExportCache = make(map[string]map[string]bool)
	}
	// An empty answer is cached too: "this directory re-exports nothing" is the
	// common case and is exactly what the repeated parse was recomputing.
	p.globReExportCache[dir] = found
	return found
}

// readRustGlobReExportedModules does the work rustGlobReExportedModules
// memoizes: one read and one parse of the directory's own module file.
func (p *RustParser) readRustGlobReExportedModules(dir string) map[string]bool {
	for _, name := range []string{"mod.rs", "lib.rs", "main.rs"} {
		src, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		// A dedicated parser: this runs before the directory's files are
		// parsed, and reusing p.parser while any tree is open is what deadlocks
		// tree-sitter.
		parser := sitter.NewParser()
		parser.SetLanguage(rust.GetLanguage())
		tree, err := parser.ParseCtx(context.TODO(), nil, src)
		if err != nil {
			continue
		}
		found := rustCollectGlobReExports(tree.RootNode(), src)
		tree.Close()
		if len(found) > 0 {
			return found
		}
	}
	return nil
}

// rustCollectGlobReExports reads the `pub use self::x::*;` and `pub use x::*;`
// declarations of one module file.
func rustCollectGlobReExports(root *sitter.Node, src []byte) map[string]bool {
	found := map[string]bool{}
	rootNamedChildren := int(root.NamedChildCount())
	for i := 0; i < rootNamedChildren; i++ {
		child := root.NamedChild(i)
		if child.Type() != rustNodeUseDeclaration {
			continue
		}
		argument := child.ChildByFieldName("argument")
		if argument == nil || argument.Type() != rustNodeUseWildcard {
			continue
		}
		path := ""
		namedCountJ := int(argument.NamedChildCount())
		for j := 0; j < namedCountJ; j++ {
			path = rustScopedTypeText(argument.NamedChild(j), src)
		}
		segments := strings.Split(path, "::")
		if len(segments) == 0 {
			continue
		}
		// `self::inner::*` and the 2015-edition `inner::*` both name a child;
		// anything deeper or rooted elsewhere is not this directory's module.
		if len(segments) == 2 && segments[0] == rustNodeSelf {
			found[segments[1]] = true
		} else if len(segments) == 1 && segments[0] != "" {
			found[segments[0]] = true
		}
	}
	return found
}

// parseFile extracts declarations, imports, and calls from a single Rust file.
func (p *RustParser) parseFile(filePath, packagePath string) (*FileAnalysis, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", filePath, err)
	}

	tree, err := p.parser.ParseCtx(context.TODO(), nil, src)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", filePath, err)
	}
	defer tree.Close()

	root := tree.RootNode()

	analysis := &FileAnalysis{
		FilePath:      filePath,
		PackagePath:   packagePath,
		Imports:       make(map[string]string),
		ImportAliases: make(map[string]string),
	}

	// Collect the file's declared-type facts before walking declarations:
	// struct and enum-variant field types, function return types, and the
	// types this file declares. The receiver-typing layer resolves through
	// them, and a `let` early in a function can name a helper declared later
	// in the file, so this has to be a separate pass.
	analysis.rustDependencies = p.crateDependencies(filePath)
	analysis.rustFacts = collectRustFileFacts(root, src, packagePath, p.crateEdition(filePath), analysis.rustDependencies, p.includeTests)
	analysis.rustFacts.fallback = p.crateIndex.factsFor(p, filePath)
	analysis.rustCrateIndex = p.crateIndex

	// Seed the crate-wide renames before the file's own imports, so a
	// file-local import of the same name still wins. Two mechanisms give a
	// crate a name the source spells differently from its identity: a
	// `[dependencies.x] package = "y"` rename in the manifest, and a crate-root
	// `extern crate y as x;`.
	// Recorded in both maps on purpose: ImportAliases is what the prefix and
	// receiver lookups expand, and rustFacts.crateAliases is the dedicated set
	// of aliases that name a whole CRATE — the only ones that may re-root a
	// path. Mixing them meant a `type BareCcm = Ccm;` alias was read as a crate
	// named Ccm.
	for alias, crateName := range p.crateManifestRenames(filePath) {
		analysis.ImportAliases[alias] = crateName
		analysis.rustFacts.crateAliases[alias] = crateName
	}
	for alias, crateName := range p.crateExternAliases(filePath) {
		analysis.ImportAliases[alias] = crateName
		analysis.rustFacts.crateAliases[alias] = crateName
	}

	// Extract the file's own top-level imports.
	p.extractScopeImports(root, src, analysis)

	// Extract function and method declarations with their calls. The analysis
	// doubles as the file-level resolution scope; nested scopes get their own
	// copy of the name tables.
	p.extractDeclarations(root, src, filePath, packagePath, analysis, analysis)

	return analysis, nil
}

// extractImports processes `use` declarations from the root node.
// Handles: `use ring::aead::Aead;` → imports["Aead"] = "ring::aead"
// Handles: `use ring::aead::{Aead, AeadCore};` → imports for each item.
// extractScopeImports records the `use`, `extern crate` and `type` items
// declared DIRECTLY in one scope — a file's top level, a module body, an impl
// or trait body, a function body, a block.
//
// It is deliberately not recursive. Walking the whole file into one map made
// every import file-global, and that is the same defect that a flat binding map
// was: two functions in one module each writing `use aes::Aes128 as Cipher;`
// and `use des::Des as Cipher;` collapsed into one entry, so the AES function
// emitted `des.(Des).encrypt_block` — a weak-cipher finding against AES code.
// A `type Cipher = des::Des;` inside a `#[cfg(test)] mod tests` hijacked the
// production code above it the same way.
func (p *RustParser) extractScopeImports(scopeNode *sitter.Node, src []byte, analysis *FileAnalysis) {
	if scopeNode == nil {
		return
	}
	scopeNodeChildren := int(scopeNode.ChildCount())
	for i := 0; i < scopeNodeChildren; i++ {
		child := scopeNode.Child(i)
		switch child.Type() {
		case rustNodeUseDeclaration:
			p.processUseDecl(child, src, analysis, "")
		case rustNodeExternCrate:
			p.recordRustExternCrateAlias(child, src, analysis)
		case rustNodeTypeItem:
			p.recordRustTypeAlias(child, src, analysis)
		}
	}
}

// collectRustAllImports gathers every import in a file, at any depth, into one
// table. It is used ONLY to qualify the crate-wide declaration index, where the
// question is "what could this bare type name mean in the file that declared
// it" and a name two scopes bind differently is dropped by the index's own
// conflict detection. Resolution never uses it: for resolution the tables have
// to be per scope, which is what rustChildImportScope provides.
func (p *RustParser) collectRustAllImports(scopeNode *sitter.Node, src []byte, analysis *FileAnalysis) {
	if scopeNode == nil {
		return
	}
	p.extractScopeImports(scopeNode, src, analysis)
	scopeNodeChildren := int(scopeNode.ChildCount())
	for i := 0; i < scopeNodeChildren; i++ {
		child := scopeNode.Child(i)
		switch child.Type() {
		case rustNodeModItem, rustNodeFunctionItem, rustNodeImplItem, rustNodeTraitItem:
			p.collectRustAllImports(child.ChildByFieldName("body"), src, analysis)
		case goNodeBlock:
			p.collectRustAllImports(child, src, analysis)
		}
	}
}

// rustScopeDeclaresImports reports whether a scope introduces any name of its
// own, so a copy of the resolution view is only made where one is needed.
func rustScopeDeclaresImports(scopeNode *sitter.Node) bool {
	if scopeNode == nil {
		return false
	}
	scopeNodeChildren := int(scopeNode.ChildCount())
	for i := 0; i < scopeNodeChildren; i++ {
		switch scopeNode.Child(i).Type() {
		case rustNodeUseDeclaration, rustNodeExternCrate, rustNodeTypeItem:
			return true
		}
	}
	return false
}

// rustChildImportScope returns a resolution view for a nested scope: a copy of
// the enclosing one, extended with the scope's own imports. The copy is what
// keeps a sibling scope's imports out — the maps are per scope, not per file.
//
// Only the name tables are copied. Everything else, including the collected
// declarations, stays shared with the analysis being built.
func (p *RustParser) rustChildImportScope(scopeNode *sitter.Node, src []byte, parent *FileAnalysis, packagePath string) *FileAnalysis {
	if !rustScopeDeclaresImports(scopeNode) && packagePath == parent.PackagePath {
		return parent
	}
	child := *parent
	child.PackagePath = packagePath
	child.Imports = make(map[string]string, len(parent.Imports))
	for name, pkg := range parent.Imports {
		child.Imports[name] = pkg
	}
	child.ImportAliases = make(map[string]string, len(parent.ImportAliases))
	for alias, target := range parent.ImportAliases {
		child.ImportAliases[alias] = target
	}
	child.WildcardImports = append([]string(nil), parent.WildcardImports...)
	// The scope's own items are collected into FRESH tables and merged over the
	// inherited copy, so a nested `type Ciph = Des;` overrides an ancestor's
	// `type Ciph = Aes128;`. Extracting straight into the copy let the
	// inherited entry block it — recordRustTypeAlias declines an alias already
	// in scope — and the inner module's DES code was reported as AES.
	own := child
	own.Imports = make(map[string]string)
	own.ImportAliases = make(map[string]string)
	own.WildcardImports = nil
	p.extractScopeImports(scopeNode, src, &own)
	for name, pkg := range own.Imports {
		child.Imports[name] = pkg
	}
	for alias, target := range own.ImportAliases {
		child.ImportAliases[alias] = target
	}
	child.WildcardImports = append(child.WildcardImports, own.WildcardImports...)
	return &child
}

// processUseDecl recursively processes a use declaration tree.
func (p *RustParser) processUseDecl(node *sitter.Node, src []byte, analysis *FileAnalysis, prefix string) {
	nodeChildren := int(node.ChildCount())
	for i := 0; i < nodeChildren; i++ {
		child := node.Child(i)
		switch child.Type() {
		case javaNodeScopedIdentifier:
			// e.g. `ring::aead::Aead`. Read by field rather than by text: the
			// edition-2018 disambiguator `use ::cipher::X` leaves an empty path
			// segment, and its source text kept the leading "::" in the package.
			fullPath := rustResolveImportPath(analysis, rustScopedTypeText(child, src))
			lastSep := strings.LastIndex(fullPath, "::")
			if lastSep > 0 {
				name := fullPath[lastSep+2:]
				pkg := fullPath[:lastSep]
				analysis.Imports[name] = pkg
			}
		case goNodeIdentifier:
			// Simple import like `use ring;`
			name := child.Content(src)
			if prefix != "" {
				analysis.Imports[name] = prefix
			}
		case "scoped_use_list":
			// e.g., `use ring::aead::{Aead, AeadCore};`
			p.processScopedUseList(child, src, analysis, "")
		case rustNodeUseWildcard:
			// e.g. `use ring::aead::*;`. The path is a CHILD of the
			// use_wildcard node; reading only the caller's prefix meant the
			// recorded list was always empty, because the sole caller passes
			// no prefix.
			p.recordRustWildcardImport(child, src, analysis, prefix)
		case rustNodeUseAsClause:
			// e.g., `use cbc::Encryptor as CbcEnc;` or `use cfb_mode as cfb;`
			p.recordRustAliasImport(child, src, analysis, prefix)
		}
	}
}

// processScopedUseList handles `path::{item1, item2}` patterns.
func (p *RustParser) processScopedUseList(node *sitter.Node, src []byte, analysis *FileAnalysis, prefix string) {
	var basePath string

	nodeChildren := int(node.ChildCount())
	for i := 0; i < nodeChildren; i++ {
		child := node.Child(i)
		switch child.Type() {
		case javaNodeScopedIdentifier, goNodeIdentifier, rustNodeCrate, rustNodeSuper, rustNodeSelf:
			// `use crate::{cvt, cvt_p}` roots the list at a `crate` node, not
			// an identifier. Reading only identifiers left the prefix empty, so
			// every item in such a list was recorded with an EMPTY package —
			// 485 edges in openssl 0.10.81 alone. Read by field, so the
			// edition-2018 disambiguator `use ::cipher::{..}` does not keep its
			// leading separator either.
			basePath = rustScopedTypeText(child, src)
		case "use_list":
			combinedPrefix := rustResolveImportPath(analysis, combineRustUsePrefix(prefix, basePath))
			p.processRustUseList(child, src, analysis, combinedPrefix)
		}
	}
}

func combineRustUsePrefix(prefix, basePath string) string {
	if prefix == "" {
		return basePath
	}
	if basePath == "" {
		return prefix
	}
	return prefix + "::" + basePath
}

func (p *RustParser) processRustUseList(node *sitter.Node, src []byte, analysis *FileAnalysis, combinedPrefix string) {
	nodeChildren := int(node.ChildCount())
	for j := 0; j < nodeChildren; j++ {
		p.processRustUseListItem(node.Child(j), src, analysis, combinedPrefix)
	}
}

func (p *RustParser) processRustUseListItem(item *sitter.Node, src []byte, analysis *FileAnalysis, combinedPrefix string) {
	switch item.Type() {
	case rustNodeSelf:
		// `use ring::digest::{self, SHA256};` binds the MODULE `digest` as well
		// as the item. Skipping it left the module bound to nothing, so a call
		// written `digest::digest(..)` resolved to a bare `digest` package —
		// which is also the name of a different crypto crate.
		if lastSep := strings.LastIndex(combinedPrefix, "::"); lastSep > 0 {
			analysis.Imports[combinedPrefix[lastSep+2:]] = combinedPrefix[:lastSep]
		}
	case goNodeIdentifier:
		analysis.Imports[rustScopedTypeText(item, src)] = combinedPrefix
	case javaNodeScopedIdentifier:
		p.recordRustScopedImport(rustScopedTypeText(item, src), analysis, combinedPrefix)
	case "scoped_use_list":
		p.processScopedUseList(item, src, analysis, combinedPrefix)
	case rustNodeUseAsClause:
		// e.g., `use cbc::{Encryptor as CbcEnc, Decryptor};`
		p.recordRustAliasImport(item, src, analysis, combinedPrefix)
	}
}

// recordRustWildcardImport records a glob import's path, resolving a relative
// root so the recorded module can be matched later.
func (p *RustParser) recordRustWildcardImport(node *sitter.Node, src []byte, analysis *FileAnalysis, prefix string) {
	path := ""
	nodeChildren := int(node.ChildCount())
	for i := 0; i < nodeChildren; i++ {
		child := node.Child(i)
		switch child.Type() {
		case javaNodeScopedIdentifier, goNodeIdentifier, rustNodeCrate, rustNodeSuper, rustNodeSelf:
			path = rustScopedTypeText(child, src)
		}
	}
	path = combineRustUsePrefix(prefix, path)
	if path == "" {
		return
	}
	path = rustResolveImportPath(analysis, path)
	for _, existing := range analysis.WildcardImports {
		if existing == path {
			return
		}
	}
	analysis.WildcardImports = append(analysis.WildcardImports, path)
}

// recordRustAliasImport records a renaming import so a call written through the
// local name still resolves to the real path. `use cbc::Encryptor as CbcEnc;`
// makes `CbcEnc::new(..)` the same call as `cbc::Encryptor::new(..)`, and the
// block-mode crates force that spelling on real consumers: cbc, cfb-mode and
// ctr all export `Encryptor`/`Decryptor`, so a file using two of them cannot
// import both under their own names. Before this, the alias was dropped and the
// call kept the unqualified `CbcEnc.new` identity, which matches no contract.
func (p *RustParser) recordRustAliasImport(node *sitter.Node, src []byte, analysis *FileAnalysis, prefix string) {
	realPath, alias, keyword := rustAliasImportParts(node, src)
	if alias == "" {
		return
	}
	if keyword == rustNodeCrate {
		// A nested `use crate::{self as x}` is the same rename written through a
		// prefix; a bare `use crate as x;` has none and means the crate root.
		crateRoot := prefix
		if crateRoot == "" {
			crateRoot = rustCrateRoot(analysis.PackagePath)
		}
		if crateRoot == "" {
			return
		}
		analysis.ImportAliases[alias] = crateRoot
		if analysis.rustFacts != nil {
			analysis.rustFacts.recordCrateReExport(alias, crateRoot)
		}
		return
	}
	if keyword == rustNodeSelf {
		if prefix == "" {
			return
		}
		analysis.ImportAliases[alias] = prefix
		return
	}
	if realPath == "" {
		return
	}
	// The path being RENAMED still has to be resolved. Recorded raw, a
	// `use crate::target as ct;` or `use super::super::target2 as t2;` put the
	// keyword itself in the package of every call written through the alias --
	// 73 edges across 51 crates, including aes 0.9.2's own hazmat round
	// functions. A prefix from an enclosing use tree is already absolute, so
	// only the nested root needs collapsing there.
	if prefix != "" {
		realPath = rustCollapseRelativeSegments(analysis, prefix+"::"+realPath)
	} else {
		realPath = rustResolveImportPath(analysis, realPath)
	}
	analysis.ImportAliases[alias] = realPath
}

// rustAliasImportParts reads a renaming `use` item: the path being renamed, the
// local name it is bound to, and which keyword root it names, if any — the
// keyword result is rustNodeSelf, rustNodeCrate, or "".
//
// Collecting only identifiers dropped `use crate as openpgp;` entirely —
// sequoia-openpgp 1.21.2 src/cert/revoke.rs:1344 (also
// :1366,1380,1404,1418,1442,1456,1485) writes exactly that, and 21 edges kept
// the local spelling as their package
// (`openpgp::packet::signature.(SignatureBuilder).new` and friends). `openpgp`
// is a real crates.io crate, so that is a wrong identity, not a missing one.
func rustAliasImportParts(node *sitter.Node, src []byte) (realPath, alias, keyword string) {
	nodeChildren := int(node.ChildCount())
	for i := 0; i < nodeChildren; i++ {
		child := node.Child(i)
		switch child.Type() {
		case javaNodeScopedIdentifier:
			realPath = rustScopedTypeText(child, src)
		case rustNodeSelf:
			// `use cbc::{self as c};` renames the module itself, so the real
			// path is the enclosing prefix rather than a named item.
			keyword = rustNodeSelf
		case rustNodeCrate:
			keyword = rustNodeCrate
		case goNodeIdentifier:
			// The first identifier is the imported path, the second the alias.
			if realPath == "" && keyword == "" {
				realPath = child.Content(src)
			} else {
				alias = child.Content(src)
			}
		}
	}
	return realPath, alias, keyword
}

// recordRustExternCrateAlias resolves the 2015-edition rename
// `extern crate openssl_sys as ffi;` so a call written `ffi::EVP_sha256()`
// keeps the crate's own identity.
//
// `use openssl_sys as ffi;` was already handled, by recordRustAliasImport. The
// `extern crate` spelling reached extractImports as an unrecognized node type
// and the rename was dropped, so the call key kept the local name — `ffi.X`
// instead of `openssl_sys.X`. That is the wrong-key case rather than the
// missing-key one: the identity looks like data and matches no contract.
// FFI binding crates are where it shows, because aliasing them is the norm.
func (p *RustParser) recordRustExternCrateAlias(node *sitter.Node, src []byte, analysis *FileAnalysis) {
	// `extern crate foo;` has one identifier and no rename; `extern crate self
	// as foo;` carries a `self` keyword node rather than a second identifier.
	// Both leave the identity alone, so require exactly the two-identifier form.
	var idents []string
	nodeChildren := int(node.ChildCount())
	for i := 0; i < nodeChildren; i++ {
		if child := node.Child(i); child.Type() == goNodeIdentifier {
			idents = append(idents, child.Content(src))
		}
	}
	if len(idents) != 2 {
		return
	}
	crateName, alias := idents[0], idents[1]
	if crateName == "" || alias == "" || alias == crateName {
		return
	}
	analysis.ImportAliases[alias] = crateName
}

func (p *RustParser) recordRustScopedImport(fullPath string, analysis *FileAnalysis, combinedPrefix string) {
	lastSep := strings.LastIndex(fullPath, "::")
	if lastSep <= 0 {
		return
	}
	name := fullPath[lastSep+2:]
	importPath := fullPath[:lastSep]
	if combinedPrefix != "" {
		// The prefix is already absolute and the item's own path may open a
		// SECOND relative root -- `use super::{super::target2::hit2, ..}` --
		// so the concatenation has to be collapsed rather than trusted.
		importPath = rustCollapseRelativeSegments(analysis, combinedPrefix+"::"+importPath)
	}
	analysis.Imports[name] = importPath
}

// extractDeclarations walks top-level items for functions and impl blocks.
func (p *RustParser) extractDeclarations(root *sitter.Node, src []byte, filePath, packagePath string, analysis, scope *FileAnalysis) {
	rootChildren := int(root.ChildCount())
	for i := 0; i < rootChildren; i++ {
		child := root.Child(i)
		switch child.Type() {
		case rustNodeFunctionItem:
			// A function's own `use` items bind only inside it.
			fnScope := p.rustChildImportScope(child.ChildByFieldName("body"), src, scope, packagePath)
			decl := p.parseFunctionItem(child, src, filePath, packagePath, "", fnScope)
			if decl != nil {
				analysis.Functions = append(analysis.Functions, *decl)
			}
		case rustNodeImplItem:
			p.processImplBlock(child, src, filePath, packagePath, analysis, scope)
		case rustNodeModItem:
			// An inline `mod x { ... }` is a module of its own, and everything
			// in it was invisible: the loop only ever looked at the file's
			// top-level children, so a crate that puts its code in inline
			// modules — or a `#[cfg(test)] mod tests` — contributed no
			// declarations and no calls at all. The module extends the package
			// path, exactly as a file-based module does, and its imports bind
			// only inside it.
			p.processRustModItem(child, src, filePath, packagePath, analysis, scope)
		case rustNodeTraitItem:
			// A trait's default method bodies are real code with real calls, and
			// they belong to the TRAIT.
			//
			// Recursing with extractDeclarations as well recorded every one of
			// them TWICE: its function_item case has no owning type, so each
			// default method also became a free function of the module.
			// magic-crypt 3.1.13 src/traits.rs:20 emitted both
			// `magic-crypt::traits.(MagicCryptTrait).encrypt_str_to_base64` and
			// `magic-crypt::traits.encrypt_str_to_base64`, and no free function
			// of that name exists anywhere in the crate. 523 duplicated edges
			// across 15 of 53 crates. A trait body holds only associated items,
			// so processRustTraitDefaults alone reaches everything there is.
			if body := child.ChildByFieldName("body"); body != nil {
				traitName := nodeFieldText(child, "name", src)
				traitScope := p.rustChildImportScope(body, src, scope, packagePath)
				p.processRustTraitDefaults(body, src, filePath, packagePath, traitName, analysis, traitScope)
			}
		}
	}
}

// rustModuleIsTestOnly reports whether a mod_item is compiled only for tests,
// which is what `#[cfg(test)]` means. Attributes are preceding siblings of the
// item they decorate, so the scan walks back over them.
//
// A default scan already skips the `tests/` directory and `*_test.rs`, and an
// inline test module is that same code by another spelling. Walking inline
// modules is required (a crate that organizes its code in them must not
// contribute nothing), which is what first made these bodies reachable: a
// crate whose published artifact uses only AES but whose inline test module
// exercises DES was reported as using DES, in a scan that did not ask for
// tests.
func rustModuleIsTestOnly(node *sitter.Node, src []byte) bool {
	for prev := node.PrevNamedSibling(); prev != nil; prev = prev.PrevNamedSibling() {
		// A comment may sit between an attribute and the item it decorates, so
		// it must not end the walk: `#[cfg(test)]`, then `// only for tests`,
		// then `mod tests` is one decorated item.
		if rustIsComment(prev.Symbol()) {
			continue
		}
		if prev.Type() != rustNodeAttributeItem {
			return false
		}
		if rustAttributeGatesOnTest(prev, src) {
			return true
		}
	}
	return false
}

// rustAttributeGatesOnTest reports whether an attribute_item is a `cfg`
// predicate naming the bare `test` flag, including when it is nested inside
// `all(..)` or `any(..)`. `#[cfg(feature = "test-utils")]` does not qualify:
// its "test-utils" is string content, not an identifier, so the two are told
// apart by shape rather than by matching text.
func rustAttributeGatesOnTest(item *sitter.Node, src []byte) bool {
	attr := rustNamedChildOfType(item, rustNodeAttribute)
	if attr == nil {
		return false
	}
	name := attr.NamedChild(0)
	if name == nil || name.Type() != goNodeIdentifier || name.Content(src) != "cfg" {
		return false
	}
	tree := rustNamedChildOfType(attr, rustNodeTokenTree)
	return tree != nil && rustTokenTreeNamesTest(tree, src)
}

// rustTokenTreeNamesTest reports whether a cfg predicate's token tree contains
// `test` as a bare identifier at any nesting depth.
func rustTokenTreeNamesTest(tree *sitter.Node, src []byte) bool {
	prevIdent := ""
	treeNamedChildren := int(tree.NamedChildCount())
	for i := 0; i < treeNamedChildren; i++ {
		child := tree.NamedChild(i)
		switch child.Type() {
		case goNodeIdentifier:
			if child.Content(src) == "test" {
				return true
			}
			prevIdent = child.Content(src)
			continue
		case rustNodeTokenTree:
			// `not(test)` gates the module on NOT being a test build, which is
			// the standard spelling for a real implementation paired with a
			// `#[cfg(test)]` mock. Descending into it read the module as
			// test-only and dropped production code — a missed detection, the
			// worse direction. `all(..)` and `any(..)` still descend.
			if prevIdent == "not" {
				break
			}
			if rustTokenTreeNamesTest(child, src) {
				return true
			}
		}
		prevIdent = ""
	}
	return false
}

// processRustModItem walks an inline module, extending the package path with
// the module's name so its declarations carry the identity a file-based module
// of the same name would.
func (p *RustParser) processRustModItem(node *sitter.Node, src []byte, filePath, packagePath string, analysis, scope *FileAnalysis) {
	body := node.ChildByFieldName("body")
	if body == nil {
		return
	}
	if !p.includeTests && rustModuleIsTestOnly(node, src) {
		return
	}
	name := nodeFieldText(node, "name", src)
	modulePath := packagePath
	if name != "" {
		modulePath = p.SubPackagePath(packagePath, name)
	}
	modScope := p.rustChildImportScope(body, src, scope, modulePath)
	p.extractDeclarations(body, src, filePath, modulePath, analysis, modScope)
}

// processRustTraitDefaults records a trait's default methods as declarations
// owned by the trait, so calls in their bodies are attributed somewhere.
func (p *RustParser) processRustTraitDefaults(body *sitter.Node, src []byte, filePath, packagePath, traitName string, analysis, scope *FileAnalysis) {
	if traitName == "" {
		return
	}
	bodyNamedChildren := int(body.NamedChildCount())
	for i := 0; i < bodyNamedChildren; i++ {
		child := body.NamedChild(i)
		if child.Type() != rustNodeFunctionItem {
			continue
		}
		fnScope := p.rustChildImportScope(child.ChildByFieldName("body"), src, scope, packagePath)
		decl := p.parseFunctionItem(child, src, filePath, packagePath, traitName, fnScope)
		if decl != nil {
			analysis.Functions = append(analysis.Functions, *decl)
		}
	}
}

// parseFunctionItem parses a function_item node into a FunctionDecl.
func (p *RustParser) parseFunctionItem(node *sitter.Node, src []byte, filePath, packagePath, typeName string, analysis *FileAnalysis) *FunctionDecl {
	return p.parseFunctionItemWithGenerics(node, src, filePath, packagePath, typeName, analysis, nil, typeName)
}

// parseFunctionItemWithGenerics parses a function, resolving its receivers with
// the generic parameters its enclosing impl block declares as well as its own.
// selfType is what `Self` and `self` mean inside the body: the impl header's
// self type WITH its path, which is not always the bare typeName the key's type
// field carries.
func (p *RustParser) parseFunctionItemWithGenerics(node *sitter.Node, src []byte, filePath, packagePath, typeName string, analysis *FileAnalysis, outerGenerics map[string]string, selfType string) *FunctionDecl {
	var name string
	var body *sitter.Node
	var paramsNode *sitter.Node

	nodeChildren := int(node.ChildCount())
	for i := 0; i < nodeChildren; i++ {
		child := node.Child(i)
		switch child.Type() {
		case goNodeIdentifier:
			name = child.Content(src)
		case "parameters":
			paramsNode = child
		case goNodeBlock:
			body = child
		}
	}

	if name == "" {
		return nil
	}

	parameters, hasSelf := parseRustParameters(paramsNode, src)
	ownerType := "module"
	ownerName := packagePath
	functionType := "function"
	if typeName != "" {
		ownerType = ownerTypeType
		ownerName = typeName
		if hasSelf {
			functionType = "method"
		} else {
			functionType = "associated_function"
		}
	}

	decl := &FunctionDecl{
		ID: FunctionID{
			Package: packagePath,
			Type:    typeName,
			Name:    name,
		},
		FilePath:     filePath,
		StartLine:    int(node.StartPoint().Row) + 1,
		EndLine:      int(node.EndPoint().Row) + 1,
		OwnerType:    ownerType,
		OwnerName:    ownerName,
		FunctionType: functionType,
		ReturnType:   parseRustReturnType(node.Content(src)),
		Parameters:   parameters,
	}

	if body != nil {
		ctx := p.newRustTypeCtx(node, paramsNode, src, analysis, selfType, outerGenerics)
		decl.Calls = p.extractCalls(body, ctx, filePath)
		decl.ReturnSources = p.extractReturnSources(body, ctx, filePath)
	}

	return decl
}

func (p *RustParser) extractReturnSources(body *sitter.Node, ctx *rustTypeCtx, filePath string) []SourceNode {
	var sources []SourceNode
	ctx.walkRustScoped(body, func(node *sitter.Node, nodeCtx *rustTypeCtx) bool {
		switch node.Type() {
		case rustNodeFunctionItem, rustNodeClosureExpression:
			// A nested function or a closure returns from ITSELF, not from the
			// declaration being parsed.
			return false
		case "return_expression":
			if expr := rustReturnExpressionNode(node); expr != nil {
				sources = append(sources, p.traceRustReturnExpression(expr, nodeCtx, filePath)...)
			}
			return false
		}
		return true
	})
	return append(sources, p.traceRustTailExpression(body, ctx, filePath)...)
}

func rustReturnExpressionNode(node *sitter.Node) *sitter.Node {
	nodeChildren := int(node.ChildCount())
	for i := 0; i < nodeChildren; i++ {
		child := node.Child(i)
		if child.IsNamed() && child.Type() != "return" {
			return child
		}
	}
	return nil
}

func (p *RustParser) traceRustTailExpression(body *sitter.Node, ctx *rustTypeCtx, filePath string) []SourceNode {
	tail := rustBlockTailExpressionNode(body, ctx.src)
	if tail == nil {
		return nil
	}
	return p.traceRustReturnExpression(tail, ctx, filePath)
}

// rustBlockTailExpressionNode returns a block's implicit tail expression: its
// last statement, when that statement is an expression with no trailing `;`.
// A block ending in a `;`-terminated statement, or in anything else, has no
// tail value.
func rustBlockTailExpressionNode(body *sitter.Node, src []byte) *sitter.Node {
	if body == nil || body.Type() != goNodeBlock {
		return nil
	}
	for i := int(body.NamedChildCount()) - 1; i >= 0; i-- {
		child := body.NamedChild(i)
		if child == nil {
			continue
		}
		if child.Type() == rustNodeExpressionStatement && child.NamedChildCount() == 1 && !strings.HasSuffix(strings.TrimSpace(child.Content(src)), ";") {
			return child.NamedChild(0)
		}
		if child.Type() != rustNodeExpressionStatement {
			return child
		}
		return nil
	}
	return nil
}

func (p *RustParser) traceRustReturnExpression(node *sitter.Node, ctx *rustTypeCtx, filePath string) []SourceNode {
	if node == nil {
		return nil
	}
	src := ctx.src
	switch node.Type() {
	case rustNodeCallExpression:
		call := p.parseCallExpr(node, ctx, filePath)
		if call == nil {
			return nil
		}
		return []SourceNode{{
			Type:       "CALL_RESULT",
			Value:      strings.TrimSpace(node.Content(src)),
			CallTarget: &call.Callee,
		}}
	case goNodeIdentifier:
		name := node.Content(src)
		return []SourceNode{{
			Type:         "VARIABLE",
			Name:         name,
			DeclaredType: ctx.declaredType(name),
			Location:     &SourceLocation{FilePath: filePath, Line: int(node.StartPoint().Row) + 1},
		}}
	}
	return nil
}

// processImplBlock processes an impl block, extracting the type name
// and all method declarations within it.
func (p *RustParser) processImplBlock(node *sitter.Node, src []byte, filePath, packagePath string, analysis, scope *FileAnalysis) {
	// The grammar exposes the impl target and the implemented trait as two
	// separate fields. `impl Digest for MyHasher` has trait=Digest and
	// type=MyHasher, and the receiver identity of every method declared in
	// the block is the TYPE, never the trait. Reading the first type-shaped
	// child instead picks up the trait for every `impl Trait for Type`
	// block — the dominant shape in the RustCrypto ecosystems — and types
	// both the declaration and every `self.x()` call inside it with the
	// trait's name.
	typeNode := node.ChildByFieldName("type")
	body := node.ChildByFieldName("body")
	if typeNode == nil || body == nil {
		return
	}
	typeName := p.extractTypeName(typeNode, src)
	if typeName == "" {
		return
	}

	implGenerics := make(map[string]string)
	collectRustGenerics(node, src, implGenerics)
	implScope := p.rustChildImportScope(body, src, scope, packagePath)
	// The impl header's own path is the self type's identity. Reducing
	// `impl From<Wire> for crate::local::Aes128` to the bare leaf `Aes128` and
	// re-resolving that through the file's imports handed the block to whatever
	// crate happens to import the same leaf: with `use aes::Aes128;` in scope
	// the block's `Self::new()` and `x.encrypt_block(..)` came out as
	// `aes.(Aes128).new` / `aes.(Aes128).encrypt_block`, both keys in aes.yaml,
	// so a crate whose own `Aes128` is a record framer was reported as
	// performing AES-128 block encryption. The written path is the answer and
	// it must not be discarded.
	selfType := rustImplSelfType(implScope, typeNode, src, typeName)
	// `impl <Trait> for <Type>` — the receiver identity is the TYPE, but the
	// methods inside are the TRAIT's API, and the trait can belong to another
	// crate. apple-codesign 0.16.0 writes
	// `impl EncodePrivateKey for InMemoryPrivateKey` under
	// `use pkcs8::EncodePrivateKey`: the type is its own, `to_pkcs8_der` is
	// pkcs8's. Recording the resolved trait path is what lets a consumer of the
	// graph tell that apart from a same-named inherent method.
	implTraits := p.rustImplTraitPaths(implScope, node, src)
	declPackage := packagePath
	if qualifiedPkg, _, ok := splitQualifiedRustType(selfType); ok && qualifiedPkg != "" {
		declPackage = qualifiedPkg
	}
	bodyChildren := int(body.ChildCount())
	for i := 0; i < bodyChildren; i++ {
		child := body.Child(i)
		if child.Type() == rustNodeFunctionItem {
			fnScope := p.rustChildImportScope(child.ChildByFieldName("body"), src, implScope, packagePath)
			decl := p.parseFunctionItemWithGenerics(child, src, filePath, declPackage, typeName, fnScope, implGenerics, selfType)
			if decl != nil {
				decl.OwnerTraits = implTraits
				analysis.Functions = append(analysis.Functions, *decl)
			}
		}
	}
}

// rustImplTraitPaths returns the trait an impl header implements, with its path
// resolved through the file's imports, or nil for an inherent impl block.
//
// `impl EncodePrivateKey for MyKey` under `use pkcs8::EncodePrivateKey;` yields
// "pkcs8::EncodePrivateKey". A header that writes the path itself
// (`impl pkcs8::EncodePrivateKey for MyKey`) keeps it. A trait the file never
// imported stays a bare name, which is what it means: a trait of the enclosing
// module, so the crate implementing it is the one being scanned.
//
// Deliberately NOT routed through rustImplSelfType: that function leaves a bare
// name bare on purpose, because the self type of an unqualified header IS the
// enclosing module's type. A trait name is the opposite case — it is usually
// imported, and the import is the only place its owning crate is written.
func (p *RustParser) rustImplTraitPaths(implScope *FileAnalysis, node *sitter.Node, src []byte) []string {
	traitNode := node.ChildByFieldName("trait")
	if traitNode == nil {
		return nil
	}
	written := rustScopedTypeText(traitNode, src)
	if written == "" {
		written = p.extractTypeName(traitNode, src)
	}
	written = stripRustGenericArgs(written)
	if written == "" {
		return nil
	}
	if strings.Contains(written, "::") {
		return []string{written}
	}
	if implScope != nil && implScope.Imports != nil {
		if pkg, ok := implScope.Imports[written]; ok && pkg != "" {
			return []string{pkg + "::" + written}
		}
	}
	return []string{written}
}

// stripRustGenericArgs drops a trait's generic arguments: `Signer<Signature>`
// names the trait `Signer`, and the argument is not part of its identity here.
func stripRustGenericArgs(name string) string {
	if i := strings.IndexByte(name, '<'); i >= 0 {
		return strings.TrimSpace(name[:i])
	}
	return strings.TrimSpace(name)
}

// rustImplSelfType returns the impl block's self type with the path the header
// wrote, resolved to an absolute module path: `impl .. for crate::local::Aes128`
// in crate `ns2` yields "ns2::local::Aes128". A header that writes no path
// yields the bare name, which is what it means — the enclosing module's type.
//
// The type field of a callee key still carries only the leaf; the path belongs
// in the package field, and this is what puts it there.
func rustImplSelfType(analysis *FileAnalysis, typeNode *sitter.Node, src []byte, typeName string) string {
	text := stripRustTypeArguments(rustScopedTypeText(typeNode, src))
	lastSep := strings.LastIndex(text, "::")
	if lastSep <= 0 {
		return typeName
	}
	prefix := resolveRustTypePackage(text[:lastSep], analysis)
	// A prefix that is not a nameable module path — `<[u8; 16]>`, a generic
	// argument, a primitive — is not an identity; the bare name is the honest
	// answer rather than putting source text in the package field.
	if rustModulePathText(prefix) == "" {
		return typeName
	}
	return prefix + "::" + typeName
}

// extractTypeName gets the simple type name from various type nodes.
func (p *RustParser) extractTypeName(node *sitter.Node, src []byte) string {
	switch node.Type() {
	case goNodeTypeIdentifier:
		return node.Content(src)
	case javaNodeGenericType:
		// `impl Trait for Box<dyn X>` is an impl for X reached through a box:
		// keying it on `Box` collapsed independent impls onto one name and
		// erased the only identity in the header. quinn-proto 0.11.9
		// src/crypto/rustls.rs:220 writes
		// `impl crypto::HeaderKey for Box<dyn HeaderProtectionKey>` and :584
		// `impl crypto::PacketKey for Box<dyn PacketKey>`; both typed as
		// `(Box)`, collided, and one was dropped. The boxed trait is the answer.
		if boxed := rustBoxedSelfType(node, src); boxed != "" {
			return boxed
		}
		// e.g., `MyStruct<T>` — get just "MyStruct"
		nodeChildren := int(node.ChildCount())
		for i := 0; i < nodeChildren; i++ {
			child := node.Child(i)
			if child.Type() == goNodeTypeIdentifier {
				return child.Content(src)
			}
		}
	case javaNodeScopedTypeIdentifier:
		// e.g., `module::Type` — get just the last segment
		content := node.Content(src)
		if idx := strings.LastIndex(content, "::"); idx >= 0 {
			return content[idx+2:]
		}
		return content
	case "dynamic_type":
		// `impl dyn Encrypter { .. }` is owned by the trait; the `dyn` keyword
		// is not part of the name and left a space in the key's type field.
		return rustTypeHead(rustScopedTypeText(node, src))
	}
	return rustTypeHead(node.Content(src))
}

// rustBoxedSelfType returns the type a smart-pointer self type wraps, or "" when
// the node is not one. `Box<dyn HeaderProtectionKey>` yields
// "HeaderProtectionKey"; `Vec<u8>` yields "" because a primitive element is not
// a nameable identity, and `MyStruct<T>` yields "" because MyStruct IS the type.
func rustBoxedSelfType(node *sitter.Node, src []byte) string {
	// The RAW text, not rustScopedTypeText: that helper drops the generic
	// argument list, which is where the identity lives.
	text := rustStripLifetimes(node.Content(src))
	head := rustTypeHead(text)
	if !rustDerefWrappers[head] {
		return ""
	}
	inner := rustTypeHead(rustUnwrapWrapperType(text, nil))
	if inner == "" || inner == head || inner == rustSelfType || !rustIsNameableType(inner) {
		return ""
	}
	return inner
}

// extractCalls walks a function body to find all call expressions.
func (p *RustParser) extractCalls(body *sitter.Node, ctx *rustTypeCtx, filePath string) []FunctionCall {
	var calls []FunctionCall
	ctx.walkRustScoped(body, func(node *sitter.Node, nodeCtx *rustTypeCtx) bool {
		if node.Type() != rustNodeCallExpression {
			return true
		}
		if call := p.parseCallExpr(node, nodeCtx, filePath); call != nil {
			setFunctionCallASTAnchor(call, node)
			// Chain identity is a property of the syntax, not of how the callee
			// resolved, so it is stamped here for every shape parseCallExpr
			// returns rather than in each of its seventeen constructors.
			call.ChainID, call.AssignedVar = rustCallChainContext(node, nodeCtx.src)
			calls = append(calls, *call)
		}
		return true
	})
	return calls
}

// parseCallExpr parses a call_expression into a FunctionCall.
func (p *RustParser) parseCallExpr(node *sitter.Node, ctx *rustTypeCtx, filePath string) *FunctionCall {
	src, analysis := ctx.src, ctx.analysis
	if node.ChildCount() == 0 {
		return nil
	}

	funcNode := node.Child(0)
	line := int(node.StartPoint().Row) + 1
	raw := funcNode.Content(src)
	args := p.extractRustCallArguments(node, src)

	// A turbofish wraps the callee in a generic_function whose first child is
	// the plain callee node; unwrap it so the cases below see the same shapes
	// they would without the type arguments.
	if funcNode.Type() == rustNodeGenericFunction && funcNode.ChildCount() > 0 {
		funcNode = funcNode.Child(0)
	}

	var call *FunctionCall
	switch funcNode.Type() {
	case javaNodeScopedIdentifier:
		// e.g., `ring::aead::Aead::new(...)` or `Aead::new(...)`
		if ufcs := p.parseUFCSCall(node, funcNode, ctx, filePath, line, args); ufcs != nil {
			call = ufcs
		} else {
			call = p.parseScopedCall(funcNode, src, filePath, line, args, analysis, ctx.selfType, ctx.generics)
		}
	case goNodeIdentifier:
		// Simple call like `encrypt(...)`
		name := funcNode.Content(src)
		// `Self(..)` constructs the impl's own tuple struct. Keyed literally it
		// produced a function named `Self` — 219 edges across 20 of 53 crates,
		// e.g. rcgen 0.13.1 src/string_types.rs:442 `Ok(Self(vec.to_vec()))` as
		// `rcgen.Self`. The impl's self type is known here, and a tuple-struct
		// constructor is keyed by the type's own name, so substitute it.
		if name == rustSelfType {
			if selfCallee, ok := rustSelfConstructorCallee(analysis, ctx.selfType); ok {
				return &FunctionCall{
					Callee:    selfCallee,
					Raw:       raw,
					FilePath:  filePath,
					Line:      line,
					Arguments: args,
					StartCol:  int(node.StartPoint().Column) + 1,
					EndCol:    int(node.EndPoint().Column) + 1,
				}
			}
		}
		// Check if this identifier was imported
		if pkg, ok := analysis.Imports[name]; ok {
			call = &FunctionCall{
				Callee:    FunctionID{Package: pkg, Name: name},
				Raw:       raw,
				FilePath:  filePath,
				Line:      line,
				Arguments: args,
			}
		} else if renamed, ok := rustRenamedFunctionCallee(analysis, name); ok && !ctx.bindings.shadows(name) {
			call = &FunctionCall{
				Callee:    renamed,
				Raw:       raw,
				FilePath:  filePath,
				Line:      line,
				Arguments: args,
			}
		} else {
			call = &FunctionCall{
				Callee:    FunctionID{Package: analysis.PackagePath, Name: name},
				Raw:       raw,
				FilePath:  filePath,
				Line:      line,
				Arguments: args,
			}
		}
	case fieldExpressionNode:
		// Method call like `self.encrypt(...)` or `obj.method(...)`
		call = p.parseFieldCall(funcNode, ctx, filePath, line, args)
	}
	if call != nil {
		call.StartCol = int(node.StartPoint().Column) + 1
		call.EndCol = int(node.EndPoint().Column) + 1
	}
	return call
}

// rustSelfConstructorCallee turns `Self(..)` into the tuple-struct constructor
// of the impl's own type, which is keyed by the type's name exactly as any other
// tuple struct is. Outside an impl — in a trait's default body, where `Self` is
// the implementing type and is not statically known (Reference, Paths -> Self) —
// there is no answer, and the second result is false.
func rustSelfConstructorCallee(analysis *FileAnalysis, selfType string) (FunctionID, bool) {
	if analysis == nil || selfType == "" || selfType == rustSelfType {
		return FunctionID{}, false
	}
	if pkg, typ, ok := splitQualifiedRustType(selfType); ok {
		return FunctionID{Package: pkg, Name: typ}, true
	}
	// The leaf need not be UpperCamelCase: curve25519-dalek's `u64x4` and
	// rustls's `u24` are tuple structs whose `Self(..)` constructor is keyed by
	// their own name like any other.
	leaf := rustTypeHead(selfType)
	if leaf == "" || leaf == rustSelfType || !rustIsNameableType(leaf) {
		return FunctionID{}, false
	}
	return FunctionID{Package: analysis.PackagePath, Name: leaf}, true
}

// parseScopedCall handles calls like `Type::method()` or `module::func()`.
// parseUFCSCall recognizes the fully-qualified-syntax form of a method call —
// `Trait::method(&mut receiver, args)` or `Type::method(receiver, args)`,
// exactly equivalent to `receiver.method(args)` — and resolves it the same
// way a dotted method call resolves, so the two spellings of one call produce
// the same receiver identity instead of the UFCS form losing it to a
// receiverless static-call resolution.
//
// The rewrite fires only when the call's first argument is a bare place
// (stripped of any `&`/`&mut`) whose OWN already-resolved type has the same
// bare name as the scoped path's prefix: `d`'s declared type substituting to
// "Digest" matches a `Digest::` prefix, and `key`'s type in
// `Aes128::new_from_slice(key)` does not match "Aes128", so a genuine
// receiverless call is never rewritten. This needs no knowledge of which
// traits exist — it reuses the identity the parser already established for
// the argument, so a mismatch is a receiverless call, not a maybe.
func (p *RustParser) parseUFCSCall(node, funcNode *sitter.Node, ctx *rustTypeCtx, filePath string, line int, args []string) *FunctionCall {
	if len(args) == 0 {
		return nil
	}
	argsNode := rustCallArgumentsNode(node)
	if argsNode == nil || argsNode.NamedChildCount() == 0 {
		return nil
	}
	receiver := rustUnwrapReferenceNode(argsNode.NamedChild(0))
	if receiver == nil || (receiver.Type() != goNodeIdentifier && receiver.Type() != rustNodeSelf) {
		return nil
	}

	src, analysis := ctx.src, ctx.analysis
	content := stripRustTypeArguments(rustScopedTypeText(funcNode, src))
	lastSep := strings.LastIndex(content, "::")
	if lastSep <= 0 {
		return nil
	}
	prefix, name := content[:lastSep], content[lastSep+2:]

	typeText := ctx.rustSubstituteGeneric(ctx.rustExprType(receiver, 0))
	if typeText == "" || rustTypeHead(typeText) != rustTypeHead(prefix) {
		return nil
	}
	pkg, typ := rustQualifyType(analysis, analysis.rustFacts, typeText)
	if typ == "" {
		return nil
	}
	return &FunctionCall{
		Callee:      FunctionID{Package: pkg, Type: typ, Name: name},
		Raw:         node.Content(src),
		FilePath:    filePath,
		Line:        line,
		Arguments:   args[1:],
		ReceiverVar: receiver.Content(src),
	}
}

// rustCallArgumentsNode returns a call expression's `arguments` node.
func rustCallArgumentsNode(node *sitter.Node) *sitter.Node {
	nodeChildren := int(node.ChildCount())
	for i := 0; i < nodeChildren; i++ {
		child := node.Child(i)
		if child.Type() == "arguments" {
			return child
		}
	}
	return nil
}

// rustUnwrapReferenceNode strips `&`/`&mut`/unary wrapper nodes down to the
// place expression underneath, mirroring how rustExprType reads through them.
func rustUnwrapReferenceNode(node *sitter.Node) *sitter.Node {
	for node != nil {
		if node.Symbol() != rustSyms.referenceExpression && node.Symbol() != rustSyms.unaryExpression {
			return node
		}
		if v := node.ChildByFieldName("value"); v != nil {
			node = v
			continue
		}
		node = rustInnerExpression(node)
	}
	return nil
}

func (p *RustParser) parseScopedCall(node *sitter.Node, src []byte, filePath string, line int, args []string, analysis *FileAnalysis, selfType string, generics map[string]string) *FunctionCall {
	// raw keeps the spelling the source used; content is what resolution reads.
	raw := stripRustTypeArguments(node.Content(src))
	content := stripRustTypeArguments(rustScopedTypeText(node, src))
	// `Self::extract(..)` inside an impl block names the impl's own type; the
	// literal kept `Self` in the key's type field, so the two spellings of one
	// call produced two identities.
	// A qualified self type keeps its path here: `rustTypeHead` strips it, and
	// stripping it sent `Self::new()` inside `impl .. for crate::local::Aes128`
	// back through the file's imports, where `use aes::Aes128;` claimed it.
	if selfType != "" && strings.HasPrefix(content, rustSelfType+"::") {
		content = selfType + content[len(rustSelfType):]
	}
	lastSep := strings.LastIndex(content, "::")
	if lastSep <= 0 {
		return nil
	}

	prefix := content[:lastSep]
	name := content[lastSep+2:]

	substituted, resolvable := rustGenericCallPrefix(prefix, generics)
	if !resolvable {
		// An unbounded generic parameter has no identity at all, so the call
		// carries no type rather than a fabricated one.
		return &FunctionCall{
			Callee:    FunctionID{Package: analysis.PackagePath, Name: name},
			Raw:       raw,
			FilePath:  filePath,
			Line:      line,
			Arguments: args,
		}
	}
	prefix = substituted

	// A module THIS FILE declares comes first, before any rename: an item in
	// the current module shadows the extern prelude, so a crate that renames a
	// dependency to `codec` in its manifest AND declares its own `mod codec`
	// means the local one. Substituting the rename first reported the local
	// type against the renamed crate — a finding for a library the code does
	// not call.
	if local, ok := rustLocalModulePath(analysis, prefix); ok {
		return &FunctionCall{
			Callee:    splitRustScopedCallee(analysis, local, name),
			Raw:       raw,
			FilePath:  filePath,
			Line:      line,
			Arguments: args,
		}
	}

	// A crate reached through an alias — `extern crate y as x;`, a manifest
	// rename, or a module's `pub use <crate> as x;` — is rooted at the crate,
	// not at this module. This has to run before the relative root is expanded:
	// once `crate::ffi::EVP_sha512` becomes `boring::ffi::EVP_sha512` the alias
	// is no longer the first segment and never applies. The same shape written
	// as a `use` was already handled; written at the CALL SITE it was not.
	if crateRooted, ok := rustCrateAliasPath(analysis, prefix); ok {
		return &FunctionCall{
			Callee:    splitRustScopedCallee(analysis, crateRooted, name),
			Raw:       raw,
			FilePath:  filePath,
			Line:      line,
			Arguments: args,
		}
	}

	// Renaming imports are substituted next: the local name carries no
	// information about the real path, and the import maps below expand by
	// concatenation, which would keep the alias in the result.
	if resolved, ok := resolveRustAliasPrefix(analysis, prefix); ok {
		return &FunctionCall{
			Callee:    splitRustScopedCallee(analysis, resolved, name),
			Raw:       raw,
			FilePath:  filePath,
			Line:      line,
			Arguments: args,
		}
	}

	// A path rooted at `crate`, `self` or `super` addresses the module tree
	// from here; resolve it to an absolute module path before anything else
	// looks at its first segment.
	if absolute := rustAbsoluteModulePath(analysis, prefix); absolute != prefix {
		return &FunctionCall{
			Callee:    splitRustScopedCallee(analysis, absolute, name),
			Raw:       raw,
			FilePath:  filePath,
			Line:      line,
			Arguments: args,
		}
	}

	// Try to resolve through imports
	// Case 1: prefix is a single identifier that was imported (e.g., `Aead::new`)
	if pkg, ok := analysis.Imports[prefix]; ok {
		// A lowercase prefix here is a MODULE (`use std::ptr;` then
		// `ptr::null_mut()`), and it stays in the key's type field on purpose:
		// the contract KB keys module-level functions that way
		// (`sodiumoxide::crypto.secretbox.gen_key`, `ring.digest.digest`), so
		// moving it into the package segment would break every such contract.
		return &FunctionCall{
			Callee:    FunctionID{Package: pkg, Type: prefix, Name: name},
			Raw:       raw,
			FilePath:  filePath,
			Line:      line,
			Arguments: args,
		}
	}

	// Case 2: prefix contains "::" — it's a path rooted at an imported segment
	// (e.g. `use ring::digest;` then `digest::Context::new`). Imports map a leaf
	// to its parent path, so the aliased segment stays in the expanded path.
	firstSep := strings.Index(prefix, "::")
	if firstSep > 0 {
		firstSegment := prefix[:firstSep]
		if pkg, ok := analysis.Imports[firstSegment]; ok {
			return &FunctionCall{
				Callee:    splitRustScopedCallee(analysis, pkg+"::"+prefix, name),
				Raw:       raw,
				FilePath:  filePath,
				Line:      line,
				Arguments: args,
			}
		}
	}

	// A prefix that is itself a rename — from the manifest or from an
	// `extern crate` — resolves to the real crate before anything else reads
	// it as a module path.
	if resolved, ok := resolveRustAliasPrefix(analysis, prefix); ok && resolved != prefix {
		return &FunctionCall{
			Callee:    splitRustScopedCallee(analysis, resolved, name),
			Raw:       raw,
			FilePath:  filePath,
			Line:      line,
			Arguments: args,
		}
	}

	// A prefix that is neither a module path nor a type name is not an
	// identity: `<[u64; 8]>::default()` must not put "[u64; 8]" in the package
	// field.
	if rustModulePathText(prefix) == "" {
		return &FunctionCall{
			Callee:    FunctionID{Package: analysis.PackagePath, Name: name},
			Raw:       raw,
			FilePath:  filePath,
			Line:      line,
			Arguments: args,
		}
	}

	// Fallback: treat the prefix as an unaliased path.
	return &FunctionCall{
		Callee:    splitRustScopedCallee(analysis, prefix, name),
		Raw:       raw,
		FilePath:  filePath,
		Line:      line,
		Arguments: args,
	}
}

// rustGenericCallPrefix substitutes a generic parameter used as a call prefix
// with its trait bound.
//
// `W::from(8)` and `T::big_sigma_1(e)` name a GENERIC PARAMETER, not a type.
// The Reference resolves an associated item on a parameter through the BOUNDS on
// it, so the bound is the identity; the parameter's own letter is a name that
// exists nowhere. Left as a type name it fell through to the file's glob imports
// and was claimed by them: orion 0.17.7 src/hazardous/hash/sha2/mod.rs declares
// `W: Word` inside `pub(crate) mod sha2_core`, whose body writes
// `use core::ops::*;`, and 11 edges came out as `core::ops.(W).from | .default |
// .size_of | .from_be_bytes` — the standard library named as the owner of a type
// parameter.
//
// The second result is false for a parameter with no bound: there is no identity
// to substitute, and inventing one is what this exists to stop.
func rustGenericCallPrefix(prefix string, generics map[string]string) (string, bool) {
	bound, isGeneric := generics[prefix]
	switch {
	case !isGeneric:
		return prefix, true
	case bound == "":
		return "", false
	}
	return bound, true
}

// rustRenamedFunctionCallee resolves a bare call written through a renaming
// import: `use pbkdf2::pbkdf2 as kdf;` then `kdf(..)`.
//
// The alias table was consulted when the local name was used as a path PREFIX
// (`kdf::inner()`) and not when it was called directly, so the whole point of
// the rename was lost: `kdf(..)` came out as `<local module>.kdf`, a function
// that exists nowhere. It costs live contract keys -- `pbkdf2.pbkdf2` and
// `pbkdf2.pbkdf2_hmac` are both in the KB, and both were unreachable through
// the renamed spelling -- and renaming an imported function is how a consumer
// disambiguates two KDFs or two hash backends in one file.
//
// Only an alias whose target is a PATH ending in a lowercase segment is a
// renamed function. A single identifier is a crate rename, and an
// UpperCamelCase leaf is a type: calling either is a different construct, and
// keying it as a function would put a type or a crate where a function belongs.
func rustRenamedFunctionCallee(analysis *FileAnalysis, name string) (FunctionID, bool) {
	if analysis == nil {
		return FunctionID{}, false
	}
	target, ok := analysis.ImportAliases[name]
	if !ok || target == "" || target == name {
		return FunctionID{}, false
	}
	lastSep := strings.LastIndex(target, "::")
	if lastSep <= 0 {
		return FunctionID{}, false
	}
	pkg, fn := target[:lastSep], target[lastSep+2:]
	if fn == "" || pkg == "" || looksLikeRustTypeName(fn) {
		return FunctionID{}, false
	}
	return FunctionID{Package: pkg, Name: fn}, true
}

// rustBareTypePackage returns the package a type named without a path belongs
// to: this crate, unless a glob import gives it another home.
func rustBareTypePackage(analysis *FileAnalysis, typeName string) string {
	if analysis == nil {
		return ""
	}
	if _, imported := analysis.Imports[typeName]; imported {
		return analysis.PackagePath
	}
	// A type the crate declares itself wins over everything: a project's own
	// `Result` alias is its own. It belongs to the module that DECLARES it,
	// which is not the module a glob reached it from.
	if analysis.rustFacts.isLocalType(typeName) &&
		rustDeclaredTypeInScope(analysis, analysis.rustFacts, typeName) {
		return rustDeclaredTypePackage(analysis, analysis.rustFacts, typeName)
	}
	// A prelude type needs no import and is not the analyzed crate's.
	if rustPreludeTypes[typeName] {
		return rustPreludePackage
	}
	// A name spelled like a generic parameter is not an item of anything a glob
	// imported: `use aes::*;` beside `pub fn run<T: Maker>() { T::build() }`
	// produced `aes.(T).build`, fabricating a cryptographic crate as the owner
	// of a type parameter. Rust's own convention — and the compiler's
	// non_camel_case_types lint — makes a single upper-case letter, optionally
	// numbered, a parameter and never an imported type.
	if looksLikeRustTypeParameter(typeName) {
		return analysis.PackagePath
	}
	if wildcard, ok := rustWildcardPackage(analysis); ok {
		return wildcard
	}
	// An intra-crate glob names the module it points at; a name it supplies is
	// that module's, not the importing module's.
	if module, ok := rustIntraCrateWildcardModule(analysis); ok {
		return module
	}
	return analysis.PackagePath
}

// looksLikeRustTypeParameter reports whether a bare name is spelled like a
// generic parameter rather than like an imported type: one upper-case letter,
// optionally followed by digits (T, W, K, T1).
func looksLikeRustTypeParameter(name string) bool {
	if name == "" || name[0] < 'A' || name[0] > 'Z' {
		return false
	}
	for i := 1; i < len(name); i++ {
		if name[i] < '0' || name[i] > '9' {
			return false
		}
	}
	return true
}

// stripRustTypeArguments removes turbofish type arguments from a scoped path so
// the callee identity does not vary with them: "Key::<ChaCha20Poly1305>::generate"
// becomes "Key::generate". Nested arguments are skipped by depth. A ">" that
// closes a return arrow is not a closer, and an unbalanced path is returned
// unchanged rather than truncated: a mangled path becomes a wrong callee
// identity, which is worse than leaving the turbofish in place.
func stripRustTypeArguments(path string) string {
	if !strings.Contains(path, "::<") {
		return path
	}
	var b strings.Builder
	depth := 0
	for i := 0; i < len(path); i++ {
		if depth == 0 && strings.HasPrefix(path[i:], "::<") {
			depth = 1
			i += 2
			continue
		}
		if depth > 0 {
			switch path[i] {
			case '<':
				depth++
			case '>':
				// The ">" of a "->" closes nothing; it belongs to a fn-pointer
				// or closure return type inside the argument list.
				if i > 0 && path[i-1] == '-' {
					continue
				}
				depth--
			}
			continue
		}
		b.WriteByte(path[i])
	}
	if depth != 0 {
		return path
	}
	return b.String()
}

// splitRustScopedCallee turns a resolved `<module path>::<maybe Type>` prefix
// into a callee. Rust modules are snake_case by convention, so an upper-cased
// last segment is the receiver type of an associated function
// (`ring::digest::Context::new`) rather than another module segment. Anything
// else stays wholly in the package path (`ring::digest::digest`).
func splitRustScopedCallee(analysis *FileAnalysis, prefix, name string) FunctionID {
	// A path rooted at a module this file declares is local, whatever crate
	// shares that name.
	if local, ok := rustLocalModulePath(analysis, prefix); ok {
		prefix = local
	} else if undeclared, ok := rustUndeclaredCratePath(analysis, prefix); ok {
		// The manifest declares no such dependency, so the segment cannot name
		// a crate; the crate's own module of that name is what it means.
		prefix = undeclared
	}
	if lastTypeSep := strings.LastIndex(prefix, "::"); lastTypeSep > 0 {
		typeName := prefix[lastTypeSep+2:]
		if !looksLikeRustTypeName(typeName) {
			return FunctionID{Package: prefix, Name: name}
		}
		return rustScopedCalleeThroughType(analysis, prefix, typeName, lastTypeSep, name)
	}

	// A bare prefix that names a type belongs in the key's TYPE field, with a
	// package behind it. Putting it in the package field instead — which is
	// what an unresolved `Keygen::make()` used to produce — makes the key
	// unqueryable: nothing indexes a type as a package. 290 such edges in
	// openssl 0.10.81, 190 in russh 0.54.6.
	if prefix != "" && looksLikeRustTypeName(prefix) {
		return FunctionID{Package: rustBareTypePackage(analysis, prefix), Type: prefix, Name: name}
	}

	return FunctionID{Package: prefix, Name: name}
}

// rustScopedCalleeThroughType resolves `<owner>::<typeName>::name` once the
// segment before name is known to be type-cased: either typeName is the
// receiver of an associated function (`ring::digest::Context::new`), or
// `Type::AssocType::item` — the segment BEFORE typeName is also type-cased, so
// what would go in the package field is a type name, and modules are never
// spelled that way. In the latter case, the middle segment is an associated
// type whose identity is the implementing type's choice and is not statically
// known (Reference, Paths -> associated items): no identity is the answer, not
// a type name in the package field. `Self::Error::InvalidOperation(..)` in
// sequoia-openpgp 1.21.2 src/packet/unknown.rs:209 emitted
// `Unknown.(Error).InvalidOperation`, and `T::Ref::from_ptr(..)` in openssl
// 0.10.81 and boring 4.9.1 src/stack.rs emitted `T.(Ref).from_ptr` — 21 edges
// of source text where a resolved package belongs.
func rustScopedCalleeThroughType(analysis *FileAnalysis, prefix, typeName string, lastTypeSep int, name string) FunctionID {
	owner := prefix[:lastTypeSep]
	ownerSep := strings.LastIndex(owner, "::")
	ownerIsTypeCased := ownerSep < 0 && looksLikeRustTypeName(owner) ||
		ownerSep > 0 && looksLikeRustTypeName(owner[ownerSep+2:])
	if ownerIsTypeCased {
		return FunctionID{Package: analysis.PackagePath, Name: name}
	}
	// owner may itself only re-export typeName: `outer::MyCipher::new(..)`
	// where outer.rs writes `pub use aes::Aes128 as MyCipher;` is the aes
	// crate's constructor, not a method the outer module declares.
	if reExportPkg, reExportTyp, ok := rustModuleReExport(analysis, owner, typeName); ok {
		return FunctionID{Package: reExportPkg, Type: reExportTyp, Name: name}
	}
	return FunctionID{Package: owner, Type: typeName, Name: name}
}

func looksLikeRustTypeName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}

	first, _ := utf8.DecodeRuneInString(name)
	return unicode.IsUpper(first)
}

// parseFieldCall handles method calls like `obj.method()` or `self.method()`.
func (p *RustParser) parseFieldCall(node *sitter.Node, ctx *rustTypeCtx, filePath string, line int, args []string) *FunctionCall {
	src, analysis := ctx.src, ctx.analysis
	field := nodeFieldText(node, "field", src)
	if field == "" {
		return nil
	}
	raw := node.Content(src)
	receiver := node.ChildByFieldName("value")

	// Resolve the receiver's type from the expression itself rather than from
	// its source text, so a method on a temporary, a chain, an awaited value,
	// a field, an index or a wrapper resolves the same way a direct binding
	// does. `self` keeps the enclosing impl's type.
	typeText := ctx.rustSubstituteGeneric(ctx.rustExprType(receiver, 0))
	if typeText != "" {
		if pkg, typ := rustQualifyType(analysis, analysis.rustFacts, typeText); typ != "" {
			return &FunctionCall{
				Callee:    FunctionID{Package: pkg, Type: typ, Name: field},
				Raw:       raw,
				FilePath:  filePath,
				Line:      line,
				Arguments: args,
				// A RESOLVED receiver is exactly the one whose lifecycle is
				// worth recovering, and it was the only shape leaving this
				// field empty: deriveObjectLifecycleCalls walks up from the
				// terminal's ReceiverVar, so `cipher.encrypt(..)` without it
				// never reaches the `Aes256Gcm::new(..)` that produced cipher.
				ReceiverVar: rustReceiverVarIdentity(receiver, src),
			}
		}
	}

	// An unresolved receiver: the identity of the receiver's type is not
	// established, so emit the call without a type rather than falling back to
	// the receiver's variable name, which would be a wrong-but-valid key that
	// nothing downstream could tell apart from a real one.
	receiverVar := ""
	if receiver != nil && (receiver.Type() == goNodeIdentifier || receiver.Type() == rustNodeSelf) {
		receiverVar = receiver.Content(src)
	}
	// A receiver that names an imported type directly is an associated-function
	// call spelled with a dot; keep that identity.
	if receiverVar != "" {
		if pkg, ok := analysis.Imports[receiverVar]; ok && looksLikeRustTypeName(receiverVar) {
			return &FunctionCall{
				Callee:    FunctionID{Package: pkg, Type: receiverVar, Name: field},
				Raw:       raw,
				FilePath:  filePath,
				Line:      line,
				Arguments: args,
			}
		}
	}
	return &FunctionCall{
		Callee:      FunctionID{Package: analysis.PackagePath, Name: field},
		Raw:         raw,
		FilePath:    filePath,
		Line:        line,
		Arguments:   args,
		ReceiverVar: receiverVar,
	}
}

func (p *RustParser) extractRustCallArguments(node *sitter.Node, src []byte) []string {
	nodeChildren := int(node.ChildCount())
	for i := 0; i < nodeChildren; i++ {
		child := node.Child(i)
		if child.Type() == "arguments" {
			return parseArgumentsFromDelimitedContent(child.Content(src))
		}
	}
	return nil
}

// newRustTypeCtx builds the resolution context for one declaration: its
// generic parameters and their bounds, and a root binding scope holding its
// parameters. Nested scopes are opened by the walk itself.
func (p *RustParser) newRustTypeCtx(fn, paramsNode *sitter.Node, src []byte, analysis *FileAnalysis, selfType string, outerGenerics map[string]string) *rustTypeCtx {
	generics := make(map[string]string, len(outerGenerics))
	for name, bound := range outerGenerics {
		generics[name] = bound
	}
	collectRustGenerics(fn, src, generics)
	ctx := &rustTypeCtx{
		src:      src,
		analysis: analysis,
		facts:    analysis.rustFacts,
		selfType: selfType,
		bindings: newRustBindings(nil),
		generics: generics,
		parser:   p,
	}
	ctx.bindParameters(paramsNode)
	return ctx
}

func collectRustParameterTypes(node *sitter.Node, src []byte) map[string]string {
	if node == nil {
		return map[string]string{}
	}
	content := trimOuterParens(node.Content(src))
	if content == "" {
		return map[string]string{}
	}

	varTypes := make(map[string]string)
	for _, part := range splitTopLevelCommaList(content) {
		name, typ, isSelf := parseRustParameterBinding(part)
		if isSelf || name == "" || typ == "" {
			continue
		}
		varTypes[name] = typ
	}
	return varTypes
}

func parseRustParameterBinding(part string) (name, typ string, isSelf bool) {
	clean := strings.TrimSpace(part)
	if clean == "" {
		return "", "", false
	}
	if strings.Contains(clean, "self") {
		return "", "", true
	}
	idx := strings.Index(clean, ":")
	if idx <= 0 {
		return "", "", false
	}
	name = strings.TrimSpace(clean[:idx])
	name = strings.TrimPrefix(name, "mut ")
	name = strings.TrimPrefix(name, "ref ")
	name = strings.TrimPrefix(name, "&")
	name = strings.TrimSpace(name)
	typ = strings.TrimSpace(clean[idx+1:])
	return name, normalizeRustTypeText(typ), false
}

func inferRustTypeFromExpr(expr string) string {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return ""
	}
	if idx := strings.Index(expr, "."); idx >= 0 {
		expr = strings.TrimSpace(expr[:idx])
	}
	if idx := strings.Index(expr, "("); idx >= 0 {
		expr = strings.TrimSpace(expr[:idx])
	}
	// A turbofish on the constructor belongs to the type, not to the variable's
	// identity: "Blowfish::<LE>::new_from_slice" must yield "Blowfish", the same
	// as the non-turbofish spelling. Without this the trailing "::<LE>" survives
	// the split below and normalizeRustTypeText truncates it to "Blowfish::",
	// which no import resolves, so the receiver falls back to the local package
	// and every later call on that variable gets a wrong callee identity.
	expr = stripRustTypeArguments(expr)
	lastSep := strings.LastIndex(expr, "::")
	if lastSep <= 0 {
		return ""
	}
	return normalizeRustTypeText(expr[:lastSep])
}

func normalizeRustTypeText(typeText string) string {
	typeText = strings.TrimSpace(typeText)
	if typeText == "" {
		return ""
	}
	typeText = strings.TrimPrefix(typeText, "&")
	typeText = strings.TrimPrefix(typeText, "mut ")
	typeText = strings.TrimSpace(typeText)
	if strings.HasPrefix(typeText, "(") && strings.HasSuffix(typeText, ")") {
		typeText = strings.TrimSpace(typeText[1 : len(typeText)-1])
	}
	if idx := strings.Index(typeText, "<"); idx >= 0 {
		typeText = strings.TrimSpace(typeText[:idx])
	}
	// Truncating at "<" can leave the "::" that introduced a turbofish. A type
	// name ending in "::" resolves against no import, so trim it rather than
	// emitting a mangled receiver type.
	typeText = strings.TrimSuffix(strings.TrimSpace(typeText), "::")
	return strings.TrimSpace(typeText)
}

func splitQualifiedRustType(typeName string) (pkg, typ string, ok bool) {
	typeName = strings.TrimSpace(typeName)
	lastSep := strings.LastIndex(typeName, "::")
	if lastSep <= 0 || lastSep >= len(typeName)-2 {
		return "", "", false
	}
	return typeName[:lastSep], typeName[lastSep+2:], true
}

func resolveRustTypePackage(pkg string, analysis *FileAnalysis) string {
	if pkg == "" {
		return pkg
	}
	// A renamed import has to be substituted here as well as on the callee path.
	// Without this, `use cfb_mode as cfb;` resolved the constructor to
	// `cfb_mode::Encryptor.new` but every later call on the receiver to
	// `cfb.Encryptor.<method>`, leaving the alias in the package segment and
	// matching no contract.
	// A module this file declares shadows any alias of the same name.
	if local, ok := rustLocalModulePath(analysis, pkg); ok {
		return local
	}
	if crateRooted, ok := rustCrateAliasPath(analysis, pkg); ok {
		return crateRooted
	}
	pkg = rustAbsoluteModulePath(analysis, pkg)
	if local, ok := rustLocalModulePath(analysis, pkg); ok {
		return local
	}
	if resolved, ok := resolveRustAliasPrefix(analysis, pkg); ok {
		return resolved
	}
	if importedPkg, ok := analysis.Imports[pkg]; ok {
		// A MODULE keeps its own segment: `use super::{hmac, ..}` binds hmac to
		// its parent, and a `hmac::Tag` receiver belongs to
		// `<parent>::hmac`, not to the parent. Dropping the segment whenever
		// the parent path already contained "::" lost rustls's own
		// `crypto::hmac` module — and would have lost `ring::aead::quic` the
		// same way. A TYPE, by contrast, IS the leaf: its package is the path
		// that imported it.
		if rustIsTypeCase(pkg) {
			return importedPkg
		}
		return importedPkg + "::" + pkg
	}
	if undeclared, ok := rustUndeclaredCratePath(analysis, pkg); ok {
		return undeclared
	}
	if firstSep := strings.Index(pkg, "::"); firstSep > 0 {
		firstSegment := pkg[:firstSep]
		if importedPkg, ok := analysis.Imports[firstSegment]; ok {
			// The imported segment is part of the path, not a stand-in for it:
			// `use crate::crypto;` then `crypto::hmac::Tag` is
			// `rustls::crypto::hmac`, not `rustls::hmac`. Dropping it lost
			// rustls's own crypto::hmac module in five files.
			if rustIsTypeCase(firstSegment) {
				return importedPkg + "::" + pkg[firstSep+2:]
			}
			return importedPkg + "::" + pkg
		}
	}
	return pkg
}

func parseRustParameters(node *sitter.Node, src []byte) ([]FunctionParameter, bool) {
	if node == nil {
		return nil, false
	}
	content := trimOuterParens(node.Content(src))
	if content == "" {
		return nil, false
	}

	parts := splitTopLevelCommaList(content)
	params := make([]FunctionParameter, 0, len(parts))
	hasSelf := false
	for _, part := range parts {
		clean := strings.TrimSpace(part)
		if clean == "" {
			continue
		}
		if strings.Contains(clean, "self") {
			hasSelf = true
		}

		typ := ""
		if idx := strings.Index(clean, ":"); idx >= 0 {
			typ = strings.TrimSpace(clean[idx+1:])
		}
		params = append(params, FunctionParameter{Type: typ})
	}

	return params, hasSelf
}

func parseRustReturnType(funcContent string) string {
	header := funcContent
	if idx := strings.Index(header, "{"); idx >= 0 {
		header = header[:idx]
	}
	if idx := strings.Index(header, "->"); idx >= 0 {
		return strings.TrimSpace(header[idx+2:])
	}
	return ""
}

// resolveRustAliasPrefix substitutes a renaming import out of a call prefix.
// The alias may be the whole prefix (`CbcEnc::new` after
// `use cbc::Encryptor as CbcEnc;`) or only its first segment (`cfb::Encryptor::new`
// after `use cfb_mode as cfb;`); in both cases the alias is replaced by the path
// it denotes rather than prefixed onto it. Returns false when no alias applies,
// so the caller falls through to the ordinary import handling unchanged.
func resolveRustAliasPrefix(analysis *FileAnalysis, prefix string) (string, bool) {
	if analysis == nil || len(analysis.ImportAliases) == 0 || prefix == "" {
		return "", false
	}
	// Follow the alias chain: `type L3 = L2; type L2 = L1; type L1 = Aes128;`
	// means a call through L3 has aes::Aes128's identity. Resolving a single
	// hop left an intermediate alias as the identity, which matches nothing.
	current := prefix
	for hop := 0; hop < rustMaxTypeDepth; hop++ {
		realPath, ok := analysis.ImportAliases[current]
		if !ok || realPath == "" || realPath == current {
			break
		}
		if qualified, ok := qualifyRustBareType(analysis, realPath); ok {
			return qualified, true
		}
		current = realPath
	}
	if current != prefix {
		return current, true
	}
	firstSep := strings.Index(prefix, "::")
	if firstSep <= 0 {
		return "", false
	}
	if realPath, ok := analysis.ImportAliases[prefix[:firstSep]]; ok {
		return realPath + prefix[firstSep:], true
	}
	return "", false
}

// qualifyRustBareType resolves a bare type name to the path it was imported
// from. A local `type Aes256Ccm = Ccm<Aes256, U10, U13>;` records `Ccm` as its
// target because that is the spelling ccm's own documentation uses, and a bare
// name carries no package: left unqualified it becomes the callee's package
// with no type at all (`Ccm.new`), which matches no contract. Resolution
// happens here rather than when the alias is recorded so it does not depend on
// `use` statements being parsed before the alias. A target naming a type this
// crate declares is not in the import map and is returned unchanged, which is
// what such an alias means.
//
// The alias map also holds renaming imports, whose target is already a real
// path: `use aes as blk;` records `blk -> aes`. Qualifying that would rewrite
// a crate root into whatever an import happens to map the same name to, so the
// target must look like a type before it is touched. Crate and module names are
// snake_case, type names are not, which is the distinction this leans on.
func qualifyRustBareType(analysis *FileAnalysis, name string) (string, bool) {
	if analysis == nil || name == "" || strings.Contains(name, "::") {
		return "", false
	}
	if !looksLikeRustTypeName(name) {
		return "", false
	}
	pkg, ok := analysis.Imports[name]
	if !ok || pkg == "" {
		return "", false
	}
	return pkg + "::" + name, true
}

// resolveRustReceiverType turns a receiver variable's recorded type into the
// package and type of its callee identity. The recorded text may already be
// qualified, may be a plain imported name, or may be a renaming import that
// names no real path on its own. When none of those apply the type stays local
// to the crate being analyzed, which is the correct answer for a type declared
// in this source.
func resolveRustReceiverType(analysis *FileAnalysis, inferredType string) (pkg, typ string) {
	if qualifiedPkg, qualifiedType, ok := splitQualifiedRustType(inferredType); ok {
		return resolveRustTypePackage(qualifiedPkg, analysis), qualifiedType
	}
	// A type this module declares wins over an import of the same name: the two
	// can only coexist in different namespaces, and the type namespace is the
	// declaration's.
	if module, ok := rustModuleDeclaredTypePackage(analysis, inferredType); ok {
		return module, inferredType
	}
	if pkg, typ, ok := resolveRustReceiverTypeViaImport(analysis, inferredType); ok {
		return pkg, typ
	}
	// An alias chain that advances without reaching a definitive answer still
	// resolves against its own last hop, not the original inferredType:
	// `type A2 = A1;` with A1 itself unresolvable means the prelude/
	// local-package fallback below is about A1, not A2.
	resolvedPkg, lastHop, definitive := resolveRustReceiverTypeViaAliasChain(analysis, inferredType)
	if definitive {
		return resolvedPkg, lastHop
	}
	// A prelude type inferred from a constructor's return (`let v = Vec::from(p);`)
	// is in scope everywhere without an import, same as one written in an
	// annotation, and belongs to the standard library rather than this crate.
	if rustPreludeTypes[lastHop] {
		return rustPreludePackage, lastHop
	}
	return analysis.PackagePath, lastHop
}

// resolveRustReceiverTypeViaImport resolves inferredType through a direct
// import naming it, if one exists.
func resolveRustReceiverTypeViaImport(analysis *FileAnalysis, inferredType string) (pkg, typ string, ok bool) {
	importedPkg, isImported := analysis.Imports[inferredType]
	if !isImported {
		return "", "", false
	}
	// The import's package may itself name no crate: russh writes
	// `use cipher::SealingKey;` for its own trait and declares no `cipher`
	// dependency.
	if undeclared, ok := rustUndeclaredCratePath(analysis, importedPkg); ok {
		return undeclared, inferredType, true
	}
	// The imported name may itself be a re-export: `use outer::MyCipher;`
	// where outer.rs writes `pub use aes::Aes128 as MyCipher;` means the
	// aes crate's identity, not outer's own path.
	if reExportPkg, reExportTyp, ok := rustModuleReExport(analysis, importedPkg, inferredType); ok {
		return reExportPkg, reExportTyp, true
	}
	return importedPkg, inferredType, true
}

// resolveRustReceiverTypeViaAliasChain follows a chain of local type aliases
// to a definitive answer. Alias chains resolve transitively: `type A2 = A1;
// type A1 = Aes128;` means a call through A2 has aes::Aes128's identity.
// Following only one link left the intermediate alias as the identity, which
// matches nothing. When no definitive answer is reached, lastHop is the
// chain's final name (inferredType itself, if there was no alias at all) for
// the caller's own prelude/local-package fallback.
func resolveRustReceiverTypeViaAliasChain(analysis *FileAnalysis, inferredType string) (pkg, lastHop string, ok bool) {
	current := inferredType
	for hop := 0; hop < rustMaxTypeDepth; hop++ {
		realPath, hasAlias := analysis.ImportAliases[current]
		if !hasAlias || realPath == "" {
			return "", current, false
		}
		if qualified, ok := qualifyRustBareType(analysis, realPath); ok {
			realPath = qualified
		}
		if aliasPkg, aliasType, ok := splitQualifiedRustType(realPath); ok {
			return aliasPkg, aliasType, true
		}
		if importedPkg, ok := analysis.Imports[realPath]; ok {
			return importedPkg, realPath, true
		}
		if realPath == current {
			return "", current, false
		}
		current = realPath
	}
	return "", current, false
}

// recordRustTypeAlias records a local `type X = a::b::C<..>;` so a call written
// through X resolves to what X actually names. This is the form the block-mode
// crates' own documentation teaches:
//
//	type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
//	let enc = Aes128CbcEnc::new(&key.into(), &iv.into());
//
// Without it, `Aes128CbcEnc::new` kept the local name as its identity and
// matched no contract, so the documented idiom produced a detection with no
// reachability behind it. Type arguments are dropped: the alias's identity is
// the path, and the concrete cipher is a generic argument the callee identity
// does not carry. Aliases naming a bare local type are recorded too and simply
// resolve to that local name, which is what they mean.
func (p *RustParser) recordRustTypeAlias(node *sitter.Node, src []byte, analysis *FileAnalysis) {
	// Read the alias and its target from the grammar's own fields. Scanning
	// children by kind made a bare target unreachable: in `type A2 = A1;` both
	// sides are `type_identifier`, so the first match filled the alias and the
	// target was dropped — the case the function's own doc comment claims to
	// handle.
	alias := nodeFieldText(node, "name", src)
	target := ""
	if targetNode := node.ChildByFieldName("type"); targetNode != nil {
		target = normalizeRustTypeText(stripRustTypeArguments(rustScopedTypeText(targetNode, src)))
		// `type Test = super::LimitedCache<..>;` names a type in the parent
		// module; left relative, the alias put "super" in the package field.
		target = rustResolveImportPath(analysis, target)
	}
	if alias == "" || target == "" || alias == target {
		return
	}
	// An alias to a shape that is not a nameable path — `type State = [u64; 8];`
	// in aes 0.8.4 — has no identity to forward to, and recording it put the
	// array's text in the package field of every call through the alias. The
	// alias stays local, which is what it means.
	if rustModulePathText(target) == "" {
		return
	}
	// A renaming import already in scope wins: it was written explicitly.
	if _, exists := analysis.ImportAliases[alias]; exists {
		return
	}
	analysis.ImportAliases[alias] = target
}
