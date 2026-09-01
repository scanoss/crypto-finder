// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/rust"

	"github.com/pelletier/go-toml/v2"
)

// Cargo lets a manifest bind a dependency to a DIFFERENT name than the crate it
// resolves to:
//
//	[dependencies.ffi]
//	version = "0.9.117"
//	package = "openssl-sys"
//
// Code then writes `ffi::EVP_sha256(..)`, and the identity of that call is
// openssl_sys — not "ffi", which names no crate anywhere. openssl 0.10.81 does
// exactly this, and it accounted for 1108 of its call edges: every one of them
// emitted a package no contract can match, silently.
//
// The rename is also how a crate depends on two major versions of the same
// library at once (`aes_v1`/`aes_v2`), which is common through a RustCrypto
// transition, and how a fork is dropped in under the upstream name.
//
// Renames are read from the crate's own manifest. Renames declared in a
// workspace's `[workspace.dependencies]` and inherited with
// `dep = { workspace = true }` are read from the workspace root manifest, found
// by walking up from the crate directory.

// rustCrateDependencies returns the names a crate declares as dependencies, as
// the identifiers code writes for them.
//
// This is the evidence that settles whether a path's first segment names a
// crate at all: russh writes `use cipher::SealingKey;` for its OWN
// `pub(crate) trait SealingKey`, and russh declares no `cipher` dependency —
// so `cipher`, a real crates.io name, could never be the answer. Without the
// manifest to check against, the segment was emitted as the package.
func rustCrateDependencies(manifestPath string) map[string]bool {
	doc := readRustManifest(manifestPath)
	if doc == nil {
		return nil
	}
	deps := make(map[string]bool)
	collectRustDependencyNames(doc, deps)
	if workspace := rustWorkspaceManifest(manifestPath); workspace != "" && workspace != manifestPath {
		if wsDoc := readRustManifest(workspace); wsDoc != nil {
			if table, ok := wsDoc["workspace"].(map[string]any); ok {
				collectRustDependencyNames(table, deps)
			}
		}
	}
	return deps
}

// collectRustDependencyNames records every dependency name a manifest document
// declares, under the identifier code uses: the table key, and the real crate
// when the key renames it.
func collectRustDependencyNames(doc map[string]any, deps map[string]bool) {
	for _, table := range rustDependencyTables {
		recordRustDependencyNames(doc[table], deps)
	}
	// `[target.'cfg(windows)'.dependencies]` declares real dependencies too.
	targets, ok := doc["target"].(map[string]any)
	if !ok {
		return
	}
	for _, spec := range targets {
		specTable, ok := spec.(map[string]any)
		if !ok {
			continue
		}
		for _, table := range rustDependencyTables {
			recordRustDependencyNames(specTable[table], deps)
		}
	}
}

// recordRustDependencyNames records one dependency table's names, under the
// identifier code uses: the table key, and the real crate when it renames one.
func recordRustDependencyNames(table any, deps map[string]bool) {
	entries, ok := table.(map[string]any)
	if !ok {
		return
	}
	for name, spec := range entries {
		deps[rustCrateIdentifier(name)] = true
		specTable, ok := spec.(map[string]any)
		if !ok {
			continue
		}
		if declared, ok := specTable["package"].(string); ok {
			deps[rustCrateIdentifier(declared)] = true
		}
	}
}

// crateDependencies returns the dependency names visible to a file, memoized
// per manifest.
func (p *RustParser) crateDependencies(filePath string) map[string]bool {
	manifest := rustCrateManifestPath(filePath)
	if manifest == "" {
		return nil
	}
	if cached, ok := p.dependencyCache[manifest]; ok {
		return cached
	}
	deps := rustCrateDependencies(manifest)
	if p.dependencyCache == nil {
		p.dependencyCache = make(map[string]map[string]bool)
	}
	p.dependencyCache[manifest] = deps
	return deps
}

// crateEdition returns the Rust edition a file's crate declares, memoized per
// manifest. Cargo's default when a manifest declares no edition is 2015, and
// the difference matters: in edition 2015 a `use` path resolves from the crate
// root, so `use des::*;` inside `mod des` names the crate's OWN root module and
// says nothing about any dependency.
func (p *RustParser) crateEdition(filePath string) string {
	manifest := rustCrateManifestPath(filePath)
	if manifest == "" {
		return rustDefaultEdition
	}
	if cached, ok := p.editionCache[manifest]; ok {
		return cached
	}
	edition := rustCrateEdition(manifest)
	if p.editionCache == nil {
		p.editionCache = make(map[string]string)
	}
	p.editionCache[manifest] = edition
	return edition
}

// rustDefaultEdition is what cargo assumes when `[package] edition` is absent.
const rustDefaultEdition = "2015"

// rustCrateEdition reads `[package] edition`, following the
// `edition.workspace = true` inheritance form to `[workspace.package] edition`.
func rustCrateEdition(manifestPath string) string {
	doc := readRustManifest(manifestPath)
	if doc == nil {
		return rustDefaultEdition
	}
	pkg, ok := doc["package"].(map[string]any)
	if !ok {
		return rustDefaultEdition
	}
	switch edition := pkg["edition"].(type) {
	case string:
		return edition
	case map[string]any:
		if inherit, ok := edition["workspace"].(bool); !ok || !inherit {
			return rustDefaultEdition
		}
	default:
		return rustDefaultEdition
	}
	workspace := rustWorkspaceManifest(manifestPath)
	if workspace == "" {
		return rustDefaultEdition
	}
	wsDoc := readRustManifest(workspace)
	if wsDoc == nil {
		return rustDefaultEdition
	}
	table, ok := wsDoc["workspace"].(map[string]any)
	if !ok {
		return rustDefaultEdition
	}
	wsPkg, ok := table["package"].(map[string]any)
	if !ok {
		return rustDefaultEdition
	}
	if edition, ok := wsPkg["edition"].(string); ok {
		return edition
	}
	return rustDefaultEdition
}

// rustDependencyTables are the manifest tables whose keys are dependency names.
var rustDependencyTables = []string{"dependencies", "dev-dependencies", "build-dependencies"}

// rustManifestRenames returns the dependency renames a crate's manifest
// declares, as the name used in source code mapped to the real crate's Rust
// identifier. Both are normalized to identifiers, because a manifest names
// crates with dashes while code always spells them with underscores.
func rustManifestRenames(manifestPath string) map[string]string {
	doc := readRustManifest(manifestPath)
	if doc == nil {
		return nil
	}
	renames := make(map[string]string)
	collectRustRenames(doc, renames)
	// A member crate can inherit a renamed dependency from its workspace with
	// `dep = { workspace = true }`, which leaves the rename in the workspace
	// root's manifest rather than the member's.
	for alias, target := range rustWorkspaceRenames(manifestPath) {
		// The member's OWN manifest wins. Letting the workspace overwrite it
		// meant a member declaring `ali = { package = "log" }` was resolved as
		// the workspace's `ali = { package = "libc" }` — a misattribution to a
		// real, different crate, the worst answer a crypto KB can be given.
		if _, declared := renames[alias]; !declared {
			renames[alias] = target
		}
	}
	if len(renames) == 0 {
		return nil
	}
	return renames
}

// rustWorkspaceRenames returns the renames a workspace root declares for its
// members to inherit.
func rustWorkspaceRenames(manifestPath string) map[string]string {
	workspace := rustWorkspaceManifest(manifestPath)
	if workspace == "" || workspace == manifestPath {
		return nil
	}
	doc := readRustManifest(workspace)
	if doc == nil {
		return nil
	}
	table, ok := doc["workspace"].(map[string]any)
	if !ok {
		return nil
	}
	inherited := make(map[string]string)
	collectRustRenames(table, inherited)
	return inherited
}

func readRustManifest(manifestPath string) map[string]any {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil
	}
	var doc map[string]any
	if err := toml.Unmarshal(data, &doc); err != nil {
		return nil
	}
	return doc
}

// collectRustRenames reads every dependency table in a manifest document,
// including the target-specific ones, recording each `package = ` rename.
func collectRustRenames(doc map[string]any, renames map[string]string) {
	for _, table := range rustDependencyTables {
		collectRustRenamesFromTable(doc[table], renames)
	}
	// `[target.'cfg(windows)'.dependencies]` holds the platform-gated
	// dependencies, and a rename there is no less real.
	targets, ok := doc["target"].(map[string]any)
	if !ok {
		return
	}
	for _, spec := range targets {
		specTable, ok := spec.(map[string]any)
		if !ok {
			continue
		}
		for _, table := range rustDependencyTables {
			collectRustRenamesFromTable(specTable[table], renames)
		}
	}
}

func collectRustRenamesFromTable(table any, renames map[string]string) {
	deps, ok := table.(map[string]any)
	if !ok {
		return
	}
	for name, spec := range deps {
		specTable, ok := spec.(map[string]any)
		if !ok {
			// `foo = "1.0"` — a plain version requirement, no rename.
			continue
		}
		declared, ok := specTable["package"].(string)
		if !ok || declared == "" {
			continue
		}
		alias := rustCrateIdentifier(name)
		target := rustCrateIdentifier(declared)
		if alias == "" || target == "" || alias == target {
			continue
		}
		renames[alias] = target
	}
}

// rustWorkspaceManifest walks up from a crate manifest to the nearest manifest
// declaring a `[workspace]`, which is where an inherited rename is written.
func rustWorkspaceManifest(manifestPath string) string {
	dir := filepath.Dir(manifestPath)
	for depth := 0; depth < 12; depth++ {
		parent := filepath.Dir(dir)
		if parent == dir || parent == "" {
			return ""
		}
		dir = parent
		candidate := filepath.Join(dir, "Cargo.toml")
		doc := readRustManifest(candidate)
		if doc == nil {
			continue
		}
		if _, ok := doc["workspace"]; ok {
			return candidate
		}
	}
	return ""
}

// rustCrateIdentifier turns a manifest crate name into the identifier code uses
// for it: cargo accepts dashes, Rust paths never contain them.
func rustCrateIdentifier(name string) string {
	return strings.ReplaceAll(strings.TrimSpace(name), "-", "_")
}

// crateManifestRenames returns the manifest renames visible to a source file,
// memoized per manifest so a crate's Cargo.toml is read once per parser
// instance rather than once per file.
func (p *RustParser) crateManifestRenames(filePath string) map[string]string {
	manifest := rustCrateManifestPath(filePath)
	if manifest == "" {
		return nil
	}
	if cached, ok := p.manifestRenameCache[manifest]; ok {
		return cached
	}
	renames := rustManifestRenames(manifest)
	if p.manifestRenameCache == nil {
		p.manifestRenameCache = make(map[string]map[string]string)
	}
	p.manifestRenameCache[manifest] = renames
	return renames
}

// rustCrateManifestPath finds the Cargo.toml governing a source file.
func rustCrateManifestPath(filePath string) string {
	dir := filepath.Dir(filePath)
	for depth := 0; depth < 12 && dir != "" && dir != string(filepath.Separator); depth++ {
		candidate := filepath.Join(dir, "Cargo.toml")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// rustCrateIndex is the crate-wide declaration index, shared by every parser
// instance a build clones, so a crate's sources are indexed once for the whole
// run rather than once per worker.
//
// It exists because the import model is per file while Rust's truth is
// per crate: `src/factory.rs` declaring `pub fn make() -> Aes128` is what types
// the receiver of `let c = make(); c.encrypt_block(..)` in `src/consumer.rs`.
// Without it that receiver stayed unresolved, which loses the finding.
type rustCrateIndex struct {
	mu     sync.Mutex
	crates map[string]*rustFileFacts
	// aliasesByDir maps a directory to the crate re-export aliases the files in
	// it declare: `pub(crate) use ring as ring_like;` in
	// src/crypto/ring/mod.rs, reached as `use super::ring_like::aead;` from
	// src/crypto/ring/tls12.rs.
	//
	// Keyed by DIRECTORY, not by crate, because the alias belongs to a module.
	// rustls declares `ring_like` twice — once for ring and once for aws-lc-rs,
	// one per backend directory — so a crate-wide table has to call it
	// ambiguous and drop both, losing the whole backend surface. The directory
	// is what distinguishes them.
	aliasesByDir map[string]map[string]string
	// builds counts how many times a crate's sources were walked. Indexing is
	// the single most expensive thing this parser does — it reads every file of
	// the crate once more — so the property that it happens ONCE per crate for
	// a whole build, across every cloned worker, is worth asserting rather than
	// assuming.
	builds int
}

func newRustCrateIndex() *rustCrateIndex {
	return &rustCrateIndex{
		crates:       make(map[string]*rustFileFacts),
		aliasesByDir: make(map[string]map[string]string),
	}
}

// crateAliasFor resolves a crate re-export alias visible to a file, searching
// its own directory and then the directories above it.
//
// No filesystem work happens here: this is called once per import path being
// resolved, and stat-ing up the tree to find the crate root on each call — under
// the index's lock — made parsing a mid-sized crate take minutes. The walk is
// bounded instead, and a directory with no aliases simply misses.
func (index *rustCrateIndex) crateAliasFor(filePath, alias string) (string, bool) {
	if index == nil || filePath == "" || alias == "" {
		return "", false
	}
	index.mu.Lock()
	defer index.mu.Unlock()
	if len(index.aliasesByDir) == 0 {
		return "", false
	}
	dir := filepath.Dir(filePath)
	for depth := 0; depth < 12; depth++ {
		if crate, ok := index.aliasesByDir[dir][alias]; ok && crate != "" {
			return crate, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", false
}

// factsFor returns the declaration index for the crate a file belongs to,
// building it on first use. A file outside any crate gets nil, and every
// accessor tolerates that.
func (index *rustCrateIndex) factsFor(parser *RustParser, filePath string) *rustFileFacts {
	if index == nil {
		return nil
	}
	root := rustCrateSourceRoot(filePath)
	if root == "" {
		return nil
	}
	index.mu.Lock()
	defer index.mu.Unlock()
	if facts, ok := index.crates[root]; ok {
		return facts
	}
	// Record the entry before building so a crate whose walk fails is not
	// retried for every one of its files.
	index.crates[root] = nil
	facts := index.indexCrateSources(parser, root)
	index.crates[root] = facts
	index.builds++
	return facts
}

// buildCount reports how many crate indexes were built.
func (index *rustCrateIndex) buildCount() int {
	if index == nil {
		return 0
	}
	index.mu.Lock()
	defer index.mu.Unlock()
	return index.builds
}

// rustCrateSourceRoot returns the directory whose subtree holds a crate's
// sources: the `src` beside its Cargo.toml, or the manifest directory itself.
func rustCrateSourceRoot(filePath string) string {
	manifest := rustCrateManifestPath(filePath)
	if manifest == "" {
		return ""
	}
	dir := filepath.Dir(manifest)
	if info, err := os.Stat(filepath.Join(dir, "src")); err == nil && info.IsDir() {
		return filepath.Join(dir, "src")
	}
	return dir
}

// indexCrateSources parses every source file under a crate root once and folds
// their declarations into one index, dropping any name two files declare
// differently. An ambiguous crate-wide answer would name one algorithm where
// another is used, so it is deliberately reduced to no answer.
func (index *rustCrateIndex) indexCrateSources(p *RustParser, root string) *rustFileFacts {
	merged := newRustFileFacts()
	crateName := rustCrateNameForRoot(root)
	// A DEDICATED parser, not p.parser. The index is built from inside
	// parseFile, whose own tree is still open on p.parser, and a tree-sitter
	// parser is not reentrant: reusing it blocked the parse indefinitely — a
	// mid-sized crate went from half a second to never finishing.
	files := p.crateSourceFiles(root)
	if len(files) == 0 {
		// No index at all, rather than an EMPTY one. Callers read a non-nil
		// fallback as "the crate's declarations are visible from here", and an
		// empty index answers "declared nowhere" for every name — which would
		// let a glob claim a name the crate declares itself, the one failure
		// mode that invents a finding. crateSourceFiles returns nothing when
		// the file cap is exceeded, so this is the abandonment path.
		return nil
	}
	indexParser := sitter.NewParser()
	indexParser.SetLanguage(rust.GetLanguage())
	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		tree, err := indexParser.ParseCtx(context.TODO(), nil, src)
		if err != nil {
			continue
		}
		modulePath := p.rustIndexPackagePath(root, crateName, path)
		facts := collectRustFileFacts(tree.RootNode(), src, modulePath, p.crateEdition(path), p.crateDependencies(path), p.includeTests)
		index.recordDirAliasesLocked(filepath.Dir(path), facts.crateAliases)
		// A recorded type is only meaningful with the imports of the file that
		// declared it: `-> Aes128` in one file means `aes::Aes128`, and a
		// consumer file that does not import Aes128 would otherwise read the
		// bare name as one of its own types. Qualify before merging, and pass
		// the file's own module path: a `use crate::ssl::Ctx;` is only absolute
		// relative to where the file sits.
		p.qualifyCrateFacts(facts, tree.RootNode(), src, modulePath)
		merged.mergeCrateFacts(facts)
		tree.Close()
	}
	resolveRustReExportChains(merged)
	return merged
}

// resolveRustReExportChains follows each re-export to whatever it ultimately
// names, once every file in the crate has contributed its own. A crate's
// public type commonly aliases its way through two or three modules before
// reaching the crate that implements it -- `pub use crate::inner::Cipher as
// MyCipher;` in one module and `pub use aes::Aes128 as Cipher;` in the module
// it names -- and only chasing the second from the first's target gives
// MyCipher the aes::Aes128 identity a contract keys on, rather than the
// intermediate module's own path.
func resolveRustReExportChains(facts *rustFileFacts) {
	const maxHops = 8
	for key, target := range facts.reExports {
		pkg, typ := target.pkg, target.typ
		seen := map[string]bool{key: true}
		for hop := 0; hop < maxHops; hop++ {
			nextKey := rustQualifyFactKey(pkg, typ)
			next, ok := facts.reExports[nextKey]
			if !ok || seen[nextKey] {
				// Missing, or a cycle: leave the chain where it stands rather
				// than loop or guess past what the crate actually declares.
				break
			}
			seen[nextKey] = true
			pkg, typ = next.pkg, next.typ
		}
		facts.reExports[key] = rustReExportTarget{pkg: pkg, typ: typ}
	}
}

// recordDirAliasesLocked stores one file's crate re-export aliases under its
// directory. Two files in one directory declaring the same alias differently is
// genuinely ambiguous and drops it; two directories declaring it are not.
//
// THE CALLER HOLDS index.mu. This runs inside the one-time index build, which
// is performed under the lock; taking it again here deadlocked every parse of a
// crate that has any such alias.
func (index *rustCrateIndex) recordDirAliasesLocked(dir string, aliases map[string]string) {
	if len(aliases) == 0 {
		return
	}
	existing := index.aliasesByDir[dir]
	if existing == nil {
		existing = make(map[string]string, len(aliases))
		index.aliasesByDir[dir] = existing
	}
	for alias, crate := range aliases {
		if had, seen := existing[alias]; seen && had != crate {
			existing[alias] = ""
			continue
		}
		if _, dropped := existing[alias]; !dropped || existing[alias] != "" {
			existing[alias] = crate
		}
	}
}

// rustCrateNameForRoot reads the crate's own name from the manifest above a
// source root, so the index can record declarations under the module path the
// resolver will look them up by.
func rustCrateNameForRoot(root string) string {
	manifest := rustCrateManifestPath(filepath.Join(root, "x.rs"))
	if manifest == "" {
		return ""
	}
	doc := readRustManifest(manifest)
	if doc == nil {
		return ""
	}
	pkg, ok := doc["package"].(map[string]any)
	if !ok {
		return ""
	}
	name, isString := pkg["name"].(string)
	if !isString {
		return ""
	}
	return name
}

// rustIndexPackagePath returns the module path a file sits at, so a type the
// index records carries an ABSOLUTE path.
//
// Recording it relative left the consuming file re-resolving a bare segment in
// its own scope, where nothing binds it, and the segment became the package:
// `cipher.(SealingKey).write` in russh, `types.(Timestamp).into` in
// sequoia-openpgp, `errors.(Result).expect` in rsa — roughly 490 edges naming
// modules as if they were crates, and `cipher`, `key` and `signature` are all
// real crates.io names.
func (p *RustParser) rustIndexPackagePath(root, crateName, filePath string) string {
	if crateName == "" {
		return ""
	}
	relative, err := filepath.Rel(root, filePath)
	if err != nil {
		return crateName
	}
	segments := []string{crateName}
	dir := filepath.Dir(relative)
	if dir != "." {
		for _, part := range strings.Split(dir, string(filepath.Separator)) {
			if part != "" {
				segments = append(segments, part)
			}
		}
	}
	path := strings.Join(segments, "::")
	return rustFileModulePath(path, filepath.Base(filePath), p.rustGlobReExportedModules(filepath.Dir(filePath)))
}

// crateSourceFiles lists a crate's Rust sources, skipping the directories the
// parser skips everywhere else and stopping at the file limit.
func (p *RustParser) crateSourceFiles(root string) []string {
	skip := p.SkipDirs()
	var paths []string
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable directory is not a reason to abandon the crate; the
			// index is best effort and the per-file facts still apply.
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if path != root && skip[entry.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) == ".rs" {
			paths = append(paths, path)
			// Past the cap the whole index is abandoned rather than half
			// built, so stop walking. A PARTIAL index is worse than none: its
			// conflict detection sees only the files it read, so a name two
			// files declare differently looks unambiguous when the second
			// declaration falls past the cap, and resolves to whichever was
			// seen. That is a wrong identity produced by a size threshold.
			if len(paths) > rustCrateIndexFileLimit {
				return fs.SkipAll
			}
		}
		return nil
	})
	if walkErr != nil || len(paths) > rustCrateIndexFileLimit {
		return nil
	}
	return paths
}

// qualifyCrateFacts rewrites a file's recorded type texts into paths that mean
// the same thing anywhere in the crate, using that file's own imports.
//
// modulePath is where the declaring file sits in the module tree, and it is
// load-bearing: a `crate::`, `self::` or `super::` root is defined against the
// file's own position, and resolving one with no position at all silently
// dropped the root. usetree's holder.rs writes `use crate::ssl::{Ctx};` and
// declares `fn ctx(&mut self) -> &mut Ctx`, so the recorded return type came
// out as `ssl::Ctx` -- and `ssl` names no crate. Inside holder.rs the same call
// resolved to `usetree::ssl.(Ctx)`, so one declaration answered two ways
// depending on which file asked.
func (p *RustParser) qualifyCrateFacts(facts *rustFileFacts, root *sitter.Node, src []byte, modulePath string) {
	staging := &FileAnalysis{
		PackagePath:   modulePath,
		Imports:       make(map[string]string),
		ImportAliases: make(map[string]string),
	}
	p.collectRustAllImports(root, src, staging)
	for name, ret := range facts.fnReturns {
		facts.fnReturns[name] = rustQualifyFactType(staging, ret)
	}
	for _, fields := range facts.structFields {
		for field, typeText := range fields {
			fields[field] = rustQualifyFactType(staging, typeText)
		}
	}
	for key, target := range facts.reExports {
		facts.reExports[key] = rustReExportTarget{
			pkg: resolveRustTypePackage(target.pkg, staging),
			typ: target.typ,
		}
	}
}

// rustQualifyFactType expands a bare type name into the path its declaring file
// imports it from, leaving everything else alone.
func rustQualifyFactType(analysis *FileAnalysis, typeText string) string {
	// The OUTERMOST name is examined first, because it is the one a path on the
	// text belongs to. Looking only through the wrapper made a qualified outer
	// name look unqualified: `signature::Result<Signature>` unwraps to
	// `Signature`, whose head is bare, so the bare branch below fired and
	// rewrote `Result` INSIDE the outer path, producing
	// `signature::rsa::Result<Signature>` — rsa 0.9.6 src/pkcs1v15.rs:697 and
	// src/pss.rs:568,587, three edges keyed `signature::rsa.(Result).expect`, a
	// crate name concatenated with a foreign module. rsa's own
	// `-> signature::Result<..>` is correct and its 18 sibling
	// `signature.(Result).*` edges prove it.
	if outerPath, outerHead := rustOuterTypeIdentity(typeText); outerPath != "" {
		resolved := resolveRustTypePackage(outerPath, analysis)
		if resolved != "" && resolved != outerPath {
			return strings.Replace(typeText, outerPath+"::"+outerHead, resolved+"::"+outerHead, 1)
		}
		return typeText
	}
	// Called before the crate-wide facts merge completes, so no
	// derefTransparent evidence from sibling files is available yet here —
	// this qualifies against the hardcoded wrapper table only.
	head := rustTypeHead(rustUnwrapAnyWrapperType(typeText, nil))
	if head == "" {
		return typeText
	}
	// A type written with a path is only meaningful with the declaring file's
	// imports too: `-> hmac::Tag` in a file that wrote `use super::{hmac, ..}`
	// means `rustls::crypto::hmac::Tag`. Recording the path as written left
	// consumers in other files resolving `hmac` against their own scope, where
	// it means nothing — five edges in rustls 0.23.20 named a package that is
	// also a real crate.
	if path := rustTypePathText(typeText); path != "" {
		resolved := resolveRustTypePackage(path, analysis)
		if resolved != "" && resolved != path {
			return strings.Replace(typeText, path+"::"+head, resolved+"::"+head, 1)
		}
		return typeText
	}
	pkg, ok := analysis.Imports[head]
	if !ok || pkg == "" {
		return typeText
	}
	return rustReplaceTypeHead(typeText, head, pkg+"::"+head)
}

// rustOuterTypeIdentity splits the path off the OUTERMOST name of some type
// text, ignoring anything inside its generic arguments: for
// `signature::Result<Signature>` it returns ("signature", "Result"), and for
// `Result<hmac::Tag, E>` it returns ("", "") because the outer name carries no
// path of its own.
func rustOuterTypeIdentity(typeText string) (path, head string) {
	base := rustStripLifetimes(strings.TrimSpace(typeText))
	if idx := strings.Index(base, "<"); idx >= 0 {
		base = strings.TrimSpace(base[:idx])
	}
	lastSep := strings.LastIndex(base, "::")
	if lastSep <= 0 {
		return "", ""
	}
	prefix := rustModulePathText(base[:lastSep])
	if prefix == "" {
		return "", ""
	}
	return prefix, base[lastSep+2:]
}

// rustCrateIndexFileLimit bounds the crate index so a pathological tree cannot
// turn one scan into an unbounded one. Crates far larger than this are rare, and
// the per-file facts still apply above the limit.
const rustCrateIndexFileLimit = 4000
