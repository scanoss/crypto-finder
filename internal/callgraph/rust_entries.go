// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package callgraph

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/scanoss/crypto-finder/internal/callgraph/entrypoints"
)

// Entry points of Rust code: what a web framework, a gRPC server or a Lambda
// runtime calls. The frameworks and the names they declare are the catalog's
// (entrypoints/rust); this file recognizes the shapes: an attribute from the
// framework's crate on a function or on an impl block, and a call that passes
// a function to the framework. fn main is a process entry and needs no
// catalog.

const (
	rustNodeStringLiteral    = "string_literal"
	rustNodeRawStringLiteral = "raw_string_literal"
	rustNodeIdentifier       = "identifier"
	rustNodeScopedIdentifier = "scoped_identifier"
	// rustEntryOriginDepth bounds how many let bindings rustValueOrigin follows.
	rustEntryOriginDepth = 6
)

// rustEntryPath turns a path as written into the absolute path its first
// segment names through the scope's imports: get under
// `use axum::routing::get;` is axum::routing::get, web::get under
// `use actix_web::web;` is actix_web::web::get. A first segment the scope does
// not import is returned as written: a crate name (axum::routing::get), or a
// local name that no catalog crate covers.
func rustEntryPath(scope *FileAnalysis, written string) string {
	written = strings.TrimPrefix(strings.TrimSpace(written), "::")
	if scope == nil || written == "" {
		return written
	}
	first, rest, nested := strings.Cut(written, "::")
	if target, ok := scope.ImportAliases[first]; ok && target != "" && target != first {
		if nested {
			return target + "::" + rest
		}
		return target
	}
	if module, ok := scope.Imports[first]; ok && module != "" {
		return module + "::" + written
	}
	return written
}

// rustCratePath spells a path with the crate names a source file uses: a
// manifest rename can carry the package's hyphenated name.
func rustCratePath(path string) string {
	return strings.ReplaceAll(path, "-", "_")
}

// rustPathParent returns the module part of an absolute path, or "" for a
// single segment.
func rustPathParent(path string) string {
	if i := strings.LastIndex(path, "::"); i > 0 {
		return path[:i]
	}
	return ""
}

func rustPathLeaf(path string) string {
	if i := strings.LastIndex(path, "::"); i >= 0 {
		return path[i+2:]
	}
	return path
}

// rustAttributeEntryMark returns the mark of the first catalog attribute on
// item, a function_item or an impl_item. Attributes are the item's preceding
// siblings. An attribute's name counts through the scope's imports, its
// qualified spelling, or, for a bare name nothing imports, a crate the crate
// root brings in with #[macro_use] extern crate.
func (p *RustParser) rustAttributeEntryMark(item *sitter.Node, src []byte, scope *FileAnalysis, filePath string) (EntryMark, bool) {
	catalog := entryCatalog()
	for prev := item.PrevNamedSibling(); prev != nil; prev = prev.PrevNamedSibling() {
		if rustIsComment(prev.Symbol()) {
			continue
		}
		if prev.Type() != rustNodeAttributeItem {
			break
		}
		attr := rustNamedChildOfType(prev, rustNodeAttribute)
		if attr == nil || attr.NamedChildCount() == 0 {
			continue
		}
		written := attr.NamedChild(0).Content(src)
		name := rustPathLeaf(written)
		if !catalog.Named(entryLanguageRust, entrypoints.ShapeDecorator, name) {
			continue
		}
		for _, pkg := range p.rustAttributePackages(scope, written, filePath) {
			if entry, ok := catalog.Match(entryLanguageRust, entrypoints.ShapeDecorator, rustCratePath(pkg), "", name); ok {
				return catalogEntryMark(&entry), true
			}
		}
	}
	return EntryMark{}, false
}

// rustAttributePackages returns the packages an attribute written as written
// may come from: its import or qualified path, the same path under each glob
// import, and for a bare name the crates a crate root brings in with
// #[macro_use].
func (p *RustParser) rustAttributePackages(scope *FileAnalysis, written, filePath string) []string {
	full := rustEntryPath(scope, written)
	var packages []string
	for _, path := range append([]string{full}, rustGlobCandidates(scope, full)...) {
		if parent := rustPathParent(path); parent != "" {
			packages = append(packages, parent)
		}
	}
	if rustPathParent(full) == "" {
		packages = append(packages, p.crateMacroUseCrates(filePath)...)
	}
	return packages
}

// recordRustRegistration records an EntryRef for each function a catalog
// registration call hands to a framework: get(handler) with get from
// axum::routing, web::get().to(handler), warp::path("x").and_then(handler).
// A function call counts through the callee's own path; a method call
// through the value it is called on, followed back through calls, method
// chains and the let bindings of the enclosing function to the path it
// starts from.
func (p *RustParser) recordRustRegistration(call *sitter.Node, ctx *rustTypeCtx, filePath string) {
	entry, ok := rustRegistrationEntry(call, ctx)
	if !ok {
		return
	}
	args := call.ChildByFieldName("arguments")
	if args == nil {
		return
	}
	sawPath := false
	mark := catalogEntryMark(&entry)
	for i := 0; i < int(args.NamedChildCount()); i++ {
		arg := args.NamedChild(i)
		switch arg.Type() {
		case rustNodeStringLiteral, rustNodeRawStringLiteral:
			sawPath = true
		case rustNodeIdentifier, rustNodeScopedIdentifier, rustNodeGenericFunction:
			if entry.Path == entrypoints.PathRequired && !sawPath {
				continue
			}
			if id, found := p.rustHandlerID(arg, ctx, filePath); found {
				p.entryRefs = append(p.entryRefs, EntryRef{Function: id, Mark: mark})
			}
		}
	}
}

// rustRegistrationEntry returns the catalog registration entry a call
// matches: by the callee's own path for a function call, by the origin of the
// value a method is called on for a method call.
func rustRegistrationEntry(call *sitter.Node, ctx *rustTypeCtx) (entrypoints.Entry, bool) {
	fn := call.ChildByFieldName("function")
	if fn != nil && fn.Type() == rustNodeGenericFunction {
		fn = fn.ChildByFieldName("function")
	}
	if fn == nil {
		return entrypoints.Entry{}, false
	}
	var name, origin string
	switch fn.Type() {
	case rustNodeIdentifier, rustNodeScopedIdentifier:
		name = rustPathLeaf(fn.Content(ctx.src))
	case rustNodeFieldExpression:
		name = nodeFieldText(fn, "field", ctx.src)
	default:
		return entrypoints.Entry{}, false
	}
	catalog := entryCatalog()
	if !catalog.Named(entryLanguageRust, entrypoints.ShapeRegistrationCall, name) {
		return entrypoints.Entry{}, false
	}
	isMethod := fn.Type() == rustNodeFieldExpression
	if isMethod {
		origin = rustValueOrigin(fn.ChildByFieldName("value"), ctx, 0)
	} else {
		origin = rustEntryPath(ctx.analysis, fn.Content(ctx.src))
	}
	for _, path := range append([]string{origin}, rustGlobCandidates(ctx.analysis, origin)...) {
		pkg := path
		if !isMethod {
			pkg = rustPathParent(path)
		}
		if entry, ok := catalog.Match(entryLanguageRust, entrypoints.ShapeRegistrationCall, rustCratePath(pkg), "", name); ok {
			return entry, true
		}
	}
	return entrypoints.Entry{}, false
}

// rustGlobCandidates returns path under each glob import of the scope
// (`use actix_web::*;` turns web::get into actix_web::web::get), when its
// first segment is not already a name the scope knows: not imported, not a
// keyword root, and not a crate the manifest declares.
func rustGlobCandidates(scope *FileAnalysis, path string) []string {
	if scope == nil || path == "" || len(scope.WildcardImports) == 0 {
		return nil
	}
	first, _, nested := strings.Cut(path, "::")
	if _, imported := scope.Imports[first]; imported {
		return nil
	}
	if _, aliased := scope.ImportAliases[first]; aliased {
		return nil
	}
	if nested && !rustSegmentCannotBeACrate(scope, first, rustCrateRoot(scope.PackagePath)) {
		return nil
	}
	candidates := make([]string, 0, len(scope.WildcardImports))
	for _, glob := range scope.WildcardImports {
		candidates = append(candidates, glob+"::"+path)
	}
	return candidates
}

// rustHandlerID is the identity of a function passed by name, resolved as a
// call to it would be. A name a local binding shadows is a value, not a
// function.
func (p *RustParser) rustHandlerID(arg *sitter.Node, ctx *rustTypeCtx, filePath string) (FunctionID, bool) {
	if arg.Type() == rustNodeGenericFunction {
		if arg = arg.ChildByFieldName("function"); arg == nil {
			return FunctionID{}, false
		}
	}
	switch arg.Type() {
	case rustNodeIdentifier:
		name := arg.Content(ctx.src)
		if ctx.bindings != nil && ctx.bindings.shadows(name) {
			return FunctionID{}, false
		}
		if pkg, ok := ctx.analysis.Imports[name]; ok {
			return FunctionID{Package: pkg, Name: name}, true
		}
		if renamed, ok := rustRenamedFunctionCallee(ctx.analysis, name); ok {
			return renamed, true
		}
		return FunctionID{Package: ctx.analysis.PackagePath, Name: name}, true
	case rustNodeScopedIdentifier:
		line := int(arg.StartPoint().Row) + 1
		if call := p.parseScopedCall(arg, ctx.src, filePath, line, nil, ctx.analysis, ctx.selfType, ctx.generics); call != nil {
			return call.Callee, true
		}
	}
	return FunctionID{}, false
}

// rustValueOrigin returns the absolute path an expression's value starts
// from: Router::new().route(..) starts from axum::Router::new under
// `use axum::Router;`, warp::path!("x").and(..) from warp::path. A variable
// is followed to the value of the let binding that declares it in the
// enclosing function. A parameter, a field or a local name no import covers
// gives a path no catalog crate covers.
func rustValueOrigin(node *sitter.Node, ctx *rustTypeCtx, depth int) string {
	if node == nil || depth > rustEntryOriginDepth {
		return ""
	}
	switch node.Symbol() {
	case rustSyms.callExpression, rustSyms.genericFunction:
		return rustValueOrigin(node.ChildByFieldName("function"), ctx, depth)
	case rustSyms.fieldExpression:
		return rustValueOrigin(node.ChildByFieldName("value"), ctx, depth)
	case rustSyms.tryExpression, rustSyms.awaitExpression, rustSyms.parenthesized, rustSyms.referenceExpression:
		if node.NamedChildCount() > 0 {
			return rustValueOrigin(node.NamedChild(0), ctx, depth)
		}
	case rustSyms.macroInvocation:
		return rustEntryPath(ctx.analysis, nodeFieldText(node, "macro", ctx.src))
	case rustSyms.scopedIdentifier:
		return rustEntryPath(ctx.analysis, node.Content(ctx.src))
	case rustSyms.identifier:
		name := node.Content(ctx.src)
		if ctx.parser == nil {
			return ""
		}
		if value := ctx.parser.rustLetValue(node, name, ctx.src); value != nil {
			return rustValueOrigin(value, ctx, depth+1)
		}
		if _, imported := ctx.analysis.Imports[name]; imported {
			return rustEntryPath(ctx.analysis, name)
		}
	}
	return ""
}

// rustLetBinding is one `let name = value` of a function, in source order.
type rustLetBinding struct {
	end   uint32
	value *sitter.Node
}

// rustLetValue returns the value of the last `let name = value` of the
// function enclosing use that ends before it, or nil. Each function's let
// bindings are indexed once per file, so a function with many registration
// calls on variables is walked once, not once per call.
func (p *RustParser) rustLetValue(use *sitter.Node, name string, src []byte) *sitter.Node {
	fn := use.Parent()
	for fn != nil && fn.Type() != rustNodeFunctionItem {
		fn = fn.Parent()
	}
	if fn == nil {
		return nil
	}
	key := [2]uint32{fn.StartByte(), fn.EndByte()}
	index, ok := p.letIndex[key]
	if !ok {
		index = rustIndexLetBindings(fn.ChildByFieldName("body"), src)
		if p.letIndex == nil {
			p.letIndex = make(map[[2]uint32]map[string][]rustLetBinding)
		}
		p.letIndex[key] = index
	}
	var found *sitter.Node
	for _, binding := range index[name] {
		if binding.end <= use.StartByte() {
			found = binding.value
		}
	}
	return found
}

// rustIndexLetBindings maps each name a let in body binds to its values, in
// source order.
func rustIndexLetBindings(body *sitter.Node, src []byte) map[string][]rustLetBinding {
	index := make(map[string][]rustLetBinding)
	var walk func(*sitter.Node)
	walk = func(n *sitter.Node) {
		if n.Type() == rustNodeLetDeclaration {
			pattern, value := n.ChildByFieldName("pattern"), n.ChildByFieldName("value")
			if pattern != nil && value != nil {
				if name := rustPatternName(pattern, src); name != "" {
					index[name] = append(index[name], rustLetBinding{end: value.EndByte(), value: value})
				}
			}
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	if body != nil {
		walk(body)
	}
	return index
}

// rustPatternName returns the name a let pattern binds when it binds one name
// (x, mut x), or "".
func rustPatternName(pattern *sitter.Node, src []byte) string {
	if pattern.Type() == rustNodeIdentifier {
		return pattern.Content(src)
	}
	text := strings.TrimSpace(pattern.Content(src))
	text = strings.TrimSpace(strings.TrimPrefix(text, "mut "))
	if strings.ContainsAny(text, " (,:{[") {
		return ""
	}
	return text
}

// crateMacroUseCrates returns the crates whose macros a crate root brings
// into every module with #[macro_use] extern crate, as Rocket's guide does.
// A package can hold a library and binaries, and which of them compiles the
// file is not known here, so every root that may: src/lib.rs, src/main.rs,
// and the binary root the file sits under in src/bin.
func (p *RustParser) crateMacroUseCrates(filePath string) []string {
	roots := rustMacroUseRoots(filePath)
	crates := make([]string, 0, len(roots))
	for _, rootFile := range roots {
		cached, ok := p.macroUseCache[rootFile]
		if !ok {
			cached = p.readCrateMacroUseCrates(rootFile)
			if p.macroUseCache == nil {
				p.macroUseCache = make(map[string][]string)
			}
			p.macroUseCache[rootFile] = cached
		}
		crates = append(crates, cached...)
	}
	return crates
}

// rustMacroUseRoots lists the crate root files that may compile filePath:
// the library and main roots of the nearest package, under src/ or at the
// package root, and the src/bin root the file sits under. A package may have
// only binaries under src/bin.
func rustMacroUseRoots(filePath string) []string {
	pkgDir := rustPackageDir(filePath)
	if pkgDir == "" {
		return nil
	}
	dir := filepath.Join(pkgDir, "src")
	candidates := []string{
		filepath.Join(dir, "lib.rs"), filepath.Join(dir, "main.rs"),
		filepath.Join(pkgDir, "lib.rs"), filepath.Join(pkgDir, "main.rs"),
	}
	if rel, err := filepath.Rel(filepath.Join(dir, "bin"), filePath); err == nil && !strings.HasPrefix(rel, "..") {
		if first, _, nested := strings.Cut(filepath.ToSlash(rel), "/"); nested {
			// src/bin/<name>/main.rs, or src/bin/<name>.rs whose submodules
			// live in src/bin/<name>/.
			candidates = append(candidates, filepath.Join(dir, "bin", first, "main.rs"), filepath.Join(dir, "bin", first+".rs"))
		} else {
			candidates = append(candidates, filePath)
		}
	}
	var roots []string
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			roots = append(roots, candidate)
		}
	}
	return roots
}

// rustPackageDir returns the directory of the nearest Cargo.toml above
// filePath, or "".
func rustPackageDir(filePath string) string {
	dir := filepath.Dir(filePath)
	for depth := 0; depth < 12 && dir != "" && dir != string(filepath.Separator); depth++ {
		if _, err := os.Stat(filepath.Join(dir, "Cargo.toml")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

func (p *RustParser) readCrateMacroUseCrates(rootFile string) []string {
	src, err := os.ReadFile(rootFile)
	if err != nil {
		return nil
	}
	tree, err := p.parser.ParseCtx(context.TODO(), nil, src)
	if err != nil {
		return nil
	}
	defer tree.Close()
	root := tree.RootNode()
	var crates []string
	for i := 0; i < int(root.NamedChildCount()); i++ {
		item := root.NamedChild(i)
		if item.Type() != rustNodeExternCrate || !rustHasMacroUse(item, src) {
			continue
		}
		if name := nodeFieldText(item, "name", src); name != "" && name != rustNodeSelf {
			crates = append(crates, name)
		}
	}
	return crates
}

// rustHasMacroUse reports whether item carries a #[macro_use] attribute.
func rustHasMacroUse(item *sitter.Node, src []byte) bool {
	for prev := item.PrevNamedSibling(); prev != nil; prev = prev.PrevNamedSibling() {
		if rustIsComment(prev.Symbol()) {
			continue
		}
		if prev.Type() != rustNodeAttributeItem {
			return false
		}
		if attr := rustNamedChildOfType(prev, rustNodeAttribute); attr != nil && attr.NamedChildCount() > 0 &&
			attr.NamedChild(0).Content(src) == "macro_use" {
			return true
		}
	}
	return false
}
