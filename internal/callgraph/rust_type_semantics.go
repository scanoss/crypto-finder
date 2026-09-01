// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// This file holds the Rust receiver-typing layer: the part of the parser that
// answers "what type is this expression?" so a method call on it carries the
// identity a rule or contract can query.
//
// It exists because the original implementation answered that question by
// cutting up the SOURCE TEXT of a `let` right-hand side — split at the first
// `.`, then at the first `(`, then at the last `::`. That reads correctly for
// exactly one shape (`let c = Type::new(..)`) and produces a wrong-but-valid
// key for every other shape Rust allows: a `.await`, a `?`, a block tail, a
// match arm, a struct field, a helper's return value, a reference, an index.
// A wrong key is worse than a missing one, because nothing downstream can
// tell it apart from a correct one.
//
// The replacement resolves types structurally, from the grammar's own fields,
// following the semantics the Rust Reference defines:
//
//   - Method-call expressions: the receiver's candidate types come from
//     repeatedly DEREFERENCING the receiver expression, so a `Box<Aes128>`,
//     an `Arc<Aes128>` and an `Aes128` all resolve to the same identity.
//   - Namespaces: names live in separate type and value namespaces, so a
//     local binding never masquerades as a type and a module never
//     masquerades as one either.

// rustMaxTypeDepth bounds the structural recursion. Rust expressions nest
// arbitrarily (`(&mut *self.inner.lock().unwrap()).update(..)`), and a
// malformed or adversarial file must not be able to spin the walker.
const rustMaxTypeDepth = 16

// rustPreludeTypes are the types the Reference puts in the standard-library
// prelude: in scope in every module with no import at all. Attributing them to
// the crate being analyzed is wrong — a `Result` a project never declared is not
// the project's type — and it is noise: openssl 0.10.81 emits over a thousand
// method calls on Result and Option, none of which is a crypto operation.
var rustPreludeTypes = map[string]bool{
	"Option": true, "Result": true, "Vec": true, "String": true, "Box": true,
	"Cow": true, "Rc": true, "Arc": true, "Some": true, "Ok": true, "Err": true,
	"None": true, "Iterator": true, "IntoIterator": true, "Default": true,
	"Clone": true, "Copy": true, "Drop": true, "From": true, "Into": true,
	"TryFrom": true, "TryInto": true, "AsRef": true, "AsMut": true,
	"ToString": true, "ToOwned": true, "Send": true, "Sync": true, "Sized": true,
	"Ord": true, "PartialOrd": true, "Eq": true, "PartialEq": true,
	"Fn": true, "FnMut": true, "FnOnce": true,
}

// rustPreludePackage is the package a prelude type is attributed to. It is
// deliberately the crate root rather than the exact module path
// (`core::result`), because it exists to keep these identities OUT of the
// analyzed crate, not to model the standard library.
const rustPreludePackage = "std"

// rustDerefWrappers are the types that implement Deref to their contents, so a
// method call written on one of them auto-dereferences to the value inside.
// `Arc<Aes128>::encrypt_block(..)` IS `Aes128::encrypt_block(..)`, which is how
// real async and dispatch code holds a cipher.
//
// Option, Result, Vec, Cell, RefCell and the locks are deliberately NOT here:
// they do not Deref to their contents, so a method called on one of them is a
// method OF the wrapper. Unwrapping them turned `cvt(..).map(..)` — a Result
// method — into `libc.(c_int).map`, 165 edges in openssl 0.10.81 attributing a
// standard-library call to a third-party type.
var rustDerefWrappers = map[string]bool{
	"Box": true, "Arc": true, "Rc": true, "Cow": true, "Pin": true,
	"ManuallyDrop": true, "Lazy": true, "OnceCell": true,
}

// rustValueWrappers hold a value without Deref-ing to it. Their contents are
// reached by a pattern (`Ok(c)`, `Some(c)`) or by an explicit accessor
// (`unwrap`, `lock`, `borrow`), never by calling a method through them.
var rustValueWrappers = map[string]bool{
	"Option": true, "Result": true, "Vec": true, "Cell": true,
	"RefCell": true, "Mutex": true, "RwLock": true, "OnceLock": true,
	"Reverse": true,
}

// rustWrapperTypes is every ownership wrapper, of either kind. A constructor
// call on one of these (`Arc::new(inner)`, `Mutex::new(inner)`) takes its
// identity from the value it was handed.
var rustWrapperTypes = map[string]bool{}

func init() {
	for name := range rustDerefWrappers {
		rustWrapperTypes[name] = true
	}
	for name := range rustValueWrappers {
		rustWrapperTypes[name] = true
	}
}

// rustContainerPreservingMethods hand back a view of the same collection, so
// the element type survives the call: `v.iter().for_each(|c| ..)`.
var rustContainerPreservingMethods = map[string]bool{
	"iter": true, "iter_mut": true, "into_iter": true, "drain": true,
	"chunks": true, "chunks_exact": true, "windows": true, "rev": true,
	"cloned": true, "copied": true, "peekable": true, "by_ref": true,
}

// rustElementYieldingMethods hand back ONE element of the collection.
var rustElementYieldingMethods = map[string]bool{
	"next": true, "last": true, "nth": true, "peek": true, "pop": true,
	"first": true, "get": true, "remove": true, "swap_remove": true,
}

// rustUnwrappingMethods hand back the value inside a wrapper, so their result
// is the inner type: `c.lock().unwrap()` is the cipher, not the Mutex.
var rustUnwrappingMethods = map[string]bool{
	"unwrap": true, "expect": true, "borrow": true, "borrow_mut": true,
	"unwrap_or_default": true, "get_mut": true, "deref": true,
	"deref_mut": true, "into_inner": true, "take": true,
}

// rustWrappingConstructors are the associated functions that take the value a
// wrapper will hold. `Vec::with_capacity(n)` does not: its argument is a length,
// and treating it as the element typed the vector by its capacity.
var rustWrappingConstructors = map[string]bool{
	"new": true, "from": true, "pin": true, "new_cyclic": true,
}

// rustPoisonableAccessors hand back the contents wrapped in a Result, because
// the lock they take can be poisoned. Modeling them as handing back the value
// directly put the `unwrap` that follows on the value's own type — an
// `aes.(Aes128).unwrap` that names a method Aes128 does not have.
var rustPoisonableAccessors = map[string]bool{
	"lock": true, "read": true, "write": true, "try_lock": true,
}

// rustTransparentMethods hand back the same value, so their result has the
// receiver's own type.
var rustTransparentMethods = map[string]bool{
	"clone": true, "to_owned": true, "as_ref": true, "as_mut": true,
	// `map_err` rewrites the ERROR of a Result and leaves its value alone, so
	// `T::new(x).map_err(..)?` has T's identity. Not recognizing it broke the
	// chain that a bare `?` resolved, losing nine dependency edges in rage
	// 0.12.1 — two spellings of one thing answering differently.
	"map_err": true,
}

// rustFileFacts is the declared-type information a file provides about itself:
// what type each struct field holds, and what type each function returns.
// Both are needed to type a receiver that arrived through a field or through a
// helper call, which the text-based inference could not see at all.
type rustFileFacts struct {
	// structFields maps a type name to its field name -> declared type text.
	structFields map[string]map[string]string
	// fnReturns maps a function name to its declared return type text. Methods
	// are keyed as "Type::method" as well as bare, so a `self.helper()` and a
	// free `helper()` both resolve.
	fnReturns map[string]string
	// localTypes records every type declared in this file, so a receiver typed
	// by one of them stays local instead of being qualified against an import
	// that happens to share the name.
	localTypes map[string]bool
	// typeModules maps a declared type's bare name to the module path that
	// DECLARES it, which is not the module that uses it. A name reached through
	// a glob — `use crate::decls::*` or the `mod tests { use super::*; }` every
	// crate writes — is bound in the importing module but belongs to the
	// declaring one, and keying it by the importer splits one type across as
	// many keys as there are importers: quinn-proto 0.11.9 declares `Assembler`
	// once in src/connection/assembler.rs and emitted 12 edges under
	// `quinn_proto::connection::assembler` and 102 under
	// `…::assembler::test`, one file, one type, two keys. Crate-wide this was
	// ~2726 edges, 14 of them on keys a contract fires on
	// (`ring::hmac::Key.new`, `ring::digest::Context.update`,
	// `openssl::rsa::Rsa.generate`).
	//
	// An empty value means AMBIGUOUS: two modules declare the name, so there is
	// no single declaring module and the importing one is the honest fallback.
	typeModules map[string]string
	// localModules records every module this file declares, inline or by
	// `mod x;`. An item declared in the current module shadows an
	// extern-crate-prelude name of the same kind, so a local `mod aes` makes
	// `aes::Aes128::new(..)` a call on THIS crate's type, not on the aes
	// crate's. Without this the shadowed name is attributed to the third-party
	// crate — the one failure mode that invents a finding for code that never
	// calls the library.
	localModules map[string]bool
	// fallback holds the crate-wide facts consulted when this file declares
	// nothing under a name. A declaration in another file of the same crate is
	// still this crate's truth: `src/factory.rs` returning an `Aes128` types
	// the receiver in `src/consumer.rs`, which a per-file view could not do.
	fallback *rustFileFacts
	// crateAliases maps a name a module re-exports a whole CRATE under, to that
	// crate. rustls writes `pub(crate) use ring as ring_like;` in one file and
	// reaches it as `use super::ring_like::aead;` from its sibling backend
	// files, which is its entire ring-backed AEAD, ECDSA and CSPRNG surface —
	// 147 call edges that resolved to a module path naming no crate.
	crateAliases map[string]string
	// reExports maps a module-qualified name (rustQualifyFactKey(module, name))
	// to the package and type a `pub use path::Item;` or `pub use path::Item as
	// Name;` re-export ultimately names, once resolveRustReExportChains has
	// followed it through every other re-export in the crate. A crate's public
	// type commonly aliases its way through two or three modules before
	// reaching the crate that implements it, and `outer::MyCipher` naming
	// `outer` as the identity — the module that merely re-exports it, not
	// `aes::Aes128` which does the encryption — is a wrong identity, not a
	// missing one.
	reExports map[string]rustReExportTarget
	// derefTransparent records a wrapper's bare name when the crate's own
	// source declares `impl<T> Deref for Wrapper<T> { type Target = T; }` (or
	// DerefMut) for it: a single type parameter, applied to the impl target
	// with no other argument, handed back verbatim as Target. That is the only
	// shape structural evidence can vouch for without guessing which of
	// several parameters is "the real one" — `secrecy::SecretBox<T>` and
	// `zeroize`'s wrappers, the pattern crates use to hold key material, take
	// this exact shape. Box/Arc/Rc stay in the hardcoded rustDerefWrappers
	// table below: their Deref impl lives in the standard library, whose
	// source this parser never reads.
	derefTransparent map[string]bool
	// conflicting names are declared more than once in the crate with
	// DIFFERENT types. They resolve to nothing: an ambiguous answer here would
	// name one algorithm where another is used, which is the failure mode this
	// parser exists to avoid.
	conflicting map[string]bool
	// edition is the Rust edition the crate's manifest declares, and
	// dependencies the names it declares as dependencies. Both are evidence a
	// syntactic shape alone cannot supply: whether a `use` path's first segment
	// names a crate at all depends on the edition, and whether the name it
	// writes IS a crate depends on the manifest.
	edition      string
	dependencies map[string]bool
	// includeTests mirrors the scan setting. The declaration walk needs it
	// for the same reason the call walk does: a `#[cfg(test)]` module's
	// declarations must not enter the crate index, or a factory declared
	// only for tests types a receiver in production code and reports the
	// crate as using an algorithm its published artifact never touches.
	includeTests bool
}

// returnType returns the declared return type of a function, looking outward to
// the crate when this file does not declare it.
func (f *rustFileFacts) returnType(name string) (string, bool) {
	if f == nil || name == "" {
		return "", false
	}
	if ret, ok := f.fnReturns[name]; ok && ret != "" {
		return ret, true
	}
	if f.conflicting[name] {
		return "", false
	}
	return f.fallback.returnType(name)
}

// fields returns a type's declared field types.
func (f *rustFileFacts) fields(typeName string) (map[string]string, bool) {
	if f == nil || typeName == "" {
		return nil, false
	}
	if fields, ok := f.structFields[typeName]; ok {
		return fields, true
	}
	if f.conflicting[typeName] {
		return nil, false
	}
	return f.fallback.fields(typeName)
}

// isLocalType reports whether the crate declares a type by this name.
func (f *rustFileFacts) isLocalType(name string) bool {
	if f == nil {
		return false
	}
	return f.localTypes[name] || f.fallback.isLocalType(name)
}

// declaringModule returns the module path that declares a type by this name,
// when exactly one module in view does.
//
// The file's own answer wins over the crate's, as everywhere else here: a name
// this file declares is what this file's code means by it. A name the crate
// declares in two different modules has no single answer and gets none — the
// caller then keys it by the using module, which is what it did before this
// existed.
func (f *rustFileFacts) declaringModule(name string) (string, bool) {
	if f == nil || name == "" {
		return "", false
	}
	if module, recorded := f.typeModules[name]; recorded {
		if module == "" {
			return "", false
		}
		return module, true
	}
	return f.fallback.declaringModule(name)
}

// reExportTarget returns the package and type a module-qualified name
// ultimately re-exports, when the crate's re-export chains have been
// resolved. key is rustQualifyFactKey(module, name).
func (f *rustFileFacts) reExportTarget(key string) (pkg, typ string, ok bool) {
	if f == nil || key == "" {
		return "", "", false
	}
	if target, recorded := f.reExports[key]; recorded {
		if target.pkg == "" {
			return "", "", false
		}
		return target.pkg, target.typ, true
	}
	return f.fallback.reExportTarget(key)
}

// isDerefTransparent reports whether the crate's own source proved a bare
// wrapper name transparent to its single generic parameter, via a real
// `impl<T> Deref for Wrapper<T> { type Target = T; }`.
func (f *rustFileFacts) isDerefTransparent(name string) bool {
	if f == nil || name == "" {
		return false
	}
	return f.derefTransparent[name] || f.fallback.isDerefTransparent(name)
}

// declaresModule reports whether the module at modulePath declares a child
// module by this name.
//
// Shadowing is lexical in both directions. A `mod des` at a file's top level
// shadows the `des` crate for that file, and for no other — consulting the
// crate-wide index made an empty `mod des;` anywhere suppress every real DES
// call elsewhere. And a module does not shadow itself: inside
// `mod pbkdf2 { use pbkdf2::pbkdf2; }` the path's first segment is the CRATE,
// because uniform paths look at the items of the current module and a module is
// not an item of itself. Recording module names file-wide made cocoon's only
// PBKDF2 call invisible to its contract.
func (f *rustFileFacts) declaresModule(modulePath, name string) bool {
	if f == nil {
		return false
	}
	return f.localModules[rustQualifyFactKey(modulePath, name)]
}

// declaresModuleAnywhere reports whether the crate declares a module by this
// name at any path. Used only to decide that a segment which cannot be a crate
// is this crate's module.
func (f *rustFileFacts) declaresModuleAnywhere(name string) bool {
	if f == nil || name == "" {
		return false
	}
	for key := range f.localModules {
		if key == name || strings.HasSuffix(key, "::"+name) {
			return true
		}
	}
	return f.fallback.declaresModuleAnywhere(name)
}

// mergeCrateFacts folds one file's declarations into a crate-wide index,
// dropping any name two files declare differently.
func (f *rustFileFacts) mergeCrateFacts(other *rustFileFacts) {
	if other == nil {
		return
	}
	f.mergeFnReturns(other)
	f.mergeStructFields(other)
	f.mergeDeclaredTypes(other)
	f.mergeReExports(other)
	for name := range other.localModules {
		f.localModules[name] = true
	}
	for name := range other.derefTransparent {
		f.derefTransparent[name] = true
	}
}

// mergeReExports folds in another file's re-export targets, dropping a key two
// files name differently for the same reason a conflicting declared type is
// dropped: two modules re-exporting the same qualified name to different
// targets is a naming collision the code cannot have, not evidence to guess
// from.
func (f *rustFileFacts) mergeReExports(other *rustFileFacts) {
	for key, target := range other.reExports {
		if f.conflicting["reexport:"+key] {
			continue
		}
		if existing, seen := f.reExports[key]; seen && existing != target {
			delete(f.reExports, key)
			f.conflicting["reexport:"+key] = true
			continue
		}
		f.reExports[key] = target
	}
}

func (f *rustFileFacts) mergeFnReturns(other *rustFileFacts) {
	for name, ret := range other.fnReturns {
		if existing, seen := f.fnReturns[name]; seen && existing != ret {
			delete(f.fnReturns, name)
			f.conflicting[name] = true
			continue
		}
		if !f.conflicting[name] {
			f.fnReturns[name] = ret
		}
	}
}

func (f *rustFileFacts) mergeStructFields(other *rustFileFacts) {
	for typeName, fields := range other.structFields {
		existing, seen := f.structFields[typeName]
		if !seen {
			f.structFields[typeName] = fields
			continue
		}
		for field, typeText := range fields {
			key := typeName + "::" + field
			// A name two files already contradicted stays dropped. Without
			// this the marker was write-only, so a third file repeating the
			// first resurrected the fact and `filepath.WalkDir` order decided
			// which cipher a struct field was reported as holding.
			if f.conflicting[key] {
				continue
			}
			if had, ok := existing[field]; ok && had != typeText {
				delete(existing, field)
				f.conflicting[key] = true
				continue
			}
			existing[field] = typeText
		}
	}
}

// mergeDeclaredTypes folds in the names another file declares, and the module
// each one is declared in. Two files declaring the same name in DIFFERENT
// modules leave it with no declaring module: naming either would attribute half
// the call sites to a module that declares something else under that name.
func (f *rustFileFacts) mergeDeclaredTypes(other *rustFileFacts) {
	for name := range other.localTypes {
		f.localTypes[name] = true
	}
	for name, module := range other.typeModules {
		if existing, seen := f.typeModules[name]; seen && existing != module {
			f.typeModules[name] = ""
			continue
		}
		f.typeModules[name] = module
	}
}

func newRustFileFacts() *rustFileFacts {
	return &rustFileFacts{
		structFields:     make(map[string]map[string]string),
		fnReturns:        make(map[string]string),
		localTypes:       make(map[string]bool),
		typeModules:      make(map[string]string),
		localModules:     make(map[string]bool),
		conflicting:      make(map[string]bool),
		crateAliases:     make(map[string]string),
		reExports:        make(map[string]rustReExportTarget),
		derefTransparent: make(map[string]bool),
	}
}

// rustReExportTarget is the package and type a re-exported name ultimately
// names.
type rustReExportTarget struct {
	pkg string
	typ string
}

// collectRustFileFacts walks the whole file — including inline `mod` blocks and
// `trait` bodies, which the declaration pass used to skip — recording the
// declared types a receiver can be resolved through.
// collectRustFileFacts records a file's declarations. packagePath is the module
// path the file itself sits at, so a declaration's qualified key matches the
// path the resolver will look it up under; the crate-wide index passes "" and
// relies on the bare keys plus its own conflict detection.
func collectRustFileFacts(
	root *sitter.Node,
	src []byte,
	packagePath, edition string,
	dependencies map[string]bool,
	includeTests bool,
) *rustFileFacts {
	f := newRustFileFacts()
	f.edition = edition
	f.dependencies = dependencies
	f.includeTests = includeTests
	f.walk(root, src, "", packagePath)
	return f
}

// rustEditionUsesUniformPaths reports whether a `use` path's first segment names
// a crate rather than an item of the crate root. That is the 2018 "uniform
// paths" change; edition 2015 resolves a `use` path from the crate root, and
// cargo's default when a manifest declares no edition IS 2015.
func rustEditionUsesUniformPaths(edition string) bool {
	switch edition {
	case "2018", "2021", "2024":
		return true
	}
	return false
}

func (f *rustFileFacts) walk(node *sitter.Node, src []byte, selfType, modulePath string) {
	if node == nil {
		return
	}
	nodeNamedChildren := int(node.NamedChildCount())
	for i := 0; i < nodeNamedChildren; i++ {
		child := node.NamedChild(i)
		switch child.Symbol() {
		case rustSyms.structItem, rustSyms.unionItem:
			f.recordStruct(child, src, modulePath)
		case rustSyms.enumItem:
			f.recordEnum(child, src, modulePath)
			f.walk(child.ChildByFieldName("body"), src, selfType, modulePath)
		case rustSyms.traitItem, rustSyms.typeItem, rustSyms.implItem:
			f.recordTypeOwner(child, src, modulePath)
		case rustSyms.functionItem, rustSyms.functionSignature:
			f.recordReturn(child, src, selfType, modulePath)
			f.walk(child.ChildByFieldName("body"), src, selfType, modulePath)
		case rustSyms.modItem:
			if !f.includeTests && rustModuleIsTestOnly(child, src) {
				continue
			}
			name := nodeFieldText(child, "name", src)
			body := child.ChildByFieldName("body")
			// A module whose ONLY item re-exports a whole crate of the same
			// name declares nothing of its own: it is that crate's API under a
			// local spelling, and the API's owner is what a contract keys on.
			if crate, isFacade := rustPassThroughReExport(body, src, name, f.edition, f.dependencies); isFacade {
				f.recordCrateReExport(name, crate)
				continue
			}
			if name != "" {
				f.localModules[rustQualifyFactKey(modulePath, name)] = true
			}
			f.walk(body, src, selfType, rustQualifyFactKey(modulePath, name))
		case rustSyms.useDeclaration:
			f.recordCrateAlias(child, src)
			f.recordItemReExport(child, src, modulePath)
		case rustSyms.externCrate:
			f.recordExternCrate(child, src)
		case rustSyms.foreignModItem:
			f.walk(child.ChildByFieldName("body"), src, selfType, modulePath)
		default:
			f.walk(child, src, selfType, modulePath)
		}
	}
}

// recordDeclaredType records a type declaration under its bare name and under
// the module that declares it.
//
// Both are needed. The bare set answers "does this crate declare the name",
// which decides whether a receiver stays local; the module answers "where", so
// the emitted key names the declaring module rather than whichever module
// globbed the name into scope. Two modules of one file declaring the same name
// make the module ambiguous, exactly as two files do.
func (f *rustFileFacts) recordDeclaredType(name, modulePath string) {
	if name == "" {
		return
	}
	f.localTypes[name] = true
	if modulePath == "" {
		// No module path to attribute it to — a snippet parsed outside any
		// crate. The name is still known to be local.
		return
	}
	if existing, seen := f.typeModules[name]; seen && existing != modulePath {
		f.typeModules[name] = ""
		return
	}
	f.typeModules[name] = modulePath
}

// recordTypeOwner records what a trait, alias or impl block contributes: the
// type name it declares, and the return types of the methods it owns.
//
// A trait's method signatures are the declared return types of every
// implementation reached through that trait, so they are recorded under the
// TRAIT's name. Recording them with no owning type let a bare method name pick
// up an unrelated inherent method's return type from elsewhere in the file.
func (f *rustFileFacts) recordTypeOwner(node *sitter.Node, src []byte, modulePath string) {
	switch node.Type() {
	case rustNodeTraitItem:
		traitName := nodeFieldText(node, "name", src)
		if traitName != "" {
			f.recordDeclaredType(traitName, modulePath)
		}
		f.walkImplBody(node.ChildByFieldName("body"), src, traitName, modulePath)
	case rustNodeTypeItem:
		if name := nodeFieldText(node, "name", src); name != "" {
			f.recordDeclaredType(name, modulePath)
		}
	case rustNodeImplItem:
		typeName := ""
		if t := node.ChildByFieldName("type"); t != nil {
			typeName = rustTypeHead(t.Content(src))
		}
		f.recordDerefTransparentWrapper(node, src)
		f.walkImplBody(node.ChildByFieldName("body"), src, typeName, modulePath)
	}
}

// recordDerefTransparentWrapper records a wrapper's bare name when this impl
// block is exactly `impl<T> Deref for Wrapper<T> { type Target = T; ... }` (or
// DerefMut): one type parameter, applied verbatim as the impl target's only
// argument, hand back verbatim as Target. Anything looser -- more than one
// parameter, or a Target that is not that bare parameter -- is left
// unrecorded rather than guessed, the same discipline every other fact here
// follows.
func (f *rustFileFacts) recordDerefTransparentWrapper(node *sitter.Node, src []byte) {
	paramName, ok := rustSingleDerefTraitParam(node, src)
	if !ok {
		return
	}
	wrapperName, ok := rustDerefWrapperName(node.ChildByFieldName("type"), src, paramName)
	if !ok {
		return
	}
	body := node.ChildByFieldName("body")
	if body == nil || !rustImplDeclaresTargetAs(body, src, paramName) {
		return
	}
	f.derefTransparent[wrapperName] = true
}

// rustSingleDerefTraitParam reports the one generic parameter of an
// `impl<T> Deref for ...` (or DerefMut) block. More than one type parameter
// leaves no way to tell which one Target forwards, so that case is left
// unrecorded rather than guessed.
func rustSingleDerefTraitParam(node *sitter.Node, src []byte) (paramName string, ok bool) {
	traitNode := node.ChildByFieldName("trait")
	if traitNode == nil {
		return "", false
	}
	traitName := rustTypeHead(traitNode.Content(src))
	if traitName != "Deref" && traitName != "DerefMut" {
		return "", false
	}
	params := make(map[string]string)
	collectRustGenericParams(node.ChildByFieldName("type_parameters"), src, params)
	if len(params) != 1 {
		return "", false
	}
	for name := range params {
		paramName = name
	}
	return paramName, true
}

// rustDerefWrapperName reports the wrapper's bare name when typeNode is
// exactly `Wrapper<paramName>` -- a generic type applied to that single type
// parameter, verbatim, with no other argument. Anything looser is left
// unrecorded rather than guessed.
func rustDerefWrapperName(typeNode *sitter.Node, src []byte, paramName string) (wrapperName string, ok bool) {
	if typeNode == nil || typeNode.Type() != javaNodeGenericType {
		return "", false
	}
	wrapperNameNode := typeNode.ChildByFieldName("type")
	argsNode := typeNode.ChildByFieldName("type_arguments")
	if wrapperNameNode == nil || argsNode == nil || int(argsNode.NamedChildCount()) != 1 {
		return "", false
	}
	arg := argsNode.NamedChild(0)
	if arg.Type() != goNodeTypeIdentifier || arg.Content(src) != paramName {
		return "", false
	}
	wrapperName = rustTypeHead(wrapperNameNode.Content(src))
	return wrapperName, wrapperName != ""
}

// rustImplDeclaresTargetAs reports whether an impl body declares `type Target
// = paramName;` verbatim, the associated type Deref requires.
func rustImplDeclaresTargetAs(body *sitter.Node, src []byte, paramName string) bool {
	bodyNamedChildren := int(body.NamedChildCount())
	for i := 0; i < bodyNamedChildren; i++ {
		child := body.NamedChild(i)
		if child.Type() != rustNodeTypeItem {
			continue
		}
		if nodeFieldText(child, "name", src) != "Target" {
			continue
		}
		return nodeFieldText(child, "type", src) == paramName
	}
	return false
}

// recordStruct records a struct or union's declared field types, twice: under
// the declaring module, which is the precise answer, and under the bare name,
// which is what a call from elsewhere in the file can find. Two modules
// declaring the same type name differently make the bare key conflict and drop.
func (f *rustFileFacts) recordStruct(node *sitter.Node, src []byte, modulePath string) {
	name := nodeFieldText(node, "name", src)
	if name == "" {
		return
	}
	f.recordDeclaredType(name, modulePath)
	body := node.ChildByFieldName("body")
	f.recordFields(rustQualifyFactKey(modulePath, name), body, src)
	f.recordFields(name, body, src)
}

// recordEnum records an enum's variant payload types under both keys.
func (f *rustFileFacts) recordEnum(node *sitter.Node, src []byte, modulePath string) {
	name := nodeFieldText(node, "name", src)
	if name == "" {
		return
	}
	f.recordDeclaredType(name, modulePath)
	body := node.ChildByFieldName("body")
	f.recordVariants(rustQualifyFactKey(modulePath, name), body, src)
	f.recordVariants(name, body, src)
}

func (f *rustFileFacts) walkImplBody(body *sitter.Node, src []byte, typeName, modulePath string) {
	if body == nil {
		return
	}
	bodyNamedChildren := int(body.NamedChildCount())
	for i := 0; i < bodyNamedChildren; i++ {
		child := body.NamedChild(i)
		if child.Type() == rustNodeFunctionItem || child.Type() == "function_signature_item" {
			f.recordReturn(child, src, typeName, modulePath)
		}
		f.walk(child, src, typeName, modulePath)
	}
}

// recordVariants records an enum variant's payload types, keyed
// "Enum::Variant", so `match algo { Algo::Aes(c) => c.encrypt_block(..) }`
// types `c` from the variant's declaration.
func (f *rustFileFacts) recordVariants(enumName string, body *sitter.Node, src []byte) {
	if body == nil {
		return
	}
	bodyNamedChildren := int(body.NamedChildCount())
	for i := 0; i < bodyNamedChildren; i++ {
		variant := body.NamedChild(i)
		if variant.Type() != "enum_variant" {
			continue
		}
		name := nodeFieldText(variant, "name", src)
		if name == "" {
			continue
		}
		f.recordFields(enumName+"::"+name, variant.ChildByFieldName("body"), src)
	}
}

func (f *rustFileFacts) recordFields(typeName string, body *sitter.Node, src []byte) {
	if body == nil {
		return
	}
	fields := f.structFields[typeName]
	if fields == nil {
		fields = make(map[string]string)
		f.structFields[typeName] = fields
	}
	idx := 0
	bodyNamedChildren := int(body.NamedChildCount())
	for i := 0; i < bodyNamedChildren; i++ {
		child := body.NamedChild(i)
		switch child.Type() {
		case "field_declaration":
			name := nodeFieldText(child, "name", src)
			typ := nodeFieldText(child, "type", src)
			if name != "" && typ != "" {
				f.putField(typeName, fields, name, typ)
			}
		case "ordered_field_declaration_list":
			f.recordFields(typeName, child, src)
		case goNodeTypeIdentifier, javaNodeGenericType, javaNodeScopedTypeIdentifier, "reference_type", "primitive_type":
			// A tuple struct's positional field: `struct Wrap(Aes128)` makes
			// `w.0` the same as a field named "0".
			f.putField(typeName, fields, strconv.Itoa(idx), child.Content(src))
			idx++
		}
	}
}

// putField records a field's declared type, dropping it when two declarations
// of the same type name disagree.
func (f *rustFileFacts) putField(typeName string, fields map[string]string, field, typeText string) {
	key := typeName + "::" + field
	if f.conflicting[key] {
		return
	}
	if existing, seen := fields[field]; seen && existing != typeText {
		delete(fields, field)
		f.conflicting[key] = true
		return
	}
	fields[field] = typeText
}

func (f *rustFileFacts) recordReturn(fn *sitter.Node, src []byte, selfType, modulePath string) {
	name := nodeFieldText(fn, "name", src)
	ret := nodeFieldText(fn, "return_type", src)
	if name == "" || ret == "" {
		return
	}
	if concrete := rustImplTraitConcreteReturn(fn, ret, src); concrete != "" {
		ret = concrete
	}
	// Module-qualified first: two modules in one file may each declare a
	// `build()` returning a different cipher, and keeping only the bare name
	// made one of them answer for both.
	if selfType != "" {
		f.putReturn(rustQualifyFactKey(modulePath, selfType)+"::"+name, ret)
		f.putReturn(selfType+"::"+name, ret)
	}
	f.putReturn(rustQualifyFactKey(modulePath, name), ret)
	f.putReturn(name, ret)
}

// putReturn records a return type, dropping the name when two declarations
// disagree. An ambiguous answer here names one algorithm where another is used;
// no answer only loses the receiver.
func (f *rustFileFacts) putReturn(key, ret string) {
	if key == "" || f.conflicting[key] {
		return
	}
	if existing, seen := f.fnReturns[key]; seen && existing != ret {
		delete(f.fnReturns, key)
		f.conflicting[key] = true
		return
	}
	f.fnReturns[key] = ret
}

// rustImplTraitConcreteReturn resolves a `-> impl Trait` return to the
// concrete type its body actually constructs, when that is a simple
// constructor call or a bare unit-like type. Rust requires every return path
// of such a function to name the same hidden concrete type (it monomorphizes
// to exactly one), so resolving any single one of them is correct — unlike
// `dyn Trait`, whose concrete type is genuinely a runtime decision. Declaring
// anything else here is left alone rather than guessed.
func rustImplTraitConcreteReturn(fn *sitter.Node, declaredReturn string, src []byte) string {
	if !strings.HasPrefix(declaredReturn, "impl ") {
		return ""
	}
	body := fn.ChildByFieldName("body")
	if body == nil {
		return ""
	}
	expr := rustBlockTailExpressionNode(body, src)
	if expr == nil {
		expr = rustFirstReturnExpressionNode(body)
	}
	return rustConstructorShapedTypeText(expr, src)
}

// rustFirstReturnExpressionNode finds the first `return expr;` in a function
// body, not descending into a nested function or closure — those return from
// themselves, not from the function being recorded.
func rustFirstReturnExpressionNode(node *sitter.Node) *sitter.Node {
	if node == nil {
		return nil
	}
	if node.Type() == "return_expression" {
		return rustReturnExpressionNode(node)
	}
	if node.Type() == rustNodeFunctionItem || node.Type() == rustNodeClosureExpression {
		return nil
	}
	namedChildren := int(node.NamedChildCount())
	for i := 0; i < namedChildren; i++ {
		if found := rustFirstReturnExpressionNode(node.NamedChild(i)); found != nil {
			return found
		}
	}
	return nil
}

// rustConstructorShapedTypeText returns the type a constructor-shaped
// expression names: `Type::method(..)` names Type, and a bare type-case
// identifier — a unit struct or a fieldless enum variant used as a value —
// names itself. Anything else yields "": there is no general way to read a
// concrete type off an arbitrary expression without real type inference.
func rustConstructorShapedTypeText(expr *sitter.Node, src []byte) string {
	if expr == nil {
		return ""
	}
	switch expr.Type() {
	case rustNodeCallExpression:
		if expr.ChildCount() == 0 {
			return ""
		}
		funcNode := expr.Child(0)
		if funcNode.Type() == rustNodeGenericFunction && funcNode.ChildCount() > 0 {
			funcNode = funcNode.Child(0)
		}
		if funcNode.Type() != javaNodeScopedIdentifier {
			return ""
		}
		content := stripRustTypeArguments(rustScopedTypeText(funcNode, src))
		lastSep := strings.LastIndex(content, "::")
		if lastSep <= 0 {
			return ""
		}
		typ := content[:lastSep]
		if !rustIsTypeCase(rustTypeHead(typ)) {
			return ""
		}
		return typ
	case goNodeIdentifier:
		name := expr.Content(src)
		if rustIsTypeCase(name) {
			return name
		}
	}
	return ""
}

// recordCrateAlias records a `use <crate> as <name>;` re-export. Only a path
// that is a single identifier counts: that is a whole crate being renamed, and
// renaming a crate is what makes the alias meaningful anywhere else in it.
func (f *rustFileFacts) recordCrateAlias(useDecl *sitter.Node, src []byte) {
	argument := useDecl.ChildByFieldName("argument")
	if argument == nil || argument.Type() != rustNodeUseAsClause {
		return
	}
	path := argument.ChildByFieldName("path")
	alias := nodeFieldText(argument, "alias", src)
	if path == nil || alias == "" || path.Type() != goNodeIdentifier {
		return
	}
	crate := path.Content(src)
	if crate == "" || crate == alias {
		return
	}
	f.recordCrateReExport(alias, crate)
}

// recordCrateReExport records that a local name stands for a whole CRATE. Two
// declarations disagreeing drop the name: an alias that could mean either of
// two crates would attribute an operation to a library the code may not call.
func (f *rustFileFacts) recordCrateReExport(alias, crate string) {
	if alias == "" || crate == "" {
		return
	}
	// An alias two declarations already contradicted stays dropped, for the
	// same reason a conflicting field does: a third declaration repeating the
	// first must not resurrect it.
	if f.conflicting["alias:"+alias] {
		return
	}
	if existing, seen := f.crateAliases[alias]; seen && existing != crate {
		delete(f.crateAliases, alias)
		f.conflicting["alias:"+alias] = true
		return
	}
	f.crateAliases[alias] = crate
}

// recordItemReExport records a `pub use path::Item;` or
// `pub use path::Item as Name;` as a re-export target: within modulePath, the
// local name (the alias, or Item when unaliased) means whatever path::Item
// names. The raw path is qualified against the declaring file's own imports in
// qualifyCrateFacts, and chains across files are followed once the whole crate
// has been indexed, in resolveRustReExportChains — a crate's public type
// commonly aliases its way through two or three modules before reaching the
// crate that implements it.
func (f *rustFileFacts) recordItemReExport(useDecl *sitter.Node, src []byte, modulePath string) {
	argument := useDecl.ChildByFieldName("argument")
	if argument == nil {
		return
	}
	var fullPath, alias string
	switch argument.Type() {
	case rustNodeUseAsClause:
		fullPath, alias, _ = rustAliasImportParts(argument, src)
	case javaNodeScopedIdentifier:
		fullPath = rustScopedTypeText(argument, src)
	default:
		return
	}
	lastSep := strings.LastIndex(fullPath, "::")
	if lastSep <= 0 {
		return
	}
	rawPkg, rawType := fullPath[:lastSep], fullPath[lastSep+2:]
	// Only a TYPE re-export gives a receiver its identity; a re-exported free
	// function or constant is not a callee key's type segment.
	if !rustIsTypeCase(rawType) {
		return
	}
	if alias == "" {
		alias = rawType
	}
	f.putReExport(rustQualifyFactKey(modulePath, alias), rawPkg, rawType)
}

// putReExport records a re-export target, dropping a name two declarations
// already contradicted for the same reason a conflicting declared type is.
func (f *rustFileFacts) putReExport(key, pkg, typ string) {
	if key == "" || pkg == "" || typ == "" {
		return
	}
	if f.conflicting["reexport:"+key] {
		return
	}
	target := rustReExportTarget{pkg: pkg, typ: typ}
	if existing, seen := f.reExports[key]; seen && existing != target {
		delete(f.reExports, key)
		f.conflicting["reexport:"+key] = true
		return
	}
	f.reExports[key] = target
}

// rustPassThroughReExport reports the crate a module is a pure facade for: a
// module whose ONLY item is `pub use <name>::*;` with <name> its own name.
//
// tokio-native-tls 0.3.1 src/lib.rs:382 writes exactly that:
//
//	pub mod native_tls { pub use native_tls::*; }
//
// Two rules of this parser pull opposite ways on that shape -- a local module
// must not swallow a dependency, and a crate's own module wins over a rename --
// and the KB convention settles it: the first segment of every key in every
// Rust contract is the crate that OWNS the API, and no contract keys a type
// through another crate's facade. This is the same decision already taken for
// manifest renames, where openssl's `ffi` resolves to openssl_sys so that
// openssl-sys.yaml matches. Reporting the facade instead attributed a TLS
// handshake to tokio-native-tls, which contains no cryptography at all.
//
// The discriminator stays narrow on purpose. Anything else in the module body
// -- one type of its own, one function, a second `use` -- and the module is a
// module: the local-module rule keeps it, and that rule is what stops a crate
// with no cryptographic dependency from reporting its own `mod des` against the
// DES crate. Only comments are ignored, because a comment is not an item.
// The `use <name>::*` inside `mod <name>` shape is only self-validating in
// edition 2018 and later, where a `use` path's first segment is a crate. In
// edition 2015 a `use` path is CRATE-ROOT-RELATIVE, so `use des::*;` inside
// `mod des` names the crate's own root module `des` and compiles with no `des`
// dependency at all: a crate with zero dependencies whose src/des.rs is a record
// framer emitted `des.(Des).new` and `des.encrypt`, both keys in des.yaml. The
// manifest is the second half of the evidence — a name it does not declare as a
// dependency cannot be the crate this module is a facade for, in any edition.
func rustPassThroughReExport(body *sitter.Node, src []byte, name, edition string, dependencies map[string]bool) (string, bool) {
	if body == nil || name == "" {
		return "", false
	}
	if !rustEditionUsesUniformPaths(edition) {
		return "", false
	}
	if !dependencies[name] && !dependencies[rustCrateIdentifier(name)] {
		return "", false
	}
	found := false
	bodyNamedChildren := int(body.NamedChildCount())
	for i := 0; i < bodyNamedChildren; i++ {
		child := body.NamedChild(i)
		if rustIsComment(child.Symbol()) {
			continue
		}
		if child.Symbol() != rustSyms.useDeclaration || found {
			return "", false
		}
		if !rustReExportsCrateGlob(child, src, name) {
			return "", false
		}
		found = true
	}
	if !found {
		return "", false
	}
	return name, true
}

// rustReExportsCrateGlob reports whether a `use` declaration is exactly
// `use <name>::*;` -- a glob over a single leading identifier, which is a crate
// root and not a path into one.
func rustReExportsCrateGlob(useDecl *sitter.Node, src []byte, name string) bool {
	argument := useDecl.ChildByFieldName("argument")
	if argument == nil || argument.Type() != rustNodeUseWildcard {
		return false
	}
	path := ""
	argumentNamedChildren := int(argument.NamedChildCount())
	for i := 0; i < argumentNamedChildren; i++ {
		path = rustScopedTypeText(argument.NamedChild(i), src)
	}
	return path == name
}

// recordExternCrate records a plain `extern crate x;`, which brings the CRATE
// into that module's scope. Edition-2015 code then reaches it as `self::x::..`,
// and without this the relative root expanded to the current module path and
// the crate's own name was appended to it — `native_tls::imp::openssl::openssl`,
// a module that does not exist, on 170 edges in native-tls 0.2.14, which left
// the entire openssl surface of a TLS wrapper invisible.
func (f *rustFileFacts) recordExternCrate(node *sitter.Node, src []byte) {
	var idents []string
	nodeChildren := int(node.ChildCount())
	for i := 0; i < nodeChildren; i++ {
		if child := node.Child(i); child.Type() == goNodeIdentifier {
			idents = append(idents, child.Content(src))
		}
	}
	// Exactly one identifier is the un-renamed form; the `as` form is an alias
	// and recordCrateAlias's caller handles it.
	if len(idents) != 1 || idents[0] == "" {
		return
	}
	if existing, seen := f.crateAliases[idents[0]]; seen && existing != idents[0] {
		return
	}
	f.crateAliases[idents[0]] = idents[0]
}

// rustQualifyFactKey prefixes a declaration key with the module that declares
// it, or returns it unchanged at a file's top level.
func rustQualifyFactKey(modulePath, name string) string {
	if modulePath == "" || name == "" {
		return name
	}
	return modulePath + "::" + name
}

// nodeFieldText returns a node field's source text, or "" when absent.
func nodeFieldText(node *sitter.Node, field string, src []byte) string {
	if node == nil {
		return ""
	}
	child := node.ChildByFieldName(field)
	if child == nil {
		return ""
	}
	return child.Content(src)
}

// rustTypeCtx carries everything the resolver needs about where an expression
// sits: the file's imports and declared types, the enclosing impl's `Self`
// type, and the types bound in scope.
type rustTypeCtx struct {
	src      []byte
	analysis *FileAnalysis
	facts    *rustFileFacts
	selfType string
	// bindings is the innermost binding scope in effect at the node being
	// resolved. Rust bindings are lexically scoped, and a single flat map per
	// function is not a safe approximation of that: two sibling blocks that
	// both bind `c` collapse into one entry, so whichever was recorded last
	// wins for the whole function — including calls that appear BEFORE it.
	// That reported an `Aes128` receiver as a `Des` one, which is worse than
	// an unresolved receiver, because it names a different algorithm with a
	// third-party crate's identity.
	bindings *rustBindings
	// parser is needed to extend the import scope when a nested block declares
	// its own `use` items.
	parser *RustParser
	// generics maps a generic parameter in scope to its first trait bound, or
	// to "" when it has none. A parameter is not a type: the Reference resolves
	// a method on it through the BOUNDS on it ("if `T` is a type parameter,
	// methods provided by trait bounds on `T` are looked up first"), so a
	// receiver typed `C` becomes the bound's identity, and an unbounded
	// parameter becomes no identity at all. Emitting `C` itself, as the parser
	// used to, invents a type that exists nowhere.
	generics map[string]string
}

// rustBindings is one lexical scope's bindings, chained to the scope that
// encloses it. A lookup walks outward, so an inner binding shadows an outer one
// inside its own scope and nowhere else.
type rustBindings struct {
	parent *rustBindings
	names  map[string]string
	// declared records every name this scope binds, INCLUDING the ones whose
	// type could not be resolved. A `let` shadows an item of the same name for
	// the rest of the block (Reference, Names -> Scopes) whether or not the
	// resolver can type it, and shadowing is what a bare call has to check
	// before it resolves the name as an import.
	declared map[string]bool
}

func newRustBindings(parent *rustBindings) *rustBindings {
	return &rustBindings{parent: parent, names: make(map[string]string), declared: make(map[string]bool)}
}

// child opens a nested scope.
func (b *rustBindings) child() *rustBindings {
	return newRustBindings(b)
}

// lookup returns the type bound to a name in the innermost scope that binds it.
func (b *rustBindings) lookup(name string) (string, bool) {
	for scope := b; scope != nil; scope = scope.parent {
		if typeText, ok := scope.names[name]; ok {
			return typeText, true
		}
	}
	return "", false
}

// bind records a binding in this scope.
func (b *rustBindings) bind(name, typeText string) {
	if b == nil || name == "" || typeText == "" {
		return
	}
	b.names[name] = typeText
}

// declare records that a name is bound in this scope, whatever its type.
func (b *rustBindings) declare(name string) {
	if b == nil || name == "" {
		return
	}
	b.declared[name] = true
}

// shadows reports whether a lexical binding of this name is in effect, in this
// scope or any enclosing one.
func (b *rustBindings) shadows(name string) bool {
	for scope := b; scope != nil; scope = scope.parent {
		if scope.declared[name] {
			return true
		}
		if _, typed := scope.names[name]; typed {
			return true
		}
	}
	return false
}

// declaredType returns the type bound to a name in scope, for the metadata a
// source node carries.
func (c *rustTypeCtx) declaredType(name string) string {
	typeText, _ := c.bindings.lookup(name)
	return typeText
}

// withBindings returns a copy of the context resolving against another scope.
func (c *rustTypeCtx) withBindings(bindings *rustBindings) *rustTypeCtx {
	next := *c
	next.bindings = bindings
	return &next
}

// rustSubstituteSelfConstPath rewrites `Self::SOME_CONST` to the impl's own type,
// which is the type an associated CONSTANT of `Self` has.
//
// `let mut A = Self::ONE; A.is_odd()` in p256 0.13.2
// src/arithmetic/scalar.rs:367 left `Self` in the receiver's path, and the
// keyword reached the key's type field: `p256::arithmetic::scalar.(Self).is_odd`.
// Same shape in orion's `Self::KEM_ID.to_be_bytes()`.
//
// Only a SCREAMING_SNAKE_CASE segment is substituted. `Self::PublicKey` is an
// associated TYPE, whose identity is the implementing type's choice and is not
// statically known (Reference, Paths -> Self); substituting the impl's own type
// there would name the wrong type, which is worse than naming none. Rust's own
// lints keep the two spellings apart: non_upper_case_globals for constants,
// non_camel_case_types for types.
func (c *rustTypeCtx) rustSubstituteSelfConstPath(text string) string {
	if c.selfType == "" || !strings.HasPrefix(text, rustSelfType+"::") {
		return text
	}
	rest := text[len(rustSelfType)+2:]
	segment := rest
	if idx := strings.Index(segment, "::"); idx > 0 {
		segment = segment[:idx]
	}
	if !rustIsScreamingCase(segment) {
		return text
	}
	return c.selfType + "::" + rest
}

// rustIsScreamingCase reports whether a path segment is spelled like an
// associated constant: upper-case letters, digits and underscores only, with at
// least one letter.
func rustIsScreamingCase(segment string) bool {
	letters := 0
	for i := 0; i < len(segment); i++ {
		ch := segment[i]
		switch {
		case ch >= 'A' && ch <= 'Z':
			letters++
		case ch >= '0' && ch <= '9', ch == '_':
		default:
			return false
		}
	}
	return letters > 0
}

// rustSubstituteGeneric replaces a generic parameter with its trait bound, or
// with the type its associated type resolves to when the KB catalogs one
// (`C::KeySize` where `C: KeyInit` names KeyInit::KeySize, not KeyInit
// itself).
func (c *rustTypeCtx) rustSubstituteGeneric(typeText string) string {
	if len(c.generics) == 0 || typeText == "" {
		return typeText
	}
	if resolved, ok := c.rustSubstituteGenericAssociatedType(typeText); ok {
		return resolved
	}
	head := rustTypeHead(typeText)
	bound, isGeneric := c.generics[head]
	if !isGeneric {
		return typeText
	}
	return bound
}

// rustSubstituteGenericAssociatedType resolves `C::Assoc` when C is a generic
// parameter bound to a trait the KB catalogs with that associated type. ok is
// false whenever there is nothing more specific than the bare trait bound
// already gives — including a cataloged (trait, name) pair with no usable
// default — so the caller falls through to its existing behavior rather than
// substituting an empty type.
func (c *rustTypeCtx) rustSubstituteGenericAssociatedType(typeText string) (string, bool) {
	if c.parser == nil || c.parser.kb == nil {
		return "", false
	}
	genericName, assocName, ok := rustSplitGenericAssociatedPath(typeText)
	if !ok {
		return "", false
	}
	bound, isGeneric := c.generics[genericName]
	if !isGeneric || bound == "" {
		return "", false
	}
	resolved, cataloged := c.parser.kb.TraitAssociatedType(bound, assocName)
	if !cataloged || resolved == "" {
		return "", false
	}
	return resolved, true
}

// rustSplitGenericAssociatedPath splits a type text of the exact shape
// `Generic::Assoc` (a bare two-segment path, once reference/pointer/mut/dyn
// noise is stripped) into its two names. A deeper path (`Generic::Assoc::More`)
// or anything else does not match this shape.
func rustSplitGenericAssociatedPath(typeText string) (generic, assoc string, ok bool) {
	t := rustStripTypeNoisePrefixes(typeText)
	idx := strings.Index(t, "::")
	if idx <= 0 {
		return "", "", false
	}
	rest := t[idx+2:]
	if rest == "" || strings.Contains(rest, "::") {
		return "", "", false
	}
	return t[:idx], rest, true
}

// collectRustGenerics records the generic parameters in scope for a
// declaration, with the trait bound each one carries — from the parameter list
// itself (`<C: BlockEncrypt>`) and from a `where` clause.
func collectRustGenerics(node *sitter.Node, src []byte, into map[string]string) {
	if node == nil {
		return
	}
	// An `impl<C: BlockEncrypt> Holder<C>` declares C for every method in the
	// block, so a method's own list is merged over the block's rather than
	// replacing it.
	collectRustGenericParams(node.ChildByFieldName("type_parameters"), src, into)
	applyRustWhereBounds(rustNamedChildOfType(node, "where_clause"), src, into)
}

// collectRustGenericParams records the parameters a `<...>` list declares, with
// any bound written inline.
func collectRustGenericParams(params *sitter.Node, src []byte, into map[string]string) {
	if params == nil {
		return
	}
	paramsNamedChildren := int(params.NamedChildCount())
	for i := 0; i < paramsNamedChildren; i++ {
		child := params.NamedChild(i)
		switch child.Type() {
		case goNodeTypeIdentifier:
			into[child.Content(src)] = ""
		case "constrained_type_parameter":
			if name := nodeFieldText(child, "left", src); name != "" {
				into[name] = rustFirstTraitBound(child.ChildByFieldName("bounds"), src)
			}
		case "optional_type_parameter":
			if name := nodeFieldText(child, "name", src); name != "" {
				into[name] = ""
			}
		}
	}
}

// applyRustWhereBounds fills in the bounds a `where` clause states for
// parameters already declared, which is the other half of the same information.
func applyRustWhereBounds(where *sitter.Node, src []byte, into map[string]string) {
	if where == nil {
		return
	}
	whereNamedChildren := int(where.NamedChildCount())
	for i := 0; i < whereNamedChildren; i++ {
		predicate := where.NamedChild(i)
		if predicate.Type() != "where_predicate" {
			continue
		}
		name := rustTypeHead(nodeFieldText(predicate, "left", src))
		if name == "" {
			continue
		}
		if _, known := into[name]; !known {
			continue
		}
		if bound := rustFirstTraitBound(predicate.ChildByFieldName("bounds"), src); bound != "" {
			into[name] = bound
		}
	}
}

// rustNamedChildOfType returns a node's first named child of a given kind. A
// `where` clause is not exposed as a named field of function_item, so it has to
// be found by kind.
func rustNamedChildOfType(node *sitter.Node, kind string) *sitter.Node {
	if node == nil {
		return nil
	}
	nodeNamedChildren := int(node.NamedChildCount())
	for i := 0; i < nodeNamedChildren; i++ {
		if child := node.NamedChild(i); child.Type() == kind {
			return child
		}
	}
	return nil
}

// rustZeroMethodMarkerTraits are prelude traits that declare no method of
// their own (auto traits and compiler-known markers). A bound to one of these
// gives a generic parameter no method to call: `T: Sized + Digest` means `T`
// answers to `Digest`'s methods, never `Sized`'s, because `Sized` has none.
// Taking whichever bound comes first in the text fabricated `std.Sized.update`
// for a real `Digest::update` call, order-dependently -- `T: Digest + Sized`
// resolved correctly by accident, `T: Sized + Digest` did not.
var rustZeroMethodMarkerTraits = map[string]bool{
	"Sized": true, "Send": true, "Sync": true, "Copy": true, "Eq": true,
}

// rustFirstTraitBound returns the first trait a bound list names that could
// actually own a called method, which is the one that gives a generic
// receiver its identity. A zero-method marker trait is skipped rather than
// returned: it can never be what a method call resolves through.
func rustFirstTraitBound(bounds *sitter.Node, src []byte) string {
	if bounds == nil {
		return ""
	}
	boundsNamedChildren := int(bounds.NamedChildCount())
	for i := 0; i < boundsNamedChildren; i++ {
		child := bounds.NamedChild(i)
		switch child.Type() {
		case goNodeTypeIdentifier, javaNodeScopedTypeIdentifier, javaNodeGenericType:
			name := rustScopedTypeText(child, src)
			if rustZeroMethodMarkerTraits[rustTypeHead(name)] {
				continue
			}
			return name
		case "lifetime", "removed_trait_bound":
			continue
		}
	}
	return ""
}

// rustExprType resolves an expression node to the type text of its value, or
// "" when the type cannot be established. Returning "" is deliberate and
// preferable to guessing: the caller emits an unresolved receiver rather than a
// confident wrong identity.
func (c *rustTypeCtx) rustExprType(node *sitter.Node, depth int) string {
	if node == nil || depth > rustMaxTypeDepth {
		return ""
	}
	if typeText, handled := c.rustTransparentExprType(node, depth); handled {
		return typeText
	}
	if typeText, handled := c.rustNamedTypeExprType(node); handled {
		return typeText
	}
	switch node.Type() {
	case "if_expression":
		return c.rustIfType(node, depth)
	case "match_expression":
		return c.rustMatchType(node, depth)
	case "struct_expression":
		return nodeFieldText(node, "name", c.src)
	case rustNodeCallExpression:
		return c.rustCallType(node, depth)
	case rustNodeFieldExpression:
		return c.rustFieldType(node, depth)
	case "index_expression":
		return rustElementType(c.rustExprType(node.NamedChild(0), depth+1))
	case "macro_invocation":
		return c.rustMacroType(node, depth)
	}
	return ""
}

// rustNamedTypeExprType handles the expression kinds whose type is written out
// in the source: a name, `self`, a path, a type node, or a cast.
func (c *rustTypeCtx) rustNamedTypeExprType(node *sitter.Node) (string, bool) {
	switch node.Symbol() {
	case rustSyms.identifier:
		return c.rustIdentifierType(node), true
	case rustSyms.selfKeyword:
		return c.rustSubstituteGeneric(c.selfType), true
	case rustSyms.scopedIdentifier, rustSyms.scopedTypeIdentifier:
		return c.rustSubstituteSelfConstPath(rustScopedTypeText(node, c.src)), true
	case rustSyms.typeIdentifier, rustSyms.genericType, rustSyms.genericTurbofish,
		rustSyms.referenceType, rustSyms.dynamicType, rustSyms.abstractType:
		return node.Content(c.src), true
	case rustSyms.typeCast:
		return nodeFieldText(node, "type", c.src), true
	}
	return "", false
}

// rustTransparentExprType handles the expression kinds that do not change the
// type of the value they hold: a turbofish, a grouping, a reference or deref, an
// `.await`, a `?`, and a block's trailing expression. Every one of these used to
// defeat the text-based inference outright.
func (c *rustTypeCtx) rustTransparentExprType(node *sitter.Node, depth int) (string, bool) {
	symbol := node.Symbol()
	if rustIsBlockLike(symbol) {
		return c.rustExprType(rustBlockTail(node), depth+1), true
	}
	switch symbol {
	case rustSyms.genericFunction:
		return c.rustExprType(node.Child(0), depth+1), true
	case rustSyms.parenthesized:
		return c.rustExprType(rustInnerExpression(node), depth+1), true
	case rustSyms.referenceExpression, rustSyms.unaryExpression:
		if v := node.ChildByFieldName("value"); v != nil {
			return c.rustExprType(v, depth+1), true
		}
		return c.rustExprType(rustInnerExpression(node), depth+1), true
	case rustSyms.awaitExpression:
		// An `async fn`'s declared return type is already its output, so
		// awaiting it is a passthrough.
		return c.rustExprType(node.NamedChild(0), depth+1), true
	case rustSyms.tryExpression:
		// `?` yields the value INSIDE the Result or Option, which does not
		// Deref to it.
		return rustUnwrappedPatternType(c.rustExprType(node.NamedChild(0), depth+1), c.facts), true
	}
	return "", false
}

// rustIdentifierType types a bare name: a binding if one is in scope, otherwise
// a type from the type namespace, and nothing at all for a value we cannot type.
func (c *rustTypeCtx) rustIdentifierType(node *sitter.Node) string {
	name := node.Content(c.src)
	if t, ok := c.bindings.lookup(name); ok && t != "" {
		return c.rustSubstituteGeneric(t)
	}
	// A bare name that is not a binding may still be a type in the type
	// namespace — an imported or locally declared one. A name that is neither is
	// a value we cannot type, not a type.
	if !looksLikeRustTypeName(name) {
		return ""
	}
	if _, ok := c.analysis.Imports[name]; ok {
		return name
	}
	if c.facts.isLocalType(name) {
		return name
	}
	return ""
}

// rustIfType types an `if` expression from whichever branch resolves.
func (c *rustTypeCtx) rustIfType(node *sitter.Node, depth int) string {
	if t := c.rustExprType(node.ChildByFieldName("consequence"), depth+1); t != "" {
		return t
	}
	if alt := node.ChildByFieldName("alternative"); alt != nil {
		return c.rustExprType(rustInnerExpression(alt), depth+1)
	}
	return ""
}

// rustCallType types the value a call produces: an associated function's own
// type for a constructor, a declared return type for a plain function, and the
// receiver's type for the wrapper-transparent methods.
func (c *rustTypeCtx) rustCallType(node *sitter.Node, depth int) string {
	fn := node.ChildByFieldName("function")
	if fn == nil {
		return ""
	}
	if fn.Type() == rustNodeGenericFunction && fn.ChildCount() > 0 {
		fn = fn.Child(0)
	}
	switch fn.Type() {
	case javaNodeScopedIdentifier:
		return c.rustScopedCallType(node, fn, depth)
	case goNodeIdentifier:
		return c.rustPlainCallType(node, fn, depth)
	case rustNodeFieldExpression:
		return c.rustMethodCallType(fn, depth)
	}
	return ""
}

// rustScopedCallType types `Type::assoc(..)`, `module::func(..)` and
// `Self::assoc(..)`.
func (c *rustTypeCtx) rustScopedCallType(node, fn *sitter.Node, depth int) string {
	path := fn.ChildByFieldName("path")
	if path == nil {
		return ""
	}
	typeText := rustScopedTypeText(path, c.src)
	// `Self::new()` inside an impl block means the impl's own type. The
	// Reference gives `Self` its own scope; keeping the literal produced keys
	// like `Self.helper` and `pkg.(Self).go`.
	if rustTypeHead(typeText) == rustSelfType && c.selfType != "" {
		if ret, ok := c.lookupReturnIn(rustTypePathText(c.selfType), rustTypeHead(c.selfType)+"::"+nodeFieldText(fn, "name", c.src)); ok {
			return ret
		}
		return c.selfType
	}
	head := rustTypeHead(typeText)
	// `Arc::new(inner)`, `Box::new(inner)`: keep the wrapper AROUND the value.
	// Collapsing it to the value made the wrapper's own methods land on the
	// value's type — `aes.(Aes128).lock` for a `Mutex::lock` — and the deref
	// rules below already see through it when a method is called on the value.
	if rustWrapperTypes[head] && rustWrappingConstructors[nodeFieldText(fn, "name", c.src)] {
		// The wrapper keeps its PATH: `tokio::sync::Mutex` and
		// `std::sync::Mutex` differ in whether their lock can be poisoned, and
		// dropping the path made the awaited one look like the other. A bare
		// name (`Vec::from`, `Mutex::new`) carries no path at all — prefixing
		// `rustModulePathText(typeText)` unconditionally duplicated the head
		// into `Vec::Vec<..>`, which `rustQualifiedIdentity` then read as a
		// module named `Vec` containing a type also named `Vec`, falling back
		// to the analyzed crate's own package for every value wrapper (Vec,
		// Option, Result never get seen through, so this never self-corrects
		// the way a Deref wrapper's own bug would).
		wrapper := head
		if path := rustTypePathText(typeText); path != "" {
			wrapper = path + "::" + head
		}
		return c.rustWrappedArgumentType(node, wrapper, depth)
	}
	if head != "" && !looksLikeRustTypeName(head) {
		// A module path, not a type: `std::ptr::null_mut()` produces no
		// receiver identity of its own.
		if ret, ok := c.lookupReturnIn(typeText, nodeFieldText(fn, "name", c.src)); ok {
			return ret
		}
		return ""
	}
	return typeText
}

// rustPlainCallType types a call written as a bare name: a free function, a
// wrapping variant constructor, or a tuple struct's constructor.
func (c *rustTypeCtx) rustPlainCallType(node, fn *sitter.Node, depth int) string {
	name := fn.Content(c.src)
	// `Some(x)` / `Ok(x)` are enum-variant constructors that wrap.
	if name == "Some" || name == "Ok" {
		wrapper := "Option"
		if name == "Ok" {
			wrapper = "Result"
		}
		return c.rustWrappedArgumentType(node, wrapper, depth)
	}
	if ret, ok := c.lookupReturn(name); ok {
		return ret
	}
	// A tuple struct's constructor is a function in the value namespace whose
	// name is the type: `struct Wrap(Aes128)` makes `Wrap(c)` a `Wrap`.
	if !looksLikeRustTypeName(name) {
		return ""
	}
	if c.facts.isLocalType(name) {
		return name
	}
	if _, ok := c.analysis.Imports[name]; ok {
		return name
	}
	return ""
}

// rustMethodCallType types the value a method call produces.
func (c *rustTypeCtx) rustMethodCallType(fn *sitter.Node, depth int) string {
	method := nodeFieldText(fn, "field", c.src)
	receiver := fn.ChildByFieldName("value")
	switch {
	case rustPoisonableAccessors[method]:
		inner := rustUnwrapWrapperType(c.rustExprType(receiver, depth+1), c.facts)
		if !rustValueWrappers[rustTypeHead(inner)] {
			return inner
		}
		arg, ok := rustGenericArgument(inner)
		if !ok {
			return inner
		}
		// Only the standard library's locks can be poisoned. tokio's are
		// awaited and hand back the guard directly, so wrapping their result in
		// a Result left the awaited value typed as one.
		if strings.Contains(inner, "tokio") {
			return arg
		}
		return "Result<" + arg + ">"
	case rustUnwrappingMethods[method]:
		// Only a wrapper has contents to hand back. Peeling unconditionally
		// stripped a generic argument off a type that is not one:
		// `Mutex<Archive<Reader>>.lock()` already yields `Archive<Reader>`, and
		// the `.unwrap()` after it peeled again, landing on `Reader` — a type
		// from a different crate than the receiver.
		// The receiver may sit behind Deref wrappers first — `.lock()` on an
		// `Arc<Mutex<T>>` reaches the Mutex through the Arc — so those are
		// peeled before asking whether what remains is a wrapper with contents
		// to hand back.
		receiverType := rustUnwrapWrapperType(c.rustExprType(receiver, depth+1), c.facts)
		if rustValueWrappers[rustTypeHead(receiverType)] {
			return rustUnwrappedPatternType(receiverType, c.facts)
		}
		return receiverType
	case rustTransparentMethods[method], rustContainerPreservingMethods[method]:
		return c.rustExprType(receiver, depth+1)
	case rustElementYieldingMethods[method]:
		return rustElementType(c.rustExprType(receiver, depth+1))
	}
	if recv := c.rustExprType(receiver, depth+1); recv != "" {
		if ret, ok := c.lookupReturnIn(rustTypePathText(recv), rustTypeHead(recv)+"::"+method); ok {
			return ret
		}
	}
	if ret, ok := c.lookupReturn(method); ok {
		return ret
	}
	return ""
}

// rustWrappedArgumentType types a wrapping constructor's result, keeping the
// wrapper around the value it was handed.
func (c *rustTypeCtx) rustWrappedArgumentType(node *sitter.Node, wrapper string, depth int) string {
	inner := rustFirstArgument(node)
	if inner == nil {
		return ""
	}
	innerType := c.rustExprType(inner, depth+1)
	if innerType == "" {
		return ""
	}
	return strings.TrimPrefix(wrapper, "::") + "<" + innerType + ">"
}

// rustMacroType types the value the standard collection macros produce. A macro
// body is opaque to the grammar, so this is deliberately limited to the ones
// whose result type is fixed by their arguments — `vec![cipher]` is a
// `Vec<Cipher>`, and that is enough for the indexing and iteration shapes real
// code uses.
func (c *rustTypeCtx) rustMacroType(node *sitter.Node, depth int) string {
	if nodeFieldText(node, "macro", c.src) != "vec" {
		return ""
	}
	nodeNamedChildren := int(node.NamedChildCount())
	for i := 0; i < nodeNamedChildren; i++ {
		child := node.NamedChild(i)
		if child.Type() != rustNodeTokenTree {
			continue
		}
		if element := c.rustTokenTreeElementType(child, depth); element != "" {
			return "Vec<" + element + ">"
		}
	}
	return ""
}

// rustTokenTreeElementType reads the one shape a macro's raw tokens can be typed
// from: an expression the grammar still parsed, or an identifier followed by a
// token tree, which is a call.
func (c *rustTypeCtx) rustTokenTreeElementType(tree *sitter.Node, depth int) string {
	namedCountJ := int(tree.NamedChildCount())
	for j := 0; j < namedCountJ; j++ {
		token := tree.NamedChild(j)
		if t := c.rustExprType(token, depth+1); t != "" {
			return t
		}
		if token.Type() != goNodeIdentifier {
			continue
		}
		next := tree.NamedChild(j + 1)
		if next == nil || next.Type() != rustNodeTokenTree {
			continue
		}
		if ret, ok := c.lookupReturn(token.Content(c.src)); ok {
			return ret
		}
	}
	return ""
}

func (c *rustTypeCtx) lookupReturn(name string) (string, bool) {
	return c.lookupReturnIn("", name)
}

// lookupReturnIn resolves a declared return type, preferring the declaration in
// the module the call's own path names.
func (c *rustTypeCtx) lookupReturnIn(pathText, name string) (string, bool) {
	if name == "" {
		return "", false
	}
	ret := ""
	for _, key := range c.factKeyCandidates(pathText, name) {
		if candidate, ok := c.facts.returnType(key); ok && candidate != "" {
			ret = candidate
			break
		}
	}
	if ret == "" {
		return "", false
	}
	return c.substituteSelfReturn(c.qualifyFactType(ret))
}

// qualifyFactType gives a bare type name THE CRATE'S OWN FACTS supplied the
// module that declares it, so the name is never re-resolved lexically in the
// scope that merely observed the value.
//
// The two are different questions. A name the programmer WRITES in a scope
// resolves in that scope, and a glob there may legitimately claim it. A name
// the resolver derived — from a declared return, a struct field, an enum
// variant — was already resolved where it was declared; re-resolving it against
// the observing scope's imports and globs hands the crate's own type to whoever
// happens to be glob-imported there. aws-lc-rs 1.12.2
// src/cipher/streaming.rs declares `BufferUpdate` at :29 and returns it at
// :169/:390; its `mod tests` at :501 writes `use paste::*;` and never writes
// `BufferUpdate` at all, yet four `.written()` calls on the returned value came
// out as `paste.(BufferUpdate).written` — a crate that exports only macros
// named as the owner of a type. The same re-resolution let `use aes::Aes128;`
// claim a `crate::local::Aes128` returned by the crate's own constructor.
//
// A name two modules of the crate declare has no single declaring module and is
// left alone: declaringModule reports nothing for it, and an imprecise crate
// answer must not displace what the scope resolved.
func (c *rustTypeCtx) qualifyFactType(typeText string) string {
	if typeText == "" {
		return typeText
	}
	// The name to qualify is the one INSIDE the wrappers: a declared
	// `-> Result<BufferUpdate<'a>, Unspecified>` carries the identity in its Ok
	// arm, and the accessor that unwraps it runs long after this point. A tuple
	// arm — `-> Result<(DecryptionContext, BufferUpdate), Unspecified>` — hands
	// one identity to each destructured binding, so every element is qualified.
	unwrapped := rustUnwrapAnyWrapperType(typeText, c.facts)
	if elements, ok := rustTupleElements(unwrapped); ok {
		for _, element := range elements {
			typeText = c.qualifyFactHead(typeText, element)
		}
		return typeText
	}
	return c.qualifyFactHead(typeText, unwrapped)
}

// qualifyFactHead rewrites one bare name inside type text to the module that
// declares it, leaving the rest of the text as it stands.
func (c *rustTypeCtx) qualifyFactHead(typeText, part string) string {
	if strings.Contains(part, "::") {
		return typeText
	}
	head := rustTypeHead(part)
	if head == "" || head == rustSelfType || !rustIsNameableType(head) {
		return typeText
	}
	if _, generic := c.generics[head]; generic {
		return typeText
	}
	module, ok := c.facts.declaringModule(head)
	if !ok || module == "" {
		return typeText
	}
	if rustIntraCrateImportWins(c.analysis, head) {
		return typeText
	}
	return rustReplaceTypeHead(typeText, head, module+"::"+head)
}

// rustTupleElements splits a parenthesised tuple type into its elements,
// respecting nested brackets. A single parenthesised type is not a tuple.
func rustTupleElements(typeText string) ([]string, bool) {
	t := strings.TrimSpace(typeText)
	if !strings.HasPrefix(t, "(") || !strings.HasSuffix(t, ")") {
		return nil, false
	}
	inner := t[1 : len(t)-1]
	var elements []string
	depth, start := 0, 0
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '<', '(', '[':
			depth++
		case '>', ')', ']':
			depth--
		case ',':
			if depth == 0 {
				elements = append(elements, strings.TrimSpace(inner[start:i]))
				start = i + 1
			}
		}
	}
	if len(elements) == 0 {
		return nil, false
	}
	return append(elements, strings.TrimSpace(inner[start:])), true
}

// rustIntraCrateImportWins reports whether an explicit import in the observing
// scope already names the public path of a type this crate declares.
//
// A crate re-exports its own types: ring declares `LessSafeKey` in
// `ring::aead::less_safe_key` and every user — including ring itself, via
// `use super::{.., LessSafeKey, ..}` in src/aead/sealing_key.rs — names it
// `ring::aead::LessSafeKey`, which is the path ring.yaml keys. When the import
// in scope resolves INSIDE this crate it is that re-export, and it is a better
// answer than the private declaring module.
//
// An import naming another crate cannot be a re-export of a type this crate
// declares, so it says nothing about the derived name and must not stop the
// declaring module from being used: that is exactly the `use aes::Aes128;`
// beside a `crate::local::Aes128` case.
func rustIntraCrateImportWins(analysis *FileAnalysis, head string) bool {
	if analysis == nil {
		return false
	}
	if _, aliased := analysis.ImportAliases[head]; aliased {
		return true
	}
	imported, ok := analysis.Imports[head]
	if !ok || imported == "" {
		return false
	}
	return rustCrateRoot(imported) == rustCrateRoot(analysis.PackagePath)
}

// rustCrateRoot returns a module path's first segment, which names the crate.
func rustCrateRoot(path string) string {
	if idx := strings.Index(path, "::"); idx > 0 {
		return path[:idx]
	}
	return path
}

// rustReplaceTypeHead substitutes the first whole-identifier occurrence of head
// in type text, keeping any wrapper, reference or generic argument around it:
// `Result<BufferUpdate<'_>, Unspecified>` becomes
// `Result<crate::path::BufferUpdate<'_>, Unspecified>`. A substring match would
// rewrite `Wrapper` when the head is `Wrap`.
func rustReplaceTypeHead(typeText, head, replacement string) string {
	for i := 0; i+len(head) <= len(typeText); i++ {
		if typeText[i:i+len(head)] != head {
			continue
		}
		if i > 0 && rustIsIdentifierByte(typeText[i-1]) {
			continue
		}
		if end := i + len(head); end < len(typeText) && rustIsIdentifierByte(typeText[end]) {
			continue
		}
		return typeText[:i] + replacement + typeText[i+len(head):]
	}
	return typeText
}

func rustIsIdentifierByte(ch byte) bool {
	switch {
	case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9', ch == '_', ch == ':':
		return true
	}
	return false
}

// substituteSelfReturn resolves a `-> Self` return type to the impl's own type.
func (c *rustTypeCtx) substituteSelfReturn(ret string) (string, bool) {
	if rustTypeHead(ret) != rustSelfType {
		return ret, true
	}
	if c.selfType == "" {
		return "", false
	}
	return c.selfType, true
}

// factKeyCandidates orders the keys a declaration could have been recorded
// under, most precise first.
//
// The precise key comes from the PATH THE SOURCE WROTE: `m2::Session` means the
// `Session` declared in module `m2`, whichever module the call sits in. Only
// when the source wrote a bare name does the caller's own module apply. Using
// the caller's module for a qualified path made two modules' same-named types
// indistinguishable, and the conflict rule then dropped both.
func (c *rustTypeCtx) factKeyCandidates(pathText, name string) []string {
	if name == "" {
		return nil
	}
	var keys []string
	if pathText != "" {
		resolved := rustAbsoluteModulePath(c.analysis, pathText)
		if local, ok := rustLocalModulePath(c.analysis, resolved); ok {
			resolved = local
		}
		if resolved != "" {
			keys = append(keys, resolved+"::"+name)
		}
	}
	if qualified := rustQualifyFactKey(c.modulePath(), name); qualified != name {
		keys = append(keys, qualified)
	}
	return append(keys, name)
}

// modulePath returns the module path of the code being resolved, relative to
// the file, for looking up module-qualified declarations.
func (c *rustTypeCtx) modulePath() string {
	if c.analysis == nil {
		return ""
	}
	return c.analysis.PackagePath
}

// rustFieldType types a field access through the declaring struct's field
// types, which is how `self.cipher.encrypt_block(..)` — a shape as common as
// the constructor idiom — gets an identity at all.
func (c *rustTypeCtx) rustFieldType(node *sitter.Node, depth int) string {
	field := nodeFieldText(node, "field", c.src)
	if field == "" {
		return ""
	}
	owner := c.rustExprType(node.ChildByFieldName("value"), depth+1)
	if owner == "" {
		return ""
	}
	head := rustTypeHead(owner)
	for _, key := range c.factKeyCandidates(rustTypePathText(owner), head) {
		if fields, ok := c.facts.fields(key); ok {
			if t, ok := fields[field]; ok {
				return c.qualifyFactType(t)
			}
		}
	}
	return ""
}

func (c *rustTypeCtx) rustMatchType(node *sitter.Node, depth int) string {
	body := node.ChildByFieldName("body")
	if body == nil {
		return ""
	}
	bodyNamedChildren := int(body.NamedChildCount())
	for i := 0; i < bodyNamedChildren; i++ {
		arm := body.NamedChild(i)
		if arm.Type() != "match_arm" {
			continue
		}
		if t := c.rustExprType(arm.ChildByFieldName("value"), depth+1); t != "" {
			return t
		}
	}
	return ""
}

// rustInnerExpression returns the single meaningful child of a wrapper node,
// skipping the punctuation the grammar keeps as anonymous children.
func rustInnerExpression(node *sitter.Node) *sitter.Node {
	if node == nil {
		return nil
	}
	nodeNamedChildren := int(node.NamedChildCount())
	for i := 0; i < nodeNamedChildren; i++ {
		child := node.NamedChild(i)
		if rustIsComment(child.Symbol()) || child.Type() == "mutable_specifier" {
			continue
		}
		return child
	}
	return nil
}

// rustBlockTail returns a block's trailing expression — the value the block
// evaluates to. Reading the block's TEXT instead is what leaked a literal
// "{ " into emitted keys.
func rustBlockTail(node *sitter.Node) *sitter.Node {
	if node == nil {
		return nil
	}
	for i := int(node.NamedChildCount()) - 1; i >= 0; i-- {
		child := node.NamedChild(i)
		if rustIsComment(child.Symbol()) {
			continue
		}
		switch child.Symbol() {
		case rustSyms.expressionStatement, rustSyms.letDeclaration:
			// A block whose last statement is a statement has no tail value.
			return nil
		}
		if child.Type() == "empty_statement" {
			return nil
		}
		return child
	}
	return nil
}

// rustScopedTypeText renders a scoped path as type text, dropping the type
// arguments a turbofish adds. Reading the node's text and splitting on "::"
// mangles `<T as Trait>::method` and `Type::<A>::method`; walking the path and
// name fields does not.
func rustScopedTypeText(node *sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}
	if text, handled := rustWrappedTypeText(node, src); handled {
		return text
	}
	switch node.Type() {
	case goNodeIdentifier, goNodeTypeIdentifier, "primitive_type", rustNodeSelf, rustNodeCrate, rustNodeSuper, "metavariable":
		return node.Content(src)
	case javaNodeGenericType, "generic_type_with_turbofish":
		if t := node.ChildByFieldName("type"); t != nil {
			return rustScopedTypeText(t, src)
		}
		return stripRustTypeArguments(node.Content(src))
	case "qualified_type":
		return rustScopedTypeText(node.ChildByFieldName("type"), src)
	case javaNodeScopedIdentifier, javaNodeScopedTypeIdentifier:
		path := rustScopedTypeText(node.ChildByFieldName("path"), src)
		name := rustScopedTypeText(node.ChildByFieldName("name"), src)
		switch {
		case path == "":
			return name
		case name == "":
			return path
		}
		return path + "::" + name
	}
	return stripRustTypeArguments(node.Content(src))
}

// rustWrappedTypeText handles the type positions that wrap another type: a
// reference, a `dyn Trait`, and the bracketed `<T as Trait>` disambiguator.
// None of their punctuation or keywords belongs to a name, and left in they
// reached the key: `&SignatureBytes<C>`, `dyn Encrypter` with a space,
// `<Aes128 as KeyInit>`.
func rustWrappedTypeText(node *sitter.Node, src []byte) (string, bool) {
	switch node.Type() {
	case "reference_type":
		if inner := node.ChildByFieldName("type"); inner != nil {
			return rustScopedTypeText(inner, src), true
		}
		return rustTypeHead(node.Content(src)), true
	case "dynamic_type":
		// The trait names the identity; `dyn` is a keyword.
		if trait := node.ChildByFieldName("trait"); trait != nil {
			return rustScopedTypeText(trait, src), true
		}
		return rustTypeHead(node.Content(src)), true
	case "bracketed_type":
		// `<Aes128 as KeyInit>::new` — the qualified type's own type is the
		// identity; the trait only disambiguates which impl is meant.
		inner := rustInnerExpression(node)
		if inner == nil {
			return "", true
		}
		if inner.Type() == "qualified_type" {
			return rustScopedTypeText(inner.ChildByFieldName("type"), src), true
		}
		return rustScopedTypeText(inner, src), true
	}
	return "", false
}

// rustFirstArgument returns a call's first argument expression.
func rustFirstArgument(call *sitter.Node) *sitter.Node {
	args := call.ChildByFieldName("arguments")
	if args == nil {
		return nil
	}
	argsNamedChildren := int(args.NamedChildCount())
	for i := 0; i < argsNamedChildren; i++ {
		child := args.NamedChild(i)
		switch child.Type() {
		case javaNodeLineComment, javaNodeBlockComment, rustNodeDocComment:
			continue
		}
		return child
	}
	return nil
}

// rustElementType turns a container type into the type of an element read out
// of it, so `v[0].encrypt_block(..)` types as the cipher and not as the Vec.
func rustElementType(container string) string {
	if container == "" {
		return ""
	}
	if inner, ok := rustGenericArgument(container); ok {
		return inner
	}
	t := strings.TrimSpace(container)
	t = strings.TrimPrefix(t, "&")
	t = strings.TrimSpace(strings.TrimPrefix(t, "mut "))
	if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
		t = strings.TrimSpace(t[1 : len(t)-1])
		if idx := strings.LastIndex(t, ";"); idx > 0 {
			t = strings.TrimSpace(t[:idx])
		}
		return t
	}
	return ""
}

// rustGenericArgument returns a generic type's first type argument.
func rustGenericArgument(typeText string) (string, bool) {
	open := strings.Index(typeText, "<")
	if open < 0 || !strings.HasSuffix(strings.TrimSpace(typeText), ">") {
		return "", false
	}
	inner := strings.TrimSpace(typeText[open+1 : strings.LastIndex(typeText, ">")])
	depth := 0
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '<', '(', '[':
			depth++
		case '>', ')', ']':
			depth--
		case ',':
			if depth == 0 {
				return strings.TrimSpace(inner[:i]), true
			}
		}
	}
	if inner == "" {
		return "", false
	}
	return inner, true
}

// rustUnwrapWrapperType sees through the ownership wrappers to the type that
// carries the identity: `Arc<Mutex<Aes128>>` is an `Aes128` for every purpose
// a crypto rule cares about. facts may be nil, which limits the check to the
// hardcoded table.
func rustUnwrapWrapperType(typeText string, facts *rustFileFacts) string {
	return rustUnwrapTypeWith(typeText, rustDerefWrappers, facts)
}

// rustUnwrapAnyWrapperType sees through either kind of wrapper, for the
// positions where the CONTENTS are what is being named — a pattern binding, or
// the result of an unwrapping accessor.
func rustUnwrapAnyWrapperType(typeText string, facts *rustFileFacts) string {
	return rustUnwrapTypeWith(typeText, rustWrapperTypes, facts)
}

// rustUnwrapTypeWith peels off a wrapper name known either to the hardcoded
// table (the standard library's own wrappers, whose Deref impl this parser
// never reads) or, additionally, to facts.isDerefTransparent — a third-party
// wrapper the analyzed crate's OWN source proved transparent by declaring a
// real `impl<T> Deref for Wrapper<T> { type Target = T; }`.
func rustUnwrapTypeWith(typeText string, wrappers map[string]bool, facts *rustFileFacts) string {
	t := strings.TrimSpace(typeText)
	for i := 0; i < rustMaxTypeDepth; i++ {
		t = strings.TrimSpace(t)
		t = strings.TrimPrefix(t, "&")
		t = strings.TrimSpace(t)
		t = strings.TrimSpace(strings.TrimPrefix(t, "mut "))
		t = strings.TrimSpace(strings.TrimPrefix(t, "dyn "))
		t = strings.TrimSpace(strings.TrimPrefix(t, "impl "))
		head := t
		if idx := strings.Index(head, "<"); idx >= 0 {
			head = strings.TrimSpace(head[:idx])
		}
		if lastSep := strings.LastIndex(head, "::"); lastSep >= 0 {
			head = head[lastSep+2:]
		}
		if !wrappers[head] && !facts.isDerefTransparent(head) {
			return t
		}
		inner, ok := rustGenericArgument(t)
		if !ok {
			return t
		}
		t = inner
	}
	return t
}

// rustTypeHead reduces type text to the bare type name a callee key carries:
// no references, no `dyn`/`impl`, no type arguments, no path.
// rustStripTypeNoisePrefixes strips the reference/pointer/mut/dyn/impl/ref
// noise a type text may carry, leaving the path underneath untouched (unlike
// rustTypeHead, which also collapses the path down to one segment).
func rustStripTypeNoisePrefixes(typeText string) string {
	t := rustStripLifetimes(strings.TrimSpace(typeText))
	for _, prefix := range []string{"&", "*const ", "*mut ", "*", "mut ", "dyn ", "impl ", "ref "} {
		t = rustStripLifetimes(strings.TrimSpace(strings.TrimPrefix(t, prefix)))
	}
	return t
}

func rustTypeHead(typeText string) string {
	t := rustStripTypeNoisePrefixes(typeText)
	if strings.HasPrefix(t, "(") && strings.HasSuffix(t, ")") {
		t = strings.TrimSpace(t[1 : len(t)-1])
	}
	if idx := strings.Index(t, "<"); idx >= 0 {
		t = strings.TrimSpace(t[:idx])
	}
	t = strings.TrimSuffix(strings.TrimSpace(t), "::")
	if idx := strings.Index(t, "+"); idx >= 0 {
		// `dyn Digest + Send` — the first bound names the identity.
		t = strings.TrimSpace(t[:idx])
	}
	// A callee key's type field carries the bare type name; the path belongs
	// in the package field.
	if lastSep := strings.LastIndex(t, "::"); lastSep >= 0 {
		t = t[lastSep+2:]
	}
	return strings.TrimSpace(t)
}

// rustIsTypeCase reports whether a path segment is spelled like a type rather
// than like a module: Rust's own conventions, which the compiler's lint set
// enforces, put types in UpperCamelCase and modules in snake_case.
func rustIsTypeCase(segment string) bool {
	if segment == "" || !rustIsNameableType(segment) {
		return false
	}
	first := segment[0]
	return first >= 'A' && first <= 'Z'
}

// resolveRustReceiverTypePackage returns the package a bare type name belongs
// to, without the type itself.
// rustModuleDeclaredTypePackage returns the package of a type the CURRENT
// MODULE declares under a name that module also imports.
//
// Rust keeps macros in a namespace of their own (Reference, Names ->
// Namespaces), so `use thiserror::Error;` — the derive macro — and
// `pub enum Error` coexist legally in one module. The import table is flat, so
// the macro import claimed the type name: russh 0.54.6 src/keys/mod.rs imports
// the macro at :67 and declares the enum at :90, and every call on the enum
// came out as `thiserror.(Error).*` instead of `russh::keys.(Error).*`.
//
// A module cannot declare a type and import a type of the same name — that is
// E0255, a hard error — so whenever both are present the import must live in
// another namespace, and the module's own declaration is what the type name
// means. The declaration has to be in THIS module: a name declared elsewhere in
// the crate does not compete with an import here.
func rustModuleDeclaredTypePackage(analysis *FileAnalysis, name string) (string, bool) {
	if analysis == nil || name == "" || analysis.rustFacts == nil {
		return "", false
	}
	if _, imported := analysis.Imports[name]; !imported {
		return "", false
	}
	module, ok := analysis.rustFacts.declaringModule(name)
	if !ok || module == "" || module != analysis.PackagePath {
		return "", false
	}
	return module, true
}

func resolveRustReceiverTypePackage(analysis *FileAnalysis, name string) string {
	pkg, _ := resolveRustReceiverType(analysis, name)
	return pkg
}

// rustStripLifetimes removes lifetime arguments from type text. A lifetime is
// part of a reference's type, never part of the name a callee key carries, and
// `&'a C` left the tick-name attached so the type resolved to nothing.
func rustStripLifetimes(typeText string) string {
	for {
		idx := strings.Index(typeText, "'")
		if idx < 0 {
			return strings.TrimSpace(typeText)
		}
		end := idx + 1
		for end < len(typeText) {
			ch := typeText[end]
			if ch == '_' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' {
				end++
				continue
			}
			break
		}
		if end == idx+1 {
			// A character literal, not a lifetime.
			return strings.TrimSpace(typeText)
		}
		typeText = strings.TrimSpace(typeText[:idx] + strings.TrimPrefix(strings.TrimSpace(typeText[end:]), ","))
	}
}

// rustTypePathText returns the module path a type text carries, or "" when the
// source wrote a bare name. No crate facts are in scope here, so this only
// unwraps the hardcoded wrapper table.
func rustTypePathText(typeText string) string {
	unwrapped := rustUnwrapAnyWrapperType(typeText, nil)
	lastSep := strings.LastIndex(unwrapped, "::")
	if lastSep <= 0 {
		return ""
	}
	return rustModulePathText(unwrapped[:lastSep])
}

// rustModulePathText reduces a type's path prefix to a module path fit for a
// callee key's package field, or "" when it is not one. A pointer or reference
// sigil, a generic argument list or an array's brackets belong to the type, not
// to a module: leaving them in produced packages like `*mut ffi` and
// `[u64; 8]`.
func rustModulePathText(prefix string) string {
	path := strings.TrimSpace(prefix)
	for _, sigil := range []string{"&", "*const ", "*mut ", "*", "mut ", "dyn ", "impl "} {
		path = strings.TrimSpace(strings.TrimPrefix(path, sigil))
	}
	if idx := strings.Index(path, "<"); idx >= 0 {
		path = strings.TrimSpace(path[:idx])
	}
	if path == "" {
		return ""
	}
	for i, segment := range strings.Split(path, "::") {
		if segment == "" {
			return ""
		}
		// A CRATE name may carry hyphens — aws-lc-rs, curve25519-dalek, md-5 —
		// and it is the leading segment of every absolute module path this
		// parser builds. Rejecting the whole path for them made every
		// crate-rooted identity unusable on hyphenated crates: an
		// `aws-lc-rs::cipher::streaming::BufferUpdate` receiver fell through to
		// the file's glob imports and came out as `paste.(BufferUpdate)`.
		// Module names cannot contain a hyphen, so only the first segment gets
		// the allowance.
		if i == 0 && rustIsCrateNameSegment(segment) {
			continue
		}
		if !rustIsNameableType(segment) {
			return ""
		}
	}
	return path
}

// rustIsCrateNameSegment reports whether a path segment is spelled like a
// crates.io crate name: what a nameable identifier allows, plus hyphens. A
// primitive stays excluded — `Self::from(8)` inside `impl Word for u64` must not
// put `u64` in the package field.
func rustIsCrateNameSegment(segment string) bool {
	if !strings.Contains(segment, "-") {
		return false
	}
	return rustIsNameableType(strings.ReplaceAll(segment, "-", "_"))
}

// rustIsNameableType reports whether a type head can appear in a callee key's
// type field: an identifier, not a slice, tuple, pointer or primitive.
func rustIsNameableType(head string) bool {
	if head == "" {
		return false
	}
	switch head {
	case "bool", "char", "str", "u8", "u16", "u32", "u64", "u128", "usize",
		"i8", "i16", "i32", "i64", "i128", "isize", "f32", "f64", "()":
		return false
	// `_` is the INFERRED-type placeholder, not a name. A tuple annotation like
	// `let (mut push_stream, header): (_, Header) = ..` distributed it to a
	// binding, and the placeholder reached the key's type field:
	// `dryoc::dryocstream::tests.(_).push` and 13 more across curve25519-dalek,
	// sequoia-openpgp and rsa.
	case "_":
		return false
	}
	for i := 0; i < len(head); i++ {
		ch := head[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9', ch == '_':
		default:
			return false
		}
	}
	return true
}

// rustQualifyType turns resolved type text into the package and type of a
// callee key, keeping a path the type text already carries and otherwise
// resolving the bare name through this file's imports.
func rustQualifyType(analysis *FileAnalysis, facts *rustFileFacts, typeText string) (pkg, typ string) {
	unwrapped := rustUnwrapWrapperType(typeText, facts)
	head := rustTypeHead(unwrapped)
	if head == "" || head == rustSelfType {
		return "", ""
	}
	// A slice, array, tuple, pointer or primitive is not a nameable type
	// identity: emitting `([u8])` or `(u64)` in a callee key's type field puts
	// source text where a resolvable name belongs.
	if !rustIsNameableType(head) {
		return "", ""
	}
	if qualifiedPkg, qualifiedType, ok := rustQualifiedIdentity(analysis, unwrapped, head); ok {
		if !rustQualifiedIdentityIsNameable(qualifiedPkg, qualifiedType) {
			return "", ""
		}
		return qualifiedPkg, qualifiedType
	}
	// A local `type X = path::To<Y>` alias resolves to what it names, which is
	// the identity a contract keys on; the alias's own name matches nothing.
	if analysis != nil {
		if _, isAlias := analysis.ImportAliases[head]; isAlias {
			return resolveRustReceiverType(analysis, head)
		}
		if module, ok := rustModuleDeclaredTypePackage(analysis, head); ok {
			return module, head
		}
		if _, imported := analysis.Imports[head]; imported {
			return resolveRustReceiverType(analysis, head)
		}
	}
	if facts.isLocalType(head) && rustDeclaredTypeInScope(analysis, facts, head) {
		return rustDeclaredTypePackage(analysis, facts, head), head
	}
	// A prelude type is in scope everywhere without an import, and it belongs to
	// the standard library, not to the crate being analyzed.
	if rustPreludeTypes[head] {
		return rustPreludePackage, head
	}
	// No explicit import binds this name, but a glob import may: the Reference
	// makes a `use path::*` bring every public item of that module into scope.
	if wildcard, ok := rustWildcardPackage(analysis); ok {
		return wildcard, head
	}
	// An INTRA-crate glob names the module it points at, and that is the package
	// of anything it supplies — including a type the crate's own facts cannot
	// see. openssl 0.10.81 src/rsa.rs produces `Rsa` from the
	// `foreign_type_and_impl_send_sync!` macro, so no declared-type fact
	// records it; its `mod test` at :592 writes `use super::*;` and 33 edges
	// came out as `openssl::rsa::test.(Rsa).*`, naming a test module as the
	// owner of a public type — and missing `openssl::rsa::Rsa.generate`, which
	// openssl.yaml keys. The same shape costs ~20 edges in boring 4.9.1
	// src/rsa.rs.
	if module, ok := rustIntraCrateWildcardModule(analysis); ok {
		return module, head
	}
	return resolveRustReceiverType(analysis, head)
}

// rustIntraCrateWildcardModule returns the module an intra-crate glob in scope
// points at, when exactly one such module is in scope.
//
// `use super::*` and `use crate::x::*` are how Rust code is normally written
// inside a crate, and a name they supply belongs to the module they name, not to
// the module that wrote the glob. Two globs naming different modules leave the
// owner ambiguous, and then the importing module is the honest answer, which is
// what this returned before.
func rustIntraCrateWildcardModule(analysis *FileAnalysis) (string, bool) {
	if analysis == nil || len(analysis.WildcardImports) == 0 {
		return "", false
	}
	crateRoot := rustCrateRoot(analysis.PackagePath)
	if crateRoot == "" {
		return "", false
	}
	found := ""
	for _, wildcard := range analysis.WildcardImports {
		if wildcard == "" || rustCrateRoot(wildcard) != crateRoot {
			continue
		}
		if wildcard == analysis.PackagePath {
			// A glob naming this very module says nothing new.
			continue
		}
		switch {
		case found == "":
			found = wildcard
		case found != wildcard:
			return "", false
		}
	}
	if found == "" {
		return "", false
	}
	return found, true
}

// rustDeclaredTypePackage returns the package a type this crate declares
// belongs to: the module that DECLARES it, not the module that reached it.
//
// The two differ whenever a name arrives through a glob, which is how Rust code
// is normally written inside a crate — `use crate::decls::*` and the
// `mod tests { use super::*; }` in nearly every file. Keying the type by the
// importing module gave one declaration as many identities as it had importers
// and none of them matched a contract keyed on the declaring path.
//
// A name two modules declare has no single declaring module, and then the
// importing module is the honest answer: it is where the source resolved the
// name, and it is what this returned before the declaring module was tracked.
func rustDeclaredTypePackage(analysis *FileAnalysis, facts *rustFileFacts, name string) string {
	if module, ok := facts.declaringModule(name); ok {
		return module
	}
	if analysis == nil {
		return ""
	}
	return analysis.PackagePath
}

// rustDeclaredTypeInScope reports whether the crate's own declaration of a bare
// name is in scope WHERE THE NAME WAS WRITTEN.
//
// A crate's declarations are the crate's truth, but a name written bare resolves
// in the module that wrote it, and a declaration in an unrelated module is not
// in that module's scope. The two only compete when a glob is also in scope, and
// then the glob is what the language resolves through:
//
//	mod a { use aes::*; Aes128::new(k) }   ->  aes.(Aes128).new
//
// Adding an unrelated `pub struct Aes128` in another file of the crate, never
// imported into `a`, moved every one of those calls onto that struct -- so
// declaring a name in ANY file of a crate suppressed the real cryptographic
// identity everywhere a glob supplied it. That is a one-line way to hide a
// finding, and it is the same defect module shadowing had before it was made
// lexical: the guard was crate-wide where the language is lexical.
//
// The declaration is in scope when this module declares it, or when an
// intra-crate glob in this scope names the module that does. A name the crate
// declares in two modules has no single answer and cannot outrank a glob that
// has one.
func rustDeclaredTypeInScope(analysis *FileAnalysis, facts *rustFileFacts, name string) bool {
	if analysis == nil {
		return true
	}
	competing, ok := rustWildcardPackage(analysis)
	if !ok || !rustGlobOutranksCrateDeclaration(analysis, competing) {
		return true
	}
	module, known := facts.declaringModule(name)
	if !known {
		// The crate declares the name but not where -- two modules declare it,
		// or it was recorded without a module. Then the crate's own answer is
		// imprecise, not absent, and the using module is where it stays. Handing
		// the name to the glob's crate instead would name a foreign owner on the
		// strength of not knowing: 413 edges moved that way on the corpus, and
		// openssl's own `Builder` became `std::io::prelude.(Builder).build`.
		return true
	}
	if module == analysis.PackagePath {
		return true
	}
	for _, wildcard := range analysis.WildcardImports {
		if wildcard == module {
			return true
		}
	}
	return false
}

// rustGlobOutranksCrateDeclaration reports whether a glob is evidence strong
// enough to beat a declaration the crate makes in another module.
//
// The manifest is that evidence, exactly as it is for a bare path segment. A
// glob over the standard library's preludes -- `use std::io::prelude::*;` and
// `use std::prelude::v1::*;`, which real crates write constantly -- says nothing
// about a name the crate declares itself, and letting it win attributed
// openssl's and ssh2's own builders and error types to `std::io::prelude`. A
// glob rooted at a name the manifest does not declare as a dependency is not a
// third-party crate at all; sequoia-openpgp refers to ITSELF as `openpgp`, so
// `use openpgp::cert::prelude::*;` is an intra-crate glob wearing another name.
func rustGlobOutranksCrateDeclaration(analysis *FileAnalysis, wildcard string) bool {
	root := wildcard
	if idx := strings.Index(root, "::"); idx > 0 {
		root = root[:idx]
	}
	switch root {
	case "", rustPreludePackage, "core", "alloc":
		return false
	}
	return analysis.rustDependencies[root] || analysis.rustDependencies[rustCrateIdentifier(root)]
}

// rustQualifiedIdentityIsNameable reports whether a resolved package/type pair
// is an identity at all, rather than source text standing where a resolved name
// belongs.
//
//   - `Self::AssocType` names the implementing type's choice, which is not
//     statically known (Reference, Paths -> Self). 73 edges carried the keyword
//     in the type field, e.g. sequoia-openpgp 1.21.2 src/parse.rs:295 emitting
//     `sequoia-openpgp::parse.(Self).from_reader`.
//   - A type-cased PACKAGE segment is never a module.
//     `C::FieldBytesSize::USIZE.saturating_sub(..)` in ecdsa 0.16.9
//     src/der.rs:279 emitted `C.(FieldBytesSize).saturating_sub`: an associated
//     item reached through a generic parameter, equally unknowable.
//
// No identity beats a wrong one in either case.
func rustQualifiedIdentityIsNameable(pkg, typ string) bool {
	return typ != rustSelfType && !rustPackageEndsInATypeName(pkg)
}

// rustPackageEndsInATypeName reports whether a resolved package path's last
// segment is spelled like a type rather than like a module. Rust's own
// conventions — and the compiler's non_camel_case_types lint — make that a
// reliable test, and no contract key in any Rust KB has a type-cased package
// segment.
func rustPackageEndsInATypeName(pkg string) bool {
	if pkg == "" {
		return false
	}
	last := pkg
	if idx := strings.LastIndex(last, "::"); idx >= 0 {
		last = last[idx+2:]
	}
	return rustIsTypeCase(last)
}

// rustQualifiedIdentity splits type text that already carries a path into the
// package and type of a callee key.
func rustQualifiedIdentity(analysis *FileAnalysis, unwrapped, head string) (pkg, typ string, ok bool) {
	// Only the path of the type's OWN name counts. Reading the last "::" of the
	// whole text found one inside a generic argument instead, and
	// rustModulePathText then truncated at the "<" and accepted the wrapper's
	// name as a path: `Result<openssl::hash::Hasher, ErrorStack>` resolved to
	// `<local module>.(Result)` rather than to `std.(Result)`.
	base := rustStripLifetimes(unwrapped)
	if idx := strings.Index(base, "<"); idx >= 0 {
		base = strings.TrimSpace(base[:idx])
	}
	lastSep := strings.LastIndex(base, "::")
	if lastSep <= 0 {
		return "", "", false
	}
	path := rustModulePathText(base[:lastSep])
	if path == "" {
		return "", "", false
	}
	// A path whose last segment names a TYPE means the trailing name is an
	// associated item or an enum variant, not a type of its own:
	// `Error::Inconsistent.into()` has receiver type Error, and `Error` belongs
	// in the type field, not the package one.
	if idx := strings.LastIndex(path, "::"); idx > 0 {
		if last := path[idx+2:]; rustIsTypeCase(last) {
			return resolveRustTypePackage(path[:idx], analysis), last, true
		}
		pkg := resolveRustTypePackage(path, analysis)
		if reExportPkg, reExportTyp, ok := rustModuleReExport(analysis, pkg, head); ok {
			return reExportPkg, reExportTyp, true
		}
		return pkg, head, true
	}
	if rustIsTypeCase(path) {
		return resolveRustReceiverTypePackage(analysis, path), path, true
	}
	pkg = resolveRustTypePackage(path, analysis)
	if reExportPkg, reExportTyp, ok := rustModuleReExport(analysis, pkg, head); ok {
		return reExportPkg, reExportTyp, true
	}
	return pkg, head, true
}

// rustModuleReExport checks whether a resolved local module re-exports name
// under it, and if so returns what the re-export ultimately names. A
// `pub use aes::Aes128 as Cipher;` in a module two hops away makes
// `mymodule::Cipher` the aes crate's identity, not mymodule's own path — the
// module merely re-exports it.
func rustModuleReExport(analysis *FileAnalysis, pkg, name string) (string, string, bool) {
	if analysis == nil || analysis.rustFacts == nil {
		return "", "", false
	}
	return analysis.rustFacts.reExportTarget(rustQualifyFactKey(pkg, name))
}

// rustIteratorElementMethods are the iterator adapters whose closure parameter
// receives one element of the receiver's collection. They are how crypto code
// loops over keys and blocks, and without them every closure parameter is
// untyped.
var rustIteratorElementMethods = map[string]bool{
	"iter": true, "iter_mut": true, "into_iter": true, "for_each": true,
	"map": true, "filter": true, "find": true, "any": true, "all": true,
	"filter_map": true, "flat_map": true, "inspect": true, "take_while": true,
	"skip_while": true, "position": true, "partition": true, "retain": true,
}

// rustVisitor is called for every node of a scoped walk, with the context whose
// bindings are in effect there. Returning false skips the node's subtree, which
// is how a walk declines to enter a closure or a nested function.
type rustVisitor func(node *sitter.Node, ctx *rustTypeCtx) bool

// walkRustScoped walks a function body maintaining Rust's lexical scopes,
// invoking visit on every node with the context whose bindings are the ones in
// effect there.
//
// Binding and use are resolved in ONE traversal rather than two, because the
// two-pass shape is what made scoping unrepresentable: a pass that only
// collects bindings has nowhere to put a scope, and a later pass that only
// reads them has no way to know which scope it is in. Here a `let` binds into
// the scope it appears in, after its own initializer has been visited, and a
// block, a match arm, a loop or a closure body each open a scope of their own.
func (c *rustTypeCtx) walkRustScoped(node *sitter.Node, visit rustVisitor) {
	if node == nil {
		return
	}
	symbol := node.Symbol()
	if rustIsBlockLike(symbol) {
		if !visit(node, c) {
			return
		}
		// A block can declare its own `use` items, and they bind only inside
		// it: `fn f() { { use aes::Aes128; .. } }` is legal and appears in
		// cfg-gated crypto code.
		inner := c.withBindings(c.bindings.child())
		if c.parser != nil {
			if scope := c.parser.rustChildImportScope(node, c.src, c.analysis, c.analysis.PackagePath); scope != c.analysis {
				next := *inner
				next.analysis = scope
				next.facts = scope.rustFacts
				inner = &next
			}
		}
		inner.walkRustChildren(node, visit)
		return
	}
	switch symbol {
	case rustSyms.letDeclaration:
		c.walkRustLet(node, visit)
		return
	case rustSyms.ifExpression, rustSyms.whileExpression:
		c.walkRustConditional(node, visit)
		return
	case rustSyms.matchExpression:
		c.walkRustMatch(node, visit)
		return
	case rustSyms.forExpression:
		c.walkRustFor(node, visit)
		return
	case rustSyms.closureExpression:
		c.walkRustClosure(node, nil, visit)
		return
	case rustSyms.callExpression:
		if !visit(node, c) {
			return
		}
		c.walkRustCallChildren(node, visit)
		return
	}
	if !visit(node, c) {
		return
	}
	c.walkRustChildren(node, visit)
}

func (c *rustTypeCtx) walkRustChildren(node *sitter.Node, visit rustVisitor) {
	// NAMED children only. An anonymous node is a literal token of the grammar
	// — `;`, `{`, `::`, `=` — and a token has no children, so nothing named can
	// hide beneath one. Visiting them anyway was roughly half of every walk,
	// and each visit is two cgo calls into tree-sitter.
	nodeNamedChildren := int(node.NamedChildCount())
	for i := 0; i < nodeNamedChildren; i++ {
		c.walkRustScoped(node.NamedChild(i), visit)
	}
}

// walkRustLet visits a `let`'s initializer in the scope that encloses it, then
// binds its pattern for the statements that FOLLOW. `let c = c.wrap();` refers
// to the outer `c` on the right-hand side, and shadows it afterwards.
func (c *rustTypeCtx) walkRustLet(node *sitter.Node, visit rustVisitor) {
	if !visit(node, c) {
		return
	}
	pattern := node.ChildByFieldName("pattern")
	nodeChildren := int(node.ChildCount())
	for i := 0; i < nodeChildren; i++ {
		child := node.Child(i)
		if child == pattern {
			continue
		}
		c.walkRustScoped(child, visit)
	}
	c.bindLet(node)
}

// walkRustConditional handles `if`/`while`, including the `if let` and
// `while let` forms whose binding is visible only inside the taken branch.
func (c *rustTypeCtx) walkRustConditional(node *sitter.Node, visit rustVisitor) {
	if !visit(node, c) {
		return
	}
	condition := node.ChildByFieldName("condition")
	consequence := node.ChildByFieldName("consequence")
	body := node.ChildByFieldName("body")
	alternative := node.ChildByFieldName("alternative")

	inner := c.withBindings(c.bindings.child())
	if condition != nil {
		c.walkRustScoped(condition, visit)
		inner.bindConditionPatterns(condition)
	}
	for _, taken := range []*sitter.Node{consequence, body} {
		if taken != nil {
			inner.walkRustScoped(taken, visit)
		}
	}
	if alternative != nil {
		// An `else` branch never sees the pattern's binding.
		c.walkRustScoped(alternative, visit)
	}
}

// bindConditionPatterns binds every `let` pattern in a condition, including the
// chained `if let A = x && let B = y` form.
func (c *rustTypeCtx) bindConditionPatterns(condition *sitter.Node) {
	if condition == nil {
		return
	}
	if condition.Type() == "let_condition" {
		value := c.rustExprType(condition.ChildByFieldName("value"), 0)
		c.bindPattern(condition.ChildByFieldName("pattern"), value, 0)
		return
	}
	conditionNamedChildren := int(condition.NamedChildCount())
	for i := 0; i < conditionNamedChildren; i++ {
		c.bindConditionPatterns(condition.NamedChild(i))
	}
}

// walkRustMatch gives every arm its own scope, bound from the matched value.
func (c *rustTypeCtx) walkRustMatch(node *sitter.Node, visit rustVisitor) {
	if !visit(node, c) {
		return
	}
	value := node.ChildByFieldName("value")
	c.walkRustScoped(value, visit)
	valueType := c.rustExprType(value, 0)
	body := node.ChildByFieldName("body")
	if body == nil {
		return
	}
	if !visit(body, c) {
		return
	}
	bodyNamedChildren := int(body.NamedChildCount())
	for i := 0; i < bodyNamedChildren; i++ {
		arm := body.NamedChild(i)
		if arm.Type() != "match_arm" {
			c.walkRustScoped(arm, visit)
			continue
		}
		inner := c.withBindings(c.bindings.child())
		pattern := arm.ChildByFieldName("pattern")
		inner.bindPattern(pattern, valueType, 0)
		// The arm's `if` GUARD is a child of the match_pattern node under field
		// name "condition", and walking only the arm's value never visited it:
		// `E::A if HmacSha256::new_from_slice(key).is_ok() => 1` lost
		// `hmac::Hmac.new_from_slice` entirely. 72 lost call sites across 12
		// crates. A guard runs before the arm is taken, so its calls are
		// reachable and its bindings are the arm's.
		if pattern != nil {
			inner.walkRustScoped(pattern.ChildByFieldName("condition"), visit)
		}
		inner.walkRustScoped(arm.ChildByFieldName("value"), visit)
	}
}

// walkRustFor binds the loop pattern to the iterated collection's element type,
// visible only inside the loop body.
func (c *rustTypeCtx) walkRustFor(node *sitter.Node, visit rustVisitor) {
	if !visit(node, c) {
		return
	}
	value := node.ChildByFieldName("value")
	c.walkRustScoped(value, visit)
	inner := c.withBindings(c.bindings.child())
	inner.bindPattern(node.ChildByFieldName("pattern"), rustElementType(c.rustExprType(value, 0)), 0)
	inner.walkRustScoped(node.ChildByFieldName("body"), visit)
}

// walkRustClosure gives a closure body its own scope, with its parameters bound
// from their annotations or from the element type the caller supplies.
func (c *rustTypeCtx) walkRustClosure(node *sitter.Node, elementType *string, visit rustVisitor) {
	if !visit(node, c) {
		return
	}
	inner := c.withBindings(c.bindings.child())
	if params := node.ChildByFieldName("parameters"); params != nil {
		paramsNamedChildren := int(params.NamedChildCount())
		for i := 0; i < paramsNamedChildren; i++ {
			param := params.NamedChild(i)
			switch {
			case param.Type() == "parameter":
				inner.bindPattern(param.ChildByFieldName("pattern"), nodeFieldText(param, "type", c.src), 0)
			case elementType != nil:
				inner.bindPattern(param, *elementType, 0)
			}
		}
	}
	inner.walkRustScoped(node.ChildByFieldName("body"), visit)
}

// walkRustCallChildren walks a call's parts, typing the parameter of a closure
// passed to an iterator adapter from the collection it iterates.
func (c *rustTypeCtx) walkRustCallChildren(node *sitter.Node, visit rustVisitor) {
	fn := node.ChildByFieldName("function")
	args := node.ChildByFieldName("arguments")
	var element *string
	if fn != nil && fn.Type() == rustNodeFieldExpression {
		if rustIteratorElementMethods[nodeFieldText(fn, "field", c.src)] {
			if t := rustElementType(c.rustExprType(fn.ChildByFieldName("value"), 0)); t != "" {
				element = &t
			}
		}
	}
	nodeChildren := int(node.ChildCount())
	for i := 0; i < nodeChildren; i++ {
		child := node.Child(i)
		if child == args && element != nil {
			c.walkRustClosureArguments(child, element, visit)
			continue
		}
		c.walkRustScoped(child, visit)
	}
}

func (c *rustTypeCtx) walkRustClosureArguments(args *sitter.Node, element *string, visit rustVisitor) {
	if !visit(args, c) {
		return
	}
	argsChildren := int(args.ChildCount())
	for i := 0; i < argsChildren; i++ {
		child := args.Child(i)
		if child.Type() == rustNodeClosureExpression {
			c.walkRustClosure(child, element, visit)
			continue
		}
		c.walkRustScoped(child, visit)
	}
}

func (c *rustTypeCtx) bindParameters(paramsNode *sitter.Node) {
	if paramsNode == nil {
		return
	}
	paramsNodeNamedChildren := int(paramsNode.NamedChildCount())
	for i := 0; i < paramsNodeNamedChildren; i++ {
		param := paramsNode.NamedChild(i)
		if param.Type() != "parameter" {
			continue
		}
		typ := nodeFieldText(param, "type", c.src)
		if typ == "" {
			continue
		}
		c.bindPattern(param.ChildByFieldName("pattern"), typ, 0)
	}
	// The pinned grammar cannot parse a turbofish in a parameter's TYPE
	// position — `fn f(dec: cbc::Decryptor::<Aes128>, buf: &mut [u8])`, which
	// rustc accepts, recovers as a single `parameter` with an ERROR node, so
	// the second parameter's type lands on the first parameter's pattern.
	// Where the grammar could not give a structure, fall back to splitting the
	// parameter list's text, and only for names the AST left unbound.
	if !rustNodeHasError(paramsNode) {
		return
	}
	for name, typ := range collectRustParameterTypes(paramsNode, c.src) {
		existing, ok := c.bindings.lookup(name)
		if !ok || existing == "" || rustTypeHead(existing) != rustTypeHead(typ) {
			// Where the two disagree, the structural read is the one the parse
			// error corrupted.
			c.bindings.bind(name, typ)
		}
	}
}

// bindLet binds a `let` declaration's pattern. An explicit annotation is the
// declared truth; only fall back to inferring from the initializer when there is
// none.
func (c *rustTypeCtx) bindLet(node *sitter.Node) {
	pattern := node.ChildByFieldName("pattern")
	if pattern == nil {
		return
	}
	if annotated := nodeFieldText(node, "type", c.src); annotated != "" {
		c.bindPattern(pattern, annotated, 0)
		return
	}
	// A `let` binds its names whatever its initializer resolves to. Returning
	// early on an untypeable value — a closure, most of all — left the name
	// unbound, and a bare call to it then resolved as an import: with
	// `use scrypt::{scrypt as scrypt_inner, ..}` in scope,
	// `let scrypt_inner = |..| {}; scrypt_inner(p, s, out)` reported a call to a
	// local closure as `scrypt.scrypt`, one of scrypt.yaml's four keys.
	c.bindPattern(pattern, c.rustExprType(node.ChildByFieldName("value"), 0), 0)
}

// rustNodeHasError reports whether a subtree contains a parse error, which means
// the grammar could not describe this construct and any structural read of it is
// unreliable.
func rustNodeHasError(node *sitter.Node) bool {
	if node == nil {
		return false
	}
	return node.HasError()
}

// bindPattern records the bindings a pattern introduces, distributing the
// matched value's type across the pattern's structure.
func (c *rustTypeCtx) bindPattern(pattern *sitter.Node, typeText string, depth int) {
	if pattern == nil || depth > rustMaxTypeDepth {
		return
	}
	switch pattern.Type() {
	case goNodeIdentifier:
		// The name is bound here whether or not its type resolves; shadowing is
		// a property of the binding, not of the type.
		c.bindings.declare(pattern.Content(c.src))
		typeText = c.rustSubstituteGeneric(typeText)
		if typeText == "" {
			return
		}
		c.bindings.bind(pattern.Content(c.src), typeText)
	case rustNodeMatchPattern, "mut_pattern", "ref_pattern", "reference_pattern", "captured_pattern":
		// A match arm wraps its pattern in `match_pattern` (which also carries
		// the optional `if` guard); the binding lives one level down.
		patternNamedChildren := int(pattern.NamedChildCount())
		for i := 0; i < patternNamedChildren; i++ {
			child := pattern.NamedChild(i)
			if child.Type() == "mutable_specifier" {
				continue
			}
			c.bindPattern(child, typeText, depth+1)
		}
	case "tuple_struct_pattern":
		c.bindTupleStructPattern(pattern, typeText, depth)
	case "struct_pattern":
		c.bindStructPattern(pattern, typeText, depth)
	case "tuple_pattern":
		c.bindTuplePattern(pattern, typeText, depth)
	case "or_pattern":
		patternNamedChildren := int(pattern.NamedChildCount())
		for i := 0; i < patternNamedChildren; i++ {
			c.bindPattern(pattern.NamedChild(i), typeText, depth+1)
		}
	case "slice_pattern":
		element := rustElementType(typeText)
		patternNamedChildren := int(pattern.NamedChildCount())
		for i := 0; i < patternNamedChildren; i++ {
			c.bindPattern(pattern.NamedChild(i), element, depth+1)
		}
	}
}

// bindTupleStructPattern handles `Ok(cipher)`, `Some(cipher)` and enum
// variants like `Algo::Aes(cipher)`. The fallible-constructor idiom
// (`if let Ok(cipher) = Aes256Gcm::new_from_slice(k)`) is the shape RustCrypto
// documents, so getting the inner type right here matters more than the
// pattern's rarity suggests.
func (c *rustTypeCtx) bindTupleStructPattern(pattern *sitter.Node, typeText string, depth int) {
	pathNode := pattern.ChildByFieldName("type")
	path := ""
	if pathNode != nil {
		path = rustScopedTypeText(pathNode, c.src)
	}
	head := rustTypeHead(path)
	if rustWrapperTypes[head] || c.facts.isDerefTransparent(head) || head == "Some" || head == "Ok" || head == "Err" {
		c.bindTupleStructSubPatterns(pattern, pathNode, rustUnwrappedPatternType(typeText, c.facts), depth)
		return
	}
	// An enum variant: the variant's own declared field types are the truth,
	// keyed as "Enum::Variant".
	if c.bindEnumVariantPattern(pattern, pathNode, path, typeText, depth) {
		return
	}
	c.bindTupleStructSubPatterns(pattern, pathNode, rustUnwrapWrapperType(typeText, c.facts), depth)
}

// rustUnwrappedPatternType returns what a wrapping pattern binds: the wrapper's
// type argument when it has one, otherwise the unwrapped type itself.
func rustUnwrappedPatternType(typeText string, facts *rustFileFacts) string {
	if arg, ok := rustGenericArgument(typeText); ok {
		return arg
	}
	return rustUnwrapAnyWrapperType(typeText, facts)
}

// bindEnumVariantPattern binds a variant's sub-patterns from the variant's
// declared payload types, reporting whether it could.
func (c *rustTypeCtx) bindEnumVariantPattern(pattern, pathNode *sitter.Node, path, typeText string, depth int) bool {
	// A map recorded for a conflicting name still exists but is empty, so a
	// candidate only counts when it actually carries the payload's type.
	var fields map[string]string
	for _, key := range c.factKeyCandidates(rustTypePathText(typeText), rustVariantKey(path, typeText)) {
		if candidate, found := c.facts.fields(key); found && candidate[strconv.Itoa(0)] != "" {
			fields = candidate
			break
		}
	}
	if fields == nil {
		return false
	}
	index := 0
	patternNamedChildren := int(pattern.NamedChildCount())
	for i := 0; i < patternNamedChildren; i++ {
		sub := pattern.NamedChild(i)
		if sub == pathNode {
			continue
		}
		c.bindPattern(sub, fields[strconv.Itoa(index)], depth+1)
		index++
	}
	return true
}

// bindTupleStructSubPatterns binds every sub-pattern of a tuple-struct pattern
// to one type.
func (c *rustTypeCtx) bindTupleStructSubPatterns(pattern, pathNode *sitter.Node, typeText string, depth int) {
	patternNamedChildren := int(pattern.NamedChildCount())
	for i := 0; i < patternNamedChildren; i++ {
		sub := pattern.NamedChild(i)
		if sub == pathNode {
			continue
		}
		c.bindPattern(sub, typeText, depth+1)
	}
}

// rustVariantKey builds the facts key for an enum variant pattern, accepting
// both the qualified `Algo::Aes` spelling and the bare `Aes` one that a
// `use Algo::*` makes legal.
func rustVariantKey(path, typeText string) string {
	if strings.Contains(path, "::") {
		segments := strings.Split(path, "::")
		if len(segments) >= 2 {
			return segments[len(segments)-2] + "::" + segments[len(segments)-1]
		}
	}
	enum := rustTypeHead(typeText)
	if enum == "" {
		return path
	}
	return enum + "::" + rustTypeHead(path)
}

func (c *rustTypeCtx) bindStructPattern(pattern *sitter.Node, typeText string, depth int) {
	owner := rustTypeHead(typeText)
	if owner == "" {
		if t := pattern.ChildByFieldName("type"); t != nil {
			owner = rustTypeHead(rustScopedTypeText(t, c.src))
		}
	}
	fields, _ := c.facts.fields(owner)
	patternNamedChildren := int(pattern.NamedChildCount())
	for i := 0; i < patternNamedChildren; i++ {
		child := pattern.NamedChild(i)
		switch child.Type() {
		case "field_pattern":
			name := nodeFieldText(child, "name", c.src)
			fieldType := fields[name]
			if sub := child.ChildByFieldName("pattern"); sub != nil {
				c.bindPattern(sub, fieldType, depth+1)
				continue
			}
			c.bindings.bind(name, fieldType)
		case "shorthand_field_identifier":
			c.bindings.bind(child.Content(c.src), fields[child.Content(c.src)])
		}
	}
}

func (c *rustTypeCtx) bindTuplePattern(pattern *sitter.Node, typeText string, depth int) {
	parts := rustTupleTypeParts(typeText)
	idx := 0
	patternNamedChildren := int(pattern.NamedChildCount())
	for i := 0; i < patternNamedChildren; i++ {
		child := pattern.NamedChild(i)
		part := ""
		if idx < len(parts) {
			part = parts[idx]
		}
		c.bindPattern(child, part, depth+1)
		idx++
	}
}

// rustTupleTypeParts splits a tuple type's components at top level.
func rustTupleTypeParts(typeText string) []string {
	t := strings.TrimSpace(typeText)
	t = strings.TrimPrefix(t, "&")
	t = strings.TrimSpace(strings.TrimPrefix(t, "mut "))
	if !strings.HasPrefix(t, "(") || !strings.HasSuffix(t, ")") {
		return nil
	}
	inner := t[1 : len(t)-1]
	var parts []string
	depth, start := 0, 0
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '<', '(', '[':
			depth++
		case '>', ')', ']':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(inner[start:i]))
				start = i + 1
			}
		}
	}
	if start < len(inner) {
		parts = append(parts, strings.TrimSpace(inner[start:]))
	}
	return parts
}

// rustPathRoots are the path roots the Reference defines as relative to the
// current position in the module tree rather than to a crate name.
var rustPathRoots = map[string]bool{rustNodeCrate: true, rustNodeSelf: true, rustNodeSuper: true}

// rustAbsoluteModulePath rewrites a crate-relative path into an absolute module
// path, which is what a callee key's package field must carry.
//
// `crate::error::ErrorStack`, `self::imp::Certificate` and `super::utils::check`
// used to be emitted with their relative root intact — 1108 such edges in
// openssl 0.10.81 and 44 in native-tls 0.2.14 — so the package field named a
// keyword instead of a module and no contract could match it.
func rustAbsoluteModulePath(analysis *FileAnalysis, path string) string {
	if analysis == nil || path == "" {
		return path
	}
	segments := strings.Split(path, "::")
	if len(segments) == 0 || !rustPathRoots[segments[0]] {
		return path
	}
	module := strings.Split(analysis.PackagePath, "::")
	switch segments[0] {
	case rustNodeCrate:
		// The crate root is the first segment of the package path; every
		// module below it is addressed from there.
		if len(module) > 0 && module[0] != "" {
			module = module[:1]
		} else {
			module = nil
		}
		segments = segments[1:]
	case rustNodeSelf:
		segments = segments[1:]
	case rustNodeSuper:
		for len(segments) > 0 && segments[0] == rustNodeSuper {
			// Never pop past the crate root. A file's package path does not
			// carry the file's own module name, so a `mod tests { use super::*; }`
			// inside a top-level file would otherwise resolve `super` to
			// nothing and record imports with an EMPTY package — 75 such edges
			// in openssl 0.10.81.
			if len(module) > 1 {
				module = module[:len(module)-1]
			}
			segments = segments[1:]
		}
	}
	joined := append([]string{}, module...)
	for _, segment := range segments {
		if segment != "" {
			joined = append(joined, segment)
		}
	}
	return strings.Join(joined, "::")
}

// rustResolveImportPath normalizes the path of a `use` declaration: a relative
// root becomes an absolute module path, and a first segment that is a crate
// rename becomes the real crate.
//
// Without the rename step the alias survives into the recorded import, so every
// item imported through it keeps a package that names no crate — `use ffi::...`
// in openssl, `use aes_alt::Aes128` in any crate that renames a dependency to
// hold two major versions at once.
func rustResolveImportPath(analysis *FileAnalysis, path string) string {
	if crateRooted, ok := rustCrateAliasPath(analysis, path); ok {
		return crateRooted
	}
	path = rustAbsoluteModulePath(analysis, path)
	path = rustCollapseRelativeSegments(analysis, path)
	// An item declared in the current module shadows the extern prelude, so a
	// `use des::Des;` in a file that declares its own `mod des` imports the
	// LOCAL type. Recording it as the crate's meant a project with no crypto
	// dependency at all emitted `des.(Des).encrypt_block` — a weak-cipher
	// finding with a third-party package identity, for code that has none.
	if local, ok := rustLocalModulePath(analysis, path); ok {
		return local
	}
	// A segment the manifest does not declare cannot be a crate: edition-2015
	// code writes `use randombytes::randombytes_into;` for its own crate-root
	// module, and recording it raw left a bare `randombytes` package on 91
	// edges in sodiumoxide 0.2.7.
	if undeclared, ok := rustUndeclaredCratePath(analysis, path); ok {
		return undeclared
	}
	if analysis == nil || path == "" || len(analysis.ImportAliases) == 0 {
		return path
	}
	first := path
	rest := ""
	if idx := strings.Index(path, "::"); idx > 0 {
		first, rest = path[:idx], path[idx:]
	}
	target, ok := analysis.ImportAliases[first]
	if !ok || target == "" || target == first {
		return path
	}
	// Only a crate-level rename applies to a path ROOT; an alias whose target
	// is itself a path is a renamed item, not a renamed crate.
	if strings.Contains(target, "::") {
		return path
	}
	return target + rest
}

// rustCrateRootSegment returns the crate a file belongs to: the first segment of
// its module path.
func rustCrateRootSegment(analysis *FileAnalysis) string {
	if analysis == nil {
		return ""
	}
	if idx := strings.Index(analysis.PackagePath, "::"); idx > 0 {
		return analysis.PackagePath[:idx]
	}
	return analysis.PackagePath
}

// rustCollapseRelativeSegments resolves a `crate`, `self` or `super` segment
// appearing INSIDE an otherwise absolute path.
//
// A use tree nests one relative root under another, and concatenating the two
// left the keyword in the middle of the result:
//
//	use super::{super::target2::hit2, sibling::hit3};
//	 -> supers::l1::l2::super::target2.hit2
//
// A package field naming a keyword matches nothing, and the same shape reached
// real code: 73 edges across 51 crates, 63 of them sequoia-openpgp's
// `crate::policy.(StandardPolicy).*` and 6 of them aes 0.9.2's own
// `crate::backends::soft::hazmat.*` round functions.
//
// rustAbsoluteModulePath handles a LEADING root, against the file's position in
// the module tree; this handles the rest, against what the path has accumulated
// so far, and must run after it.
func rustCollapseRelativeSegments(analysis *FileAnalysis, path string) string {
	if path == "" || !strings.Contains(path, "::") {
		return path
	}
	if !strings.Contains(path, rustNodeSuper) && !strings.Contains(path, rustNodeCrate) &&
		!strings.Contains(path, rustNodeSelf) {
		return path
	}
	crateRoot := rustCrateRootSegment(analysis)
	out := make([]string, 0, 8)
	for _, segment := range strings.Split(path, "::") {
		switch segment {
		case "":
		case rustNodeCrate:
			out = out[:0]
			if crateRoot != "" {
				out = append(out, crateRoot)
			}
		case rustNodeSelf:
			// `self` names the position already reached.
		case rustNodeSuper:
			// Never pop past the crate root: a path that did would record an
			// empty package, which matches nothing either.
			if len(out) > 1 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, segment)
		}
	}
	return strings.Join(out, "::")
}

// rustLocalModulePath qualifies a path whose first segment names a module this
// file declares, so a locally shadowed name keeps this crate's identity.
func rustLocalModulePath(analysis *FileAnalysis, path string) (string, bool) {
	if analysis == nil || analysis.rustFacts == nil || path == "" {
		return "", false
	}
	first := path
	if idx := strings.Index(path, "::"); idx > 0 {
		first = path[:idx]
	}
	if !analysis.rustFacts.declaresModule(analysis.PackagePath, first) {
		return "", false
	}
	// An explicit import of the same name was written on purpose and wins.
	if _, imported := analysis.Imports[first]; imported {
		return "", false
	}
	if analysis.PackagePath == "" {
		return path, true
	}
	return analysis.PackagePath + "::" + path, true
}

// rustCrateAliasPath rewrites a path whose first non-relative segment names a
// crate the crate re-exports under another name.
//
// `use super::ring_like::aead;` is not a module of this crate: `ring_like` is
// the crate `ring`, re-exported one module up. Prepending the current module
// path instead produced a package that names no crate at all.
func rustCrateAliasPath(analysis *FileAnalysis, path string) (string, bool) {
	if analysis == nil || analysis.rustFacts == nil || path == "" {
		return "", false
	}
	segments := strings.Split(path, "::")
	start := 0
	for start < len(segments) && rustPathRoots[segments[start]] {
		start++
	}
	if start >= len(segments) {
		return "", false
	}
	crate, ok := analysis.rustFacts.crateAliases[segments[start]]
	if !ok || crate == "" {
		// Not declared in this file: ask the directory tree, where a module's
		// own re-export lives.
		crate, ok = analysis.rustCrateIndex.crateAliasFor(analysis.FilePath, segments[start])
		if !ok {
			return "", false
		}
	}
	// A file-local binding of the same name was written deliberately.
	if _, imported := analysis.Imports[segments[start]]; imported {
		return "", false
	}
	rewritten := append([]string{crate}, segments[start+1:]...)
	return strings.Join(rewritten, "::"), true
}

// rustUndeclaredCratePath qualifies a path whose first segment cannot name a
// crate, because the manifest declares no such dependency, but which the crate
// does declare as a module of its own.
//
// This is the last line of defense for the whole family of bare module segments
// reaching the package field — `cipher.(SealingKey).write` in russh,
// `types.(Timestamp).into` in sequoia-openpgp, `errors.(Result).expect` in rsa.
// It is evidence, not a heuristic: `cipher`, `types` and `errors` are all real
// crates.io names, and the manifest is what says whether this crate uses them.
func rustUndeclaredCratePath(analysis *FileAnalysis, path string) (string, bool) {
	if analysis == nil || path == "" || len(analysis.rustDependencies) == 0 {
		return "", false
	}
	first := path
	if idx := strings.Index(path, "::"); idx > 0 {
		first = path[:idx]
	}
	crateRoot := ""
	if segments := strings.Split(analysis.PackagePath, "::"); len(segments) > 0 {
		crateRoot = segments[0]
	}
	if !rustSegmentCannotBeACrate(analysis, first, crateRoot) {
		return "", false
	}
	// Not a crate. If this crate declares a module by that name anywhere, that
	// is what the source means.
	if analysis.rustFacts == nil || !analysis.rustFacts.declaresModuleAnywhere(first) {
		return "", false
	}
	if crateRoot == "" {
		return path, true
	}
	return crateRoot + "::" + path, true
}

// rustSegmentCannotBeACrate reports whether a path's leading segment is ruled
// out as a crate name by the manifest.
func rustSegmentCannotBeACrate(analysis *FileAnalysis, first, crateRoot string) bool {
	switch {
	case first == "", first == crateRoot, rustPathRoots[first]:
		return false
	case first == "std", first == "core", first == "alloc", first == rustPreludePackage:
		return false
	case analysis.rustDependencies[first], analysis.rustDependencies[rustCrateIdentifier(first)]:
		// A declared dependency: the segment names a crate, as written.
		return false
	}
	return true
}

// rustWildcardPackage resolves a name that no explicit import binds, using the
// file's glob imports.
//
// `use aes::*; let c = Aes128::new(..)` is legal and common, and the wildcard
// path was never even recorded (the guard that read it could not be reached),
// so every call through a glob import resolved to the local package. Only
// wildcards rooted OUTSIDE this crate are considered, and only when exactly one
// applies: a glob names no members, so with two candidates the honest answer is
// that the identity is unresolved. Guessing between them would fabricate a
// third-party identity, the one failure mode a crypto rule must never see.
func rustWildcardPackage(analysis *FileAnalysis) (string, bool) {
	if analysis == nil || len(analysis.WildcardImports) == 0 {
		return "", false
	}
	// A glob may only claim a name once we can see that the crate does not
	// declare it itself, and that takes crate-wide visibility. Without it — a
	// source tree with no Cargo.toml anywhere above it — "not declared here"
	// means "not visible from here", not "not declared". Claiming the name
	// anyway attributed a local type to a third-party crate: a `use des::*`
	// beside the crate's own `Framer` produced `des.(Framer).encrypt_block`, a
	// weak-cipher identity for a type the crate declares. Staying local loses a
	// resolution; guessing invents a finding.
	if analysis.rustFacts == nil || analysis.rustFacts.fallback == nil {
		return "", false
	}
	found, sharedRoot, ambiguous := rustExternalWildcards(analysis)
	switch {
	case found == "":
		return "", false
	case ambiguous:
		// Several globs from the SAME crate (`use aes::*; use aes::cipher::*;`)
		// leave the module ambiguous but the crate certain, and the crate is
		// what a contract keys on.
		return sharedRoot, true
	}
	return found, true
}

// rustExternalWildcards reduces a file's glob imports to the one that could
// supply a name, reporting the crate they share when there is more than one.
// Globs rooted at this crate are not candidates: a name they supply is this
// crate's own either way.
func rustExternalWildcards(analysis *FileAnalysis) (found, sharedRoot string, ambiguous bool) {
	crateRoot := ""
	if segments := strings.Split(analysis.PackagePath, "::"); len(segments) > 0 {
		crateRoot = segments[0]
	}
	for _, wildcard := range analysis.WildcardImports {
		if wildcard == "" {
			continue
		}
		root := wildcard
		if idx := strings.Index(root, "::"); idx > 0 {
			root = root[:idx]
		}
		if rustPathRoots[root] || root == crateRoot {
			continue
		}
		switch {
		case found == "":
			found, sharedRoot = wildcard, root
		case found != wildcard:
			ambiguous = true
			if root != sharedRoot {
				// Globs from two different crates: the name could come from
				// either, so there is no identity to give it.
				return "", "", false
			}
		}
	}
	return found, sharedRoot, ambiguous
}

// crateExternAliases returns the crate-level `extern crate X as Y;` renames
// that a file can see.
//
// `extern crate` is a crate-root item: an alias declared in lib.rs is in scope
// for every module of that crate, and Rust code written against a -sys crate
// uses exactly that (`extern crate openssl_sys as ffi;` in openssl's lib.rs,
// then `ffi::SSL_new(..)` throughout). The parser's import model is per file, so
// every one of those calls resolved to a crate named "ffi" -- 1090 edges in
// openssl 0.10.81, none of which any contract can match.
//
// The crate root is found by walking up to the directory holding Cargo.toml and
// reading its src/lib.rs or src/main.rs; results are cached per parser instance,
// so a crate's root is parsed once per worker rather than once per file.
func (p *RustParser) crateExternAliases(filePath string) map[string]string {
	rootFile := rustCrateRootFile(filePath)
	if rootFile == "" {
		return nil
	}
	if cached, ok := p.crateAliasCache[rootFile]; ok {
		return cached
	}
	aliases := p.readCrateExternAliases(rootFile)
	if p.crateAliasCache == nil {
		p.crateAliasCache = make(map[string]map[string]string)
	}
	p.crateAliasCache[rootFile] = aliases
	return aliases
}

func (p *RustParser) readCrateExternAliases(rootFile string) map[string]string {
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
	staging := &FileAnalysis{
		Imports:       make(map[string]string),
		ImportAliases: make(map[string]string),
	}
	rootNamedChildren := int(root.NamedChildCount())
	for i := 0; i < rootNamedChildren; i++ {
		child := root.NamedChild(i)
		if child.Type() == "extern_crate_declaration" {
			p.recordRustExternCrateAlias(child, src, staging)
		}
	}
	if len(staging.ImportAliases) == 0 {
		return nil
	}
	return staging.ImportAliases
}

// rustCrateRootFile locates the crate root source file for a path inside a
// crate, or "" when there is none to find.
func rustCrateRootFile(filePath string) string {
	dir := filepath.Dir(filePath)
	for depth := 0; depth < 12 && dir != "" && dir != string(filepath.Separator); depth++ {
		if _, err := os.Stat(filepath.Join(dir, "Cargo.toml")); err == nil {
			for _, candidate := range []string{
				filepath.Join(dir, "src", "lib.rs"),
				filepath.Join(dir, "src", "main.rs"),
				filepath.Join(dir, "lib.rs"),
				filepath.Join(dir, "main.rs"),
			} {
				if _, err := os.Stat(candidate); err == nil {
					return candidate
				}
			}
			return ""
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}
