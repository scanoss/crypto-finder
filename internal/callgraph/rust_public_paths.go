// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"slices"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// rustPublicTypePaths reads a file's `pub use` items and records in
// facts.publicTypePaths, for each type one of them re-exports, its public path
// mapped to the path it names: `pub use self::signing_key::SigningKey;` in
// rsa's src/pkcs1v15.rs gives
// "rsa::pkcs1v15::SigningKey" -> "rsa::pkcs1v15::signing_key::SigningKey".
// Only a plain `pub` re-export makes a path public; `pub(crate) use` and a
// private `use` bind a name a consumer can never import.
func (p *RustParser) rustPublicTypePaths(scope *sitter.Node, src []byte, modulePath string, facts *rustFileFacts) {
	if scope == nil {
		return
	}
	for i := 0; i < int(scope.NamedChildCount()); i++ {
		child := scope.NamedChild(i)
		switch child.Type() {
		case rustNodeModItem:
			if !p.includeTests && rustModuleIsTestOnly(child, src) {
				continue
			}
			if name := nodeFieldText(child, "name", src); name != "" {
				p.rustPublicTypePaths(child.ChildByFieldName("body"), src, rustQualifyFactKey(modulePath, name), facts)
			}
		case rustNodeUseDeclaration:
			if rustItemVisibility(child, src) == "pub" {
				p.recordRustPublicUse(child, src, modulePath, facts)
			}
		}
	}
}

// recordRustPublicUse records the types one `pub use` item re-exports from
// modulePath.
func (p *RustParser) recordRustPublicUse(useDecl *sitter.Node, src []byte, modulePath string, facts *rustFileFacts) {
	staging := &FileAnalysis{
		PackagePath:   modulePath,
		Imports:       make(map[string]string),
		ImportAliases: make(map[string]string),
		// The file's own facts, so `pub use keys::PublicKeyParts;` beside
		// `mod keys;` resolves to that module, not a crate.
		rustFacts: facts,
	}
	p.processUseDecl(useDecl, src, staging, "")
	for name, pkg := range staging.Imports {
		if rustIsTypeCase(name) && pkg != "" {
			facts.publicTypePaths[rustQualifyFactKey(modulePath, name)] = rustQualifyFactKey(pkg, name)
		}
	}
	for alias, target := range staging.ImportAliases {
		leaf := target
		if i := strings.LastIndex(target, "::"); i >= 0 {
			leaf = target[i+2:]
		}
		if rustIsTypeCase(alias) && rustIsTypeCase(leaf) {
			facts.publicTypePaths[rustQualifyFactKey(modulePath, alias)] = target
		}
	}
}

// rustItemVisibility returns an item's visibility modifier as written, or ""
// for a private item.
func rustItemVisibility(item *sitter.Node, src []byte) string {
	for i := 0; i < int(item.NamedChildCount()); i++ {
		if child := item.NamedChild(i); child.Type() == "visibility_modifier" {
			return strings.Join(strings.Fields(child.Content(src)), "")
		}
	}
	return ""
}

// mergePublicTypePaths folds one file's public re-exports into the crate's,
// dropping a public path two files point at different types.
func (f *rustFileFacts) mergePublicTypePaths(other *rustFileFacts) {
	for public, target := range other.publicTypePaths {
		if f.conflicting["public:"+public] {
			continue
		}
		if existing, seen := f.publicTypePaths[public]; seen && existing != target {
			delete(f.publicTypePaths, public)
			f.conflicting["public:"+public] = true
			continue
		}
		f.publicTypePaths[public] = target
	}
}

// resolveRustPublicTypeChains follows each public path through the re-exports
// it names to the path that declares the type: lib.rs's
// `pub use crate::pkcs1v15::SigningKey;` would otherwise name another
// re-export, not the `signing_key` module the declaration lives in.
func resolveRustPublicTypeChains(facts *rustFileFacts) {
	const maxHops = 8
	for public, target := range facts.publicTypePaths {
		seen := map[string]bool{public: true}
		for hop := 0; hop < maxHops; hop++ {
			next, ok := facts.publicTypePaths[target]
			if !ok || seen[target] {
				break
			}
			seen[target] = true
			target = next
		}
		facts.publicTypePaths[public] = target
	}
}

// PublicTypePaths returns, for every type a parsed crate re-exports, the
// declaring path mapped to the sorted public paths it is re-exported under.
// A declaration keyed by the module that defines it can then also be found by
// the path a consumer imports, which is the path a contract names.
func (p *RustParser) PublicTypePaths() map[string][]string {
	index := p.crateIndex
	if index == nil {
		return nil
	}
	index.mu.Lock()
	defer index.mu.Unlock()
	out := make(map[string][]string)
	for _, facts := range index.crates {
		if facts == nil {
			continue
		}
		for public, declaring := range facts.publicTypePaths {
			if public != declaring {
				out[declaring] = append(out[declaring], public)
			}
		}
	}
	for declaring, public := range out {
		slices.Sort(public)
		out[declaring] = slices.Compact(public)
	}
	return out
}
