// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"context"
	"testing"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/rust"
)

// The Rust parser resolves identities from the grammar's named node kinds and
// named FIELDS. Both are the grammar's interface, and both change across
// tree-sitter-rust releases: v0.23.2 adds `gen_block`, v0.24.0 introduces
// `type_parameter`, `lifetime_parameter` and `use_bounds`, which reshapes the
// children of `type_parameters`.
//
// A field that no longer exists does not fail: ChildByFieldName returns nil and
// the parser silently resolves nothing, which reads exactly like code that has
// no crypto in it. These tests exist so that a grammar change breaks a TEST
// rather than the output. A mutation run over the field names this parser reads
// found `macro`, `consequence` and `alternative` guarded by nothing at all.
//
// The pin these facts were recorded against: ABI 14, 341 symbols, the node set
// shared by tree-sitter-rust v0.21.0 through v0.23.0.

func rustGrammarParse(t *testing.T, src string) *sitter.Node {
	t.Helper()
	parser := sitter.NewParser()
	parser.SetLanguage(rust.GetLanguage())
	tree, err := parser.ParseCtx(context.TODO(), nil, []byte(src))
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	t.Cleanup(tree.Close)
	return tree.RootNode()
}

// findRustNode returns the first node of a kind in document order.
func findRustNode(root *sitter.Node, kind string) *sitter.Node {
	if root == nil {
		return nil
	}
	if root.Type() == kind {
		return root
	}
	for i := 0; i < int(root.ChildCount()); i++ {
		if found := findRustNode(root.Child(i), kind); found != nil {
			return found
		}
	}
	return nil
}

// Every node kind the parser names must exist in the grammar it is compiled
// against. A typo, or a kind renamed by an upgrade, is otherwise invisible: the
// switch case simply never matches.
func TestRustGrammar_EveryNodeKindTheParserNamesExists(t *testing.T) {
	t.Parallel()

	language := rust.GetLanguage()
	known := map[string]bool{}
	for symbol := uint32(0); symbol < language.SymbolCount(); symbol++ {
		known[language.SymbolName(sitter.Symbol(symbol))] = true
	}

	for _, kind := range []string{
		// Items and modules
		"source_file", rustNodeModItem, rustNodeImplItem, rustNodeTraitItem,
		rustNodeFunctionItem, "function_signature_item", rustNodeTypeItem,
		"struct_item", "enum_item", "union_item", "const_item", "static_item",
		"foreign_mod_item", "extern_crate_declaration", "declaration_list",
		// Imports
		"use_declaration", "use_list", "scoped_use_list", "use_wildcard",
		rustNodeUseAsClause,
		// Paths
		javaNodeScopedIdentifier, javaNodeScopedTypeIdentifier, goNodeIdentifier,
		goNodeTypeIdentifier, rustNodeSelf, rustNodeCrate, rustNodeSuper,
		"qualified_type", "bracketed_type", javaNodeGenericType,
		"generic_type_with_turbofish", rustNodeGenericFunction, "type_arguments",
		// Expressions
		rustNodeCallExpression, rustNodeFieldExpression, "field_identifier",
		"arguments", "await_expression", "try_expression", "index_expression",
		"reference_expression", "unary_expression", "parenthesized_expression",
		"type_cast_expression", "struct_expression", "tuple_expression",
		"closure_expression", "closure_parameters", "macro_invocation",
		rustNodeTokenTree, "return_expression", rustNodeExpressionStatement,
		// Scopes and control flow
		goNodeBlock, "unsafe_block", "async_block", "const_block", "try_block",
		"if_expression", "match_expression", "match_block", "match_arm",
		rustNodeMatchPattern, "let_condition", "let_chain", "for_expression",
		"while_expression", "loop_expression",
		// Declarations and patterns
		rustNodeLetDeclaration, "parameters", "parameter", "self_parameter",
		"field_declaration", "field_declaration_list",
		"ordered_field_declaration_list", "enum_variant", "enum_variant_list",
		"tuple_pattern", "struct_pattern", "tuple_struct_pattern", "or_pattern",
		"ref_pattern", "mut_pattern", "slice_pattern", "captured_pattern",
		"field_pattern", "shorthand_field_identifier", "mutable_specifier",
		// Generics
		"type_parameters", "constrained_type_parameter", "optional_type_parameter",
		"where_clause", "where_predicate", "trait_bounds",
		// Types
		"reference_type", "pointer_type", "array_type", "primitive_type",
		"dynamic_type", "abstract_type", "tuple_type",
		// Comments
		javaNodeLineComment, javaNodeBlockComment, rustNodeDocComment,
	} {
		if !known[kind] {
			t.Errorf("node kind %q is not in this grammar; the parser names it and would silently never match", kind)
		}
	}
}

// Every field the parser reads must resolve on a construct that uses it. This is
// the half a symbol check cannot cover: a field can be renamed while the node
// kind stays.
func TestRustGrammar_EveryFieldTheParserReadsResolves(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		src    string
		kind   string
		fields []string
	}{
		{
			name:   "impl block exposes its target and its trait separately",
			src:    `impl Digest for MyHasher { fn update(&self) {} }`,
			kind:   rustNodeImplItem,
			fields: []string{"type", "trait", "body"},
		},
		{
			name:   "let declaration exposes pattern, type, value and else",
			src:    `fn f() { let Some(x): Option<u8> = y else { return; }; }`,
			kind:   rustNodeLetDeclaration,
			fields: []string{"pattern", "type", "value", "alternative"},
		},
		{
			name:   "call exposes its callee and its arguments",
			src:    `fn f() { g(1); }`,
			kind:   rustNodeCallExpression,
			fields: []string{"function", "arguments"},
		},
		{
			name:   "field expression exposes receiver and field",
			src:    `fn f() { a.b(); }`,
			kind:   rustNodeFieldExpression,
			fields: []string{"value", "field"},
		},
		{
			name:   "scoped identifier exposes path and name",
			src:    `fn f() { a::b(); }`,
			kind:   javaNodeScopedIdentifier,
			fields: []string{"path", "name"},
		},
		{
			name:   "scoped use list exposes its path",
			src:    `use aes::{Aes128, Aes256};`,
			kind:   "scoped_use_list",
			fields: []string{"path"},
		},
		{
			name:   "use as clause exposes path and alias",
			src:    `use cbc::Encryptor as Enc;`,
			kind:   rustNodeUseAsClause,
			fields: []string{"path", "alias"},
		},
		{
			name:   "function exposes name, parameters, return type and body",
			src:    `fn f(a: u8) -> u16 { 0 }`,
			kind:   rustNodeFunctionItem,
			fields: []string{"name", "parameters", "return_type", "body"},
		},
		{
			name:   "parameter exposes pattern and type",
			src:    `fn f(a: u8) {}`,
			kind:   "parameter",
			fields: []string{"pattern", "type"},
		},
		{
			name:   "field declaration exposes name and type",
			src:    `struct S { cipher: Aes128 }`,
			kind:   "field_declaration",
			fields: []string{"name", "type"},
		},
		{
			name:   "struct exposes name and body",
			src:    `struct S { a: u8 }`,
			kind:   "struct_item",
			fields: []string{"name", "body"},
		},
		{
			name:   "enum variant exposes name and body",
			src:    `enum E { V(u8) }`,
			kind:   "enum_variant",
			fields: []string{"name", "body"},
		},
		{
			name:   "type alias exposes name and target",
			src:    `type A = aes::Aes128;`,
			kind:   rustNodeTypeItem,
			fields: []string{"name", "type"},
		},
		{
			name:   "if expression exposes condition, consequence and alternative",
			src:    `fn f() { if a { b() } else { c() } }`,
			kind:   "if_expression",
			fields: []string{"condition", "consequence", "alternative"},
		},
		{
			name:   "let condition exposes pattern and value",
			src:    `fn f() { if let Some(x) = y { } }`,
			kind:   "let_condition",
			fields: []string{"pattern", "value"},
		},
		{
			name:   "match exposes value and body; arms expose pattern and value",
			src:    `fn f() { match a { B(c) => d(), _ => e() } }`,
			kind:   "match_arm",
			fields: []string{"pattern", "value"},
		},
		{
			name:   "for expression exposes pattern, value and body",
			src:    `fn f() { for c in v { c.go(); } }`,
			kind:   "for_expression",
			fields: []string{"pattern", "value", "body"},
		},
		{
			name:   "closure exposes parameters and body",
			src:    `fn f() { let g = |c| c.go(); }`,
			kind:   "closure_expression",
			fields: []string{"parameters", "body"},
		},
		{
			name:   "macro invocation exposes its macro name",
			src:    `fn f() { let v = vec![a]; }`,
			kind:   "macro_invocation",
			fields: []string{"macro"},
		},
		{
			name:   "constrained type parameter exposes its bounds",
			src:    `fn f<C: BlockEncrypt>(c: &C) {}`,
			kind:   "constrained_type_parameter",
			fields: []string{"left", "bounds"},
		},
		{
			name:   "where predicate exposes its subject and bounds",
			src:    `fn f<C>(c: &C) where C: BlockEncrypt {}`,
			kind:   "where_predicate",
			fields: []string{"left", "bounds"},
		},
		{
			name:   "module exposes name and body",
			src:    `mod inner { fn f() {} }`,
			kind:   rustNodeModItem,
			fields: []string{"name", "body"},
		},
		{
			name:   "trait exposes name and body",
			src:    `trait T { fn f(&self) {} }`,
			kind:   rustNodeTraitItem,
			fields: []string{"name", "body"},
		},
		{
			name:   "generic type exposes its base type",
			src:    `type A = Encryptor<Aes128>;`,
			kind:   javaNodeGenericType,
			fields: []string{"type"},
		},
		{
			name:   "qualified type exposes the type and the trait",
			src:    `fn f() { <Aes128 as KeyInit>::new(); }`,
			kind:   "qualified_type",
			fields: []string{"type", "alias"},
		},
		{
			name:   "struct expression exposes its name",
			src:    `fn f() { let s = S { a: 1 }; }`,
			kind:   "struct_expression",
			fields: []string{"name"},
		},
		{
			name:   "reference expression exposes its value",
			src:    `fn f() { g(&a); }`,
			kind:   "reference_expression",
			fields: []string{"value"},
		},
		{
			name:   "cast exposes its target type",
			src:    `fn f() { let a = b as u8; }`,
			kind:   "type_cast_expression",
			fields: []string{"type"},
		},
		{
			name:   "field pattern exposes its name",
			src:    `fn f() { let S { cipher: c } = s; }`,
			kind:   "field_pattern",
			fields: []string{"name", "pattern"},
		},
		{
			name:   "tuple struct pattern exposes its type",
			src:    `fn f() { let E::V(c) = e; }`,
			kind:   "tuple_struct_pattern",
			fields: []string{"type"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := rustGrammarParse(t, tc.src)
			node := findRustNode(root, tc.kind)
			if node == nil {
				t.Fatalf("this grammar produced no %q for %q", tc.kind, tc.src)
			}
			for _, field := range tc.fields {
				if node.ChildByFieldName(field) == nil {
					t.Errorf("%s has no field %q in this grammar; a read of it resolves nothing, silently", tc.kind, field)
				}
			}
		})
	}
}

// The pinned grammar cannot parse a turbofish in a parameter's TYPE position,
// which rustc accepts. The parser compensates with a text fallback gated on the
// parse error, so the day an upgrade fixes the grammar this test says so and the
// fallback can go.
func TestRustGrammar_ParameterTurbofishStillFailsToParse(t *testing.T) {
	t.Parallel()

	root := rustGrammarParse(t, `fn f(dec: cbc::Decryptor::<Aes128>, buf: &mut [u8]) {}`)
	if !root.HasError() {
		t.Error("this grammar now parses a turbofish in a parameter type; the ERROR-gated text fallback in bindParameters is obsolete and should be removed")
	}
}

// Async closures and `gen` blocks are the known staleness of this pin. When an
// upgrade lands, these stop erroring and the documented limitation can be
// dropped.
func TestRustGrammar_KnownStalenessIsStillPresent(t *testing.T) {
	t.Parallel()

	for name, src := range map[string]string{
		"async closure": `fn f() { let g = async |x| { x }; }`,
		"gen block":     `fn f() { let g = gen { yield 1; }; let _ = g; }`,
	} {
		root := rustGrammarParse(t, src)
		if !root.HasError() {
			t.Errorf("%s now parses cleanly; the documented Rust limitation for it is obsolete", name)
		}
	}
}

// The parser dispatches on tree-sitter's integer node symbols, resolved once at
// package init. A kind name the grammar does not have resolves to zero, and its
// switch case can then never match — which reads exactly like source that has no
// such construct in it. That is the failure mode a grammar upgrade produces, and
// the reason the resolution records what it could not find.
func TestRustGrammar_EverySymbolTheParserDispatchesOnResolves(t *testing.T) {
	t.Parallel()

	if len(rustMissingSymbols) != 0 {
		t.Errorf("these node kinds are dispatched on but do not exist in this grammar: %v", rustMissingSymbols)
	}
}

// A resolved symbol must actually match the nodes it names. The check above only
// proves the name exists; this proves the integer is wired to the right field, so
// a mis-assigned entry in the table cannot pass unnoticed.
func TestRustGrammar_ResolvedSymbolsMatchTheirNodes(t *testing.T) {
	t.Parallel()

	root := rustGrammarParse(t, `use aes::Aes128;
type Alias = Aes128;
struct S { f: u8 }
enum E { V(u8) }
trait T { fn t(&self); }
impl S { fn m(&self) -> u8 { 0 } }
mod inner { }
fn f(a: &u8) -> u8 {
    let x = g(a)?;
    let y = S { f: 1 };
    let z = &y.f;
    let w = if true { 1 } else { 2 };
    match w { _ => () }
    for _i in 0..1 { }
    while false { }
    let c = |v| v;
    unsafe { }
    let _ = vec![1];
    let _ = x as u8;
    return *z;
}
`)
	for _, tc := range []struct {
		kind   string
		symbol sitter.Symbol
	}{
		{"use_declaration", rustSyms.useDeclaration},
		{rustNodeTypeItem, rustSyms.typeItem},
		{"struct_item", rustSyms.structItem},
		{"enum_item", rustSyms.enumItem},
		{rustNodeTraitItem, rustSyms.traitItem},
		{rustNodeImplItem, rustSyms.implItem},
		{rustNodeModItem, rustSyms.modItem},
		{rustNodeFunctionItem, rustSyms.functionItem},
		{rustNodeLetDeclaration, rustSyms.letDeclaration},
		{goNodeBlock, rustSyms.block},
		{"if_expression", rustSyms.ifExpression},
		{"match_expression", rustSyms.matchExpression},
		{"match_arm", rustSyms.matchArm},
		{"for_expression", rustSyms.forExpression},
		{"while_expression", rustSyms.whileExpression},
		{rustNodeClosureExpression, rustSyms.closureExpression},
		{"unsafe_block", rustSyms.unsafeBlock},
		{rustNodeCallExpression, rustSyms.callExpression},
		{rustNodeFieldExpression, rustSyms.fieldExpression},
		{"try_expression", rustSyms.tryExpression},
		{"struct_expression", rustSyms.structExpression},
		{"reference_expression", rustSyms.referenceExpression},
		{"unary_expression", rustSyms.unaryExpression},
		{"type_cast_expression", rustSyms.typeCast},
		{"macro_invocation", rustSyms.macroInvocation},
		{"return_expression", rustSyms.returnExpression},
		{goNodeIdentifier, rustSyms.identifier},
		{goNodeTypeIdentifier, rustSyms.typeIdentifier},
		{javaNodeScopedIdentifier, rustSyms.scopedIdentifier},
	} {
		node := findRustNode(root, tc.kind)
		if node == nil {
			t.Errorf("the fixture produced no %q, so its symbol is unverified", tc.kind)
			continue
		}
		if node.Symbol() != tc.symbol {
			t.Errorf("symbol for %q is %d, but a real %s node has %d — the table entry is wired to the wrong kind",
				tc.kind, tc.symbol, tc.kind, node.Symbol())
		}
	}
}
