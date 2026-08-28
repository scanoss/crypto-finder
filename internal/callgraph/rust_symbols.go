// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/rust"
)

// tree-sitter identifies a node's kind by an INTEGER; `Node.Type()` crosses into
// C, converts a C string into a Go string — allocating — and only then compares
// bytes. The walkers here visit every node of every file, several times over:
// 327,160 nodes for openssl 0.10.81 alone, so that is on the order of a million
// conversions per crate. Resolving the integers once at init and comparing them
// instead cut allocations by 6x on a full walk (393k to 66k) at 19% less memory.
//
// The measured time difference is small — about 1.4% — because the dominant cost
// of walking is the cgo call per child, not reading the kind. This exists for the
// allocation pressure across a mining run, and for the check below.
//
// The second reason is robustness: a kind name that the grammar does not have
// resolves to zero and its switch case can then never match, which reads exactly
// like source that contains no such construct. Resolving up front records every
// such name in rustMissingSymbols, which a test asserts is empty. A typo, or a
// kind renamed by a grammar upgrade, fails there instead of silently emitting
// nothing.
type rustSymbolTable struct {
	// Scopes and statements
	block               sitter.Symbol
	unsafeBlock         sitter.Symbol
	asyncBlock          sitter.Symbol
	constBlock          sitter.Symbol
	tryBlock            sitter.Symbol
	letDeclaration      sitter.Symbol
	expressionStatement sitter.Symbol
	// Control flow
	ifExpression    sitter.Symbol
	whileExpression sitter.Symbol
	matchExpression sitter.Symbol
	matchArm        sitter.Symbol
	matchPattern    sitter.Symbol
	letCondition    sitter.Symbol
	forExpression   sitter.Symbol
	// Calls and access
	callExpression      sitter.Symbol
	fieldExpression     sitter.Symbol
	genericFunction     sitter.Symbol
	closureExpression   sitter.Symbol
	awaitExpression     sitter.Symbol
	tryExpression       sitter.Symbol
	indexExpression     sitter.Symbol
	referenceExpression sitter.Symbol
	unaryExpression     sitter.Symbol
	parenthesized       sitter.Symbol
	typeCast            sitter.Symbol
	structExpression    sitter.Symbol
	tupleExpression     sitter.Symbol
	macroInvocation     sitter.Symbol
	returnExpression    sitter.Symbol
	// Names and types
	identifier           sitter.Symbol
	typeIdentifier       sitter.Symbol
	scopedIdentifier     sitter.Symbol
	scopedTypeIdentifier sitter.Symbol
	selfKeyword          sitter.Symbol
	genericType          sitter.Symbol
	genericTurbofish     sitter.Symbol
	referenceType        sitter.Symbol
	dynamicType          sitter.Symbol
	abstractType         sitter.Symbol
	// Items
	functionItem      sitter.Symbol
	functionSignature sitter.Symbol
	implItem          sitter.Symbol
	traitItem         sitter.Symbol
	modItem           sitter.Symbol
	foreignModItem    sitter.Symbol
	structItem        sitter.Symbol
	unionItem         sitter.Symbol
	enumItem          sitter.Symbol
	typeItem          sitter.Symbol
	useDeclaration    sitter.Symbol
	externCrate       sitter.Symbol
	// Comments
	lineComment  sitter.Symbol
	blockComment sitter.Symbol
	docComment   sitter.Symbol
}

// rustSyms is resolved once at package init against the grammar every
// RustParser instance is compiled with.
var rustSyms, rustMissingSymbols = resolveRustSymbols(rust.GetLanguage())

func resolveRustSymbols(language *sitter.Language) (rustSymbolTable, []string) {
	var table rustSymbolTable
	wanted := map[string]*sitter.Symbol{
		goNodeBlock:                   &table.block,
		"unsafe_block":                &table.unsafeBlock,
		"async_block":                 &table.asyncBlock,
		"const_block":                 &table.constBlock,
		"try_block":                   &table.tryBlock,
		rustNodeLetDeclaration:        &table.letDeclaration,
		rustNodeExpressionStatement:   &table.expressionStatement,
		"if_expression":               &table.ifExpression,
		"while_expression":            &table.whileExpression,
		"match_expression":            &table.matchExpression,
		"match_arm":                   &table.matchArm,
		rustNodeMatchPattern:          &table.matchPattern,
		"let_condition":               &table.letCondition,
		"for_expression":              &table.forExpression,
		rustNodeCallExpression:        &table.callExpression,
		rustNodeFieldExpression:       &table.fieldExpression,
		rustNodeGenericFunction:       &table.genericFunction,
		rustNodeClosureExpression:     &table.closureExpression,
		"await_expression":            &table.awaitExpression,
		"try_expression":              &table.tryExpression,
		"index_expression":            &table.indexExpression,
		"reference_expression":        &table.referenceExpression,
		"unary_expression":            &table.unaryExpression,
		"parenthesized_expression":    &table.parenthesized,
		"type_cast_expression":        &table.typeCast,
		"struct_expression":           &table.structExpression,
		"tuple_expression":            &table.tupleExpression,
		"macro_invocation":            &table.macroInvocation,
		"return_expression":           &table.returnExpression,
		goNodeIdentifier:              &table.identifier,
		goNodeTypeIdentifier:          &table.typeIdentifier,
		javaNodeScopedIdentifier:      &table.scopedIdentifier,
		javaNodeScopedTypeIdentifier:  &table.scopedTypeIdentifier,
		rustNodeSelf:                  &table.selfKeyword,
		javaNodeGenericType:           &table.genericType,
		"generic_type_with_turbofish": &table.genericTurbofish,
		"reference_type":              &table.referenceType,
		"dynamic_type":                &table.dynamicType,
		"abstract_type":               &table.abstractType,
		rustNodeFunctionItem:          &table.functionItem,
		"function_signature_item":     &table.functionSignature,
		rustNodeImplItem:              &table.implItem,
		rustNodeTraitItem:             &table.traitItem,
		rustNodeModItem:               &table.modItem,
		"foreign_mod_item":            &table.foreignModItem,
		"struct_item":                 &table.structItem,
		"union_item":                  &table.unionItem,
		"enum_item":                   &table.enumItem,
		rustNodeTypeItem:              &table.typeItem,
		rustNodeUseDeclaration:        &table.useDeclaration,
		rustNodeExternCrate:           &table.externCrate,
		javaNodeLineComment:           &table.lineComment,
		javaNodeBlockComment:          &table.blockComment,
		rustNodeDocComment:            &table.docComment,
	}

	found := make(map[string]bool, len(wanted))
	for symbol := uint32(0); symbol < language.SymbolCount(); symbol++ {
		name := language.SymbolName(sitter.Symbol(symbol))
		target, ok := wanted[name]
		if !ok || found[name] {
			continue
		}
		if language.SymbolType(sitter.Symbol(symbol)) != sitter.SymbolTypeRegular {
			continue
		}
		*target = sitter.Symbol(symbol)
		found[name] = true
	}

	var missing []string
	for name := range wanted {
		if !found[name] {
			missing = append(missing, name)
		}
	}
	return table, missing
}

// rustIsBlockLike reports whether a symbol opens a block scope.
func rustIsBlockLike(symbol sitter.Symbol) bool {
	switch symbol {
	case rustSyms.block, rustSyms.unsafeBlock, rustSyms.asyncBlock,
		rustSyms.constBlock, rustSyms.tryBlock:
		return true
	}
	return false
}

// rustIsComment reports whether a symbol is a comment of any kind.
func rustIsComment(symbol sitter.Symbol) bool {
	switch symbol {
	case rustSyms.lineComment, rustSyms.blockComment, rustSyms.docComment:
		return true
	}
	return false
}
