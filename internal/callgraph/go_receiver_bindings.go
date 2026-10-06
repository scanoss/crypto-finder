// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	sitter "github.com/smacker/go-tree-sitter"
)

// goReceiverBindings counts how many times the enclosing top-level function
// binds name: as a parameter or result, by `:=`, `=` or `var`, as a range,
// receive or type-switch variable, or by taking its address. A variable
// bound exactly once, by the call that produced it, still holds that call's
// value wherever it is read; any further binding means a reader cannot tell
// which value reaches it. Closures count with the function they sit in, so a
// binding inside one makes the name ambiguous too.
//
// The count is 0 when the call is not inside a function declaration.
func goReceiverBindings(call *sitter.Node, name string, src []byte) int {
	var fn *sitter.Node
	for n := call; n != nil; n = n.Parent() {
		if t := n.Type(); t == goNodeFunctionDecl || t == goNodeMethodDecl {
			fn = n
		}
	}
	if fn == nil {
		return 0
	}
	return countGoBindings(fn, name, src)
}

func countGoBindings(node *sitter.Node, name string, src []byte) int {
	count := 0
	switch node.Type() {
	case goNodeShortVarDeclaration, goNodeAssignmentStmt:
		count += countGoIdentifiers(node.ChildByFieldName(goFieldLeft), name, src)
	case goNodeRangeClause, goNodeReceiveStatement:
		count += countGoIdentifiers(node.ChildByFieldName(goFieldLeft), name, src)
	case goNodeVarSpec, goNodeParameterDecl, goNodeVariadicParam:
		for i := 0; i < int(node.NamedChildCount()); i++ {
			child := node.NamedChild(i)
			if child.Type() == goNodeIdentifier && child.Content(src) == name {
				count++
			}
		}
	case goNodeTypeSwitch:
		count += countGoIdentifiers(node.ChildByFieldName("alias"), name, src)
	case goNodeUnaryExpression:
		if op := node.ChildByFieldName("operator"); op != nil && op.Content(src) == "&" {
			if operand := node.ChildByFieldName("operand"); operand != nil && operand.Type() == goNodeIdentifier && operand.Content(src) == name {
				count++
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		count += countGoBindings(node.Child(i), name, src)
	}
	return count
}

// countGoIdentifiers counts the bare identifiers named name directly in a
// binding list (`a, b := ...`). A selector or index target is not a binding of
// the name.
func countGoIdentifiers(list *sitter.Node, name string, src []byte) int {
	if list == nil {
		return 0
	}
	if list.Type() == goNodeIdentifier {
		if list.Content(src) == name {
			return 1
		}
		return 0
	}
	count := 0
	for i := 0; i < int(list.NamedChildCount()); i++ {
		child := list.NamedChild(i)
		if child.Type() == goNodeIdentifier && child.Content(src) == name {
			count++
		}
	}
	return count
}
