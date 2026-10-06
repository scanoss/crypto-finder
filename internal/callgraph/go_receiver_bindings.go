// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"math"

	sitter "github.com/smacker/go-tree-sitter"
)

// goCaseScopes are the clause nodes whose body is a scope without a block
// node of its own.
var goCaseScopes = map[string]bool{
	"expression_case": true, "default_case": true, "type_case": true, "communication_case": true,
}

// goBinding is one place a function binds a name. The name is visible from
// end, within [scopeStart, scopeEnd).
type goBinding struct {
	end, scopeStart, scopeEnd uint32
	// declares is false for a plain `=`, which writes a variable declared
	// elsewhere (possibly outside the function) rather than introducing one.
	declares bool
}

// goBindingIndexes indexes, once per top-level function, every binding of
// every name, so a call asks "is this receiver bound once, above me?" without
// walking the function again. Reset it when the tree is closed.
type goBindingIndexes struct {
	byFunction map[uintptr]map[string][]goBinding
}

func (g *goBindingIndexes) reset() { g.byFunction = nil }

// boundOnce reports whether name, used by the call, is bound exactly once in
// the enclosing top-level function and that binding is in scope at the call:
// it precedes the call and its scope contains it. Anything else, including a
// name the function does not bind (a package variable), is false: a reader
// cannot tell which value reaches the call.
//
// Only a declaring binding makes the name local: a parameter or result, `:=`,
// `var`, a range or receive variable declared with `:=`, or a type-switch
// variable. A plain `=` and an address-of still count as bindings, so they
// poison a declared name, but a name whose only binding is `=` belongs to an
// outer scope and its value at the call is unknown. Closures count with the
// function they sit in.
func (g *goBindingIndexes) boundOnce(call *sitter.Node, name string, src []byte) bool {
	var fn *sitter.Node
	for n := call; n != nil; n = n.Parent() {
		if t := n.Type(); t == goNodeFunctionDecl || t == goNodeMethodDecl {
			fn = n
		}
	}
	if fn == nil {
		return false
	}
	if g.byFunction == nil {
		g.byFunction = make(map[uintptr]map[string][]goBinding)
	}
	index, ok := g.byFunction[fn.ID()]
	if !ok {
		index = make(map[string][]goBinding)
		collectGoBindings(fn, fn, src, index)
		g.byFunction[fn.ID()] = index
	}
	bindings := index[name]
	if len(bindings) != 1 {
		return false
	}
	b := bindings[0]
	return b.declares && b.end <= call.StartByte() && b.scopeStart <= call.StartByte() && call.EndByte() <= b.scopeEnd
}

func collectGoBindings(node, fn *sitter.Node, src []byte, index map[string][]goBinding) {
	end := node.EndByte()
	scope := fn
	declares := true
	var names []*sitter.Node
	switch node.Type() {
	case goNodeShortVarDeclaration, goNodeAssignmentStmt, goNodeRangeClause, goNodeReceiveStatement:
		names = goIdentifiersIn(node.ChildByFieldName(goFieldLeft))
		declares = goHasShortDeclaration(node)
	case goNodeTypeSwitch:
		names = goIdentifiersIn(node.ChildByFieldName("alias"))
	case goNodeVarSpec:
		names = goIdentifiersIn(node)
	case goNodeParameterDecl, goNodeVariadicParam:
		names, end = goIdentifiersIn(node), 0
	case goNodeUnaryExpression:
		if op := node.ChildByFieldName("operator"); op != nil && op.Content(src) == "&" {
			names, end, declares = goIdentifiersIn(node.ChildByFieldName("operand")), math.MaxUint32, false
		}
	}
	if len(names) > 0 && end != math.MaxUint32 {
		scope = goScopeOf(node, fn)
	}
	for _, name := range names {
		text := name.Content(src)
		index[text] = append(index[text], goBinding{end: end, scopeStart: scope.StartByte(), scopeEnd: scope.EndByte(), declares: declares})
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectGoBindings(node.Child(i), fn, src, index)
	}
}

// goHasShortDeclaration reports whether a binding statement declares with
// `:=`, as opposed to assigning with `=`.
func goHasShortDeclaration(node *sitter.Node) bool {
	for i := 0; i < int(node.ChildCount()); i++ {
		if node.Child(i).Type() == ":=" {
			return true
		}
	}
	return false
}

// goIdentifiersIn returns the bare identifiers directly in a binding list, or
// the node itself when it is one. A selector or index target binds nothing.
func goIdentifiersIn(list *sitter.Node) []*sitter.Node {
	if list == nil {
		return nil
	}
	if list.Type() == goNodeIdentifier {
		return []*sitter.Node{list}
	}
	var out []*sitter.Node
	for i := 0; i < int(list.NamedChildCount()); i++ {
		if child := list.NamedChild(i); child.Type() == goNodeIdentifier {
			out = append(out, child)
		}
	}
	return out
}

// goScopeOf returns the innermost scope a binding node sits in. A parameter
// belongs to the function or literal that declares it.
func goScopeOf(node, fn *sitter.Node) *sitter.Node {
	for n := node.Parent(); n != nil; n = n.Parent() {
		if t := n.Type(); goOpensScope(t) || goCaseScopes[t] || n == fn {
			return n
		}
	}
	return fn
}
