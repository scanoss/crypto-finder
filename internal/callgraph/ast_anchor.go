// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"fmt"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// callAnchors sets the AST anchors of the calls found in one parse tree. It
// indexes each ancestor's named children once and reuses that index for every
// later call under the same ancestor, so a file with n sibling statements that
// each hold a call costs O(n) child visits, not O(n) per call. The zero value
// is ready to use; reset drops the indexes once the tree is closed.
type callAnchors struct {
	// childIndexes maps a parent to the named-child index of each of its
	// named, non-comment children, keyed by child ID (the identity Node.Equal
	// compares). Keying parents by pointer keeps their tree's nodes reachable,
	// so no other tree can reuse a cached child ID.
	childIndexes map[*sitter.Node]map[uintptr]int
}

func (a *callAnchors) set(call *FunctionCall, node *sitter.Node) {
	if call == nil || node == nil {
		return
	}
	call.ASTKind = node.Type()
	call.NamedASTPath = a.namedASTPath(node)
}

func (a *callAnchors) reset() {
	a.childIndexes = nil
}

// namedASTPath encodes each relative named node as <kind>[<zero-based named-child index>] from the containing function to the call.
// A call with no function container above it (a Go package-level variable
// initializer, a JavaScript top-level statement) has no anchor, and the walk
// learns that before it computes any index.
func (a *callAnchors) namedASTPath(node *sitter.Node) string {
	lineage := []*sitter.Node{node}
	for current := node; ; {
		parent := current.Parent()
		if parent == nil {
			return ""
		}
		lineage = append(lineage, parent)
		if isFunctionContainer(parent.Type()) {
			break
		}
		current = parent
	}
	parts := make([]string, 0, len(lineage)-1)
	for i := len(lineage) - 2; i >= 0; i-- {
		index, ok := a.childIndex(lineage[i+1], lineage[i])
		if !ok {
			return ""
		}
		parts = append(parts, fmt.Sprintf("%s[%d]", lineage[i].Type(), index))
	}
	return strings.Join(parts, "/")
}

func (a *callAnchors) childIndex(parent, child *sitter.Node) (int, bool) {
	indexes, ok := a.childIndexes[parent]
	if !ok {
		indexes = namedChildIndexes(parent)
		if a.childIndexes == nil {
			a.childIndexes = make(map[*sitter.Node]map[uintptr]int)
		}
		a.childIndexes[parent] = indexes
	}
	index, ok := indexes[child.ID()]
	return index, ok
}

// namedChildIndexes visits parent's children once with a cursor; NamedChild(i)
// would rescan from the first child for every i.
func namedChildIndexes(parent *sitter.Node) map[uintptr]int {
	indexes := make(map[uintptr]int)
	cursor := sitter.NewTreeCursor(parent)
	defer cursor.Close()
	for ok := cursor.GoToFirstChild(); ok; ok = cursor.GoToNextSibling() {
		child := cursor.CurrentNode()
		if !child.IsNamed() || strings.Contains(child.Type(), "comment") {
			continue
		}
		indexes[child.ID()] = len(indexes)
	}
	return indexes
}

// isFunctionContainer reports whether kind is a node type that bounds a
// FunctionDecl's own call anchoring: the walk in namedASTPath stops there and
// renders the path relative to it. "static_initializer"/"field_declaration"
// anchor Java's synthetic `<clinit>` (class-load calls that sit directly in
// a class body, outside any method). "module" and "class_definition" anchor
// Python's synthetic `<module>`/`<clinit>` decls the same way: calls made
// directly in module-level statements or directly in a class body, outside
// any function/method, have no function_definition ancestor to stop at
// otherwise, so the walk would exhaust at the tree root and yield "" — which
// is exactly the anchor Java's own class-init entries were added to avoid.
// Safe for ordinary methods/functions: a real function_definition/
// method_definition is always encountered strictly before its enclosing
// module or class_definition, so this never changes their anchor.
func isFunctionContainer(kind string) bool {
	switch kind {
	case "function_declaration", "function_definition", "function_item", "method_declaration", "constructor_declaration", "method_definition", "arrow_function", "function_expression", "generator_function_declaration", "lambda_expression", "static_initializer", "field_declaration", pythonOwnerTypeModule, pythonNodeClassDefinition:
		return true
	default:
		return false
	}
}
