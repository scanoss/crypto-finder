// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"fmt"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

func setFunctionCallASTAnchor(call *FunctionCall, node *sitter.Node) {
	if call == nil || node == nil {
		return
	}
	call.ASTKind = node.Type()
	call.NamedASTPath = namedASTPath(node)
}

// namedASTPath encodes each relative named node as <kind>[<zero-based named-child index>] from the containing function to the call.
func namedASTPath(node *sitter.Node) string {
	var parts []string
	for current, parent := node, node.Parent(); current != nil && parent != nil; current, parent = parent, parent.Parent() {
		index := namedChildIndex(parent, current)
		if index < 0 {
			return ""
		}
		parts = append(parts, fmt.Sprintf("%s[%d]", current.Type(), index))
		if isFunctionContainer(parent.Type()) {
			for left, right := 0, len(parts)-1; left < right; left, right = left+1, right-1 {
				parts[left], parts[right] = parts[right], parts[left]
			}
			return strings.Join(parts, "/")
		}
	}
	return ""
}

func namedChildIndex(parent, child *sitter.Node) int {
	index := 0
	// The count is hoisted out of the loop condition on purpose: every
	// tree-sitter node access is a cgo call, and evaluating it once per
	// iteration doubled the cost of a scan that runs for every call expression
	// in every file.
	parentNamedChildren := int(parent.NamedChildCount())
	for i := 0; i < parentNamedChildren; i++ {
		namedChild := parent.NamedChild(i)
		if strings.Contains(namedChild.Type(), "comment") {
			continue
		}
		if namedChild.Equal(child) {
			return index
		}
		index++
	}
	return -1
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
