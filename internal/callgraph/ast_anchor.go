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
	for i := 0; i < int(parent.NamedChildCount()); i++ {
		if parent.NamedChild(i).Equal(child) {
			return i
		}
	}
	return -1
}

func isFunctionContainer(kind string) bool {
	switch kind {
	case "function_declaration", "function_definition", "function_item", "method_declaration", "constructor_declaration", "method_definition", "arrow_function", "lambda_expression":
		return true
	default:
		return false
	}
}
