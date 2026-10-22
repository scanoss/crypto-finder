// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"context"
	"fmt"
	"os"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

const (
	nodeClassDeclaration      = "class_declaration"
	nodeExportSpecifier       = "export_specifier"
	nodeShorthandProperty     = "shorthand_property_identifier"
	nodePair                  = "pair"
	nodeModuleExportsTarget   = "module.exports"
	nodeObjectDefineProperty  = "Object.defineProperty"
	nodeCommonJSExportsObject = "exports"
)

// NodeExportLines returns every module-level name a JavaScript or TypeScript
// file exports, mapped to the 1-based line that gives it its value. Unlike the
// entry-point exports it counts values of any kind, so a factory-built export
// such as `export const secp256k1 = createCurve(...)` is included.
func NodeExportLines(filePath string) (map[string]int, error) {
	parser := NewNodeParser().parserForFile(filePath)
	if parser == nil {
		return nil, fmt.Errorf("callgraph: node exports: unsupported source file %s", filePath)
	}
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("callgraph: node exports: read %s: %w", filePath, err)
	}
	tree, err := parser.ParseCtx(context.TODO(), nil, src)
	if err != nil {
		return nil, fmt.Errorf("callgraph: node exports: parse %s: %w", filePath, err)
	}
	defer tree.Close()

	out := make(map[string]int)
	root := tree.RootNode()
	for i := 0; i < int(root.NamedChildCount()); i++ {
		stmt := root.NamedChild(i)
		switch stmt.Type() {
		case nodeExportKind:
			nodeDeclarationExportLines(stmt.ChildByFieldName("declaration"), src, out)
			nodeClauseExportLines(stmt, src, out)
		case nodeExpressionStatement:
			if stmt.NamedChildCount() > 0 {
				nodeCommonJSExportLines(stmt.NamedChild(0), src, out)
			}
		}
	}
	return out, nil
}

func nodeLine(n *sitter.Node) int { return int(n.StartPoint().Row) + 1 }

// nodeDeclarationExportLines records `export const a = ..., b = ...`,
// `export function f`, and `export class C`.
func nodeDeclarationExportLines(decl *sitter.Node, src []byte, out map[string]int) {
	if decl == nil {
		return
	}
	switch decl.Type() {
	case nodeFunctionDeclaration, nodeGeneratorDeclaration, nodeClassDeclaration, nodeAbstractClassDeclaration:
		if name := decl.ChildByFieldName("name"); name != nil {
			out[name.Content(src)] = nodeLine(decl)
		}
	case nodeLexicalDeclaration, nodeVariableDeclaration:
		for i := 0; i < int(decl.NamedChildCount()); i++ {
			declarator := decl.NamedChild(i)
			if name := declarator.ChildByFieldName("name"); declarator.Type() == nodeVariableDeclarator && name != nil {
				out[name.Content(src)] = nodeLine(declarator)
			}
		}
	}
}

// nodeClauseExportLines records `export { a, b as c }`; a declaration of the
// same name keeps its own line.
func nodeClauseExportLines(stmt *sitter.Node, src []byte, out map[string]int) {
	for i := 0; i < int(stmt.NamedChildCount()); i++ {
		clause := stmt.NamedChild(i)
		if clause.Type() != nodeExportClauseKind {
			continue
		}
		for j := 0; j < int(clause.NamedChildCount()); j++ {
			spec := clause.NamedChild(j)
			name := spec.ChildByFieldName("name")
			if spec.Type() != nodeExportSpecifier || name == nil {
				continue
			}
			exported := name.Content(src)
			if alias := spec.ChildByFieldName("alias"); alias != nil {
				exported = alias.Content(src)
			}
			if _, seen := out[exported]; !seen {
				out[exported] = nodeLine(spec)
			}
		}
	}
}

// nodeCommonJSExportLines records exports.x = v, module.exports.x = v,
// module.exports = {a, b: c} and tsc's Object.defineProperty(exports, "x", ...).
func nodeCommonJSExportLines(expr *sitter.Node, src []byte, out map[string]int) {
	switch expr.Type() {
	case nodeAssignmentExpression:
		nodeCommonJSAssignmentLines(expr, src, out)
	case nodeCallExpression:
		nodeDefinePropertyExportLine(expr, src, out)
	}
}

// tsc's `exports.x = void 0` forward declarations are not values and are skipped.
func nodeCommonJSAssignmentLines(expr *sitter.Node, src []byte, out map[string]int) {
	left, right := expr.ChildByFieldName("left"), expr.ChildByFieldName("right")
	if left == nil || right == nil || left.Type() != nodeMemberExpression ||
		strings.HasPrefix(strings.TrimSpace(right.Content(src)), "void ") {
		return
	}
	target := left.Content(src)
	switch {
	case target == nodeModuleExportsTarget && right.Type() == nodeObjectLiteral:
		for i := 0; i < int(right.NamedChildCount()); i++ {
			member := right.NamedChild(i)
			if member.Type() == nodeShorthandProperty {
				out[member.Content(src)] = nodeLine(member)
			} else if key := member.ChildByFieldName("key"); member.Type() == nodePair && key != nil {
				out[unquoteNodeString(key.Content(src))] = nodeLine(member)
			}
		}
	case strings.HasPrefix(target, nodeCommonJSExportsObject+".") || strings.HasPrefix(target, nodeModuleExportsTarget+"."):
		if name, _ := nodeAssignmentTarget(left, src); name != "" {
			out[name] = nodeLine(expr)
		}
	}
}

func nodeDefinePropertyExportLine(expr *sitter.Node, src []byte, out map[string]int) {
	fn, args := expr.ChildByFieldName("function"), expr.ChildByFieldName("arguments")
	if fn == nil || args == nil || fn.Content(src) != nodeObjectDefineProperty || args.NamedChildCount() < 2 {
		return
	}
	if args.NamedChild(0).Content(src) != nodeCommonJSExportsObject || args.NamedChild(1).Type() != nodeStringNode {
		return
	}
	out[unquoteNodeString(args.NamedChild(1).Content(src))] = nodeLine(expr)
}
