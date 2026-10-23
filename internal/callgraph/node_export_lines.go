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
	exports, err := NodeModuleExports(filePath)
	if err != nil {
		return nil, err
	}
	return exports.Lines, nil
}

// NodeExports is what one module exports: its own names, and the modules it
// re-exports wholesale (`export * from './x'`, tsc's `__exportStar(require('./x'), exports)`).
type NodeExports struct {
	Lines    map[string]int
	StarFrom []string
}

// NodeModuleExports reads the exports of one JavaScript or TypeScript file. A
// name assigned through an alias of the exports object counts too:
// `var elliptic = exports; elliptic.ec = ...` and `module.exports = bls; bls.x = ...`.
func NodeModuleExports(filePath string) (*NodeExports, error) {
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

	out := &NodeExports{Lines: make(map[string]int)}
	root := tree.RootNode()
	aliases := nodeExportAliases(root, src)
	for i := 0; i < int(root.NamedChildCount()); i++ {
		stmt := root.NamedChild(i)
		switch stmt.Type() {
		case nodeExportKind:
			nodeDeclarationExportLines(stmt.ChildByFieldName("declaration"), src, out.Lines)
			nodeClauseExportLines(stmt, src, out.Lines)
			if from := nodeStarExportSource(stmt, src); from != "" {
				out.StarFrom = append(out.StarFrom, from)
			}
		case nodeExpressionStatement:
			if stmt.NamedChildCount() == 0 {
				continue
			}
			expr := stmt.NamedChild(0)
			nodeCommonJSExportLines(expr, src, out.Lines)
			nodeAliasExportLine(expr, src, aliases, out.Lines)
			if from := nodeExportStarCall(expr, src); from != "" {
				out.StarFrom = append(out.StarFrom, from)
			}
		}
	}
	return out, nil
}

// nodeExportAliases returns the module-level names bound to the exports object.
func nodeExportAliases(root *sitter.Node, src []byte) map[string]bool {
	aliases := make(map[string]bool)
	for i := 0; i < int(root.NamedChildCount()); i++ {
		stmt := root.NamedChild(i)
		switch stmt.Type() {
		case nodeLexicalDeclaration, nodeVariableDeclaration:
			for j := 0; j < int(stmt.NamedChildCount()); j++ {
				d := stmt.NamedChild(j)
				name, value := d.ChildByFieldName("name"), d.ChildByFieldName("value")
				if name != nil && value != nil && isNodeExportsObject(value.Content(src)) {
					aliases[name.Content(src)] = true
				}
			}
		case nodeExpressionStatement:
			// module.exports = bls: the members later assigned to bls are exports.
			if expr := stmt.NamedChild(0); expr != nil && expr.Type() == nodeAssignmentExpression {
				left, right := expr.ChildByFieldName("left"), expr.ChildByFieldName("right")
				if left != nil && right != nil && left.Content(src) == nodeModuleExportsTarget && right.Type() == goNodeIdentifier {
					aliases[right.Content(src)] = true
				}
			}
		}
	}
	return aliases
}

func isNodeExportsObject(text string) bool {
	return text == nodeCommonJSExportsObject || text == nodeModuleExportsTarget
}

// nodeAliasExportLine records alias.name = value for an alias of the exports object.
func nodeAliasExportLine(expr *sitter.Node, src []byte, aliases map[string]bool, out map[string]int) {
	if expr.Type() != nodeAssignmentExpression || len(aliases) == 0 {
		return
	}
	left := expr.ChildByFieldName("left")
	if left == nil || left.Type() != nodeMemberExpression {
		return
	}
	obj, prop := left.ChildByFieldName("object"), left.ChildByFieldName("property")
	if obj == nil || prop == nil || obj.Type() != goNodeIdentifier || !aliases[obj.Content(src)] {
		return
	}
	if _, seen := out[prop.Content(src)]; !seen {
		out[prop.Content(src)] = nodeLine(expr)
	}
}

// nodeStarExportSource returns the module of `export * from 'x'`.
func nodeStarExportSource(stmt *sitter.Node, src []byte) string {
	source := stmt.ChildByFieldName("source")
	if source == nil || !strings.Contains(stmt.Content(src), "*") || stmt.ChildByFieldName("declaration") != nil {
		return ""
	}
	for i := 0; i < int(stmt.NamedChildCount()); i++ {
		if c := stmt.NamedChild(i); c.Type() == nodeExportClauseKind || c.Type() == "namespace_export" {
			return "" // `export { a } from` and `export * as ns from` name their exports
		}
	}
	return unquoteNodeString(source.Content(src))
}

// nodeExportStarCall returns the module of tsc's __exportStar(require('x'), exports),
// in any of its spellings (`tslib_1.__exportStar`, `(0, tslib_1.__exportStar)`).
func nodeExportStarCall(expr *sitter.Node, src []byte) string {
	if expr.Type() != nodeCallExpression {
		return ""
	}
	fn, args := expr.ChildByFieldName("function"), expr.ChildByFieldName("arguments")
	if fn == nil || args == nil || !strings.HasSuffix(strings.TrimRight(fn.Content(src), ")"), "__exportStar") || args.NamedChildCount() < 1 {
		return ""
	}
	req := args.NamedChild(0)
	if req.Type() != nodeCallExpression {
		return ""
	}
	reqFn, reqArgs := req.ChildByFieldName("function"), req.ChildByFieldName("arguments")
	if reqFn == nil || reqArgs == nil || reqFn.Content(src) != nodeRequireFunction || reqArgs.NamedChildCount() != 1 || reqArgs.NamedChild(0).Type() != nodeStringNode {
		return ""
	}
	return unquoteNodeString(reqArgs.NamedChild(0).Content(src))
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
		nodeExportObjectLines(right, src, out)
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

// nodeExportObjectLines records the members of module.exports = {a, b: c, d() {}}.
func nodeExportObjectLines(object *sitter.Node, src []byte, out map[string]int) {
	for i := 0; i < int(object.NamedChildCount()); i++ {
		member := object.NamedChild(i)
		switch member.Type() {
		case nodeShorthandProperty:
			out[member.Content(src)] = nodeLine(member)
		case nodePair:
			if key := member.ChildByFieldName("key"); key != nil {
				out[unquoteNodeString(key.Content(src))] = nodeLine(member)
			}
		case nodeMethodDefinition:
			if name := member.ChildByFieldName("name"); name != nil {
				out[unquoteNodeString(name.Content(src))] = nodeLine(member)
			}
		}
	}
}
