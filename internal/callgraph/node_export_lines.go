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

// NodeExports is what one module exports: its own names, the modules it
// re-exports wholesale (`export * from './x'`, tsc's `__exportStar(require('./x'), exports)`),
// the modules it re-exports under a name (`export * as ns from './x'`), the
// modules whose exported factory it calls (`module.exports = require('./lib')(addon)`),
// and what its own exported factory returns.
type NodeExports struct {
	Lines       map[string]int
	StarFrom    []string
	NamespaceOf map[string]string
	FactoryFrom []string
	Returned    map[string]int
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

	out := &NodeExports{Lines: make(map[string]int), NamespaceOf: make(map[string]string), Returned: make(map[string]int)}
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
			if ns, from := nodeNamespaceExport(stmt, src); ns != "" {
				out.Lines[ns] = nodeLine(stmt)
				out.NamespaceOf[ns] = from
			}
		case nodeExpressionStatement:
			if stmt.NamedChildCount() == 0 {
				continue
			}
			expr := stmt.NamedChild(0)
			nodeCommonJSExportLines(expr, src, out.Lines)
			if from := nodeExportStarCall(expr, src); from != "" {
				out.StarFrom = append(out.StarFrom, from)
			}
		}
	}
	nodeAliasExportLines(root, src, aliases, out.Lines)
	nodeModuleExportsValues(root, src, out)
	return out, nil
}

// nodeModuleExportsValues reads `module.exports = <value>` anywhere in the file
// (also inside try or a guard): a required module is re-exported, a called
// required module is a factory to read, and an exported function returns its API.
func nodeModuleExportsValues(root *sitter.Node, src []byte, out *NodeExports) {
	nodeWalk(root, func(n *sitter.Node) {
		if n.Type() != nodeAssignmentExpression {
			return
		}
		left, right := n.ChildByFieldName("left"), n.ChildByFieldName("right")
		if left == nil || right == nil || left.Content(src) != nodeModuleExportsTarget {
			return
		}
		nodeModuleExportsValue(root, right, src, out)
	})
}

func nodeModuleExportsValue(root, right *sitter.Node, src []byte, out *NodeExports) {
	if from := nodeRequireSource(right, src); from != "" {
		out.StarFrom = append(out.StarFrom, from)
		return
	}
	switch right.Type() {
	case nodeCallExpression:
		if from := nodeRequireSource(right.ChildByFieldName("function"), src); from != "" {
			out.FactoryFrom = append(out.FactoryFrom, from)
		}
	case nodeArrowFunction, nodeFunctionExpression:
		nodeFunctionReturnLines(right, src, out.Returned)
	case goNodeIdentifier:
		if fn := nodeTopLevelFunction(root, right.Content(src), src); fn != nil {
			nodeFunctionReturnLines(fn, src, out.Returned)
		}
	}
}

// nodeTopLevelFunction returns the function a top-level declaration names:
// `function f() {}` or `const f = () => {}`.
func nodeTopLevelFunction(root *sitter.Node, name string, src []byte) *sitter.Node {
	for i := 0; i < int(root.NamedChildCount()); i++ {
		stmt := root.NamedChild(i)
		if stmt.Type() == nodeFunctionDeclaration {
			if n := stmt.ChildByFieldName("name"); n != nil && n.Content(src) == name {
				return stmt
			}
			continue
		}
		for j := 0; j < int(stmt.NamedChildCount()); j++ {
			d := stmt.NamedChild(j)
			if d.Type() != nodeVariableDeclarator {
				continue
			}
			n, v := d.ChildByFieldName("name"), d.ChildByFieldName("value")
			if n != nil && v != nil && n.Content(src) == name && (v.Type() == nodeArrowFunction || v.Type() == nodeFunctionExpression) {
				return v
			}
		}
	}
	return nil
}

// nodeRequireSource returns the module of `require('x')`.
func nodeRequireSource(n *sitter.Node, src []byte) string {
	if n == nil || n.Type() != nodeCallExpression {
		return ""
	}
	fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
	if fn == nil || args == nil || fn.Content(src) != nodeRequireFunction || args.NamedChildCount() != 1 || args.NamedChild(0).Type() != nodeStringNode {
		return ""
	}
	return unquoteNodeString(args.NamedChild(0).Content(src))
}

// nodeFunctionReturnLines reads the object literal a function returns from its
// body: `(x) => ({...})` or a top-level `return {...}`, also frozen.
func nodeFunctionReturnLines(fn *sitter.Node, src []byte, out map[string]int) {
	body := fn.ChildByFieldName("body")
	for body != nil && body.Type() == goNodeParenExpr && body.NamedChildCount() > 0 {
		body = body.NamedChild(0)
	}
	if body == nil {
		return
	}
	if body.Type() == nodeObjectLiteral {
		nodeExportObjectLines(body, src, out)
		return
	}
	for i := 0; i < int(body.NamedChildCount()); i++ {
		if stmt := body.NamedChild(i); stmt.Type() == goNodeReturnStatement && stmt.NamedChildCount() == 1 {
			if obj := nodeUnfrozen(stmt.NamedChild(0), src); obj.Type() == nodeObjectLiteral {
				nodeExportObjectLines(obj, src, out)
			}
		}
	}
}

// nodeUnfrozen returns the object of `Object.freeze(obj)`, else n.
func nodeUnfrozen(n *sitter.Node, src []byte) *sitter.Node {
	if n.Type() != nodeCallExpression {
		return n
	}
	fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
	if fn != nil && args != nil && fn.Content(src) == "Object.freeze" && args.NamedChildCount() == 1 {
		return args.NamedChild(0)
	}
	return n
}

// nodeExportAliases returns the names bound to the exports object anywhere in
// the file: `var e = exports`, `module.exports = lib` (also inside a UMD guard),
// and the parameter of an IIFE called with module.exports (tweetnacl's
// `(function(nacl) {...})(module.exports)`).
func nodeExportAliases(root *sitter.Node, src []byte) map[string]bool {
	aliases := make(map[string]bool)
	nodeWalk(root, func(n *sitter.Node) {
		switch n.Type() {
		case nodeVariableDeclarator:
			name, value := n.ChildByFieldName("name"), n.ChildByFieldName("value")
			if name != nil && value != nil && isNodeExportsObject(value.Content(src)) {
				aliases[name.Content(src)] = true
			}
		case nodeAssignmentExpression:
			left, right := n.ChildByFieldName("left"), n.ChildByFieldName("right")
			if left != nil && right != nil && left.Content(src) == nodeModuleExportsTarget && right.Type() == goNodeIdentifier {
				aliases[right.Content(src)] = true
			}
		case nodeCallExpression:
			if param := nodeExportsIIFEParam(n, src); param != "" {
				aliases[param] = true
			}
		}
	})
	return aliases
}

// nodeExportsIIFEParam returns the first parameter of an IIFE whose first
// argument mentions module.exports.
func nodeExportsIIFEParam(call *sitter.Node, src []byte) string {
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	for fn != nil && fn.Type() == goNodeParenExpr && fn.NamedChildCount() > 0 {
		fn = fn.NamedChild(0)
	}
	if fn == nil || args == nil || args.NamedChildCount() == 0 || (fn.Type() != nodeFunctionExpression && fn.Type() != nodeArrowFunction) {
		return ""
	}
	if !strings.Contains(args.NamedChild(0).Content(src), nodeModuleExportsTarget) {
		return ""
	}
	params := fn.ChildByFieldName("parameters")
	if params == nil || params.NamedChildCount() == 0 || params.NamedChild(0).Type() != goNodeIdentifier {
		return ""
	}
	return params.NamedChild(0).Content(src)
}

// nodeAliasExportLines records, anywhere in the file, `alias.name = v`,
// `alias.name.sub = v` (as name) and the keys of `var alias = { ... }`.
func nodeAliasExportLines(root *sitter.Node, src []byte, aliases map[string]bool, out map[string]int) {
	if len(aliases) == 0 {
		return
	}
	nodeWalk(root, func(n *sitter.Node) {
		switch n.Type() {
		case nodeAssignmentExpression:
			if name := nodeAliasMember(n.ChildByFieldName("left"), src, aliases); name != "" {
				if _, seen := out[name]; !seen {
					out[name] = nodeLine(n)
				}
			}
		case nodeVariableDeclarator:
			name, value := n.ChildByFieldName("name"), n.ChildByFieldName("value")
			if name != nil && value != nil && aliases[name.Content(src)] && value.Type() == nodeObjectLiteral {
				nodeExportObjectLines(value, src, out)
			}
		}
	})
}

// nodeAliasMember returns the member right after an alias at the base of a
// member chain: "sjcl.cipher.aes" with alias sjcl gives "cipher".
func nodeAliasMember(left *sitter.Node, src []byte, aliases map[string]bool) string {
	member := ""
	for left != nil && left.Type() == nodeMemberExpression {
		if prop := left.ChildByFieldName("property"); prop != nil {
			member = prop.Content(src)
		}
		obj := left.ChildByFieldName("object")
		if obj != nil && obj.Type() == goNodeIdentifier {
			if aliases[obj.Content(src)] {
				return member
			}
			return ""
		}
		left = obj
	}
	return ""
}

func nodeWalk(n *sitter.Node, visit func(*sitter.Node)) {
	stack := []*sitter.Node{n}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		visit(cur)
		for i := int(cur.NamedChildCount()) - 1; i >= 0; i-- {
			stack = append(stack, cur.NamedChild(i))
		}
	}
}

func isNodeExportsObject(text string) bool {
	return text == nodeCommonJSExportsObject || text == nodeModuleExportsTarget
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

// nodeNamespaceExport returns the name and module of `export * as ns from 'x'`.
func nodeNamespaceExport(stmt *sitter.Node, src []byte) (string, string) {
	source := stmt.ChildByFieldName("source")
	if source == nil {
		return "", ""
	}
	for i := 0; i < int(stmt.NamedChildCount()); i++ {
		if c := stmt.NamedChild(i); c.Type() == "namespace_export" && c.NamedChildCount() == 1 {
			return unquoteNodeString(c.NamedChild(0).Content(src)), unquoteNodeString(source.Content(src))
		}
	}
	return "", ""
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
