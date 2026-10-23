// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

const (
	nodeSpreadElement   = "spread_element"
	nodeStatementBlock  = "statement_block"
	nodeImportSpecifier = "import_specifier"
	nodeNamespaceImport = "namespace_import"
	nodeAwaitExpression = "await_expression"
	nodeDefaultExport   = "default"
	nodeProgram         = "program"
	nodeFieldKey        = "key"
	nodeFieldName       = "name"
	nodeClassBody       = "class_body"
	nodeObjectFreeze    = "Object.freeze"
	nodeLiteralFalse    = "false"
	nodeLiteralNull     = "null"
	nodeLiteralTrue     = "true"

	// nodeShapeDepth bounds how many calls, bindings and modules one shape follows.
	nodeShapeDepth = 16
)

// NodeShapes resolves which members an exported value has, following calls,
// spreads and imports across the modules of one package. A shape that depends
// on something only known at run time is reported as unknown, not guessed.
type NodeShapes struct {
	parser  *NodeParser
	modules map[string]*nodeShapeModule
}

type nodeShapeModule struct {
	path string
	src  []byte
	tree *sitter.Tree
	root *sitter.Node
}

type nodeShape struct {
	keys map[string]bool
	open bool
}

// NewNodeShapes returns an empty resolver; Close releases its parse trees.
func NewNodeShapes() *NodeShapes {
	return &NodeShapes{parser: NewNodeParser(), modules: make(map[string]*nodeShapeModule)}
}

// Close releases the parse trees.
func (s *NodeShapes) Close() {
	for _, m := range s.modules {
		m.tree.Close()
	}
}

// ExportMembers returns the members of the value file exports as name. ok is
// false when they cannot be known statically: a class, a function, or an
// object built from something that is not in the package source.
func (s *NodeShapes) ExportMembers(file, name string) (map[string]bool, bool) {
	mod := s.module(file)
	if mod == nil {
		return nil, false
	}
	value, vmod := s.exportValue(mod, name, 0)
	if value == nil {
		return nil, false
	}
	sh := s.valueShape(vmod, value, name, 0)
	if sh.open {
		return nil, false
	}
	return sh.keys, true
}

// ExportIsCallable reports whether file's export name is a class or function,
// the only exports a constructor api can name. known is false when the value
// is only decided at run time, such as a factory's result.
func (s *NodeShapes) ExportIsCallable(file, name string) (callable, known bool) {
	mod := s.module(file)
	if mod == nil {
		return false, false
	}
	value, vmod := s.exportValue(mod, name, 0)
	return s.callable(vmod, value, 0)
}

func (s *NodeShapes) callable(m *nodeShapeModule, n *sitter.Node, depth int) (callable, known bool) {
	n = nodeUnwrapValue(n)
	if n == nil || depth > nodeShapeDepth {
		return false, false
	}
	switch {
	case nodeIsFunction(n):
		return true, true
	case n.Type() == goNodeIdentifier:
		value, vm := s.binding(m, n, n.Content(m.src), depth)
		return s.callable(vm, value, depth+1)
	case n.Type() == nodeCallExpression:
		fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
		if fn != nil && args != nil && fn.Content(m.src) == nodeRequireFunction && args.NamedChildCount() == 1 {
			if target := s.relative(m, unquoteNodeString(args.NamedChild(0).Content(m.src))); target != nil {
				value, vm := s.exportValue(target, nodeDefaultExport, depth+1)
				return s.callable(vm, value, depth+1)
			}
		}
		return false, false // a factory may return a class
	case nodeIsLiteral(n):
		return false, true
	}
	return false, false
}

func nodeIsLiteral(n *sitter.Node) bool {
	switch n.Type() {
	case nodeStringNode, "number", "template_string", nodeLiteralTrue, nodeLiteralFalse, nodeLiteralNull, nodeObjectLiteral, "array", "regex":
		return true
	}
	return false
}

// valueShape is shapeOf, with a class or function read as its members.
func (s *NodeShapes) valueShape(m *nodeShapeModule, n *sitter.Node, name string, depth int) nodeShape {
	if n != nil && nodeIsFunction(n) {
		return s.functionShape(m, n, name)
	}
	return s.shapeOf(m, n, depth)
}

// functionShape is what a class or constructor function offers: its methods,
// fields and statics, and `Name.x` / `Name.prototype.x` assignments. Anything
// it inherits is not tracked, so a subclass is unknown.
func (s *NodeShapes) functionShape(m *nodeShapeModule, fn *sitter.Node, name string) nodeShape {
	if n := fn.ChildByFieldName(nodeFieldName); n != nil {
		name = n.Content(m.src)
	}
	sh := nodeClassBodyShape(m, fn)
	if sh.open || name == "" || name == nodeDefaultExport {
		return sh
	}
	nodeWalk(m.root, func(n *sitter.Node) {
		switch n.Type() {
		case nodeAssignmentExpression:
			s.addAssignedMember(m, n, name, &sh)
		case nodeCallExpression:
			if nodeInheritsFrom(m, n, name) {
				sh.open = true
			}
		}
	})
	return sh
}

// nodeClassBodyShape reads a class's methods and fields; a subclass is unknown.
func nodeClassBodyShape(m *nodeShapeModule, fn *sitter.Node) nodeShape {
	sh := nodeShape{keys: make(map[string]bool)}
	body := fn.ChildByFieldName("body")
	if body == nil || body.Type() != nodeClassBody {
		return sh
	}
	for i := 0; i < int(fn.NamedChildCount()); i++ {
		if fn.NamedChild(i).Type() == "class_heritage" {
			return open()
		}
	}
	for i := 0; i < int(body.NamedChildCount()); i++ {
		if key := nodeClassMemberName(m, body.NamedChild(i)); key != "" {
			sh.keys[key] = true
		}
	}
	return sh
}

func nodeClassMemberName(m *nodeShapeModule, member *sitter.Node) string {
	for _, field := range []string{nodeFieldName, "property"} {
		if key := member.ChildByFieldName(field); key != nil {
			return strings.TrimPrefix(key.Content(m.src), "#")
		}
	}
	return ""
}

// nodeInheritsFrom reports `inherits(name, Base)` and the like, which give
// name members this module does not list.
func nodeInheritsFrom(m *nodeShapeModule, call *sitter.Node, name string) bool {
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	return fn != nil && args != nil && nodeInherits(fn.Content(m.src)) && args.NamedChildCount() > 0 &&
		strings.HasPrefix(args.NamedChild(0).Content(m.src), name)
}

func (s *NodeShapes) addAssignedMember(m *nodeShapeModule, n *sitter.Node, name string, sh *nodeShape) {
	left, right := n.ChildByFieldName("left"), n.ChildByFieldName("right")
	if left == nil || right == nil {
		return
	}
	target := left.Content(m.src)
	switch {
	case target == name+"."+nodePrototypeMember:
		sh.merge(s.shapeOf(m, right, 0))
	case strings.HasPrefix(target, name+"."+nodePrototypeMember+"."):
		sh.keys[strings.SplitN(strings.TrimPrefix(target, name+"."+nodePrototypeMember+"."), ".", 2)[0]] = true
	case strings.HasPrefix(target, name+"."):
		sh.keys[strings.SplitN(strings.TrimPrefix(target, name+"."), ".", 2)[0]] = true
	}
}

func nodeInherits(fn string) bool {
	return fn == "inherits" || strings.HasSuffix(fn, ".inherits") || fn == "Object.setPrototypeOf" || fn == "Object.assign"
}

func (s *NodeShapes) module(path string) *nodeShapeModule {
	if m, ok := s.modules[path]; ok {
		return m
	}
	s.modules[path] = nil
	parser := s.parser.parserForFile(path)
	if parser == nil {
		return nil
	}
	src, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	tree, err := parser.ParseCtx(context.TODO(), nil, src)
	if err != nil {
		return nil
	}
	m := &nodeShapeModule{path: path, src: src, tree: tree, root: tree.RootNode()}
	s.modules[path] = m
	return m
}

func (s *NodeShapes) relative(from *nodeShapeModule, spec string) *nodeShapeModule {
	if !strings.HasPrefix(spec, ".") {
		return nil // another package's values are not this package's API
	}
	base := filepath.Join(filepath.Dir(from.path), filepath.FromSlash(spec))
	candidates := []string{base}
	for _, ext := range []string{".js", ".ts", ".mjs", ".cjs"} {
		candidates = append(candidates, base+ext, filepath.Join(base, "index"+ext))
	}
	if strings.HasSuffix(base, ".js") {
		candidates = append(candidates, strings.TrimSuffix(base, ".js")+".ts")
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return s.module(c)
		}
	}
	return nil
}

func open() nodeShape { return nodeShape{open: true} }

func (sh *nodeShape) merge(o nodeShape) {
	if o.open {
		sh.open = true
		return
	}
	for k := range o.keys {
		sh.keys[k] = true
	}
}

func (s *NodeShapes) shapeOf(m *nodeShapeModule, n *sitter.Node, depth int) nodeShape {
	n = nodeUnwrapValue(n)
	if n == nil || depth > nodeShapeDepth {
		return open()
	}
	switch n.Type() {
	case nodeObjectLiteral:
		return s.objectShape(m, n, depth)
	case nodeCallExpression:
		return s.callShape(m, n, depth)
	case goNodeIdentifier:
		value, vm := s.binding(m, n, n.Content(m.src), depth)
		if value == nil {
			return open()
		}
		return s.valueShape(vm, value, n.Content(m.src), depth+1)
	}
	return open()
}

func (s *NodeShapes) objectShape(m *nodeShapeModule, obj *sitter.Node, depth int) nodeShape {
	sh := nodeShape{keys: make(map[string]bool)}
	for i := 0; i < int(obj.NamedChildCount()); i++ {
		member := obj.NamedChild(i)
		switch member.Type() {
		case nodeShorthandProperty:
			sh.keys[member.Content(m.src)] = true
		case nodePair, nodeMethodDefinition:
			field := nodeFieldKey
			if member.Type() == nodeMethodDefinition {
				field = nodeFieldName
			}
			key := member.ChildByFieldName(field)
			if key == nil || key.Type() == "computed_property_name" {
				return open()
			}
			sh.keys[unquoteNodeString(key.Content(m.src))] = true
		case nodeSpreadElement:
			if member.NamedChildCount() == 0 {
				return open()
			}
			sh.merge(s.shapeOf(m, member.NamedChild(0), depth+1))
		case goNodeComment:
		default:
			return open()
		}
		if sh.open {
			return sh
		}
	}
	return sh
}

func (s *NodeShapes) callShape(m *nodeShapeModule, call *sitter.Node, depth int) nodeShape {
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if fn == nil || args == nil {
		return open()
	}
	switch fn.Content(m.src) {
	case nodeObjectFreeze:
		if args.NamedChildCount() != 1 {
			return open()
		}
		return s.shapeOf(m, args.NamedChild(0), depth+1)
	case "Object.assign":
		sh := nodeShape{keys: make(map[string]bool)}
		for i := 0; i < int(args.NamedChildCount()); i++ {
			sh.merge(s.shapeOf(m, args.NamedChild(i), depth+1))
		}
		return sh
	case nodeRequireFunction:
		if args.NamedChildCount() == 1 && args.NamedChild(0).Type() == nodeStringNode {
			if target := s.relative(m, unquoteNodeString(args.NamedChild(0).Content(m.src))); target != nil {
				return s.moduleShape(target, depth+1)
			}
		}
		return open()
	}
	callee, cm := s.callee(m, fn, depth)
	if callee == nil {
		return open()
	}
	return s.returnShape(cm, callee, depth+1)
}

// callee resolves the function a call expression invokes.
func (s *NodeShapes) callee(m *nodeShapeModule, fn *sitter.Node, depth int) (*sitter.Node, *nodeShapeModule) {
	fn = nodeUnwrapValue(fn)
	if fn == nil {
		return nil, nil
	}
	switch fn.Type() {
	case goNodeIdentifier:
		value, vm := s.binding(m, fn, fn.Content(m.src), depth)
		if value != nil && nodeIsFunction(value) {
			return value, vm
		}
	case nodeArrowFunction, nodeFunctionExpression:
		return fn, m
	case nodeCallExpression: // require('./lib')(addon)
		inner := fn.ChildByFieldName("function")
		args := fn.ChildByFieldName("arguments")
		if inner != nil && args != nil && inner.Content(m.src) == nodeRequireFunction && args.NamedChildCount() == 1 {
			if target := s.relative(m, unquoteNodeString(args.NamedChild(0).Content(m.src))); target != nil {
				value, vm := s.exportValue(target, nodeDefaultExport, depth+1)
				if value != nil && nodeIsFunction(value) {
					return value, vm
				}
			}
		}
	}
	return nil, nil
}

// returnShape is the union of what a function returns; a function whose
// returns cannot all be read is unknown.
func (s *NodeShapes) returnShape(m *nodeShapeModule, fn *sitter.Node, depth int) nodeShape {
	body := fn.ChildByFieldName("body")
	if body == nil {
		return open()
	}
	if body.Type() != nodeStatementBlock {
		return s.shapeOf(m, body, depth)
	}
	sh := nodeShape{keys: make(map[string]bool)}
	found := false
	nodeWalkSkippingFunctions(body, func(n *sitter.Node) {
		if n.Type() != goNodeReturnStatement || sh.open {
			return
		}
		found = true
		if n.NamedChildCount() == 0 {
			return
		}
		sh.merge(s.shapeOf(m, n.NamedChild(0), depth))
	})
	if !found {
		return open()
	}
	return sh
}

// binding resolves a name visible at n: a declaration in an enclosing
// function, then the module's top level, then an import.
func (s *NodeShapes) binding(m *nodeShapeModule, at *sitter.Node, name string, depth int) (*sitter.Node, *nodeShapeModule) {
	for scope := at.Parent(); scope != nil; scope = scope.Parent() {
		if nodeIsFunction(scope) || scope.Type() == nodeMethodDefinition {
			if _, param := nodeScopeDeclaration(scope, name, m.src); param {
				return nil, nil // a parameter is only known at run time, and shadows outer names
			}
			continue
		}
		if scope.Type() != nodeStatementBlock && scope.Type() != nodeProgram {
			continue
		}
		if value := nodeShapeDeclaration(scope, name, m.src); value != nil {
			return value, m
		}
		if scope.Type() == nodeProgram {
			return s.importedBinding(m, scope, name, depth)
		}
	}
	return nil, nil
}

func (s *NodeShapes) importedBinding(m *nodeShapeModule, program *sitter.Node, name string, depth int) (*sitter.Node, *nodeShapeModule) {
	spec, imported := nodeImportOf(program, name, m.src)
	if spec == "" {
		return nil, nil
	}
	target := s.relative(m, spec)
	if target == nil {
		return nil, nil
	}
	return s.exportValue(target, imported, depth+1)
}

// exportValue returns the value a module exports as name ("default" for the
// module's own value), following re-exports.
func (s *NodeShapes) exportValue(m *nodeShapeModule, name string, depth int) (*sitter.Node, *nodeShapeModule) {
	if m == nil || depth > nodeShapeDepth {
		return nil, nil
	}
	for i := 0; i < int(m.root.NamedChildCount()); i++ {
		stmt := m.root.NamedChild(i)
		switch stmt.Type() {
		case nodeExportKind:
			if value, vm := s.esExportValue(m, stmt, name, depth); value != nil {
				return value, vm
			}
		case nodeExpressionStatement:
			if value := nodeShapeCommonJSExport(stmt, name, m.src); value != nil {
				return value, m
			}
		}
	}
	for i := 0; i < int(m.root.NamedChildCount()); i++ {
		stmt := m.root.NamedChild(i)
		if stmt.Type() != nodeExportKind || name == nodeDefaultExport {
			continue
		}
		if from := nodeStarExportSource(stmt, m.src); from != "" {
			if value, vm := s.exportValue(s.relative(m, from), name, depth+1); value != nil {
				return value, vm
			}
		}
	}
	return nil, nil
}

func (s *NodeShapes) esExportValue(m *nodeShapeModule, stmt *sitter.Node, name string, depth int) (*sitter.Node, *nodeShapeModule) {
	if nodeIsDefaultExport(stmt) {
		if name != nodeDefaultExport {
			return nil, nil
		}
		if v := stmt.ChildByFieldName("value"); v != nil {
			return v, m
		}
		return stmt.ChildByFieldName("declaration"), m
	}
	if decl := stmt.ChildByFieldName("declaration"); decl != nil {
		return nodeDeclarationValue(decl, name, m.src), m
	}
	for j := 0; j < int(stmt.NamedChildCount()); j++ {
		clause := stmt.NamedChild(j)
		if clause.Type() != nodeExportClauseKind {
			continue
		}
		spec, local := nodeClauseSpecifier(clause, name, m.src)
		if spec == nil {
			continue
		}
		if source := stmt.ChildByFieldName("source"); source != nil {
			return s.exportValue(s.relative(m, unquoteNodeString(source.Content(m.src))), local, depth+1)
		}
		return s.binding(m, spec, local, depth)
	}
	return nil, nil
}

func nodeIsDefaultExport(stmt *sitter.Node) bool {
	for i := 0; i < int(stmt.ChildCount()); i++ {
		if stmt.Child(i).Type() == nodeDefaultExport {
			return true
		}
	}
	return false
}

// nodeDeclarationValue returns what `export function|class|const name` binds.
func nodeDeclarationValue(decl *sitter.Node, name string, src []byte) *sitter.Node {
	if n := decl.ChildByFieldName(nodeFieldName); n != nil && n.Content(src) == name {
		return decl
	}
	for j := 0; j < int(decl.NamedChildCount()); j++ {
		d := decl.NamedChild(j)
		if n := d.ChildByFieldName(nodeFieldName); d.Type() == nodeVariableDeclarator && n != nil && n.Content(src) == name {
			return d.ChildByFieldName("value")
		}
	}
	return nil
}

// nodeClauseSpecifier finds the `export { local as name }` specifier for name.
func nodeClauseSpecifier(clause *sitter.Node, name string, src []byte) (*sitter.Node, string) {
	for k := 0; k < int(clause.NamedChildCount()); k++ {
		spec := clause.NamedChild(k)
		local, exported := spec.ChildByFieldName(nodeFieldName), spec.ChildByFieldName("alias")
		if exported == nil {
			exported = local
		}
		if local != nil && unquoteNodeString(exported.Content(src)) == name {
			return spec, local.Content(src)
		}
	}
	return nil, ""
}

// moduleShape is the set of names a module exports, or the shape of what it
// assigns to module.exports.
func (s *NodeShapes) moduleShape(m *nodeShapeModule, depth int) nodeShape {
	if value, vm := s.exportValue(m, nodeDefaultExport, depth); value != nil {
		return s.shapeOf(vm, value, depth+1)
	}
	exports, err := NodeModuleExports(m.path)
	if err != nil || len(exports.StarFrom) > 0 {
		return open()
	}
	sh := nodeShape{keys: make(map[string]bool)}
	for k := range exports.Lines {
		sh.keys[k] = true
	}
	return sh
}

// nodeShapeCommonJSExport reads `exports.name = v`, `module.exports.name = v`,
// `module.exports = {name: v}` and, for "default", `module.exports = v`.
func nodeShapeCommonJSExport(stmt *sitter.Node, name string, src []byte) *sitter.Node {
	if stmt.NamedChildCount() == 0 || stmt.NamedChild(0).Type() != nodeAssignmentExpression {
		return nil
	}
	expr := stmt.NamedChild(0)
	left, right := expr.ChildByFieldName("left"), expr.ChildByFieldName("right")
	if left == nil || right == nil {
		return nil
	}
	target := left.Content(src)
	switch {
	case target == nodeModuleExportsTarget && name == nodeDefaultExport:
		return right
	case target == nodeModuleExportsTarget && right.Type() == nodeObjectLiteral:
		for i := 0; i < int(right.NamedChildCount()); i++ {
			if p := right.NamedChild(i); p.Type() == nodePair {
				if key := p.ChildByFieldName("key"); key != nil && unquoteNodeString(key.Content(src)) == name {
					return p.ChildByFieldName("value")
				}
			}
		}
	case target == nodeCommonJSExportsObject+"."+name || target == nodeModuleExportsTarget+"."+name:
		return right
	}
	return nil
}

// nodeShapeDeclaration finds `const|let|var name = v` or `function name` among
// the direct statements of a block or program.
func nodeShapeDeclaration(scope *sitter.Node, name string, src []byte) *sitter.Node {
	for i := 0; i < int(scope.NamedChildCount()); i++ {
		stmt := scope.NamedChild(i)
		if stmt.Type() == nodeExportKind {
			if decl := stmt.ChildByFieldName("declaration"); decl != nil {
				stmt = decl
			}
		}
		switch stmt.Type() {
		case nodeFunctionDeclaration, nodeClassDeclaration:
			if n := stmt.ChildByFieldName(nodeFieldName); n != nil && n.Content(src) == name {
				return stmt
			}
		case nodeLexicalDeclaration, nodeVariableDeclaration:
			for j := 0; j < int(stmt.NamedChildCount()); j++ {
				d := stmt.NamedChild(j)
				if n := d.ChildByFieldName(nodeFieldName); d.Type() == nodeVariableDeclarator && n != nil && n.Content(src) == name {
					return d.ChildByFieldName("value")
				}
			}
		}
	}
	return nil
}

// nodeImportOf returns the module and the imported name a top-level import
// binds to local ("default" for a default import, "" for a namespace).
func nodeImportOf(program *sitter.Node, local string, src []byte) (string, string) {
	for i := 0; i < int(program.NamedChildCount()); i++ {
		stmt := program.NamedChild(i)
		source := stmt.ChildByFieldName("source")
		if stmt.Type() != nodeImportStatement || source == nil {
			continue
		}
		imported := ""
		nodeWalk(stmt, func(n *sitter.Node) {
			if name := nodeImportedName(n, local, src); name != "" {
				imported = name
			}
		})
		if imported != "" {
			return unquoteNodeString(source.Content(src)), imported
		}
	}
	return "", ""
}

// nodeImportedName returns the imported name when n binds local.
func nodeImportedName(n *sitter.Node, local string, src []byte) string {
	switch n.Type() {
	case nodeImportSpecifier:
		name, alias := n.ChildByFieldName(nodeFieldName), n.ChildByFieldName("alias")
		if alias == nil {
			alias = name
		}
		if name != nil && alias.Content(src) == local {
			return unquoteNodeString(name.Content(src))
		}
	case goNodeIdentifier:
		if p := n.Parent(); p != nil && p.Type() == nodeImportClause && n.Content(src) == local {
			return nodeDefaultExport
		}
	}
	return ""
}

func nodeUnwrapValue(n *sitter.Node) *sitter.Node {
	for n != nil && (n.Type() == goNodeParenExpr || n.Type() == nodeAwaitExpression) && n.NamedChildCount() > 0 {
		n = n.NamedChild(int(n.NamedChildCount()) - 1)
	}
	return n
}

func nodeIsFunction(n *sitter.Node) bool {
	switch n.Type() {
	case nodeFunctionDeclaration, nodeFunctionExpression, nodeArrowFunction, nodeClassDeclaration, nodeClassExpression:
		return true
	}
	return false
}

// nodeWalkSkippingFunctions visits n's subtree without entering nested functions.
func nodeWalkSkippingFunctions(n *sitter.Node, visit func(*sitter.Node)) {
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		if nodeIsFunction(c) || c.Type() == nodeMethodDefinition {
			continue
		}
		visit(c)
		nodeWalkSkippingFunctions(c, visit)
	}
}

// NodeCodeNames returns the identifiers a JavaScript or TypeScript file's code
// names, leaving out comments and strings.
func NodeCodeNames(path string) (map[string]bool, error) {
	parser := NewNodeParser().parserForFile(path)
	if parser == nil {
		return nil, fmt.Errorf("callgraph: node names: unsupported source file %s", path)
	}
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("callgraph: node names: read %s: %w", path, err)
	}
	tree, err := parser.ParseCtx(context.TODO(), nil, src)
	if err != nil {
		return nil, fmt.Errorf("callgraph: node names: parse %s: %w", path, err)
	}
	defer tree.Close()
	names := make(map[string]bool)
	nodeWalk(tree.RootNode(), func(n *sitter.Node) {
		switch n.Type() {
		case goNodeIdentifier, "property_identifier", nodeShorthandProperty, "private_property_identifier":
			names[strings.TrimPrefix(n.Content(src), "#")] = true
		}
	})
	return names, nil
}
