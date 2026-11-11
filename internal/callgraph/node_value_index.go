// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strconv"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// maxNodeDeclsPerName bounds the declarations of one name a use is resolved
// against. A minified bundle declares `e` thousands of times; such a name
// resolves to nothing instead of costing a scan per use.
const maxNodeDeclsPerName = 64

const (
	nodeArrayPattern            = "array_pattern"
	nodeAugmentedAssignment     = "augmented_assignment_expression"
	nodeSubscriptExpression     = "subscript_expression"
	nodeObjectAssignmentPattern = "object_assignment_pattern"
	nodeRestPattern             = "rest_pattern"
	nodeUpdateExpression        = "update_expression"
	nodeUnaryExpression         = "unary_expression"
	nodePropertyIdentifier      = "property_identifier"
	nodeCatchClause             = "catch_clause"
	nodeEnumDeclaration         = "enum_declaration"
	nodeForStatement            = "for_statement"
	nodeFunctionNode            = "function"
	nodeGeneratorFunction       = "generator_function"
	nodeModuleNode              = "module"
	nodeInternalModule          = "internal_module"
	nodeThisNode                = "this"
	nodeProgramNode             = "program"
	nodeArgumentsObject         = "arguments"
)

type nodeDeclKind uint8

const (
	nodeDeclOther nodeDeclKind = iota
	nodeDeclConst
	nodeDeclLet
	nodeDeclVar
	nodeDeclParam
	nodeDeclClass
	nodeDeclEnum
	nodeDeclImport
)

// nodeDecl is one binding of a name: where it is visible, what it holds.
type nodeDecl struct {
	kind nodeDeclKind
	// scope is the node whose byte range the binding is visible in.
	scope *sitter.Node
	// fn is the function the binding belongs to, nil at module level.
	fn    *sitter.Node
	name  *sitter.Node
	value *sitter.Node
	// paramIndex is the position a caller fills; plainParam marks a plain
	// name with no default, destructuring or rest, in a function with no
	// `this` parameter.
	paramIndex int
	plainParam bool
	// module and member name the export a named import of a project module
	// binds. module is empty for a package, a default import, or anything
	// the importer cannot pin to one export.
	module, member string
	// exportKey is the NamedValue key of what the binding refers to in another
	// project module: its export for a named import or a destructured
	// require, the module itself for a namespace, default or whole require
	// import. A write through the binding, or its escape, may change values
	// under it (exportWrite).
	exportKey string
	// writes counts the assignments to the binding after its declaration;
	// memberWrites marks a member of it assigned, deleted or redefined
	// through Object.assign and the like; escapes counts its uses other than
	// reading a member: passing, aliasing or spreading it, after which it may
	// be mutated where the file cannot see.
	writes       int
	memberWrites bool
	escapes      int
	// memberValue marks a member of a binding that holds a construction read
	// other than as the callee of a direct call in the binding's own
	// function: `o.m` taken as a value, or `o.m()` inside a closure.
	memberValue bool
}

// nodeValueIndex holds, for one file, every binding of every name and every
// use that writes one, so a use resolves to the one binding it reads and is
// refused when that binding may hold anything else.
type nodeValueIndex struct {
	src                               []byte
	filePath, packagePath, modulePath string
	decls                             map[string][]*nodeDecl
	// argumentsUsers holds the functions that read `arguments`, which
	// aliases their parameters in sloppy mode.
	argumentsUsers map[uint32]bool
	// disabled marks a file that binds names dynamically (eval, with).
	disabled bool
	// propertyWrites counts, per property name, the writes anywhere in the
	// file to `o.<name>` or `o["<name>"]` through an object other than this.
	propertyWrites map[string]int
	// exportWrites holds what this file may change in other project modules.
	exportWrites map[NamedValueWrite]bool
}

func newNodeValueIndex(root *sitter.Node, src []byte, filePath, packagePath, modulePath string) *nodeValueIndex {
	x := &nodeValueIndex{
		src: src, filePath: filePath, packagePath: packagePath, modulePath: modulePath,
		decls:          make(map[string][]*nodeDecl),
		argumentsUsers: make(map[uint32]bool),
		propertyWrites: make(map[string]int),
	}
	x.collectDecls(root, root, nil)
	x.collectUses(root)
	return x
}

func isNodeFunctionLike(t string) bool {
	switch t {
	case nodeFunctionDeclaration, nodeGeneratorDeclaration, nodeFunctionExpression, nodeFunctionNode, nodeGeneratorFunction, nodeArrowFunction, nodeMethodDefinition:
		return true
	}
	return false
}

func isNodeBlockScope(t string) bool {
	switch t {
	case nodeStatementBlock, nodeProgramNode, nodeForStatement, nodeForInStatement, "switch_body", "class_static_block":
		return true
	}
	return false
}

// nodeBlockScopeOf is the nearest block that holds node, the scope of a let,
// const, class or enum declared there.
func nodeBlockScopeOf(node *sitter.Node) *sitter.Node {
	for p := node.Parent(); p != nil; p = p.Parent() {
		if isNodeBlockScope(p.Type()) {
			return p
		}
	}
	return node
}

// nodeEnclosingFunction is the nearest function node holding node, nil at
// module level.
func nodeEnclosingFunction(node *sitter.Node) *sitter.Node {
	for p := node.Parent(); p != nil; p = p.Parent() {
		if isNodeFunctionLike(p.Type()) {
			return p
		}
	}
	return nil
}

func (x *nodeValueIndex) add(name *sitter.Node, d *nodeDecl) {
	d.name = name
	text := name.Content(x.src)
	x.decls[text] = append(x.decls[text], d)
}

// addNamed records the declaration a node's name field binds, if it has one.
func (x *nodeValueIndex) addNamed(node *sitter.Node, d nodeDecl) {
	if name := node.ChildByFieldName("name"); name != nil {
		x.add(name, &d)
	}
}

func (x *nodeValueIndex) addPattern(pattern *sitter.Node, d nodeDecl) {
	names := make(map[string]bool)
	collectNodePatternNames(pattern, x.src, names)
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		if (n.Type() == goNodeIdentifier || n.Type() == nodeShorthandPattern) && names[n.Content(x.src)] {
			copied := d
			x.add(n, &copied)
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(pattern)
}

func (x *nodeValueIndex) collectDecls(node, root, fn *sitter.Node) {
	if !x.declare(node, root, fn) {
		return
	}
	if isNodeFunctionLike(node.Type()) {
		fn = node
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		x.collectDecls(node.NamedChild(i), root, fn)
	}
}

// declare records the bindings node introduces, and reports whether its
// children still need a visit.
func (x *nodeValueIndex) declare(node, root, fn *sitter.Node) bool {
	switch t := node.Type(); t {
	case nodeVariableDeclarator:
		x.declarator(node, fn, root)
	case javaNodeClassDeclaration, nodeAbstractClassDeclaration:
		x.addNamed(node, nodeDecl{kind: nodeDeclClass, scope: nodeBlockScopeOf(node), fn: fn, value: node})
	case nodeClassExpression:
		x.addNamed(node, nodeDecl{scope: node, fn: fn})
	case nodeEnumDeclaration:
		kind := nodeDeclEnum
		if parent := node.Parent(); parent != nil && parent.Type() == "ambient_declaration" {
			kind = nodeDeclOther
		}
		x.addNamed(node, nodeDecl{kind: kind, scope: nodeBlockScopeOf(node), fn: fn, value: node})
	case nodeInternalModule, nodeModuleNode:
		x.addNamed(node, nodeDecl{scope: nodeBlockScopeOf(node), fn: fn})
	case nodeImportStatement:
		x.importStatement(node, root)
		return false
	case nodeCatchClause:
		if param := node.ChildByFieldName("parameter"); param != nil {
			x.addPattern(param, nodeDecl{scope: node, fn: fn})
		}
	case nodeForInStatement:
		if kind := node.ChildByFieldName("kind"); kind != nil {
			scope := node
			if kind.Content(x.src) == "var" {
				scope = x.varScope(fn, root)
			}
			x.addPattern(node.ChildByFieldName("left"), nodeDecl{scope: scope, fn: fn})
		}
	default:
		if isNodeFunctionLike(t) {
			x.function(node, root, fn)
		}
	}
	return true
}

// function records a function's own name and its parameters. A declared
// function's name is scoped to the enclosing function: Annex B hoists a
// block's function there, and the wider scope can only shadow more, never
// resolve more.
func (x *nodeValueIndex) function(node, root, fn *sitter.Node) {
	switch node.Type() {
	case nodeFunctionDeclaration, nodeGeneratorDeclaration:
		x.addNamed(node, nodeDecl{scope: x.varScope(fn, root), fn: fn})
	case nodeMethodDefinition:
	default:
		x.addNamed(node, nodeDecl{scope: node, fn: fn})
	}
	x.parameters(node)
}

func (x *nodeValueIndex) varScope(fn, root *sitter.Node) *sitter.Node {
	if fn != nil {
		return fn
	}
	return root
}

func (x *nodeValueIndex) declarator(node, fn, root *sitter.Node) {
	name, value := node.ChildByFieldName("name"), node.ChildByFieldName("value")
	parent := node.Parent()
	if name == nil || parent == nil {
		return
	}
	d := nodeDecl{fn: fn, value: value, scope: nodeBlockScopeOf(node)}
	switch parent.Type() {
	case nodeVariableDeclaration:
		d.kind, d.scope = nodeDeclVar, x.varScope(fn, root)
	case nodeLexicalDeclaration:
		d.kind = nodeDeclLet
		if kind := parent.ChildByFieldName("kind"); kind != nil && kind.Content(x.src) == "const" {
			d.kind = nodeDeclConst
		}
	}
	if binding, ok := nodeRequireBinding(value, x.src); ok {
		x.requireDecl(name, d, binding)
		return
	}
	if name.Type() == goNodeIdentifier {
		x.add(name, &d)
		return
	}
	d.kind, d.value = nodeDeclOther, nil
	x.addPattern(name, d)
}

// requireDecl records the names `const m = require('./m')` and `const { a, b:
// c } = require('./m')` bind as imports of the module's members.
func (x *nodeValueIndex) requireDecl(name *sitter.Node, d nodeDecl, binding nodeBinding) {
	module, relative := resolveNodeRelativeModule(x.filePath, x.packagePath, binding.module)
	d.kind, d.value = nodeDeclImport, nil
	if !relative {
		module = ""
	}
	if name.Type() == goNodeIdentifier {
		d.module, d.member = module, binding.member
		d.exportKey = nodeExportKey(module, binding.member)
		x.add(name, &d)
		return
	}
	if name.Type() != nodeObjectPattern {
		d.kind, d.module = nodeDeclOther, ""
		x.addPattern(name, d)
		return
	}
	for i := 0; i < int(name.NamedChildCount()); i++ {
		item := name.NamedChild(i)
		entry := d
		local, member := nodeRequiredMember(item, x.src)
		if local == nil {
			entry.kind, entry.module = nodeDeclOther, ""
			x.addPattern(item, entry)
			continue
		}
		entry.module, entry.member = module, joinNodeMember(binding.member, member)
		entry.exportKey = nodeExportKey(module, entry.member)
		x.add(local, &entry)
	}
}

// nodeRequiredMember reads one entry of `const { a, b: c } = require(..)`:
// the local it binds and the member it names, or no local for a nested
// pattern or a computed key.
func nodeRequiredMember(item *sitter.Node, src []byte) (*sitter.Node, string) {
	switch item.Type() {
	case nodeShorthandPattern:
		return item, item.Content(src)
	case nodePairPattern:
		key, alias := item.ChildByFieldName("key"), item.ChildByFieldName("value")
		if key != nil && alias != nil && alias.Type() == goNodeIdentifier && key.Type() == nodePropertyIdentifier {
			return alias, key.Content(src)
		}
	}
	return nil, ""
}

// importStatement records the names an ESM import binds. Only a named import
// of a project module pins an export; a namespace import of one pins the
// module itself.
func (x *nodeValueIndex) importStatement(node, root *sitter.Node) {
	module := ""
	if source := node.ChildByFieldName("source"); source != nil {
		if resolved, ok := resolveNodeRelativeModule(x.filePath, x.packagePath, unquoteNodeString(source.Content(x.src))); ok {
			module = resolved
		}
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		if child := node.NamedChild(i); child.Type() != nodeStringNode {
			x.importClause(child, root, module)
		}
	}
}

func (x *nodeValueIndex) importClause(n, root *sitter.Node, module string) {
	switch n.Type() {
	case nodeImportSpecifier:
		name, local := n.ChildByFieldName("name"), n.ChildByFieldName("name")
		if alias := n.ChildByFieldName("alias"); alias != nil {
			local = alias
		}
		if name == nil {
			return
		}
		d := &nodeDecl{kind: nodeDeclImport, scope: root, module: module, member: unquoteNodeString(name.Content(x.src))}
		d.exportKey = nodeExportKey(module, d.member)
		if nodeHasInlineTypeKeyword(n) {
			d.kind, d.module, d.exportKey = nodeDeclOther, "", ""
		}
		x.add(local, d)
	case nodeNamespaceImport:
		for i := 0; i < int(n.NamedChildCount()); i++ {
			if id := n.NamedChild(i); id.Type() == goNodeIdentifier {
				x.add(id, &nodeDecl{kind: nodeDeclImport, scope: root, module: module, exportKey: module})
			}
		}
	case goNodeIdentifier:
		// A default import, or `import q = require(..)`: neither pins one
		// export by name, but CommonJS exports live under the module key.
		x.add(n, &nodeDecl{scope: root, exportKey: module})
	default:
		for i := 0; i < int(n.NamedChildCount()); i++ {
			x.importClause(n.NamedChild(i), root, module)
		}
	}
}

// parameters records a function's parameters with the position a caller fills.
func (x *nodeValueIndex) parameters(fn *sitter.Node) {
	if single := fn.ChildByFieldName("parameter"); single != nil {
		x.add(single, &nodeDecl{kind: nodeDeclParam, scope: fn, fn: fn, plainParam: single.Type() == goNodeIdentifier})
		return
	}
	params := fn.ChildByFieldName("parameters")
	if params == nil {
		return
	}
	hasThis := false
	for i := 0; i < int(params.NamedChildCount()); i++ {
		if pattern := params.NamedChild(i).ChildByFieldName("pattern"); pattern != nil && pattern.Type() == nodeThisNode {
			hasThis = true
		}
	}
	index := 0
	for i := 0; i < int(params.NamedChildCount()); i++ {
		child := params.NamedChild(i)
		if child.Type() == goNodeComment {
			continue
		}
		d := nodeDecl{kind: nodeDeclParam, scope: fn, fn: fn, paramIndex: index, plainParam: !hasThis}
		index++
		pattern := child
		if child.Type() == nodeRequiredParameter || child.Type() == nodeOptionalParameter {
			pattern = child.ChildByFieldName("pattern")
			d.plainParam = d.plainParam && child.ChildByFieldName("value") == nil
		}
		switch {
		case pattern == nil:
		case pattern.Type() == goNodeIdentifier:
			x.add(pattern, &d)
		default:
			d.plainParam = false
			x.addPattern(pattern, d)
		}
	}
}

// nodeWriteTarget returns the target a write expression assigns, augments,
// increments or deletes, nil for any other node.
func nodeWriteTarget(node *sitter.Node, src []byte) *sitter.Node {
	switch node.Type() {
	case nodeAssignmentExpression, nodeAugmentedAssignment:
		return node.ChildByFieldName("left")
	case nodeUpdateExpression:
		return node.ChildByFieldName("argument")
	case nodeUnaryExpression:
		if op := node.ChildByFieldName("operator"); op != nil && op.Content(src) == "delete" {
			return node.ChildByFieldName("argument")
		}
	case nodeForInStatement:
		if node.ChildByFieldName("kind") == nil {
			return node.ChildByFieldName("left")
		}
	}
	return nil
}

// eachNodeWriteLeaf calls visit with every name, member and subscript a write
// target writes, looking through destructuring patterns but not their
// default values.
func eachNodeWriteLeaf(target *sitter.Node, visit func(*sitter.Node)) {
	if target == nil {
		return
	}
	switch target.Type() {
	case goNodeIdentifier, nodeShorthandPattern, nodeMemberExpression, nodeSubscriptExpression:
		visit(target)
	case nodePairPattern:
		eachNodeWriteLeaf(target.ChildByFieldName("value"), visit)
	case nodeAssignmentPattern, nodeObjectAssignmentPattern:
		eachNodeWriteLeaf(target.ChildByFieldName("left"), visit)
	case nodeObjectPattern, nodeArrayPattern, nodeRestPattern, javaNodeParenthesizedExpr:
		for i := 0; i < int(target.NamedChildCount()); i++ {
			eachNodeWriteLeaf(target.NamedChild(i), visit)
		}
	}
}

// collectUses counts every write to a binding, every write through one, and
// every use that lets an object escape.
func (x *nodeValueIndex) collectUses(node *sitter.Node) {
	if target := nodeWriteTarget(node, x.src); target != nil {
		eachNodeWriteLeaf(target, x.write)
	}
	switch node.Type() {
	case "with_statement":
		x.disabled = true
	case nodeCallExpression:
		x.call(node)
	case goNodeIdentifier:
		x.identifier(node)
	case nodeShorthandProperty:
		if d := x.resolve(node.Content(x.src), node); d != nil {
			// Re-exporting another module's object lets a third one write it.
			x.exportEscape(d)
			if !nodeIsModuleExportsObject(node.Parent(), x.src) {
				d.escapes++
			}
		}
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		x.collectUses(node.NamedChild(i))
	}
}

func (x *nodeValueIndex) write(leaf *sitter.Node) {
	if leaf.Type() == nodeMemberExpression || leaf.Type() == nodeSubscriptExpression {
		x.exportWrite(leaf, false)
		x.markMemberWrite(nodeMemberRoot(leaf))
		if name, ok := x.writtenProperty(leaf); ok {
			x.propertyWrites[name]++
		}
		return
	}
	if d := x.resolve(leaf.Content(x.src), leaf); d != nil {
		d.writes++
	}
}

// writtenProperty names the property a member or subscript write target
// sets through an object other than this, when its key is spelled: `o.f`,
// `o.#f`, `o["f"]`.
func (x *nodeValueIndex) writtenProperty(leaf *sitter.Node) (string, bool) {
	if object := leaf.ChildByFieldName("object"); object == nil || object.Type() == nodeThisNode {
		return "", false
	}
	return x.spelledProperty(leaf)
}

// spelledProperty names the property a member or subscript access reads,
// when its key is spelled: `o.f`, `o.#f`, `o["f"]`.
func (x *nodeValueIndex) spelledProperty(leaf *sitter.Node) (string, bool) {
	if leaf.Type() == nodeMemberExpression {
		if property := leaf.ChildByFieldName("property"); property != nil {
			return property.Content(x.src), true
		}
		return "", false
	}
	if index := leaf.ChildByFieldName("index"); index != nil && index.Type() == nodeStringNode {
		if quoted, ok := canonicalNodeStringLiteral(index.Content(x.src)); ok {
			name, err := strconv.Unquote(quoted)
			return name, err == nil
		}
	}
	return "", false
}

// nodeMemberRoot is the object a chain of member and subscript accesses
// starts from: `a` in `a.b[c].d`.
func nodeMemberRoot(node *sitter.Node) *sitter.Node {
	for node != nil && (node.Type() == nodeMemberExpression || node.Type() == nodeSubscriptExpression) {
		node = node.ChildByFieldName("object")
	}
	return node
}

var nodeObjectMutators = map[string]bool{
	"Object.assign": true, "Object.defineProperty": true, "Object.defineProperties": true, "Object.setPrototypeOf": true,
	"Reflect.set": true, "Reflect.defineProperty": true, "Reflect.deleteProperty": true, "Reflect.setPrototypeOf": true,
}

// nodeMutatedObject returns the object a call such as Object.assign(o, ..)
// writes members of, nil for any other call.
func nodeMutatedObject(call *sitter.Node, src []byte) *sitter.Node {
	function := call.ChildByFieldName("function")
	if function == nil || !nodeObjectMutators[function.Content(src)] {
		return nil
	}
	if args := nodeArgumentNodes(call); len(args) > 0 {
		return args[0]
	}
	return nil
}

func (x *nodeValueIndex) call(node *sitter.Node) {
	if function := node.ChildByFieldName("function"); function != nil && function.Content(x.src) == "eval" {
		x.disabled = true
	}
	if object := nodeMutatedObject(node, x.src); object != nil {
		x.exportWrite(object, true)
		x.markMemberWrite(object)
	}
}

func (x *nodeValueIndex) markMemberWrite(root *sitter.Node) {
	if root == nil || root.Type() != goNodeIdentifier {
		return
	}
	if d := x.resolve(root.Content(x.src), root); d != nil {
		d.memberWrites = true
	}
}

// memberWritten reports whether a member of the binding name resolves to at
// node is written anywhere in the file.
func (x *nodeValueIndex) memberWritten(name string, node *sitter.Node) bool {
	d := x.resolve(name, node)
	return d != nil && d.memberWrites
}

// identifier counts a use of a name that is not a read of one of its members
// or a declaration of it.
func (x *nodeValueIndex) identifier(node *sitter.Node) {
	name := node.Content(x.src)
	if name == nodeArgumentsObject {
		for p := node.Parent(); p != nil; p = p.Parent() {
			if isNodeFunctionLike(p.Type()) && p.Type() != nodeArrowFunction {
				x.argumentsUsers[p.StartByte()] = true
				break
			}
		}
		return
	}
	parent := node.Parent()
	if parent == nil {
		return
	}
	if parent.Type() == nodeMemberExpression && nodeIsNameField(parent, node) {
		x.memberRead(name, node, parent)
		x.exportRead(parent)
		return
	}
	if nodeIsNameField(parent, node) {
		return
	}
	if d := x.resolve(name, node); d != nil {
		d.escapes++
		if parent.Type() == nodeSubscriptExpression && sameSyntaxNode(parent.ChildByFieldName("object"), node) {
			x.exportRead(parent)
		} else {
			x.exportEscape(d)
		}
	}
}

func nodeExportKey(module, member string) string {
	if module == "" || member == "" {
		return module
	}
	return module + "." + member
}

func (x *nodeValueIndex) exportEscape(d *nodeDecl) {
	if d.exportKey != "" {
		x.addExportWrite(NamedValueWrite{Key: d.exportKey, MembersOnly: true})
	}
}

// exportRead records a member chain from a binding of another module taken
// as a value, `f(cfg.Opts)` or `o = cfg.Opts`, as a members-only write: the
// object it names may be written where the file cannot see. A string read
// this way changes nothing, and a callee `cfg.load()` is no value.
func (x *nodeValueIndex) exportRead(member *sitter.Node) {
	top := member
	for parent := top.Parent(); parent != nil; parent = top.Parent() {
		if t := parent.Type(); t != nodeMemberExpression && t != nodeSubscriptExpression || !sameSyntaxNode(parent.ChildByFieldName("object"), top) {
			break
		}
		top = parent
	}
	if parent := top.Parent(); parent != nil && parent.Type() == nodeCallExpression && sameSyntaxNode(parent.ChildByFieldName("function"), top) {
		return
	}
	x.exportWrite(top, true)
}

// exportWrite records what a write through chain may change in another
// project module, when chain is a member chain from a binding of one of its
// exports or from `require("./m")`: the key the chain spells, or every key
// under the part before a computed step.
func (x *nodeValueIndex) exportWrite(chain *sitter.Node, membersOnly bool) {
	var reversed []string
	root := unwrapNodeValue(chain)
	for root != nil && (root.Type() == nodeMemberExpression || root.Type() == nodeSubscriptExpression) {
		if name, ok := x.spelledProperty(root); ok && !strings.Contains(name, ".") {
			reversed = append(reversed, name)
		} else {
			reversed, membersOnly = nil, true
		}
		root = unwrapNodeValue(root.ChildByFieldName("object"))
	}
	key := x.exportKeyOf(root)
	if key == "" {
		return
	}
	for i := len(reversed) - 1; i >= 0; i-- {
		key += "." + reversed[i]
	}
	x.addExportWrite(NamedValueWrite{Key: key, MembersOnly: membersOnly})
}

func (x *nodeValueIndex) exportKeyOf(root *sitter.Node) string {
	if root == nil {
		return ""
	}
	if root.Type() == goNodeIdentifier {
		if d := x.resolve(root.Content(x.src), root); d != nil {
			return d.exportKey
		}
		return ""
	}
	binding, ok := nodeRequireBinding(root, x.src)
	if !ok {
		return ""
	}
	module, relative := resolveNodeRelativeModule(x.filePath, x.packagePath, binding.module)
	if !relative {
		return ""
	}
	return nodeExportKey(module, binding.member)
}

func (x *nodeValueIndex) addExportWrite(write NamedValueWrite) {
	if x.exportWrites == nil {
		x.exportWrites = make(map[NamedValueWrite]bool)
	}
	x.exportWrites[write] = true
}

// memberRead marks memberValue on a binding that holds a construction when
// member, read off node, is not the callee of a direct call in that
// binding's own function.
func (x *nodeValueIndex) memberRead(name string, node, member *sitter.Node) {
	d := x.resolve(name, node)
	if d == nil || d.memberValue || d.value == nil || unwrapNodeValue(d.value).Type() != nodeNewExpression {
		return
	}
	call := member.Parent()
	if call == nil || call.Type() != nodeCallExpression || !sameSyntaxNode(call.ChildByFieldName("function"), member) ||
		!sameOptionalNode(nodeEnclosingFunction(node), d.fn) {
		d.memberValue = true
	}
}

// nodeIsNameField reports node as the object a member read starts from, or
// the name a declaration, import or export introduces.
func nodeIsNameField(parent, node *sitter.Node) bool {
	switch parent.Type() {
	case nodeMemberExpression:
		object := parent.ChildByFieldName("object")
		return object != nil && sameSyntaxNode(object, node)
	case nodeVariableDeclarator, nodeFunctionDeclaration, nodeGeneratorDeclaration, nodeFunctionExpression, javaNodeClassDeclaration, nodeEnumDeclaration:
		name := parent.ChildByFieldName("name")
		return name != nil && sameSyntaxNode(name, node)
	case nodeExportSpecifier, nodeImportSpecifier, nodeNamespaceImport, nodeImportClause:
		return true
	}
	return false
}

// resolve returns the binding a use of name at node reads: the declaration
// with the innermost scope holding node. Two declarations in that scope, or
// too many declarations of the name, resolve to nothing.
func (x *nodeValueIndex) resolve(name string, node *sitter.Node) *nodeDecl {
	if x == nil || x.disabled {
		return nil
	}
	decls := x.decls[name]
	if len(decls) > maxNodeDeclsPerName {
		return nil
	}
	at := node.StartByte()
	var best *nodeDecl
	tie := false
	for _, d := range decls {
		if at < d.scope.StartByte() || at >= d.scope.EndByte() {
			continue
		}
		switch {
		case best == nil || nodeRangeWithin(d.scope, best.scope) && !sameSyntaxNode(d.scope, best.scope):
			best, tie = d, false
		case sameSyntaxNode(d.scope, best.scope):
			tie = true
		}
	}
	if tie {
		return nil
	}
	return best
}

func nodeRangeWithin(inner, outer *sitter.Node) bool {
	return inner.StartByte() >= outer.StartByte() && inner.EndByte() <= outer.EndByte()
}

// stable reports whether a variable binding holds its initializer at node: a
// const or let the file never assigns again, or a var declared, unconditionally,
// earlier in the same function as node.
func (x *nodeValueIndex) stable(d *nodeDecl, node *sitter.Node) bool {
	if d.value == nil || d.writes != 0 {
		return false
	}
	switch d.kind {
	case nodeDeclConst, nodeDeclLet:
		return true
	case nodeDeclVar:
		return x.varInitializedBefore(d, node)
	case nodeDeclOther, nodeDeclParam, nodeDeclClass, nodeDeclEnum, nodeDeclImport:
	}
	return false
}

// varInitializedBefore reports a var whose declaration is a statement of its
// function's body, or of the module, that ends before node, in that same
// function. A var has no temporal dead zone: a read before it is undefined.
func (x *nodeValueIndex) varInitializedBefore(d *nodeDecl, node *sitter.Node) bool {
	statement := d.name.Parent()
	if statement != nil {
		statement = statement.Parent()
	}
	if statement == nil || node.StartByte() < statement.EndByte() || !sameOptionalNode(nodeEnclosingFunction(node), d.fn) {
		return false
	}
	body := statement.Parent()
	return body != nil && (body.Type() == nodeProgramNode || d.fn != nil && sameSyntaxNode(body, d.fn.ChildByFieldName("body")))
}

// parameter reports the position of a plain parameter of the function holding
// node, which the function never reassigns nor aliases through `arguments`.
func (x *nodeValueIndex) parameter(d *nodeDecl, node *sitter.Node) (int, bool) {
	if d.kind != nodeDeclParam || !d.plainParam || d.writes != 0 || x.argumentsUsers[d.fn.StartByte()] {
		return 0, false
	}
	return d.paramIndex, sameOptionalNode(nodeEnclosingFunction(node), d.fn)
}

func sameOptionalNode(a, b *sitter.Node) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return sameSyntaxNode(a, b)
}

// nodeIsModuleExportsObject reports the object of `module.exports = {..}`,
// whose shorthand members are exports, not escapes.
func nodeIsModuleExportsObject(object *sitter.Node, src []byte) bool {
	if object == nil || object.Type() != nodeObjectLiteral {
		return false
	}
	assign := object.Parent()
	if assign == nil || assign.Type() != nodeAssignmentExpression {
		return false
	}
	left := assign.ChildByFieldName("left")
	return left != nil && left.Content(src) == nodeModuleExportsTarget
}
