// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

const (
	// nodeValueMaxDepth bounds how many `const a = b` hops, and nested
	// construction arguments, one argument is followed through.
	nodeValueMaxDepth = 4
	nodeStringType    = "string"
	nodeNumberType    = "number"
	nodeNumberNode    = "number"
	nodeTemplateNode  = "template_string"
)

// nodeArgumentSources is FunctionCall.ArgumentSources for a call or new
// expression: one entry per argument, nil where the value is not known. A
// call with arguments always gets one entry per argument, so a caller whose
// argument is unknown counts as such instead of being skipped.
func (p *NodeParser) nodeArgumentSources(call *sitter.Node, count int) [][]SourceNode {
	if p.values == nil || count == 0 {
		return nil
	}
	sources := make([][]SourceNode, count)
	args := nodeArgumentNodes(call)
	if len(args) != count {
		return sources
	}
	for i, arg := range args {
		sources[i] = p.nodeValueSource(arg, 0)
	}
	return sources
}

// nodeArgumentNodes returns the argument expressions of a call or new
// expression, comments left out.
func nodeArgumentNodes(call *sitter.Node) []*sitter.Node {
	list := call.ChildByFieldName("arguments")
	if list == nil {
		return nil
	}
	args := make([]*sitter.Node, 0, list.NamedChildCount())
	for i := 0; i < int(list.NamedChildCount()); i++ {
		if arg := list.NamedChild(i); arg.Type() != goNodeComment {
			args = append(args, arg)
		}
	}
	return args
}

// unwrapNodeValue sees through what does not change a value: parentheses and
// TypeScript's `as`, `satisfies` and `!`.
func unwrapNodeValue(node *sitter.Node) *sitter.Node {
	for node != nil && nodeIsTransparentWrapper(node.Type()) && node.NamedChildCount() > 0 {
		node = node.NamedChild(0)
	}
	return node
}

// nodeValueSource is the provenance of an expression whose value the file
// pins: a literal, a parameter of the enclosing function, a stable local or
// module binding of one, a member of an enum-like object or TypeScript enum,
// an export of another project module (left to the post-parse fold), or a
// getter called on a construction. Anything else yields nothing.
func (p *NodeParser) nodeValueSource(node *sitter.Node, depth int) []SourceNode {
	x := p.values
	node = unwrapNodeValue(node)
	if node == nil || x == nil {
		return nil
	}
	switch node.Type() {
	case nodeStringNode, nodeTemplateNode:
		if literal, ok := canonicalNodeStringLiteral(node.Content(x.src)); ok {
			return []SourceNode{{Type: sourceNodeValue, Value: literal}}
		}
	case nodeNumberNode:
		return []SourceNode{{Type: sourceNodeValue, Value: node.Content(x.src)}}
	case goNodeIdentifier, nodeShorthandProperty:
		return p.nodeIdentifierSource(node, depth)
	case nodeMemberExpression:
		return p.nodeMemberSource(node, depth)
	case nodeCallExpression:
		return p.nodeGetterSource(node, depth)
	}
	return nil
}

func (x *nodeValueIndex) location(node *sitter.Node) *SourceLocation {
	return &SourceLocation{FilePath: x.filePath, Line: int(node.StartPoint().Row) + 1}
}

func (p *NodeParser) nodeIdentifierSource(node *sitter.Node, depth int) []SourceNode {
	x := p.values
	name := node.Content(x.src)
	d := x.resolve(name, node)
	if d == nil {
		return nil
	}
	if index, ok := x.parameter(d, node); ok {
		return []SourceNode{{Type: sourceNodeParameter, Name: name, ParameterIndex: index, Location: x.location(node)}}
	}
	switch d.kind {
	case nodeDeclConst, nodeDeclLet, nodeDeclVar:
		if depth >= nodeValueMaxDepth || !x.stable(d, node) {
			return nil
		}
		if value := p.nodeValueSource(d.value, depth+1); value != nil {
			return []SourceNode{{Type: sourceNodeVariable, Name: name, SourceNodes: value}}
		}
	case nodeDeclImport:
		return x.importSource(d, node, nil)
	case nodeDeclOther, nodeDeclParam, nodeDeclClass, nodeDeclEnum:
	}
	return nil
}

// importSource is a placeholder for an export of another project module,
// keyed `<module>.<export>[.<member>]`, which the post-parse fold resolves
// once that module is parsed, or drops. expr is the whole use: the imported
// name, or the member chain rest climbs from it.
func (x *nodeValueIndex) importSource(d *nodeDecl, expr *sitter.Node, rest []string) []SourceNode {
	var path []string
	if d.member != "" {
		path = strings.Split(d.member, ".")
	}
	path = append(path, rest...)
	if d.module == "" || len(path) == 0 || d.memberWrites {
		return nil
	}
	text := expr.Content(x.src)
	return []SourceNode{{
		Type:     sourceNodeExpression,
		Value:    text,
		Location: x.location(expr),
		nameRef:  &nameRef{expr: text, tiers: [][]string{{d.module + "." + strings.Join(path, ".")}}, placeholder: true},
	}}
}

// nodeMemberChain splits a member chain `a.b.c` into its root identifier and
// the property names after it. A computed access or a root that is not a
// name yields no root.
func nodeMemberChain(node *sitter.Node, src []byte) (*sitter.Node, []string) {
	var rest []string
	for node.Type() == nodeMemberExpression {
		property := node.ChildByFieldName("property")
		if property == nil || property.Type() != nodePropertyIdentifier {
			return nil, nil
		}
		rest = append([]string{property.Content(src)}, rest...)
		node = unwrapNodeValue(node.ChildByFieldName("object"))
		if node == nil {
			return nil, nil
		}
	}
	if node.Type() != goNodeIdentifier {
		return nil, nil
	}
	return node, rest
}

func (p *NodeParser) nodeMemberSource(node *sitter.Node, depth int) []SourceNode {
	x := p.values
	root, rest := nodeMemberChain(node, x.src)
	if root == nil {
		return nil
	}
	d := x.resolve(root.Content(x.src), root)
	if d == nil {
		return nil
	}
	if d.kind == nodeDeclImport {
		return x.importSource(d, node, rest)
	}
	if len(rest) != 1 || depth >= nodeValueMaxDepth {
		return nil
	}
	member, ok := x.members(d)[rest[0]]
	if !ok {
		return nil
	}
	value := p.nodeValueSource(member, depth+1)
	if value == nil {
		return nil
	}
	return []SourceNode{{
		Type:         sourceNodeField,
		Name:         node.Content(x.src),
		DeclaredType: nodeValueType(value),
		Location:     x.location(member),
		SourceNodes:  value,
	}}
}

func nodeValueType(sources []SourceNode) string {
	for len(sources) == 1 {
		if sources[0].Type == sourceNodeValue {
			if strings.HasPrefix(sources[0].Value, `"`) {
				return nodeStringType
			}
			return nodeNumberType
		}
		sources = sources[0].SourceNodes
	}
	return ""
}

// members returns the members of an enum-like binding by name, each with its
// value expression: the string members of a TypeScript enum, and the
// properties of a const bound to `Object.freeze({..})`, or to a plain object
// literal the file neither writes through nor lets escape. An object with a
// spread, a computed key, a method or an accessor has none: any of them may
// decide what a member holds.
func (x *nodeValueIndex) members(d *nodeDecl) map[string]*sitter.Node {
	switch d.kind {
	case nodeDeclEnum:
		if d.memberWrites {
			return nil
		}
		return x.enumMembers(d.value.ChildByFieldName("body"))
	case nodeDeclConst:
		object, frozen := x.frozenObject(unwrapNodeValue(d.value))
		if object == nil || !frozen && (d.memberWrites || d.escapes > 0) {
			return nil
		}
		return x.objectMembers(object)
	case nodeDeclOther, nodeDeclLet, nodeDeclVar, nodeDeclParam, nodeDeclClass, nodeDeclImport:
	}
	return nil
}

// frozenObject returns the object literal a value is, and whether it is
// wrapped in `Object.freeze`.
func (x *nodeValueIndex) frozenObject(value *sitter.Node) (*sitter.Node, bool) {
	if value == nil {
		return nil, false
	}
	if value.Type() == nodeObjectLiteral {
		return value, false
	}
	if value.Type() != nodeCallExpression {
		return nil, false
	}
	function := value.ChildByFieldName("function")
	args := nodeArgumentNodes(value)
	if function == nil || function.Content(x.src) != "Object.freeze" || len(args) != 1 || x.resolve("Object", value) != nil {
		return nil, false
	}
	if object := unwrapNodeValue(args[0]); object != nil && object.Type() == nodeObjectLiteral {
		return object, true
	}
	return nil, false
}

func (x *nodeValueIndex) objectMembers(object *sitter.Node) map[string]*sitter.Node {
	members := make(map[string]*sitter.Node)
	duplicate := make(map[string]bool)
	add := func(key string, value *sitter.Node) {
		if _, seen := members[key]; seen {
			duplicate[key] = true
		}
		members[key] = value
	}
	for i := 0; i < int(object.NamedChildCount()); i++ {
		switch member := object.NamedChild(i); member.Type() {
		case goNodeComment:
		case nodeShorthandProperty:
			add(member.Content(x.src), member)
		case nodePair:
			key, value := member.ChildByFieldName("key"), member.ChildByFieldName("value")
			name, ok := nodePropertyKey(key, x.src)
			if !ok || value == nil {
				return nil
			}
			add(name, value)
		default:
			return nil
		}
	}
	for key := range duplicate {
		delete(members, key)
	}
	return members
}

func nodePropertyKey(key *sitter.Node, src []byte) (string, bool) {
	if key == nil {
		return "", false
	}
	switch key.Type() {
	case nodePropertyIdentifier:
		return key.Content(src), true
	case nodeStringNode:
		literal, ok := canonicalNodeStringLiteral(key.Content(src))
		if !ok {
			return "", false
		}
		return literal[1 : len(literal)-1], !strings.ContainsAny(literal, `\.`)
	}
	return "", false
}

// enumMembers returns the members of an enum body initialized with a string
// literal. A numeric or auto-numbered member is left out.
func (x *nodeValueIndex) enumMembers(body *sitter.Node) map[string]*sitter.Node {
	if body == nil {
		return nil
	}
	members := make(map[string]*sitter.Node)
	for i := 0; i < int(body.NamedChildCount()); i++ {
		member := body.NamedChild(i)
		if member.Type() != "enum_assignment" {
			continue
		}
		value := member.ChildByFieldName("value")
		name, ok := nodePropertyKey(member.ChildByFieldName("name"), x.src)
		if ok && value != nil && (value.Type() == nodeStringNode || value.Type() == nodeTemplateNode) {
			members[name] = value
		}
	}
	return members
}

// nodeGetterSource marks `X.m()` whose receiver is `new C(..)`, written in
// place or bound once to a function local nothing writes through, with that
// construction, for foldConstructorGetters. C is a class this module declares
// once at its top level, or one a named import of a project module binds.
func (p *NodeParser) nodeGetterSource(call *sitter.Node, depth int) []SourceNode {
	x := p.values
	function := call.ChildByFieldName("function")
	if function == nil || function.Type() != nodeMemberExpression || len(nodeArgumentNodes(call)) != 0 || depth >= nodeValueMaxDepth {
		return nil
	}
	method := function.ChildByFieldName("property")
	receiver := unwrapNodeValue(function.ChildByFieldName("object"))
	if method == nil || method.Type() != nodePropertyIdentifier || receiver == nil {
		return nil
	}
	if receiver.Type() == goNodeIdentifier {
		receiver = x.localConstruction(receiver, call)
	}
	if receiver == nil || receiver.Type() != nodeNewExpression {
		return nil
	}
	class, ok := x.constructedClass(receiver.ChildByFieldName("constructor"))
	if !ok {
		return nil
	}
	args := nodeArgumentNodes(receiver)
	ref := &ctorGetterRef{
		constructor: FunctionID{Package: class.Package, Type: class.Type, Name: nodeConstructorKeyword},
		method:      method.Content(x.src),
		arguments:   make([]ctorArgument, len(args)),
	}
	for i, arg := range args {
		ref.arguments[i] = ctorArgument{splat: arg.Type() == nodeSpreadElement, sources: p.nodeValueSource(arg, depth+1)}
	}
	target := FunctionID{Package: class.Package, Type: class.Type, Name: ref.method}
	return []SourceNode{{
		Type:       sourceNodeCallResult,
		Value:      call.Content(x.src),
		CallTarget: &target,
		Location:   x.location(call),
		getter:     ref,
	}}
}

// localConstruction returns the `new C(..)` a function local holds at use:
// a const or never reassigned let of the function holding use, no member of
// which is written, used only as the receiver of direct method calls in that
// function. Passed, aliased, returned, stored or captured, the object
// reaches code that may write its fields.
func (x *nodeValueIndex) localConstruction(name, use *sitter.Node) *sitter.Node {
	d := x.resolve(name.Content(x.src), name)
	if d == nil || d.fn == nil || (d.kind != nodeDeclConst && d.kind != nodeDeclLet) ||
		!x.stable(d, use) || d.memberWrites || d.escapes > 0 || d.memberValue || !sameOptionalNode(nodeEnclosingFunction(use), d.fn) {
		return nil
	}
	return unwrapNodeValue(d.value)
}

// constructedClass names the class `new <constructor>` constructs.
func (x *nodeValueIndex) constructedClass(constructor *sitter.Node) (FunctionID, bool) {
	if constructor == nil {
		return FunctionID{}, false
	}
	root, rest := nodeMemberChain(constructor, x.src)
	if root == nil {
		return FunctionID{}, false
	}
	name := root.Content(x.src)
	d := x.resolve(name, root)
	if d == nil {
		return FunctionID{}, false
	}
	switch {
	case d.kind == nodeDeclClass && len(rest) == 0 && d.fn == nil && len(x.decls[name]) == 1 && d.scope.Type() == nodeProgramNode:
		return FunctionID{Package: x.modulePath, Type: name}, true
	case d.kind == nodeDeclImport && d.module != "" && (d.member != "" || len(rest) > 0):
		pkg, last := nodeBinding{module: d.module, member: d.member}.qualify(rest...)
		return FunctionID{Package: pkg, Type: last}, last != ""
	}
	return FunctionID{}, false
}

// recordNodeNamedValues records what this module exports under
// `<module>.<export>`, and each member of an exported enum-like object or
// enum under `<module>.<export>.<member>`: ESM `export const`, `export enum`
// and `export { a as b }`, and CommonJS `module.exports = {..}` or
// `exports.a = ..`. A re-export from another module, a default export and an
// exported let or var are left out.
func (p *NodeParser) recordNodeNamedValues(root *sitter.Node, analysis *FileAnalysis) {
	if p.values == nil || p.values.disabled {
		return
	}
	for i := 0; i < int(root.NamedChildCount()); i++ {
		statement := root.NamedChild(i)
		if statement.Type() != nodeExportKind || statement.ChildByFieldName("source") != nil {
			continue
		}
		if declaration := statement.ChildByFieldName("declaration"); declaration != nil {
			p.recordNodeExportedDeclaration(declaration, analysis)
			continue
		}
		for j := 0; j < int(statement.NamedChildCount()); j++ {
			if clause := statement.NamedChild(j); clause.Type() == nodeExportClauseKind {
				p.recordNodeExportClause(clause, analysis)
			}
		}
	}
	p.recordNodeCommonJSExports(root, analysis)
}

// recordNodeExportClause records `export { a, b as c }` of this module's own
// bindings.
func (p *NodeParser) recordNodeExportClause(clause *sitter.Node, analysis *FileAnalysis) {
	x := p.values
	for k := 0; k < int(clause.NamedChildCount()); k++ {
		specifier := clause.NamedChild(k)
		name, alias := specifier.ChildByFieldName("name"), specifier.ChildByFieldName("alias")
		if name == nil || specifier.Type() != nodeExportSpecifier {
			continue
		}
		if alias == nil {
			alias = name
		}
		if d := x.resolve(name.Content(x.src), specifier); d != nil {
			p.recordNodeExport(analysis, alias.Content(x.src), d)
		}
	}
}

func (p *NodeParser) recordNodeExportedDeclaration(declaration *sitter.Node, analysis *FileAnalysis) {
	x := p.values
	var names []*sitter.Node
	switch declaration.Type() {
	case nodeLexicalDeclaration:
		for i := 0; i < int(declaration.NamedChildCount()); i++ {
			if name := declaration.NamedChild(i).ChildByFieldName("name"); name != nil && name.Type() == goNodeIdentifier {
				names = append(names, name)
			}
		}
	case nodeEnumDeclaration:
		names = append(names, declaration.ChildByFieldName("name"))
	}
	for _, name := range names {
		if d := x.resolve(name.Content(x.src), name); d != nil && sameSyntaxNode(d.name, name) {
			p.recordNodeExport(analysis, name.Content(x.src), d)
		}
	}
}

// recordNodeExport records the value d holds, and its members, as export name.
func (p *NodeParser) recordNodeExport(analysis *FileAnalysis, name string, d *nodeDecl) {
	x := p.values
	key := x.modulePath + "." + name
	switch d.kind {
	case nodeDeclConst:
		if x.stable(d, d.name) {
			p.recordNodeValue(analysis, key, d.value)
			p.recordNodeMembers(analysis, key, d)
		}
	case nodeDeclEnum:
		p.recordNodeMembers(analysis, key, d)
	case nodeDeclImport:
		if sources := x.importSource(d, d.name, nil); sources != nil {
			recordNamedValue(analysis, key, NamedValue{FilePath: x.filePath, Line: int(d.name.StartPoint().Row) + 1, ref: sources[0].nameRef})
		}
	case nodeDeclOther, nodeDeclLet, nodeDeclVar, nodeDeclParam, nodeDeclClass:
	}
}

func (p *NodeParser) recordNodeMembers(analysis *FileAnalysis, key string, d *nodeDecl) {
	if d == nil {
		return
	}
	for member, value := range p.values.members(d) {
		p.recordNodeValue(analysis, key+"."+member, value)
	}
}

// recordNodeValue records under key the literal value resolves to through
// this module, or the export of another module it names.
func (p *NodeParser) recordNodeValue(analysis *FileAnalysis, key string, value *sitter.Node) {
	sources := p.nodeValueSource(value, 0)
	decl := NamedValue{DeclaredType: nodeValueType(sources), FilePath: p.values.filePath, Line: int(value.StartPoint().Row) + 1}
	for len(sources) == 1 {
		switch node := sources[0]; {
		case node.Type == sourceNodeValue:
			decl.Value = node.Value
			recordNamedValue(analysis, key, decl)
			return
		case node.nameRef != nil:
			decl.ref = node.nameRef
			recordNamedValue(analysis, key, decl)
			return
		}
		sources = sources[0].SourceNodes
	}
}

// nodeCommonJSWrite is one assignment to `module.exports` or to one of its
// members.
type nodeCommonJSWrite struct {
	statement, value *sitter.Node
}

// recordNodeCommonJSExports records the exports a module assigns once, at its
// top level: every member of the one `module.exports = {..}` when nothing
// else writes an export, else each `exports.a = ..` or `module.exports.a =
// ..` that is the only write of a.
func (p *NodeParser) recordNodeCommonJSExports(root *sitter.Node, analysis *FileAnalysis) {
	x := p.values
	writes, ok := x.commonJSWrites(root)
	if !ok || len(writes) == 0 {
		return
	}
	if _, whole := writes[""]; whole {
		value, single := nodeSingleTopLevelWrite(writes[""])
		if !single || len(writes) != 1 {
			return
		}
		for member, memberValue := range x.commonJSObjectMembers(value) {
			p.recordNodeValue(analysis, x.modulePath+"."+member, memberValue)
			p.recordNodeMembers(analysis, x.modulePath+"."+member, x.identifierDecl(memberValue))
		}
		return
	}
	for target, list := range writes {
		if value, single := nodeSingleTopLevelWrite(list); single {
			p.recordNodeValue(analysis, x.modulePath+"."+target, value)
			p.recordNodeMembers(analysis, x.modulePath+"."+target, x.identifierDecl(value))
		}
	}
}

// commonJSWrites collects the writes to each export, keyed by its name, ""
// for `module.exports` itself. ok is false when an export is written in a way
// no name spells: a member of one, a computed key, `exports` rebound, or
// Object.assign(module.exports, ..).
func (x *nodeValueIndex) commonJSWrites(root *sitter.Node) (map[string][]nodeCommonJSWrite, bool) {
	writes := make(map[string][]nodeCommonJSWrite)
	ok := true
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		if n.Type() == nodeAssignmentExpression || n.Type() == nodeAugmentedAssignment {
			left := n.ChildByFieldName("left")
			if target, isExport := nodeCommonJSExportTarget(left, x.src); isExport {
				writes[target] = append(writes[target], nodeCommonJSWrite{statement: n.Parent(), value: n.ChildByFieldName("right")})
				ok = ok && !strings.ContainsAny(target, ".[") && left.Content(x.src) != nodeCommonJSExportsObject
			}
		}
		if n.Type() == nodeCallExpression {
			if _, isExport := nodeCommonJSExportTarget(nodeMutatedObject(n, x.src), x.src); isExport {
				ok = false
			}
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(root)
	return writes, ok
}

// nodeSingleTopLevelWrite returns the value of the one write in list when it
// is a statement of the module's top level.
func nodeSingleTopLevelWrite(list []nodeCommonJSWrite) (*sitter.Node, bool) {
	if len(list) != 1 || list[0].value == nil || list[0].statement == nil {
		return nil, false
	}
	parent := list[0].statement.Parent()
	if list[0].statement.Type() != nodeExpressionStatement || parent == nil || parent.Type() != nodeProgramNode {
		return nil, false
	}
	return list[0].value, true
}

// commonJSObjectMembers returns the members `module.exports = value` exports:
// those of an object literal, frozen or not, or of an enum-like binding.
func (x *nodeValueIndex) commonJSObjectMembers(value *sitter.Node) map[string]*sitter.Node {
	value = unwrapNodeValue(value)
	if object, _ := x.frozenObject(value); object != nil {
		return x.objectMembers(object)
	}
	if d := x.identifierDecl(value); d != nil {
		return x.members(d)
	}
	return nil
}

func (x *nodeValueIndex) identifierDecl(value *sitter.Node) *nodeDecl {
	value = unwrapNodeValue(value)
	if value == nil || value.Type() != goNodeIdentifier && value.Type() != nodeShorthandProperty {
		return nil
	}
	return x.resolve(value.Content(x.src), value)
}

// nodeCommonJSExportTarget reports the export a write target names: "" for
// `module.exports` or `exports` itself, `a` for `exports.a` and
// `module.exports.a`, and a target holding a dot or bracket for a member of
// one or a computed export.
func nodeCommonJSExportTarget(target *sitter.Node, src []byte) (string, bool) {
	if target == nil {
		return "", false
	}
	text := target.Content(src)
	for _, prefix := range []string{nodeModuleExportsTarget, nodeCommonJSExportsObject} {
		if text == prefix {
			return "", true
		}
		if rest, ok := strings.CutPrefix(text, prefix); ok && (strings.HasPrefix(rest, ".") || strings.HasPrefix(rest, "[")) {
			return strings.TrimPrefix(rest, "."), true
		}
	}
	return "", false
}
