// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	sitter "github.com/smacker/go-tree-sitter"
)

// nodeConstructorGetters returns the return source of each method of a class
// whose whole body is `return this.f`, when the constructor sets f from one
// of its plain parameters and nothing else in the class writes f: a FIELD
// with that PARAMETER as its one source, the shape constructorFieldParameter
// reads. A class that extends another, writes `this` by computed key or
// through Object.assign, or whose members the file reassigns has none.
func (x *nodeValueIndex) nodeConstructorGetters(class *sitter.Node, owner string) map[string]SourceNode {
	body := class.ChildByFieldName("body")
	if x == nil || x.disabled || body == nil || x.memberWritten(owner, class) || nodeClassHasHeritage(class) {
		return nil
	}
	methods, writes := x.classMembers(body)
	ctors := methods[nodeConstructorKeyword]
	if len(ctors) != 1 || ctors[0] == nil || !x.countThisWrites(body, writes) {
		return nil
	}
	fields := x.constructorParameterFields(ctors[0], writes)
	getters := make(map[string]SourceNode)
	for name, defs := range methods {
		if len(defs) != 1 || defs[0] == nil || name == nodeConstructorKeyword {
			continue
		}
		if field, ok := x.returnedThisField(defs[0]); ok {
			if param, set := fields[field]; set {
				getters[name] = SourceNode{Type: sourceNodeField, Name: field, SourceNodes: []SourceNode{param}}
			}
		}
	}
	return getters
}

func nodeClassHasHeritage(class *sitter.Node) bool {
	for i := 0; i < int(class.NamedChildCount()); i++ {
		if class.NamedChild(i).Type() == nodeClassHeritage {
			return true
		}
	}
	return false
}

// classMembers indexes a class body's methods by name, nil for a static,
// accessor or async member, which makes a plain method of the same name
// ambiguous, and counts each field an initializer writes.
func (x *nodeValueIndex) classMembers(body *sitter.Node) (map[string][]*sitter.Node, map[string]int) {
	methods := make(map[string][]*sitter.Node)
	writes := make(map[string]int)
	for i := 0; i < int(body.NamedChildCount()); i++ {
		member := body.NamedChild(i)
		name := member.ChildByFieldName("name")
		if name == nil {
			continue
		}
		key := name.Content(x.src)
		switch member.Type() {
		case nodeMethodDefinition:
			if nodeMethodHasModifier(member) {
				member = nil
			}
			methods[key] = append(methods[key], member)
		case nodeFieldDefinition, nodePublicFieldDefinition:
			if member.ChildByFieldName("value") != nil {
				writes[key]++
			}
		}
	}
	return methods, writes
}

func nodeMethodHasModifier(method *sitter.Node) bool {
	for _, modifier := range nodeMemberModifiers {
		if hasNodeToken(method, modifier) {
			return true
		}
	}
	return hasNodeToken(method, "*")
}

// countThisWrites counts, per field, the writes to `this.<field>` anywhere in
// node, a TypeScript parameter property included. It reports false when a
// write names no field: `this[k] = v`, Object.assign(this, ..).
func (x *nodeValueIndex) countThisWrites(node *sitter.Node, writes map[string]int) bool {
	ok := true
	eachNodeWriteLeaf(nodeWriteTarget(node, x.src), func(leaf *sitter.Node) {
		ok = x.countThisWrite(leaf, writes) && ok
	})
	if mutated := nodeMutatedObject(node, x.src); node.Type() == nodeCallExpression && mutated != nil && mutated.Type() == nodeThisNode {
		ok = false
	}
	if node.Type() == nodeRequiredParameter || node.Type() == nodeOptionalParameter {
		if pattern := node.ChildByFieldName("pattern"); pattern != nil && nodeIsParameterProperty(node) {
			writes[pattern.Content(x.src)]++
		}
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		ok = x.countThisWrites(node.NamedChild(i), writes) && ok
	}
	return ok
}

func (x *nodeValueIndex) countThisWrite(leaf *sitter.Node, writes map[string]int) bool {
	object := leaf.ChildByFieldName("object")
	if object == nil || object.Type() != nodeThisNode {
		return true
	}
	property := leaf.ChildByFieldName("property")
	if leaf.Type() == nodeSubscriptExpression || property == nil {
		return false
	}
	writes[property.Content(x.src)]++
	return true
}

// nodeIsParameterProperty reports `constructor(private a: T)`, which declares
// and assigns the field a.
func nodeIsParameterProperty(param *sitter.Node) bool {
	for i := 0; i < int(param.ChildCount()); i++ {
		switch child := param.Child(i); child.Type() {
		case "accessibility_modifier", "override_modifier", "readonly":
			return true
		}
	}
	return false
}

// constructorParameterFields maps each field the constructor assigns, outside
// any nested function, from one of its plain parameters, and that nothing
// else in the class writes, to that parameter.
func (x *nodeValueIndex) constructorParameterFields(ctor *sitter.Node, writes map[string]int) map[string]SourceNode {
	fields := make(map[string]SourceNode)
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		if isNodeFunctionLike(n.Type()) && !sameSyntaxNode(n, ctor) {
			return
		}
		if field, param, ok := x.constructorFieldAssignment(n, ctor, writes); ok {
			fields[field] = param
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(ctor)
	return fields
}

// constructorFieldAssignment reads `this.f = p` where p is a plain parameter
// of ctor and f is written nowhere else.
func (x *nodeValueIndex) constructorFieldAssignment(n, ctor *sitter.Node, writes map[string]int) (string, SourceNode, bool) {
	if n.Type() != nodeAssignmentExpression {
		return "", SourceNode{}, false
	}
	right := n.ChildByFieldName("right")
	field, ok := x.thisField(n.ChildByFieldName("left"))
	if !ok || writes[field] != 1 || right == nil || right.Type() != goNodeIdentifier {
		return "", SourceNode{}, false
	}
	d := x.resolve(right.Content(x.src), right)
	if d == nil || !sameOptionalNode(d.fn, ctor) {
		return "", SourceNode{}, false
	}
	index, isParam := x.parameter(d, right)
	if !isParam {
		return "", SourceNode{}, false
	}
	return field, SourceNode{Type: sourceNodeParameter, Name: right.Content(x.src), ParameterIndex: index, Location: x.location(n)}, true
}

// thisField reports f for `this.f` and `this.#f`.
func (x *nodeValueIndex) thisField(node *sitter.Node) (string, bool) {
	if node == nil || node.Type() != nodeMemberExpression {
		return "", false
	}
	object, property := node.ChildByFieldName("object"), node.ChildByFieldName("property")
	if object == nil || property == nil || object.Type() != nodeThisNode {
		return "", false
	}
	return property.Content(x.src), true
}

// returnedThisField reports f for a method `m() { return this.f; }` with no
// parameters.
func (x *nodeValueIndex) returnedThisField(method *sitter.Node) (string, bool) {
	params, body := method.ChildByFieldName("parameters"), method.ChildByFieldName("body")
	if params == nil || params.NamedChildCount() != 0 || body == nil {
		return "", false
	}
	var statements []*sitter.Node
	for i := 0; i < int(body.NamedChildCount()); i++ {
		if statement := body.NamedChild(i); statement.Type() != goNodeComment {
			statements = append(statements, statement)
		}
	}
	if len(statements) != 1 || statements[0].Type() != nodeReturnStatement || statements[0].NamedChildCount() != 1 {
		return "", false
	}
	return x.thisField(unwrapNodeValue(statements[0].NamedChild(0)))
}
