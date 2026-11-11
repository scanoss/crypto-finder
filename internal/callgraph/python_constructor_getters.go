// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	sitter "github.com/smacker/go-tree-sitter"
)

// pythonConstructorGetters returns the return source of each method of a class
// body whose whole body is `return self.f`, when `__init__` sets f from one of
// its positional parameters and nothing else in the class writes f: a FIELD
// with that PARAMETER as its one source, the shape constructorFieldParameter
// reads.
//
// Only the class's own code is read, so a class with a base other than object
// (whose methods may write f too) or a decorator (which may replace the class)
// carries none. Neither does a class that hands `self` to other code, which
// could then write f, or that customizes construction or attribute access.
func pythonConstructorGetters(class, body *sitter.Node, src []byte, filePath string) map[string]SourceNode {
	if !pythonPlainClass(class, src) {
		return nil
	}
	defs, classNames := pythonClassMembers(body, src)
	for _, hook := range []string{"__new__", "__setattr__", "__delattr__", "__getattribute__"} {
		if len(defs[hook]) > 0 || classNames[hook] {
			return nil
		}
	}
	inits := defs[pythonInitMethodName]
	writes := make(map[string]int)
	if len(inits) != 1 || inits[0] == nil || !pythonCountSelfWrites(body, src, writes) {
		return nil
	}
	fields := pythonInitParameterFields(inits[0], src, filePath, writes)
	getters := make(map[string]SourceNode)
	for name, nodes := range defs {
		if len(nodes) != 1 || nodes[0] == nil {
			continue
		}
		field, ok := pythonReturnedSelfField(nodes[0], src)
		if param, set := fields[field]; ok && set && len(defs[field]) == 0 && !classNames[field] {
			// A class attribute of that name may be a property or descriptor
			// whose setter stores something else.
			getters[name] = SourceNode{Type: sourceNodeField, Name: field, SourceNodes: []SourceNode{param}}
		}
	}
	return getters
}

// pythonClassMembers indexes a class body's methods by name, a decorated one
// as nil, and the names its plain assignments bind.
func pythonClassMembers(body *sitter.Node, src []byte) (defs map[string][]*sitter.Node, assigned map[string]bool) {
	defs = make(map[string][]*sitter.Node)
	assigned = make(map[string]bool)
	for i := 0; i < int(body.NamedChildCount()); i++ {
		child := body.NamedChild(i)
		switch child.Symbol() {
		case pythonSyms.decoratedDefinition:
			// A decorated method may replace a plain one of the same name.
			if def := child.ChildByFieldName("definition"); def != nil && def.Symbol() == pythonSyms.functionDefinition {
				defs[pythonFunctionDefName(def, src)] = append(defs[pythonFunctionDefName(def, src)], nil)
			}
		case pythonSyms.functionDefinition:
			defs[pythonFunctionDefName(child, src)] = append(defs[pythonFunctionDefName(child, src)], child)
		case pythonSyms.expressionStatement:
			if child.NamedChildCount() == 1 && child.NamedChild(0).Symbol() == pythonSyms.assignment {
				if left := child.NamedChild(0).ChildByFieldName("left"); left != nil && left.Symbol() == pythonSyms.identifier {
					assigned[left.Content(src)] = true
				}
			}
		}
	}
	return defs, assigned
}

// pythonPlainClass reports a class statement with no decorator, no keyword
// such as metaclass=, and no base but object.
func pythonPlainClass(class *sitter.Node, src []byte) bool {
	if parent := class.Parent(); parent == nil || parent.Symbol() == pythonSyms.decoratedDefinition {
		return false
	}
	bases := class.ChildByFieldName("superclasses")
	if bases == nil {
		return true
	}
	for i := 0; i < int(bases.NamedChildCount()); i++ {
		if base := bases.NamedChild(i); base.Symbol() != pythonSyms.identifier || base.Content(src) != "object" {
			return false
		}
	}
	return true
}

// pythonCountSelfWrites counts, per attribute name, the statements anywhere in
// node that assign, augment or delete `self.<name>`. It reports false when the
// class writes attributes in a way no name spells (setattr, __dict__), or uses
// `self` other than to reach one of its attributes: passed, returned or stored,
// the object reaches code that may write any attribute.
func pythonCountSelfWrites(node *sitter.Node, src []byte, writes map[string]int) bool {
	switch node.Symbol() {
	case pythonSyms.assignment, pythonSyms.augmentedAssignment:
		pythonCountSelfTargets(node.ChildByFieldName("left"), src, writes)
	case pythonSyms.deleteStatement:
		pythonCountSelfTargets(node.NamedChild(0), src, writes)
	case pythonSyms.identifier:
		switch name := node.Content(src); name {
		case "setattr", "__dict__", "vars":
			return false
		case pythonSelfObjectName:
			if !pythonSelfAttributeObject(node) {
				return false
			}
		}
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		if !pythonCountSelfWrites(node.NamedChild(i), src, writes) {
			return false
		}
	}
	return true
}

func pythonCountSelfTargets(target *sitter.Node, src []byte, writes map[string]int) {
	if target == nil {
		return
	}
	if field, ok := pythonSelfAttribute(target, src); ok {
		writes[field]++
		return
	}
	if target.Symbol() == pythonSyms.attribute || target.Symbol() == pythonSyms.subscript {
		return
	}
	for i := 0; i < int(target.NamedChildCount()); i++ {
		pythonCountSelfTargets(target.NamedChild(i), src, writes)
	}
}

// pythonSelfAttributeObject reports an identifier that is the object of an
// attribute (`self.f`) or a parameter declaring it.
func pythonSelfAttributeObject(node *sitter.Node) bool {
	parent := node.Parent()
	if parent == nil {
		return false
	}
	switch parent.Symbol() {
	case pythonSyms.parameters, pythonSyms.typedParameter:
		return true
	case pythonSyms.attribute:
		return pythonIsFieldChild(parent, "object", node)
	}
	return false
}

func pythonSelfAttribute(node *sitter.Node, src []byte) (string, bool) {
	if node.Symbol() != pythonSyms.attribute {
		return "", false
	}
	object, attr := node.ChildByFieldName("object"), node.ChildByFieldName("attribute")
	if object == nil || attr == nil || object.Symbol() != pythonSyms.identifier || object.Content(src) != pythonSelfObjectName {
		return "", false
	}
	return attr.Content(src), true
}

// pythonInitParameterFields maps each attribute `__init__` assigns exactly once
// from a positional parameter its body never rebinds, to that parameter.
func pythonInitParameterFields(init *sitter.Node, src []byte, filePath string, writes map[string]int) map[string]SourceNode {
	_, body, paramNode := pythonFunctionDefParts(init, src)
	params := parsePythonParameters(paramNode, src)
	positional := pythonPositionalParameterCount(paramNode) - 1
	if body == nil || len(params) == 0 {
		return nil
	}
	index := make(map[string]int)
	for i, param := range params[1:] {
		if i < positional {
			index[param.Name] = i
		}
	}
	rebound := make(map[string]bool)
	pythonCollectBindings(body, src, rebound)
	fields := make(map[string]SourceNode)
	var walk func(node *sitter.Node)
	walk = func(node *sitter.Node) {
		if node.Symbol() == pythonSyms.assignment {
			left, right := node.ChildByFieldName("left"), node.ChildByFieldName("right")
			if field, ok := pythonSelfAttribute(left, src); ok && right != nil && right.Symbol() == pythonSyms.identifier && writes[field] == 1 {
				if i, isParam := index[right.Content(src)]; isParam && !rebound[right.Content(src)] {
					fields[field] = SourceNode{
						Type:           sourceNodeParameter,
						Name:           right.Content(src),
						ParameterIndex: i,
						Location:       &SourceLocation{FilePath: filePath, Line: int(node.StartPoint().Row) + 1},
					}
				}
			}
		}
		for i := 0; i < int(node.NamedChildCount()); i++ {
			walk(node.NamedChild(i))
		}
	}
	walk(body)
	return fields
}

// pythonReturnedSelfField reports f for a method `def m(self): return self.f`,
// a docstring allowed before the return.
func pythonReturnedSelfField(def *sitter.Node, src []byte) (string, bool) {
	_, body, params := pythonFunctionDefParts(def, src)
	if body == nil || params == nil || params.NamedChildCount() != 1 || params.NamedChild(0).Symbol() != pythonSyms.identifier {
		return "", false
	}
	var statements []*sitter.Node
	for i := 0; i < int(body.NamedChildCount()); i++ {
		statement := body.NamedChild(i)
		if len(statements) == 0 && statement.Symbol() == pythonSyms.expressionStatement &&
			statement.NamedChildCount() == 1 && statement.NamedChild(0).Symbol() == pythonSyms.string {
			continue
		}
		statements = append(statements, statement)
	}
	if len(statements) != 1 || statements[0].Type() != "return_statement" || statements[0].NamedChildCount() != 1 {
		return "", false
	}
	return pythonSelfAttribute(statements[0].NamedChild(0), src)
}

// pythonGetterRef is the getter reference of a call `X.m()` whose receiver is
// a constructor call `C(...)`, written in place or bound once to a local X.
func (p *PythonParser) pythonGetterRef(call *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, bindings pythonBindings, fw *pythonFileWalk, depth int) *ctorGetterRef {
	fn := call.ChildByFieldName("function")
	if args := pythonArgumentListChild(call); fn == nil || fn.Symbol() != pythonSyms.attribute || args == nil || args.NamedChildCount() != 0 {
		return nil
	}
	receiver, method := fn.ChildByFieldName("object"), fn.ChildByFieldName("attribute")
	if receiver != nil && receiver.Symbol() == pythonSyms.identifier {
		receiver = bindings.locals.construction(receiver.Content(src))
	}
	if receiver == nil || method == nil || receiver.Symbol() != pythonSyms.call || depth+1 >= pythonArgProvenanceMaxDepth {
		return nil
	}
	construction := p.parseCallExpr(receiver, src, filePath, analysis, bindings, fw, depth+1)
	if construction == nil || construction.Callee.Name != constructorMethodName {
		return nil
	}
	return &ctorGetterRef{
		constructor: construction.Callee,
		method:      method.Content(src),
		arguments:   pythonConstructionArguments(pythonArgumentListChild(receiver), construction.ArgumentSources, src),
	}
}

// pythonConstructionArguments pairs each argument of a call's list with its
// sources, which are index-parallel to the list's named children.
func pythonConstructionArguments(list *sitter.Node, sources [][]SourceNode, src []byte) []ctorArgument {
	if list == nil {
		return nil
	}
	args := make([]ctorArgument, 0, list.NamedChildCount())
	for i := 0; i < int(list.NamedChildCount()); i++ {
		var arg ctorArgument
		if i < len(sources) {
			arg.sources = sources[i]
		}
		switch child := list.NamedChild(i); child.Type() {
		case goNodeComment:
			continue
		case "keyword_argument":
			if name := child.ChildByFieldName("name"); name != nil {
				arg.keyword = name.Content(src)
			}
		case "list_splat", "dictionary_splat":
			arg.splat = true
		}
		args = append(args, arg)
	}
	return args
}
