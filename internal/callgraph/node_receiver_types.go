// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// Typed receivers for JavaScript and TypeScript.
//
// A call `x.m()` on a project class names no module in its text, so without a
// type it resolves to nothing. The types here are only ones the source
// declares: a `new X()` initialiser, an annotation, a declared return type.
// A name whose type the source does not settle gets none, and a call on it
// stays unresolved rather than being matched by method name.

const (
	nodeAbstractClassDeclaration = "abstract_class_declaration"
	nodeTypeAnnotation           = "type_annotation"
	nodeTypeIdentifier           = "type_identifier"
	nodeExportKind               = "export_statement"
	nodeConstructorKeyword       = "constructor"
	nodeClassHeritage            = "class_heritage"
	nodeNestedTypeIdentifier     = "nested_type_identifier"
)

// nodeTypeRef names a class: the module that declares it and its name. With
// viaReturn it names instead a function of the project, whose declared return
// class the builder reads once every module is parsed: the function may
// live in a module not yet parsed.
type nodeTypeRef struct {
	pkg       string
	name      string
	viaReturn bool
	// inferredField names the unannotated class field the type was read from;
	// the builder drops it when code outside the class assigns that field.
	inferredField string
}

// nodeTypeFacts accumulates the declared type of each name, dropping a name as
// soon as two declarations disagree or one gives it no type.
type nodeTypeFacts struct {
	types    map[string]nodeTypeRef
	poisoned map[string]bool
}

func newNodeTypeFacts() *nodeTypeFacts {
	return &nodeTypeFacts{types: make(map[string]nodeTypeRef), poisoned: make(map[string]bool)}
}

func (f *nodeTypeFacts) set(name string, ref nodeTypeRef, ok bool) {
	if f.poisoned[name] {
		return
	}
	if existing, seen := f.types[name]; ok && (!seen || existing == ref) {
		f.types[name] = ref
		return
	}
	f.poison(name)
}

func (f *nodeTypeFacts) poison(name string) {
	f.poisoned[name] = true
	delete(f.types, name)
}

// nodeFileTypes holds what one file declares about types.
type nodeFileTypes struct {
	modulePath string
	// filePath and pkgPath locate the file, to resolve the relative specifier
	// of an inline require.
	filePath string
	pkgPath  string
	bindings nodeBindings
	// project names the imports that resolve to a module of the scanned tree.
	// A class from any other import is a library's, whose methods the contract
	// resolver types.
	project    map[string]bool
	classes    map[string]bool
	funcs      map[string]bool
	moduleVars map[string]nodeTypeRef
	fields     map[string]map[string]nodeTypeRef
	// inferredFields marks the fields typed from an initialiser, not an annotation.
	inferredFields map[string]map[string]bool
	instances      map[string]FunctionID
	// defaultClass is the class `export default class X` or `export default X`
	// makes the module's default export.
	defaultClass FunctionID
	// assignedProps holds the property names assigned on an object other than
	// `this`: `svc.h = value`.
	assignedProps map[string]bool
}

// nodeScope is the typing context of the function being parsed.
type nodeScope struct {
	// own and shadowed are the names the function declares itself, so a module
	// variable of the same name is not the receiver.
	own      map[string]bool
	shadowed map[string]bool
	vars     map[string]nodeTypeRef
	// names caches localNames once the scope is complete.
	names map[string]bool
}

// nodeProjectImports lists the local names bound to a module of the scanned
// tree. It must run before resolveNodeRelativeImports rewrites the specifiers.
func nodeProjectImports(bindings nodeBindings, filePath, packagePath string) map[string]bool {
	project := make(map[string]bool)
	for name, binding := range bindings {
		if _, ok := resolveNodeRelativeModule(filePath, packagePath, binding.module); ok {
			project[name] = true
		}
	}
	return project
}

func newNodeFileTypes(p *NodeParser, root *sitter.Node, src []byte, modulePath string, bindings nodeBindings, project map[string]bool) *nodeFileTypes {
	f := &nodeFileTypes{
		modulePath: modulePath,
		bindings:   bindings,
		project:    project,
		classes:    make(map[string]bool),
		funcs:      make(map[string]bool),
		moduleVars: make(map[string]nodeTypeRef),
		fields:     make(map[string]map[string]nodeTypeRef),
		instances:  make(map[string]FunctionID),

		inferredFields: make(map[string]map[string]bool),
		assignedProps:  make(map[string]bool),
	}
	f.collectClassNames(root, src)
	f.collectAssignedProps(root, src)
	f.collectFunctionNames(root, src)
	// Module variables read the classes and functions above, and the fields
	// read the module variables' classes, so the order is fixed.
	p.file = f
	defer func() { p.file = nil }()
	p.scope = &nodeScope{}
	defer func() { p.scope = nil }()
	vars := p.declaredVarTypes(nil, root, src)
	f.moduleVars = vars
	f.collectFields(p, root, src)
	f.collectInstances(root, src)
	return f
}

// collectClassNames records the classes the file declares by name. A name
// declared twice, as by a class in an inner scope, names no class here.
func (f *nodeFileTypes) collectClassNames(root *sitter.Node, src []byte) {
	count := make(map[string]int)
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		switch n.Type() {
		case javaNodeClassDeclaration, nodeAbstractClassDeclaration, nodeClassExpression:
			if name := nodeClassOwner(n, src); name != "" {
				count[name]++
			}
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(root)
	for name, n := range count {
		f.classes[name] = n == 1
	}
}

// nodeClassOwner names a class as extractClassMethods does: its own name, or
// the variable a class expression is bound to.
func nodeClassOwner(class *sitter.Node, src []byte) string {
	if name := class.ChildByFieldName("name"); name != nil {
		return name.Content(src)
	}
	if parent := class.Parent(); parent != nil && parent.Type() == nodeVariableDeclarator {
		if name := parent.ChildByFieldName("name"); name != nil && name.Type() == goNodeIdentifier {
			return name.Content(src)
		}
	}
	return ""
}

// resolveClass maps a type name written in this file to the class it names:
// one the file declares, or one a project module exports.
func (f *nodeFileTypes) resolveClass(name string) (nodeTypeRef, bool) {
	if binding, bound := f.bindings[name]; bound && binding.module != "" {
		if !f.project[name] {
			return nodeTypeRef{}, false
		}
		if binding.isDefault || binding.member == nodeDefaultKeyword {
			// The local name says nothing about the class the module exports
			// by default; the builder reads that from the module itself.
			return nodeTypeRef{pkg: binding.module, name: nodeDefaultKeyword}, true
		}
		pkg, last := binding.qualify()
		if last == "" {
			last = name
		}
		return nodeTypeRef{pkg: pkg, name: last}, true
	}
	if f.classes[name] {
		return nodeTypeRef{pkg: f.modulePath, name: name}, true
	}
	return nodeTypeRef{}, false
}

// nodeAnnotatedType returns the name of a plain annotated class type. A
// union, a generic, an `any` and a qualified name are not one, and the type
// they declare is not settled here.
func nodeAnnotatedType(n *sitter.Node, src []byte) string {
	if n != nil && n.Type() == nodeTypeAnnotation {
		if n.NamedChildCount() != 1 {
			return ""
		}
		n = n.NamedChild(0)
	}
	if n == nil || n.Type() != nodeTypeIdentifier {
		return ""
	}
	return n.Content(src)
}

func (f *nodeFileTypes) annotatedClass(n *sitter.Node, src []byte) (nodeTypeRef, bool) {
	name := nodeAnnotatedType(n, src)
	if name == "" {
		return nodeTypeRef{}, false
	}
	return f.resolveClass(name)
}

// collectFunctionNames records the functions the file declares at its top
// level by name. A name declared twice names none here; a function nested in
// another is no module function.
func (f *nodeFileTypes) collectFunctionNames(root *sitter.Node, src []byte) {
	count := make(map[string]int)
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		if n.Type() == nodeFunctionDeclaration {
			if name := n.ChildByFieldName("name"); name != nil {
				count[name.Content(src)]++
			}
		}
		if n != root && n.Type() != nodeExportKind {
			return
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(root)
	for name, n := range count {
		f.funcs[name] = n == 1
	}
}

// constructed returns the class `new X(..)` builds, when X is a class of this
// file or of a project module and no local variable shadows the name.
func (f *nodeFileTypes) constructed(expr *sitter.Node, src []byte, scope *nodeScope) (nodeTypeRef, bool) {
	constructor := expr.ChildByFieldName("constructor")
	if constructor == nil {
		return nodeTypeRef{}, false
	}
	switch constructor.Type() {
	case goNodeIdentifier:
		name := constructor.Content(src)
		if scope.declares(name) {
			return nodeTypeRef{}, false
		}
		return f.resolveClass(name)
	case nodeMemberExpression:
		object := constructor.ChildByFieldName("object")
		property := constructor.ChildByFieldName("property")
		if object == nil || property == nil {
			return nodeTypeRef{}, false
		}
		first, suffix := splitNodeMemberObject(object.Content(src))
		binding, bound := f.bindings.lookup(scope.localNames(), first)
		if !bound || !f.project[first] {
			return nodeTypeRef{}, false
		}
		pkg, name := binding.qualify(suffix, property.Content(src))
		return nodeTypeRef{pkg: pkg, name: name}, name != ""
	}
	return nodeTypeRef{}, false
}

func (s *nodeScope) declares(name string) bool {
	return s != nil && (s.own[name] || s.shadowed[name])
}

func (s *nodeScope) localNames() map[string]bool {
	if s == nil {
		return nil
	}
	if s.names == nil {
		s.names = make(map[string]bool, len(s.own)+len(s.shadowed))
		for name := range s.own {
			s.names[name] = true
		}
		for name := range s.shadowed {
			s.names[name] = true
		}
	}
	return s.names
}

// initializerType types the value a declaration, field or assignment stores:
// a constructor call, or a call to a function of the project, whose declared
// return class is read later.
func (f *nodeFileTypes) initializerType(value *sitter.Node, src []byte, scope *nodeScope) (nodeTypeRef, bool) {
	switch value.Type() {
	case nodeNewExpression:
		return f.constructed(value, src, scope)
	case nodeCallExpression:
		function := value.ChildByFieldName("function")
		if function == nil || function.Type() != goNodeIdentifier || scope.declares(function.Content(src)) {
			return nodeTypeRef{}, false
		}
		name := function.Content(src)
		if binding, bound := f.bindings[name]; bound && binding.module != "" {
			if !f.project[name] || binding.isDefault || binding.member == nodeDefaultKeyword {
				return nodeTypeRef{}, false
			}
			pkg, last := binding.qualify()
			if last == "" {
				last = name
			}
			return nodeTypeRef{pkg: pkg, name: last, viaReturn: true}, true
		}
		if f.funcs[name] {
			return nodeTypeRef{pkg: f.modulePath, name: name, viaReturn: true}, true
		}
	}
	return nodeTypeRef{}, false
}

// declaredVarTypes returns the class of each variable the code under body
// declares, for the parameters in params. A variable is typed only when every
// declaration of the name agrees and nothing rebinds it, anywhere in body, a
// nested function included. nested scopes' own declarations are theirs.
func (p *NodeParser) declaredVarTypes(params, body *sitter.Node, src []byte) map[string]nodeTypeRef {
	facts := newNodeTypeFacts()
	p.declaredParamTypes(params, src, facts)
	p.walkVarDeclarations(body, src, false, facts)
	return facts.types
}

// declaredParamTypes types the parameters that annotate a plain class. One
// that does not, or that destructures, gives its names no type.
func (p *NodeParser) declaredParamTypes(params *sitter.Node, src []byte, facts *nodeTypeFacts) {
	if params == nil {
		return
	}
	for i := 0; i < int(params.NamedChildCount()); i++ {
		param := params.NamedChild(i)
		pattern := param.ChildByFieldName("pattern")
		plain := (param.Type() == nodeRequiredParameter || param.Type() == nodeOptionalParameter) && pattern != nil && pattern.Type() == goNodeIdentifier
		if !plain {
			poisonNodePattern(param, src, facts)
			continue
		}
		ref, ok := p.file.annotatedClass(param.ChildByFieldName("type"), src)
		facts.set(pattern.Content(src), ref, ok)
	}
}

// walkVarDeclarations records each declaration under n and poisons each name
// something rebinds. A nested function's own declarations are its own, but an
// assignment inside it still rebinds the name outside.
func (p *NodeParser) walkVarDeclarations(n *sitter.Node, src []byte, nested bool, facts *nodeTypeFacts) {
	if n == nil {
		return
	}
	nested = nested || isNodeNestedScope(n.Type())
	switch n.Type() {
	case nodeVariableDeclarator:
		if !nested {
			p.declareVarType(n, src, facts)
		}
	case nodeAssignmentExpression, "augmented_assignment_expression":
		poisonNodePattern(n.ChildByFieldName("left"), src, facts)
	case nodeForInStatement:
		if !nested {
			poisonNodePattern(n.ChildByFieldName("left"), src, facts)
		}
	case javaNodeCatchClause:
		if !nested {
			poisonNodePattern(n.ChildByFieldName("parameter"), src, facts)
		}
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		p.walkVarDeclarations(n.NamedChild(i), src, nested, facts)
	}
}

func (p *NodeParser) declareVarType(declarator *sitter.Node, src []byte, facts *nodeTypeFacts) {
	name := declarator.ChildByFieldName("name")
	if name == nil {
		return
	}
	if name.Type() != goNodeIdentifier {
		poisonNodePattern(name, src, facts)
		return
	}
	var (
		ref nodeTypeRef
		ok  bool
	)
	if annotation := declarator.ChildByFieldName("type"); annotation != nil {
		ref, ok = p.file.annotatedClass(annotation, src)
	} else if value := declarator.ChildByFieldName("value"); value != nil {
		ref, ok = p.file.initializerType(value, src, p.scope)
	}
	facts.set(name.Content(src), ref, ok)
}

// poisonNodePattern drops every name a binding or assignment target writes.
// A member target such as `this.f` writes no variable.
func poisonNodePattern(n *sitter.Node, src []byte, facts *nodeTypeFacts) {
	if n == nil {
		return
	}
	switch n.Type() {
	case goNodeIdentifier, nodeShorthandPattern, "shorthand_property_identifier":
		facts.poison(n.Content(src))
		return
	case nodeMemberExpression, "subscript_expression":
		return
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		poisonNodePattern(n.NamedChild(i), src, facts)
	}
}

// scopeFor builds the typing context of a function from its parameters and
// body. Names a declaration rebinds in a way the facts cannot follow are kept
// in shadowed, so a module variable of the same name is not read in their
// place.
func (p *NodeParser) scopeFor(params, body *sitter.Node, own map[string]bool, src []byte) *nodeScope {
	if p.file == nil {
		return nil
	}
	scope := &nodeScope{own: own, shadowed: make(map[string]bool)}
	collectNodeWrittenNames(params, src, scope.shadowed)
	collectNodeWrittenNames(body, src, scope.shadowed)
	if body != nil {
		if single := body.Parent().ChildByFieldName("parameter"); single != nil && single.Type() == goNodeIdentifier {
			scope.shadowed[single.Content(src)] = true
		}
		collectEnclosingFunctionNames(body.Parent(), src, scope.shadowed)
	}
	previous := p.scope
	p.scope = scope
	defer func() { p.scope = previous }()
	scope.vars = p.declaredVarTypes(params, body, src)
	return scope
}

// collectEnclosingFunctionNames adds every name a function around n declares:
// its parameters and variables. A nested function reads such a name from the
// enclosing function, never from the module, so it is shadowed there; its type
// is not followed.
func collectEnclosingFunctionNames(n *sitter.Node, src []byte, into map[string]bool) {
	for outer := n.Parent(); outer != nil; outer = outer.Parent() {
		switch outer.Type() {
		case nodeFunctionDeclaration, nodeGeneratorDeclaration, "generator_function", nodeArrowFunction, nodeFunctionExpression, nodeMethodDefinition:
		default:
			continue
		}
		params := outer.ChildByFieldName("parameters")
		body := outer.ChildByFieldName("body")
		for name := range collectNodeLocalNames(params, body, src) {
			into[name] = true
		}
		collectNodeWrittenNames(params, src, into)
		collectNodeWrittenNames(body, src, into)
		if single := outer.ChildByFieldName("parameter"); single != nil && single.Type() == goNodeIdentifier {
			into[single.Content(src)] = true
		}
	}
}

// collectNodeWrittenNames adds the names a destructuring declaration, a loop
// head or a catch clause binds, which collectNodeLocalNames does not see.
func collectNodeWrittenNames(n *sitter.Node, src []byte, into map[string]bool) {
	if n == nil {
		return
	}
	facts := newNodeTypeFacts()
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		switch n.Type() {
		case nodeVariableDeclarator:
			if name := n.ChildByFieldName("name"); name != nil && name.Type() != goNodeIdentifier {
				poisonNodePattern(name, src, facts)
			}
		case nodeForInStatement:
			poisonNodePattern(n.ChildByFieldName("left"), src, facts)
		case javaNodeCatchClause:
			poisonNodePattern(n.ChildByFieldName("parameter"), src, facts)
		}
		if isNodeNestedScope(n.Type()) {
			return
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(n)
	for name := range facts.poisoned {
		into[name] = true
	}
}

// varType returns the declared class of a bare variable in the current scope:
// a local, or else a module variable.
func (p *NodeParser) varType(name string) (nodeTypeRef, bool) {
	if p.scope != nil {
		if ref, ok := p.scope.vars[name]; ok {
			return ref, true
		}
		if p.scope.declares(name) {
			return nodeTypeRef{}, false
		}
	}
	if binding, bound := p.file.bindings[name]; bound && binding.module != "" {
		return nodeTypeRef{}, false
	}
	ref, ok := p.file.moduleVars[name]
	return ref, ok
}

// receiverType returns the class an expression is declared to be an instance
// of.
func (p *NodeParser) receiverType(expr *sitter.Node, src []byte, owner string) (nodeTypeRef, bool) {
	if p.file == nil || expr == nil {
		return nodeTypeRef{}, false
	}
	switch expr.Type() {
	case rustNodeParenthesizedExpression, "non_null_expression":
		if expr.NamedChildCount() == 1 {
			return p.receiverType(expr.NamedChild(0), src, owner)
		}
	case goNodeIdentifier:
		return p.varType(expr.Content(src))
	case nodeNewExpression, nodeCallExpression:
		return p.file.initializerType(expr, src, p.scope)
	case nodeMemberExpression:
		object := expr.ChildByFieldName("object")
		property := expr.ChildByFieldName("property")
		if owner == "" || object == nil || property == nil || object.Type() != javaThisKeyword {
			return nodeTypeRef{}, false
		}
		name := property.Content(src)
		ref, ok := p.file.fields[owner][name]
		if ok && p.file.inferredFields[owner][name] {
			ref.inferredField = name
		}
		return ref, ok
	}
	return nodeTypeRef{}, false
}

// typeNodeReceiver points `x.m()` at the method m of x's declared class, unless
// the receiver is an import, which the call's package already names.
func (p *NodeParser) typeNodeReceiver(call *FunctionCall, object *sitter.Node, src []byte, owner string, imported bool) {
	if imported || call.Callee.Type != "" {
		return
	}
	ref, ok := p.receiverType(object, src, owner)
	switch {
	case !ok:
	case ref.viaReturn:
		call.nodeReturnOf = FunctionID{Package: ref.pkg, Name: ref.name}
	default:
		if ref.name == nodeDefaultKeyword || ref.inferredField != "" {
			call.nodeUntyped = call.Callee
			call.nodeInferredField = ref.inferredField
		}
		call.Callee = FunctionID{Package: ref.pkg, Type: ref.name, Name: call.Callee.Name}
	}
}

// markImportedInstance names the export a call's receiver imports from a
// project module, as `module.name` for a named export and `module.default`
// for the default one. The builder replaces the callee when that export is an
// instance of a class.
func (p *NodeParser) markImportedInstance(call *FunctionCall, binding nodeBinding, first, suffix string) {
	if p.file == nil || !p.file.project[first] {
		return
	}
	call.nodeInstanceKey = call.Callee.Package
	if suffix == "" && (binding.isDefault || binding.member == nodeDefaultKeyword) {
		call.nodeInstanceKey = binding.module + "." + nodeDefaultKeyword
	}
}

// collectFields records the declared class of each instance field of each
// class: an annotation, else the one class every initialiser and `this.f =`
// assignment constructs, constructor parameter properties included.
func (f *nodeFileTypes) collectFields(p *NodeParser, root *sitter.Node, src []byte) {
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		switch n.Type() {
		case javaNodeClassDeclaration, nodeAbstractClassDeclaration, nodeClassExpression:
			if owner := nodeClassOwner(n, src); owner != "" && f.classes[owner] {
				f.fields[owner] = p.classFieldTypes(n, src)
			}
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(root)
}

func (p *NodeParser) classFieldTypes(class *sitter.Node, src []byte) map[string]nodeTypeRef {
	body := class.ChildByFieldName("body")
	if body == nil {
		return nil
	}
	f := p.file
	declared := make(map[string]nodeTypeRef)
	hasAnnotation := make(map[string]bool)
	inferred := newNodeTypeFacts()
	ctorParams := make(map[string]nodeTypeRef)
	for i := 0; i < int(body.NamedChildCount()); i++ {
		member := body.NamedChild(i)
		switch member.Type() {
		case nodePublicFieldDefinition, nodeFieldDefinition:
			p.recordFieldDefinition(member, src, declared, hasAnnotation, inferred)
		case nodeMethodDefinition:
			if name := member.ChildByFieldName("name"); name != nil && name.Content(src) == nodeConstructorKeyword {
				recordConstructorParams(f, member, src, declared, hasAnnotation, ctorParams)
			}
		}
	}
	// Every `this.f = value` in the class, wherever it sits, is one more
	// declaration of f. Only the constructor's own parameters name a type.
	for i := 0; i < int(body.NamedChildCount()); i++ {
		member := body.NamedChild(i)
		params := map[string]nodeTypeRef(nil)
		if name := member.ChildByFieldName("name"); member.Type() == nodeMethodDefinition && name != nil && name.Content(src) == nodeConstructorKeyword {
			params = ctorParams
		}
		p.recordFieldAssignments(member, src, params, inferred)
	}
	fields, inferredNames := mergeFieldTypes(declared, hasAnnotation, inferred)
	f.inferredFields[nodeClassOwner(class, src)] = inferredNames
	return fields
}

// mergeFieldTypes settles each field's type: an annotation wins over what an
// initialiser infers, and an annotated field of no plain class has none. It
// also names the fields whose type was only inferred.
func mergeFieldTypes(declared map[string]nodeTypeRef, hasAnnotation map[string]bool, inferred *nodeTypeFacts) (fields map[string]nodeTypeRef, inferredNames map[string]bool) {
	fields = make(map[string]nodeTypeRef, len(declared)+len(inferred.types))
	inferredNames = make(map[string]bool, len(inferred.types))
	for name, ref := range inferred.types {
		fields[name] = ref
		inferredNames[name] = !hasAnnotation[name]
	}
	for name, ref := range declared {
		fields[name] = ref
		inferredNames[name] = false
	}
	for name := range hasAnnotation {
		if _, ok := declared[name]; !ok {
			delete(fields, name)
		}
	}
	return fields, inferredNames
}

func (p *NodeParser) recordFieldDefinition(member *sitter.Node, src []byte, declared map[string]nodeTypeRef, hasAnnotation map[string]bool, inferred *nodeTypeFacts) {
	nameNode := member.ChildByFieldName("name")
	if nameNode == nil {
		nameNode = member.ChildByFieldName("property")
	}
	if nameNode == nil {
		return
	}
	name := nameNode.Content(src)
	if hasNodeToken(member, "static") {
		// Reached as `Class.f`, never as `this.f`; `this.f` is then not it.
		inferred.poison(name)
		hasAnnotation[name] = true
		return
	}
	if annotation := member.ChildByFieldName("type"); annotation != nil {
		hasAnnotation[name] = true
		if ref, ok := p.file.annotatedClass(annotation, src); ok {
			declared[name] = ref
		}
		return
	}
	if value := member.ChildByFieldName("value"); value != nil {
		ref, ok := p.file.initializerType(value, src, nil)
		inferred.set(name, ref, ok)
		return
	}
}

func recordConstructorParams(f *nodeFileTypes, ctor *sitter.Node, src []byte, declared map[string]nodeTypeRef, hasAnnotation map[string]bool, ctorParams map[string]nodeTypeRef) {
	params := ctor.ChildByFieldName("parameters")
	if params == nil {
		return
	}
	for i := 0; i < int(params.NamedChildCount()); i++ {
		param := params.NamedChild(i)
		pattern := param.ChildByFieldName("pattern")
		if (param.Type() != nodeRequiredParameter && param.Type() != nodeOptionalParameter) || pattern == nil || pattern.Type() != goNodeIdentifier {
			continue
		}
		name := pattern.Content(src)
		ref, ok := f.annotatedClass(param.ChildByFieldName("type"), src)
		if ok {
			ctorParams[name] = ref
		}
		if hasNodeChildType(param, "accessibility_modifier") || hasNodeToken(param, "readonly") {
			hasAnnotation[name] = true
			if ok {
				declared[name] = ref
			}
		}
	}
}

func (p *NodeParser) recordFieldAssignments(n *sitter.Node, src []byte, ctorParams map[string]nodeTypeRef, inferred *nodeTypeFacts) {
	if n.Type() == nodeAssignmentExpression {
		p.recordFieldAssignment(n, src, ctorParams, inferred)
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		p.recordFieldAssignments(n.NamedChild(i), src, ctorParams, inferred)
	}
}

func (p *NodeParser) recordFieldAssignment(assign *sitter.Node, src []byte, ctorParams map[string]nodeTypeRef, inferred *nodeTypeFacts) {
	left := assign.ChildByFieldName("left")
	right := assign.ChildByFieldName("right")
	if left == nil || right == nil || left.Type() != nodeMemberExpression {
		return
	}
	object := left.ChildByFieldName("object")
	property := left.ChildByFieldName("property")
	if object == nil || property == nil || object.Type() != javaThisKeyword {
		return
	}
	name := property.Content(src)
	if right.Type() == goNodeIdentifier {
		if ref, ok := ctorParams[right.Content(src)]; ok {
			inferred.set(name, ref, true)
			return
		}
	}
	ref, ok := p.file.initializerType(right, src, nil)
	inferred.set(name, ref, ok)
}

func hasNodeToken(n *sitter.Node, token string) bool {
	for i := 0; i < int(n.ChildCount()); i++ {
		if child := n.Child(i); !child.IsNamed() && child.Type() == token {
			return true
		}
	}
	return false
}

func hasNodeChildType(n *sitter.Node, nodeType string) bool {
	for i := 0; i < int(n.NamedChildCount()); i++ {
		if n.NamedChild(i).Type() == nodeType {
			return true
		}
	}
	return false
}

// collectInstances records the module-level instances the file exports:
// `export const x = new X()`, `export default new X()` and `export default x`
// for a module variable of known class. A `let` export can be rebound by an
// importer's module and is left out.
func (f *nodeFileTypes) collectInstances(root *sitter.Node, src []byte) {
	for i := 0; i < int(root.NamedChildCount()); i++ {
		export := root.NamedChild(i)
		if export.Type() != nodeExportKind {
			continue
		}
		if decl := export.ChildByFieldName("declaration"); decl != nil {
			f.exportDeclaredInstances(decl, src)
			if hasNodeToken(export, nodeDefaultKeyword) {
				f.recordDefaultClass(nodeClassOwnerOf(decl, src))
			}
			continue
		}
		value := export.ChildByFieldName("value")
		if value == nil {
			continue
		}
		if value.Type() == goNodeIdentifier {
			f.recordDefaultClass(value.Content(src))
		}
		var ref nodeTypeRef
		var ok bool
		switch value.Type() {
		case nodeNewExpression:
			ref, ok = f.constructed(value, src, nil)
		case goNodeIdentifier:
			ref, ok = f.moduleVars[value.Content(src)]
		}
		if ok && !ref.viaReturn {
			f.instances[nodeDefaultKeyword] = FunctionID{Package: ref.pkg, Type: ref.name}
		}
	}
}

// nodeClassOwnerOf names the class a declaration declares, or "" for another
// declaration.
func nodeClassOwnerOf(decl *sitter.Node, src []byte) string {
	switch decl.Type() {
	case javaNodeClassDeclaration, nodeAbstractClassDeclaration:
		if name := decl.ChildByFieldName("name"); name != nil {
			return name.Content(src)
		}
	}
	return ""
}

func (f *nodeFileTypes) recordDefaultClass(name string) {
	if name != "" && f.classes[name] {
		f.defaultClass = FunctionID{Package: f.modulePath, Type: name}
	}
}

// collectAssignedProps records each property written on an object other than
// `this`: any such write may replace the value of a class field of that name.
func (f *nodeFileTypes) collectAssignedProps(root *sitter.Node, src []byte) {
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		switch n.Type() {
		case nodeAssignmentExpression, "augmented_assignment_expression":
			if left := n.ChildByFieldName("left"); left != nil && left.Type() == nodeMemberExpression {
				object := left.ChildByFieldName("object")
				property := left.ChildByFieldName("property")
				if object != nil && property != nil && object.Type() != javaThisKeyword {
					f.assignedProps[property.Content(src)] = true
				}
			}
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(root)
}

func (f *nodeFileTypes) exportDeclaredInstances(decl *sitter.Node, src []byte) {
	if decl.Type() != "lexical_declaration" || !hasNodeToken(decl, "const") {
		return
	}
	for i := 0; i < int(decl.NamedChildCount()); i++ {
		declarator := decl.NamedChild(i)
		if declarator.Type() != nodeVariableDeclarator {
			continue
		}
		name := declarator.ChildByFieldName("name")
		if name == nil || name.Type() != goNodeIdentifier {
			continue
		}
		if ref, ok := f.moduleVars[name.Content(src)]; ok && !ref.viaReturn {
			f.instances[name.Content(src)] = FunctionID{Package: ref.pkg, Type: ref.name}
		}
	}
}

// nodeModuleInstance is an exported instance in the graph's index. A module
// path two files share is ambiguous and resolves to nothing.
type nodeModuleInstance struct {
	class     FunctionID
	ambiguous bool
}

// mergeNodeFileFacts folds what one Node file declares about the classes it
// exports and the properties it writes into the graph.
func mergeNodeFileFacts(graph *CallGraph, analysis *FileAnalysis) {
	mergeNodeInstances(graph, analysis)
	for name := range analysis.nodeAssignedProps {
		if graph.nodeAssignedProps == nil {
			graph.nodeAssignedProps = make(map[string]bool)
		}
		graph.nodeAssignedProps[name] = true
	}
	if analysis.nodeDefaultClass != (FunctionID{}) {
		if graph.nodeDefaultClasses == nil {
			graph.nodeDefaultClasses = make(map[string]nodeModuleInstance)
		}
		module := nodeModulePath(analysis.PackagePath, analysis.FilePath)
		if existing, seen := graph.nodeDefaultClasses[module]; seen && existing.class != analysis.nodeDefaultClass {
			graph.nodeDefaultClasses[module] = nodeModuleInstance{ambiguous: true}
		} else {
			graph.nodeDefaultClasses[module] = nodeModuleInstance{class: analysis.nodeDefaultClass}
		}
	}
	for _, owner := range analysis.nodeSupertypeOwners {
		if graph.nodeClassOwners == nil {
			graph.nodeClassOwners = make(map[string]bool)
		}
		graph.nodeClassOwners[normalizeHierarchyName(owner)] = true
	}
}

func mergeNodeInstances(graph *CallGraph, analysis *FileAnalysis) {
	if len(analysis.nodeInstances) == 0 {
		return
	}
	if graph.nodeInstances == nil {
		graph.nodeInstances = make(map[string]nodeModuleInstance)
	}
	module := nodeModulePath(analysis.PackagePath, analysis.FilePath)
	for name, class := range analysis.nodeInstances {
		key := module + "." + name
		if existing, seen := graph.nodeInstances[key]; seen && existing.class != class {
			graph.nodeInstances[key] = nodeModuleInstance{ambiguous: true}
			continue
		}
		graph.nodeInstances[key] = nodeModuleInstance{class: class}
	}
}

// resolveNodeTypedReceivers completes the receivers the parser could type only
// from another module: a call on an imported singleton, and a call on a value
// that a function of the project returns. It runs before the caller index is
// built.
func resolveNodeTypedReceivers(graph *CallGraph) {
	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			call := &fn.Calls[i]
			if class, ok := nodeReceiverClass(graph, call); ok {
				call.Callee = FunctionID{Package: class.Package, Type: class.Type, Name: call.Callee.Name}
				continue
			}
			if call.nodeUntyped == (FunctionID{}) {
				continue
			}
			if class, ok := graph.nodeDeclaredClass(call.Callee); ok && !graph.nodeFieldReassigned(call) {
				call.Callee = FunctionID{Package: class.Package, Type: class.Type, Name: call.Callee.Name}
			} else {
				call.Callee = call.nodeUntyped
			}
		}
	}
}

// nodeReceiverClass is the class a call's receiver is declared to be: the
// class of the instance its imported module exports, or the return class the
// function that produced it declares.
func nodeReceiverClass(graph *CallGraph, call *FunctionCall) (FunctionID, bool) {
	if call.nodeInstanceKey != "" {
		if instance, ok := graph.nodeInstances[call.nodeInstanceKey]; ok && !instance.ambiguous {
			return graph.nodeDeclaredClass(instance.class)
		}
	}
	if call.nodeReturnOf != (FunctionID{}) {
		if decl := graph.Functions[call.nodeReturnOf.String()]; decl != nil && decl.nodeReturnClass.Type != "" {
			return graph.nodeDeclaredClass(decl.nodeReturnClass)
		}
	}
	return FunctionID{}, false
}

// nodeDeclaredClass turns the class a Node type names into the class itself.
// The default export of a module names the class that module declares as
// default, whatever an importer calls it; a module with no such class, or with
// two files claiming its path, names none.
func (g *CallGraph) nodeDeclaredClass(class FunctionID) (FunctionID, bool) {
	if class.Type != nodeDefaultKeyword {
		return class, class.Type != ""
	}
	exported, ok := g.nodeDefaultClasses[class.Package]
	if !ok || exported.ambiguous {
		return FunctionID{}, false
	}
	return exported.class, true
}

// nodeFieldReassigned reports whether a call typed from an unannotated field
// has that field written somewhere outside the class, in any scanned module.
func (g *CallGraph) nodeFieldReassigned(call *FunctionCall) bool {
	return call.nodeInferredField != "" && g.nodeAssignedProps[call.nodeInferredField]
}

// recordNodeSupertypes records a class's direct supertypes, each resolved
// through the file's imports to the module that declares it, so a library's
// `Base` is never taken for a project class of the same name. A base the file
// does not resolve to a class stays unresolvable, so the ancestry reads as only
// partly recorded. A class with no base is recorded only when it owns no
// function declaration, such as an abstract class whose methods are all
// abstract, so a call typed as it still reaches its subclasses' overrides.
func (p *NodeParser) recordNodeSupertypes(class *sitter.Node, src []byte, modulePath, owner string, first int, analysis *FileAnalysis) {
	if p.file == nil || !p.file.classes[owner] {
		return
	}
	bases := p.file.resolvedClassBases(class, src)
	if len(bases) == 0 && len(analysis.Functions) > first {
		return
	}
	if analysis.Supertypes == nil {
		analysis.Supertypes = make(map[string][]string)
	}
	key := modulePath + "." + owner
	analysis.Supertypes[key] = append([]string{}, bases...)
	analysis.nodeSupertypeOwners = append(analysis.nodeSupertypeOwners, key)
}

// resolvedClassBases lists the classes a heritage clause names as
// `module.Class`, or the unresolvable marker for a base that is not a plain
// reference to a class of the file or of a project module.
func (f *nodeFileTypes) resolvedClassBases(class *sitter.Node, src []byte) []string {
	var bases []string
	var collect func(n *sitter.Node)
	collect = func(n *sitter.Node) {
		switch n.Type() {
		case goNodeIdentifier, nodeTypeIdentifier:
			bases = append(bases, f.resolveBase(n.Content(src), "", ""))
		case nodeMemberExpression, nodeNestedTypeIdentifier:
			bases = append(bases, f.resolveQualifiedBase(n.Content(src)))
		case javaNodeGenericType:
			if n.NamedChildCount() > 0 {
				collect(n.NamedChild(0))
			}
		case nodeClassHeritage, "implements_clause", "extends_clause":
			for _, child := range heritageTargets(n) {
				collect(child)
			}
		default:
			bases = append(bases, javaUnresolvableSupertype)
		}
	}
	for i := 0; i < int(class.NamedChildCount()); i++ {
		if child := class.NamedChild(i); child.Type() == nodeClassHeritage {
			collect(child)
		}
	}
	return bases
}

// heritageTargets lists the nodes of a heritage clause that name a class: the
// value of an `extends` clause, without its type arguments, or each named child
// of the other clauses.
func heritageTargets(clause *sitter.Node) []*sitter.Node {
	if value := clause.ChildByFieldName("value"); value != nil {
		return []*sitter.Node{value}
	}
	var targets []*sitter.Node
	for i := 0; i < int(clause.NamedChildCount()); i++ {
		if child := clause.NamedChild(i); child.Type() != "type_arguments" {
			targets = append(targets, child)
		}
	}
	return targets
}

// resolveQualifiedBase resolves `ns.Name`, written as a base, through a
// namespace import of a project module.
func (f *nodeFileTypes) resolveQualifiedBase(text string) string {
	text = strings.TrimSpace(text)
	dot := strings.LastIndex(text, ".")
	if dot < 0 || strings.ContainsAny(text, "()[]<> ") {
		return javaUnresolvableSupertype
	}
	first, suffix := splitNodeMemberObject(text[:dot])
	return f.resolveBase(first, suffix, text[dot+1:])
}

// resolveBase names the class a base reference denotes: a bare name resolves as
// a type does, and `ns.Name` through a namespace import of a project module.
func (f *nodeFileTypes) resolveBase(first, suffix, last string) string {
	if last == "" {
		ref, ok := f.resolveClass(first)
		if !ok || ref.name == nodeDefaultKeyword {
			return javaUnresolvableSupertype
		}
		binding, bound := f.bindings[first]
		if bound && binding.module != "" && binding.member == "" {
			// A namespace or `require` binding is a module, not a class.
			return javaUnresolvableSupertype
		}
		return ref.pkg + "." + ref.name
	}
	binding, bound := f.bindings[first]
	if !bound || !f.project[first] || binding.isDefault || binding.member == nodeDefaultKeyword {
		return javaUnresolvableSupertype
	}
	pkg, name := binding.qualify(suffix, last)
	if name == "" {
		return javaUnresolvableSupertype
	}
	return pkg + "." + name
}
