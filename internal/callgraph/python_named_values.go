// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

const (
	pythonFieldName  = "name"
	pythonStrType    = "str"
	pythonEnumModule = "enum"
)

// recordPythonNamedValues records the module's string constants under
// `<module>.NAME` and the string members of its module-level Enum classes
// under `<module>.Cls.M.value` and `.name`, plus `<module>.Cls.M` itself when
// the enum is a str subclass, whose members are the strings.
func recordPythonNamedValues(root *sitter.Node, src []byte, analysis *FileAnalysis, fw *pythonFileWalk) {
	if fw.moduleSources.all {
		return
	}
	module := analysis.PackagePath
	for name, e := range fw.moduleSources.byName {
		if e.poisoned || e.value == nil || e.value.Symbol() != pythonSyms.string {
			continue
		}
		recordNamedValue(analysis, module+"."+name, NamedValue{
			Value:        e.text,
			DeclaredType: pythonStrType,
			FilePath:     analysis.FilePath,
			Line:         int(e.value.StartPoint().Row) + 1,
		})
	}
	for i := 0; i < int(root.NamedChildCount()); i++ {
		class := root.NamedChild(i)
		if class.Symbol() == pythonSyms.decoratedDefinition {
			class = class.ChildByFieldName("definition")
		}
		if class == nil || class.Symbol() != pythonSyms.classDefinition {
			continue
		}
		nameNode := class.ChildByFieldName(pythonFieldName)
		if nameNode == nil || !fw.moduleSources.boundOnlyBy(nameNode.Content(src), pythonBoundClass) {
			continue
		}
		isEnum, strValued := pythonEnumKind(class, src, analysis)
		if isEnum {
			recordPythonEnumMembers(class, src, analysis, module+"."+nameNode.Content(src), strValued)
		}
	}
}

// pythonEnumKind admits a class whose bases are only enum.Enum,
// enum.StrEnum and str. Any other base may redefine what a member is.
func pythonEnumKind(class *sitter.Node, src []byte, analysis *FileAnalysis) (isEnum, strValued bool) {
	supers := class.ChildByFieldName("superclasses")
	if supers == nil {
		return false, false
	}
	str := false
	for i := 0; i < int(supers.NamedChildCount()); i++ {
		switch pythonEnumBaseName(supers.NamedChild(i), src, analysis) {
		case pythonStrType:
			str = true
		case "Enum":
			isEnum = true
		case "StrEnum":
			isEnum, str = true, true
		default:
			return false, false
		}
	}
	return isEnum, isEnum && str
}

func pythonEnumBaseName(base *sitter.Node, src []byte, analysis *FileAnalysis) string {
	text := base.Content(src)
	switch base.Symbol() {
	case pythonSyms.identifier:
		if _, imported := analysis.Imports[text]; !imported && text == pythonStrType {
			return text
		}
		if analysis.Imports[text] == pythonEnumModule && analysis.FromImports[text] {
			return pythonImportedName(analysis, text)
		}
	case pythonSyms.attribute:
		module, member, _ := strings.Cut(text, ".")
		if analysis.Imports[module] == pythonEnumModule && !analysis.FromImports[module] {
			return member
		}
	}
	return ""
}

// recordPythonEnumMembers records each member the class body binds exactly
// once to a plain string. A member whose value repeats an earlier one is an
// alias, and its name is the earlier member's.
func recordPythonEnumMembers(class *sitter.Node, src []byte, analysis *FileAnalysis, owner string, strValued bool) {
	canonical := make(map[string]string)
	for _, assign := range pythonEnumMemberAssignments(class.ChildByFieldName("body"), src) {
		name := assign.ChildByFieldName("left").Content(src)
		right := assign.ChildByFieldName("right")
		if strings.HasPrefix(name, "_") || right == nil || right.Symbol() != pythonSyms.string || !pythonPlainString(right, src) {
			continue
		}
		literal := right.Content(src)
		value := literal[1 : len(literal)-1]
		if _, ok := canonical[value]; !ok {
			canonical[value] = name
		}
		decl := NamedValue{Value: literal, DeclaredType: pythonStrType, FilePath: analysis.FilePath, Line: int(assign.StartPoint().Row) + 1}
		decl.fixedUnder = owner
		key := owner + "." + name
		recordNamedValue(analysis, key+".value", decl)
		if strValued {
			recordNamedValue(analysis, key, decl)
		}
		decl.Value = `"` + canonical[value] + `"`
		recordNamedValue(analysis, key+".name", decl)
	}
}

// pythonEnumMemberAssignments returns the `NAME = value` statements of a class
// body whose name nothing else in the body binds.
func pythonEnumMemberAssignments(body *sitter.Node, src []byte) []*sitter.Node {
	if body == nil {
		return nil
	}
	bindings := make(map[string]int)
	var assigns []*sitter.Node
	for i := 0; i < int(body.NamedChildCount()); i++ {
		name, assign := pythonClassBodyBinding(body.NamedChild(i), src)
		if name != "" {
			bindings[name]++
		}
		if assign != nil {
			assigns = append(assigns, assign)
		}
	}
	members := assigns[:0]
	for _, assign := range assigns {
		if bindings[assign.ChildByFieldName("left").Content(src)] == 1 {
			members = append(members, assign)
		}
	}
	return members
}

// pythonClassBodyBinding returns the name a class-body statement binds, with
// the assignment when it is a plain `NAME = value`.
func pythonClassBodyBinding(stmt *sitter.Node, src []byte) (string, *sitter.Node) {
	if stmt.Symbol() == pythonSyms.decoratedDefinition {
		stmt = stmt.ChildByFieldName("definition")
	}
	if stmt == nil {
		return "", nil
	}
	switch stmt.Symbol() {
	case pythonSyms.functionDefinition, pythonSyms.classDefinition:
		if name := stmt.ChildByFieldName(pythonFieldName); name != nil {
			return name.Content(src), nil
		}
	case pythonSyms.expressionStatement:
		if stmt.NamedChildCount() != 1 || stmt.NamedChild(0).Symbol() != pythonSyms.assignment {
			return "", nil
		}
		assign := stmt.NamedChild(0)
		if left := assign.ChildByFieldName("left"); left != nil && left.Symbol() == pythonSyms.identifier {
			return left.Content(src), assign
		}
	}
	return "", nil
}

// pythonNamedValueSource emits a placeholder for a name or dotted name that
// may denote a NamedValue of another module (or an Enum member of this one),
// which the post-parse fold resolves or drops.
func pythonNamedValueSource(argNode *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, bindings pythonBindings, fw *pythonFileWalk) []SourceNode {
	expr := argNode.Content(src)
	ref := pythonNamedValueRef(expr, analysis, bindings, fw)
	if ref == nil {
		return nil
	}
	return []SourceNode{{
		Type:     "EXPRESSION",
		Value:    expr,
		Location: &SourceLocation{FilePath: filePath, Line: int(argNode.StartPoint().Row) + 1},
		nameRef:  ref,
	}}
}

// pythonNamedValueRef keys expr by the module its first name binds: a
// from-import names `<module>.<original>`, a module import names the module,
// and a class of this module names `<this module>.<class>`. A first name the
// module binds more than once, or the enclosing function binds at all,
// resolves to nothing.
func pythonNamedValueRef(expr string, analysis *FileAnalysis, bindings pythonBindings, fw *pythonFileWalk) *nameRef {
	for _, segment := range strings.Split(expr, ".") {
		if !isSimplePythonIdentifier(segment) {
			return nil
		}
	}
	first, rest, dotted := strings.Cut(expr, ".")
	if _, known := bindings.locals.lookup(first); known || pythonNameLocallyShadowed(bindings, fw, first) {
		return nil
	}
	key, imported := pythonImportKey(first, analysis)
	switch {
	case imported && fw.moduleSources.boundOnlyBy(first, pythonBoundImport):
		if !dotted && !analysis.FromImports[first] {
			return nil
		}
	case !imported && dotted && fw.moduleSources.boundOnlyBy(first, pythonBoundClass):
		key = analysis.PackagePath + "." + first
	default:
		return nil
	}
	if dotted {
		key += "." + rest
	}
	return &nameRef{expr: expr, tiers: [][]string{{key}}, placeholder: true}
}

// pythonImportKey is the key of what an imported name binds: a from-import
// names `<module>.<original>`, a module import the module.
func pythonImportKey(name string, analysis *FileAnalysis) (string, bool) {
	module, imported := analysis.Imports[name]
	if !imported {
		return "", false
	}
	if analysis.FromImports[name] {
		return module + "." + pythonImportedName(analysis, name), true
	}
	return module, true
}

// pythonImportUse is a use of an imported name that may change a value of
// the module it imports: path is the attribute chain after the name.
type pythonImportUse struct {
	root, path  string
	membersOnly bool
}

// notePythonImportUse records what a use of an imported name may change in
// another module: the attribute chain it assigns or deletes, or, when the name
// or a chain from it is taken as a value (passed, aliased, returned, stored),
// any member of the object that names. A subscript or dunder step (`s[k]`,
// `s.__dict__`) widens the use to every member before that step. Reading a
// string this way changes nothing, since a string has no members.
func (fw *pythonFileWalk) notePythonImportUse(node *sitter.Node, src []byte, analysis *FileAnalysis) {
	root := node.Content(src)
	if _, imported := analysis.Imports[root]; !imported || !pythonNameRead(node) {
		return
	}
	var path []string
	top := node
	for parent := top.Parent(); parent != nil; parent = top.Parent() {
		sym := parent.Symbol()
		if sym == pythonSyms.subscript && sameSyntaxNode(parent.ChildByFieldName("value"), top) {
			fw.addImportUse(root, path, true)
			return
		}
		if sym != pythonSyms.attribute || !sameSyntaxNode(parent.ChildByFieldName("object"), top) {
			break
		}
		attr := parent.ChildByFieldName("attribute").Content(src)
		if strings.HasPrefix(attr, "__") {
			fw.addImportUse(root, path, true)
			return
		}
		path = append(path, attr)
		top = parent
	}
	if parent := top.Parent(); parent != nil && parent.Symbol() == pythonSyms.call && sameSyntaxNode(parent.ChildByFieldName("function"), top) {
		return
	}
	written := pythonWriteTarget(top)
	if written && len(path) == 0 {
		return
	}
	fw.addImportUse(root, path, !written)
}

func (fw *pythonFileWalk) addImportUse(root string, path []string, membersOnly bool) {
	if fw.importUses == nil {
		fw.importUses = make(map[pythonImportUse]bool)
	}
	fw.importUses[pythonImportUse{root: root, path: strings.Join(path, "."), membersOnly: membersOnly}] = true
}

// pythonNameRead reports an identifier that reads a name, as opposed to an
// attribute's member name or what a statement binds or declares: an import, a
// parameter, a keyword argument's name, a def or class name, a global or
// nonlocal.
func pythonNameRead(node *sitter.Node) bool {
	parent := node.Parent()
	if parent == nil {
		return false
	}
	switch parent.Type() {
	case pythonNodeAttribute:
		return sameSyntaxNode(parent.ChildByFieldName("object"), node)
	case pythonNodeDottedName, pythonNodeAliasedImport, pythonNodeRelativeImport, pythonNodeParameters, "lambda_parameters",
		pythonNodeTypedParameter, pythonNodeListSplatPattern, pythonNodeDictSplatPattern, "global_statement", "nonlocal_statement", "as_pattern_target":
		return false
	case pythonKeywordArgument, pythonNodeDefaultParameter, pythonNodeTypedDefaultParam, pythonNodeFunctionDefinition, pythonNodeClassDefinition:
		return !sameSyntaxNode(parent.ChildByFieldName(pythonFieldName), node)
	}
	return true
}

// pythonWriteTarget reports an expression a statement assigns, augments or
// deletes, alone or inside a target tuple or list.
func pythonWriteTarget(expr *sitter.Node) bool {
	for {
		parent := expr.Parent()
		if parent == nil {
			return false
		}
		switch sym := parent.Symbol(); sym {
		case pythonSyms.assignment, pythonSyms.augmentedAssignment, pythonSyms.forStatement, pythonSyms.forInClause:
			return sameSyntaxNode(parent.ChildByFieldName("left"), expr)
		case pythonSyms.deleteStatement:
			return true
		case pythonSyms.patternList, pythonSyms.tuplePattern, pythonSyms.listPattern:
			expr = parent
			continue
		}
		switch parent.Type() {
		case "tuple", "list", javaNodeParenthesizedExpr, "expression_list":
			expr = parent
			continue
		}
		return false
	}
}

// recordPythonNamedValueWrites records, under the key the imported name
// binds, each use notePythonImportUse collected.
func recordPythonNamedValueWrites(analysis *FileAnalysis, fw *pythonFileWalk) {
	for use := range fw.importUses {
		key, ok := pythonImportKey(use.root, analysis)
		if !ok {
			continue
		}
		if use.path != "" {
			key += "." + use.path
		}
		recordNamedValueWrite(analysis, NamedValueWrite{Key: key, MembersOnly: use.membersOnly})
	}
}

func isSimplePythonIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}
