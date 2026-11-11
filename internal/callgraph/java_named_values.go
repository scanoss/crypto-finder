// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

const javaNodeConstantDeclaration = "constant_declaration"

// collectJavaNamedValues records the String constants and enum constants of
// every named type declared among nodes, nested types included, into analysis.
func collectJavaNamedValues(nodes []*sitter.Node, src []byte, analysis *FileAnalysis, outerType string) {
	for _, child := range nodes {
		switch child.Type() {
		case javaNodeClassDeclaration, javaNodeInterfaceDeclaration, javaNodeEnumDeclaration,
			javaNodeRecordDeclaration, javaNodeAnnotationTypeDecl:
		default:
			continue
		}
		name, body := javaTypeNameAndBody(child, src)
		if name == "" || body == nil {
			continue
		}
		owner := javaNestedTypeName(outerType, name)
		// Interface and annotation fields are implicitly public static final.
		implicit := child.Type() == javaNodeInterfaceDeclaration || child.Type() == javaNodeAnnotationTypeDecl
		members := javaTypeBodyMembers(body)
		if child.Type() == javaNodeEnumDeclaration {
			recordJavaEnumConstants(members, src, analysis, owner)
		}
		for _, member := range members {
			switch member.Type() {
			case javaNodeFieldDeclaration, javaNodeConstantDeclaration:
			default:
				continue
			}
			if !implicit && (!javaHasModifier(member, src, "static") || !javaHasModifier(member, src, "final")) {
				continue
			}
			recordJavaStringConstants(member, src, analysis, owner)
		}
		collectJavaNamedValues(members, src, analysis, owner)
	}
}

// recordJavaEnumConstants records what `Owner.C.name()` yields for each enum
// constant, which Enum declares final, and what each other no-argument method
// yields when it returns a field the constructor sets from a parameter the
// constant's arguments fill. `Owner.C.toString()` yields the name when neither
// the enum nor the constant's own body overrides toString. A method the
// constant's body overrides is not recorded. The bare `Owner.C` is not
// recorded: an enum constant is not a String.
func recordJavaEnumConstants(members []*sitter.Node, src []byte, analysis *FileAnalysis, owner string) {
	overridden := javaDeclaresMethod(members, src, "toString")
	key := javaQualifiedName(javaAnalysisPackagePath(analysis), owner)
	methods := make(map[string]*FunctionDecl)
	for i := range analysis.Functions {
		if decl := &analysis.Functions[i]; decl.ID.Package == analysis.PackagePath && decl.ID.Type == owner {
			methods[decl.ID.Name] = decl
		}
	}
	for _, member := range members {
		if member.Type() != javaNodeEnumConstant {
			continue
		}
		nameNode := member.ChildByFieldName(javaFieldName)
		if nameNode == nil {
			continue
		}
		name := nameNode.Content(src)
		value := NamedValue{
			Value:        `"` + name + `"`,
			DeclaredType: "String",
			FilePath:     analysis.FilePath,
			Line:         int(member.StartPoint().Row) + 1,
		}
		recordNamedValue(analysis, key+"."+name+".name()", value)
		body := javaTypeBodyMembers(member.ChildByFieldName("body"))
		if !overridden && !javaDeclaresMethod(body, src, "toString") {
			recordNamedValue(analysis, key+"."+name+".toString()", value)
		}
		recordJavaEnumGetters(member, body, src, analysis, owner, methods, key+"."+name+".", value)
	}
}

// recordJavaEnumGetters records, under prefix, what each no-argument method
// yields for the constant member by the constructor-getter rule.
func recordJavaEnumGetters(member *sitter.Node, body []*sitter.Node, src []byte, analysis *FileAnalysis, owner string, methods map[string]*FunctionDecl, prefix string, at NamedValue) {
	var args []*sitter.Node
	if list := member.ChildByFieldName("arguments"); list != nil {
		for i := 0; i < int(list.NamedChildCount()); i++ {
			args = append(args, list.NamedChild(i))
		}
	}
	ctor := methods[javaMethodWithArity(constructorMethodName, len(args))]
	for id, method := range methods {
		plain, isGetter := strings.CutSuffix(id, "#0")
		if !isGetter || plain == clinitMethodName || javaDeclaresMethod(body, src, plain) {
			continue
		}
		if _, param, ok := constructorFieldParameter(method, ctor); ok {
			if value, ok := javaNamedValueOf(args[param.ParameterIndex], src, analysis, owner, at); ok {
				recordNamedValue(analysis, prefix+plain+"()", value)
			}
		}
	}
}

// javaNamedValueOf is the value an initializer or argument expression gives:
// a String literal, or a name that denotes one.
func javaNamedValueOf(expr *sitter.Node, src []byte, analysis *FileAnalysis, owner string, at NamedValue) (NamedValue, bool) {
	text := strings.TrimSpace(expr.Content(src))
	switch expr.Type() {
	case "string_literal":
		if strings.HasPrefix(text, `"""`) {
			return NamedValue{}, false
		}
		at.Value = text
	case javaNodeIdentifier, javaNodeFieldAccess:
		at.Value = ""
		at.ref = newJavaNameRef(text, analysis, owner)
		if at.ref == nil {
			return NamedValue{}, false
		}
	default:
		return NamedValue{}, false
	}
	return at, true
}

func javaDeclaresMethod(members []*sitter.Node, src []byte, method string) bool {
	for _, member := range members {
		if member.Type() != javaNodeMethodDeclaration {
			continue
		}
		name := member.ChildByFieldName(javaFieldName)
		params := member.ChildByFieldName("parameters")
		if name != nil && name.Content(src) == method && params != nil && params.NamedChildCount() == 0 {
			return true
		}
	}
	return false
}

// javaTypeNameAndBody is parseJavaClass widened to interface bodies.
func javaTypeNameAndBody(node *sitter.Node, src []byte) (string, *sitter.Node) {
	name, body := parseJavaClass(node, src)
	if body != nil {
		return name, body
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if child := node.Child(i); child.Type() == "interface_body" {
			return name, child
		}
	}
	return name, nil
}

func recordJavaStringConstants(member *sitter.Node, src []byte, analysis *FileAnalysis, owner string) {
	declaredType := ""
	if typeNode := member.ChildByFieldName(javaFieldType); typeNode != nil {
		declaredType = strings.TrimSpace(typeNode.Content(src))
	}
	for i := 0; i < int(member.ChildCount()); i++ {
		declarator := member.Child(i)
		if declarator.Type() != javaNodeVariableDeclarator {
			continue
		}
		nameNode := declarator.ChildByFieldName(javaFieldName)
		valueNode := declarator.ChildByFieldName(javaFieldValue)
		if nameNode == nil || valueNode == nil {
			continue
		}
		constant, ok := javaNamedValueOf(valueNode, src, analysis, owner, NamedValue{
			DeclaredType: declaredType,
			FilePath:     analysis.FilePath,
			Line:         int(declarator.StartPoint().Row) + 1,
		})
		if !ok {
			continue
		}
		recordNamedValue(analysis, javaQualifiedName(javaAnalysisPackagePath(analysis), owner+"."+nameNode.Content(src)), constant)
	}
}

// javaNameRefUse builds the reference for a name used as a value inside
// currentClass, unless its first segment is a local, parameter or field,
// which shadows any type of the same name.
func javaNameRefUse(expr string, analysis *FileAnalysis, currentClass string, varTypes map[string]string, origins map[string]varOrigin) *nameRef {
	first, _, _ := strings.Cut(expr, ".")
	if _, ok := varTypes[first]; ok {
		return nil
	}
	if _, ok := origins[first]; ok {
		return nil
	}
	return newJavaNameRef(expr, analysis, currentClass)
}

// newJavaNameRef resolves expr, a bare NAME or a Qualifier.NAME written in
// currentClass, to the constant keys it could denote:
//
//   - bare NAME: a field of currentClass or an enclosing type, innermost first;
//     then a single static import; then the static on-demand imports.
//   - Qualifier.NAME: a type declared in this file (member types of the
//     enclosing types first) or a single-type import decides alone; otherwise
//     the same package, then the on-demand imports, then the qualifier read as
//     a fully qualified name.
func newJavaNameRef(expr string, analysis *FileAnalysis, currentClass string) *nameRef {
	if analysis == nil || !isResolvableJavaTypeReference(expr) {
		return nil
	}
	first, _, dotted := strings.Cut(expr, ".")
	if first == javaThisKeyword || first == javaSuperKeyword {
		return nil
	}
	pkg := javaAnalysisPackagePath(analysis)
	scopes := javaEnclosingTypeScopes(currentClass)
	var tiers [][]string
	if !dotted {
		for _, scope := range scopes {
			tiers = append(tiers, []string{javaQualifiedName(pkg, scope+"."+expr)})
		}
		if owner, ok := analysis.Imports[expr]; ok {
			tiers = append(tiers, []string{owner + "." + expr})
		}
		if keys := javaPrefixedKeys(analysis.StaticWildcardImports, expr); len(keys) > 0 {
			tiers = append(tiers, keys)
		}
		return newNameRef(expr, tiers)
	}
	for _, scope := range append(scopes, "") {
		if _, declared := analysis.ClassBases[javaNestedTypeName(scope, first)]; declared {
			return newNameRef(expr, [][]string{{javaQualifiedName(pkg, javaNestedTypeName(scope, expr))}})
		}
	}
	if owner, ok := analysis.Imports[first]; ok {
		return newNameRef(expr, [][]string{{owner + "." + expr}})
	}
	tiers = append(tiers, []string{javaQualifiedName(pkg, expr)})
	if keys := javaPrefixedKeys(analysis.WildcardImports, expr); len(keys) > 0 {
		tiers = append(tiers, keys)
	}
	if qualifier := expr[:strings.LastIndex(expr, ".")]; strings.Contains(qualifier, ".") {
		tiers = append(tiers, []string{expr})
	}
	return newNameRef(expr, tiers)
}

// javaEnclosingTypeScopes lists "A.B.C", "A.B", "A" for currentClass "A.B.C".
func javaEnclosingTypeScopes(currentClass string) []string {
	var scopes []string
	for scope := currentClass; scope != ""; {
		scopes = append(scopes, scope)
		dot := strings.LastIndex(scope, ".")
		if dot < 0 {
			break
		}
		scope = scope[:dot]
	}
	return scopes
}

func javaPrefixedKeys(prefixes []string, name string) []string {
	keys := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		keys = append(keys, prefix+"."+name)
	}
	return keys
}

func javaQualifiedName(pkg, name string) string {
	if pkg == "" {
		return name
	}
	return pkg + "." + name
}
