// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// maxJavaConstantDepth bounds how many `static final String A = B;` hops a
// reference is followed before it is left unresolved.
const maxJavaConstantDepth = 8

const javaNodeConstantDeclaration = "constant_declaration"

// JavaStringConstant is a compile-time String constant a Java type declares:
// a `static final` field, or any interface field, initialized from a string
// literal or from another such constant. Keyed by the owner type's fully
// qualified name plus ".NAME" (nested types joined with dots).
type JavaStringConstant struct {
	// Value is the initializer literal, quotes included. Empty when the
	// initializer names another constant.
	Value        string
	DeclaredType string
	FilePath     string
	Line         int
	// ref is the constant an initializer like `A = B` names.
	ref *javaConstantRef
	// ambiguous marks a key that two source files declare differently.
	ambiguous bool
}

// javaConstantRef is a name in source that may denote a String constant,
// carried with the keys it could resolve to. The keys come in precedence
// tiers, the way Java scoping orders them; the first tier with a recorded
// constant decides, and two matches within one tier leave it unresolved.
type javaConstantRef struct {
	expr  string
	tiers [][]string
}

// collectJavaStringConstants records the String constants of every named type
// declared among nodes, nested types included, into analysis.
func collectJavaStringConstants(nodes []*sitter.Node, src []byte, analysis *FileAnalysis, outerType string) {
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
		collectJavaStringConstants(members, src, analysis, owner)
	}
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
		constant := JavaStringConstant{
			DeclaredType: declaredType,
			FilePath:     analysis.FilePath,
			Line:         int(declarator.StartPoint().Row) + 1,
		}
		value := strings.TrimSpace(valueNode.Content(src))
		switch valueNode.Type() {
		case "string_literal":
			if strings.HasPrefix(value, `"""`) {
				continue
			}
			constant.Value = value
		case javaNodeIdentifier, javaNodeFieldAccess:
			constant.ref = newJavaConstantRef(value, analysis, owner)
			if constant.ref == nil {
				continue
			}
		default:
			continue
		}
		if analysis.JavaStringConstants == nil {
			analysis.JavaStringConstants = make(map[string]JavaStringConstant)
		}
		key := javaQualifiedName(javaAnalysisPackagePath(analysis), owner+"."+nameNode.Content(src))
		analysis.JavaStringConstants[key] = constant
	}
}

// javaConstantUse builds the reference for a name used as a value inside
// currentClass, unless its first segment is a local, parameter or field,
// which shadows any type of the same name.
func javaConstantUse(expr string, analysis *FileAnalysis, currentClass string, varTypes map[string]string, origins map[string]varOrigin) *javaConstantRef {
	first, _, _ := strings.Cut(expr, ".")
	if _, ok := varTypes[first]; ok {
		return nil
	}
	if _, ok := origins[first]; ok {
		return nil
	}
	return newJavaConstantRef(expr, analysis, currentClass)
}

// newJavaConstantRef resolves expr, a bare NAME or a Qualifier.NAME written in
// currentClass, to the constant keys it could denote:
//
//   - bare NAME: a field of currentClass or an enclosing type, innermost first;
//     then a single static import; then the static on-demand imports.
//   - Qualifier.NAME: a type declared in this file (member types of the
//     enclosing types first) or a single-type import decides alone; otherwise
//     the same package, then the on-demand imports, then the qualifier read as
//     a fully qualified name.
func newJavaConstantRef(expr string, analysis *FileAnalysis, currentClass string) *javaConstantRef {
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
		return javaConstantRefFromTiers(expr, tiers)
	}
	for _, scope := range append(scopes, "") {
		if _, declared := analysis.ClassBases[javaNestedTypeName(scope, first)]; declared {
			return javaConstantRefFromTiers(expr, [][]string{{javaQualifiedName(pkg, javaNestedTypeName(scope, expr))}})
		}
	}
	if owner, ok := analysis.Imports[first]; ok {
		return javaConstantRefFromTiers(expr, [][]string{{owner + "." + expr}})
	}
	tiers = append(tiers, []string{javaQualifiedName(pkg, expr)})
	if keys := javaPrefixedKeys(analysis.WildcardImports, expr); len(keys) > 0 {
		tiers = append(tiers, keys)
	}
	if qualifier := expr[:strings.LastIndex(expr, ".")]; strings.Contains(qualifier, ".") {
		tiers = append(tiers, []string{expr})
	}
	return javaConstantRefFromTiers(expr, tiers)
}

func javaConstantRefFromTiers(expr string, tiers [][]string) *javaConstantRef {
	if len(tiers) == 0 {
		return nil
	}
	return &javaConstantRef{expr: expr, tiers: tiers}
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

// mergeJavaStringConstants adds one file's constants to the graph. A key that
// another file already declares with a different value becomes ambiguous.
func mergeJavaStringConstants(graph *CallGraph, analysis *FileAnalysis) {
	if len(analysis.JavaStringConstants) == 0 {
		return
	}
	if graph.JavaStringConstants == nil {
		graph.JavaStringConstants = make(map[string]JavaStringConstant, len(analysis.JavaStringConstants))
	}
	for key, constant := range analysis.JavaStringConstants {
		existing, ok := graph.JavaStringConstants[key]
		if !ok {
			graph.JavaStringConstants[key] = constant
			continue
		}
		if existing.ref == nil && constant.ref == nil && existing.Value == constant.Value {
			continue
		}
		existing.ambiguous = true
		graph.JavaStringConstants[key] = existing
	}
}

// foldJavaStringConstants rewrites every source node whose name resolves to
// exactly one recorded String constant into the shape a same-class final
// field already has: a FIELD at the declaration with the literal as its one
// VALUE child. It runs once every file is parsed, since the declaring file may
// be parsed after the one using the constant.
func foldJavaStringConstants(graph *CallGraph) {
	if graph == nil {
		return
	}
	for _, fn := range graph.Functions {
		foldJavaConstantNodes(fn.ReturnSources, graph.JavaStringConstants)
		for i := range fn.Calls {
			for _, sources := range fn.Calls[i].ArgumentSources {
				foldJavaConstantNodes(sources, graph.JavaStringConstants)
			}
		}
		if fn.InferredReturn != nil {
			foldJavaConstantNodes(fn.InferredReturn.Provenance, graph.JavaStringConstants)
		}
	}
}

func foldJavaConstantNodes(nodes []SourceNode, constants map[string]JavaStringConstant) {
	for i := range nodes {
		node := &nodes[i]
		foldJavaConstantNodes(node.SourceNodes, constants)
		ref := node.javaConstant
		if ref == nil {
			continue
		}
		node.javaConstant = nil
		constant, ok := resolveJavaStringConstant(constants, ref, 0, nil)
		if !ok {
			continue
		}
		*node = SourceNode{
			Type:         sourceNodeField,
			Name:         ref.expr,
			DeclaredType: constant.DeclaredType,
			Location:     &SourceLocation{FilePath: constant.FilePath, Line: constant.Line},
			SourceNodes:  []SourceNode{{Type: sourceNodeValue, Value: constant.Value}},
			Flow:         node.Flow,
		}
	}
}

// resolveJavaStringConstant returns the constant ref denotes, with the literal
// of the final link when its initializer names another constant.
func resolveJavaStringConstant(constants map[string]JavaStringConstant, ref *javaConstantRef, depth int, visiting map[string]bool) (JavaStringConstant, bool) {
	key, ok := ref.lookup(constants)
	if !ok {
		return JavaStringConstant{}, false
	}
	constant := constants[key]
	if constant.ambiguous {
		return JavaStringConstant{}, false
	}
	if constant.ref == nil {
		return constant, constant.Value != ""
	}
	if depth >= maxJavaConstantDepth || visiting[key] {
		return JavaStringConstant{}, false
	}
	if visiting == nil {
		visiting = make(map[string]bool)
	}
	visiting[key] = true
	target, ok := resolveJavaStringConstant(constants, constant.ref, depth+1, visiting)
	if !ok {
		return JavaStringConstant{}, false
	}
	constant.Value = target.Value
	return constant, true
}

func (r *javaConstantRef) lookup(constants map[string]JavaStringConstant) (string, bool) {
	for _, tier := range r.tiers {
		match := ""
		for _, key := range tier {
			if _, ok := constants[key]; !ok || key == match {
				continue
			}
			if match != "" {
				return "", false
			}
			match = key
		}
		if match != "" {
			return match, true
		}
	}
	return "", false
}
