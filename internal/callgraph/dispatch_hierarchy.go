// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package callgraph

import (
	"sort"
	"strings"
)

// hierarchyMaxDepth bounds the ancestor walk. Real inheritance chains are far
// shallower; the cap only guards against a malformed or cyclic hierarchy.
const hierarchyMaxDepth = 32

// dispatchHierarchy answers "is type A a subtype of type B" for the dispatch
// expansions, from every hierarchy the graph knows:
//
//   - graph.TypeHierarchy, the fully qualified parents indexed from bytecode
//     (Java) or dependency metadata (Python);
//   - graph.SourceSupertypes, the parser-resolved extends/implements clauses
//     of source-declared Java types;
//   - FunctionDecl.OwnerBases, simple base names, used only for a type that
//     has no other recorded supertypes and resolved the same way the fragment export
//     recovers source hierarchy: a same-package type wins, otherwise a name
//     unique across the graph; an ambiguous or unknown name resolves to
//     nothing.
//
// A type the hierarchy says nothing about is a subtype of nothing but itself.
// That is the deliberate, sound fallback: without evidence the expansions add
// no edge rather than guessing by method name.
//
// Go interfaces are satisfied structurally, so for the Go ecosystem
// implementsStructurally stands in for the nominal check.
type dispatchHierarchy struct {
	parents   map[string][]string
	ancestors map[string]map[string]bool

	// Go method sets, built on first use: owner key -> "name#arity" set.
	goMethodSets map[string]map[string]bool
	graph        *CallGraph
}

func newDispatchHierarchy(graph *CallGraph) *dispatchHierarchy {
	h := &dispatchHierarchy{
		parents:   make(map[string][]string),
		ancestors: make(map[string]map[string]bool),
		graph:     graph,
	}
	for owner, bases := range graph.TypeHierarchy {
		h.addParents(normalizeHierarchyName(owner), bases)
	}
	for owner, bases := range graph.SourceSupertypes {
		h.addParents(normalizeHierarchyName(owner), bases)
	}

	typesBySimple := make(map[string][]string)
	pkgByOwner := make(map[string]string)
	simpleBases := make(map[string][]string)
	for _, decl := range graph.Functions {
		if decl == nil || decl.ID.Type == "" {
			continue
		}
		owner := declOwnerFQN(decl.ID)
		if _, seen := pkgByOwner[owner]; !seen {
			pkgByOwner[owner] = decl.ID.Package
			simple := simpleTypeName(owner)
			typesBySimple[simple] = append(typesBySimple[simple], owner)
		}
		if len(decl.OwnerBases) > 0 && simpleBases[owner] == nil {
			simpleBases[owner] = decl.OwnerBases
		}
	}
	for owner, bases := range simpleBases {
		if len(h.parents[owner]) > 0 {
			continue
		}
		for _, base := range bases {
			if resolved := resolveSimpleBase(base, pkgByOwner[owner], typesBySimple); resolved != "" {
				h.addParents(owner, []string{resolved})
			}
		}
	}
	return h
}

// mergeSourceSupertypes folds one file's resolved supertypes into the graph.
func mergeSourceSupertypes(graph *CallGraph, supertypes map[string][]string) {
	if len(supertypes) == 0 {
		return
	}
	if graph.SourceSupertypes == nil {
		graph.SourceSupertypes = make(map[string][]string)
	}
	for owner, bases := range supertypes {
		for _, base := range bases {
			if !stringSliceContains(graph.SourceSupertypes[owner], base) {
				graph.SourceSupertypes[owner] = append(graph.SourceSupertypes[owner], base)
			}
		}
	}
}

func (h *dispatchHierarchy) addParents(owner string, bases []string) {
	if owner == "" {
		return
	}
	existing := h.parents[owner]
	for _, base := range bases {
		base = normalizeHierarchyName(strings.TrimSpace(stripGenericSuffix(base)))
		if base == "" || base == owner || stringSliceContains(existing, base) {
			continue
		}
		existing = append(existing, base)
	}
	h.parents[owner] = existing
}

// resolveSimpleBase resolves one simple (or already qualified) base name
// recorded in OwnerBases to a type declared in the graph.
func resolveSimpleBase(base, ownerPkg string, typesBySimple map[string][]string) string {
	base = strings.TrimSpace(stripGenericSuffix(base))
	if base == "" {
		return ""
	}
	if strings.Contains(base, ".") && !looksLikeJavaTypeName(base) {
		return normalizeHierarchyName(base)
	}
	candidates := typesBySimple[simpleTypeName(base)]
	for _, candidate := range candidates {
		if ownerPkg != "" && candidate == ownerPkg+"."+base {
			return candidate
		}
	}
	if len(candidates) == 1 {
		return candidates[0]
	}
	return ""
}

// isSubtype reports whether sub is super or transitively extends/implements it.
func (h *dispatchHierarchy) isSubtype(sub, super string) bool {
	sub, super = normalizeHierarchyName(sub), normalizeHierarchyName(super)
	if sub == "" || super == "" {
		return false
	}
	if sub == super {
		return true
	}
	return h.ancestorSet(sub)[super]
}

func (h *dispatchHierarchy) ancestorSet(typeName string) map[string]bool {
	if set, ok := h.ancestors[typeName]; ok {
		return set
	}
	set := make(map[string]bool)
	frontier := []string{typeName}
	for depth := 0; depth < hierarchyMaxDepth && len(frontier) > 0; depth++ {
		var next []string
		for _, current := range frontier {
			for _, parent := range h.parents[current] {
				if parent == typeName || set[parent] {
					continue
				}
				set[parent] = true
				next = append(next, parent)
			}
		}
		frontier = next
	}
	h.ancestors[typeName] = set
	return set
}

// hasAncestorNamed reports whether some type whose simple name is sub has an
// ancestor whose simple name is super. Used for overload applicability, where
// the call site only knows erased simple type names.
func (h *dispatchHierarchy) hasAncestorNamed(sub, super string, typesBySimple map[string][]string) bool {
	for _, owner := range typesBySimple[sub] {
		for ancestor := range h.ancestorSet(owner) {
			if simpleTypeName(ancestor) == super {
				return true
			}
		}
	}
	return false
}

// implementsStructurally reports whether the Go type owning candidate declares
// every method of iface by name and arity. Methods promoted from an embedded
// field are not in the graph under the embedding type, so such a type is not
// seen as an implementation; that trades a missed edge for never inventing
// one.
func (h *dispatchHierarchy) implementsStructurally(candidate, iface FunctionID) bool {
	if h.goMethodSets == nil {
		h.goMethodSets = make(map[string]map[string]bool)
		for _, fn := range h.graph.Functions {
			if fn == nil || fn.ID.Type == "" {
				continue
			}
			key := goMethodSetKey(fn.ID.Package, fn.ID.Type, fn.OwnerType == ownerTypeInterface)
			set := h.goMethodSets[key]
			if set == nil {
				set = make(map[string]bool)
				h.goMethodSets[key] = set
			}
			set[methodArityKey(fn.ID.Name)] = true
		}
	}
	required := h.goMethodSets[goMethodSetKey(iface.Package, iface.Type, true)]
	if len(required) == 0 {
		return false
	}
	have := h.goMethodSets[goMethodSetKey(candidate.Package, candidate.Type, false)]
	for method := range required {
		if !have[method] {
			return false
		}
	}
	return true
}

func goMethodSetKey(pkg, typ string, isInterface bool) string {
	prefix := "T|"
	if isInterface {
		prefix = "I|"
	}
	return prefix + pkg + "|" + strings.TrimLeft(typ, "*")
}

// declOwnerFQN renders the fully qualified owning type of a method ID in the
// form the hierarchy uses.
func declOwnerFQN(id FunctionID) string {
	return normalizeHierarchyName(interfaceDeclaredType(id))
}

// normalizeHierarchyName folds the binary nested-type separator used by
// bytecode ($) into the source form (.) so both sources agree on one name.
func normalizeHierarchyName(name string) string {
	return strings.ReplaceAll(strings.TrimLeft(name, "*"), "$", ".")
}

func stringSliceContains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// javaPrimitiveWidening lists, for each primitive, the primitives it widens
// to without a cast (JLS 5.1.2).
const (
	javaBooleanType = "boolean"
	javaCharType    = "char"
)

var javaPrimitiveWidening = map[string][]string{
	"byte":       {"short", "int", "long", "float", "double"},
	"short":      {"int", "long", "float", "double"},
	javaCharType: {"int", "long", "float", "double"},
	"int":        {"long", "float", "double"},
	"long":       {"float", "double"},
	"float":      {"double"},
}

var javaBoxedTypes = map[string]string{
	javaBooleanType: "Boolean", "byte": "Byte", "short": "Short", javaCharType: "Character",
	"int": "Integer", "long": "Long", "float": "Float", "double": "Double",
}

// overloadSelector picks, among the same-arity overloads of one method on one
// type, those a call site can actually invoke given the static argument types
// it records.
type overloadSelector struct {
	hierarchy     *dispatchHierarchy
	typesBySimple map[string][]string
}

func newOverloadSelector(graph *CallGraph, hierarchy *dispatchHierarchy) *overloadSelector {
	typesBySimple := make(map[string][]string)
	seen := make(map[string]bool)
	add := func(owner string) {
		if owner == "" || seen[owner] {
			return
		}
		seen[owner] = true
		simple := simpleTypeName(owner)
		typesBySimple[simple] = append(typesBySimple[simple], owner)
	}
	for _, fn := range graph.Functions {
		if fn != nil && fn.ID.Type != "" {
			add(declOwnerFQN(fn.ID))
		}
	}
	for owner := range hierarchy.parents {
		add(owner)
	}
	for simple := range typesBySimple {
		sort.Strings(typesBySimple[simple])
	}
	return &overloadSelector{hierarchy: hierarchy, typesBySimple: typesBySimple}
}

// selectOverloads narrows candidates (keys of same-name, same-arity methods on
// one type) to the overloads the call site can invoke given the static
// argument types it records:
//
//  1. When some overloads declare exactly the recorded type at every argument
//     whose type is known, those are the most specific applicable methods and
//     javac picks among them, so only they are kept.
//  2. Otherwise every overload whose parameters accept the recorded types is
//     kept (see assignable).
//  3. When none is applicable the call site carries type information the graph
//     cannot reconcile (erasure, an unindexed supertype); every candidate is
//     kept, as before, rather than dropping the call.
//
// An argument whose type the call site does not record constrains nothing.
func (s *overloadSelector) selectOverloads(graph *CallGraph, call *FunctionCall, candidates []string) []string {
	if len(candidates) < 2 || call == nil {
		return candidates
	}
	var exact, applicable []string
	for _, key := range candidates {
		fn := graph.Functions[key]
		if fn == nil {
			applicable = append(applicable, key)
			continue
		}
		known, matched, accepted := s.matchArguments(fn, call)
		if known > 0 && matched == known {
			exact = append(exact, key)
		}
		if accepted {
			applicable = append(applicable, key)
		}
	}
	switch {
	case len(exact) > 0:
		return exact
	case len(applicable) > 0:
		return applicable
	default:
		return candidates
	}
}

// matchArguments compares fn's parameters with the call's recorded argument
// types: known counts arguments with a recorded type, matched those whose type
// equals the parameter type, and accepted is false when some recorded type
// cannot be passed to its parameter.
func (s *overloadSelector) matchArguments(fn *FunctionDecl, call *FunctionCall) (known, matched int, accepted bool) {
	accepted = true
	for i, param := range fn.Parameters {
		arg := stripGenericSuffix(staticArgumentType(call, i))
		if arg == "" {
			continue
		}
		known++
		paramType := stripGenericSuffix(normalizeJavaTypeName(param.Type))
		if arg == paramType {
			matched++
			continue
		}
		if !s.assignable(arg, paramType) {
			accepted = false
		}
	}
	return known, matched, accepted
}

// assignable reports whether a value of static type arg can be passed to a
// parameter of type param. Both are erased simple names as the Java parser
// records them. A parameter type that is a type variable, or a reference type
// the graph knows nothing about, accepts anything: nothing proves it cannot.
func (s *overloadSelector) assignable(arg, param string) bool {
	if arg == param || param == "" || param == "Object" {
		return true
	}
	argArray, paramArray := strings.HasSuffix(arg, "[]"), strings.HasSuffix(param, "[]")
	if argArray && paramArray {
		return s.assignable(strings.TrimSuffix(arg, "[]"), strings.TrimSuffix(param, "[]"))
	}
	if paramArray {
		// A varargs parameter also accepts a single element.
		return s.assignable(arg, strings.TrimSuffix(param, "[]"))
	}
	if argArray {
		return false
	}
	if isJavaPrimitive(arg) {
		return primitiveAssignable(arg, param)
	}
	if isJavaPrimitive(param) {
		return unboxedAssignable(arg, param)
	}
	if isJavaTypeVariable(param) || len(s.typesBySimple[param]) == 0 {
		return true
	}
	return s.hierarchy.hasAncestorNamed(arg, param, s.typesBySimple)
}

// primitiveAssignable covers widening (JLS 5.1.2) and boxing to the wrapper
// or one of its supertypes.
func primitiveAssignable(arg, param string) bool {
	if stringSliceContains(javaPrimitiveWidening[arg], param) || javaBoxedTypes[arg] == param {
		return true
	}
	switch param {
	case "Serializable", "Comparable":
		return true
	case "Number":
		return arg != javaBooleanType && arg != javaCharType
	}
	return false
}

// unboxedAssignable covers unboxing a wrapper, then widening it.
func unboxedAssignable(arg, param string) bool {
	for primitive, boxed := range javaBoxedTypes {
		if boxed == arg && (primitive == param || stringSliceContains(javaPrimitiveWidening[primitive], param)) {
			return true
		}
	}
	return false
}

func isJavaPrimitive(name string) bool {
	_, ok := javaBoxedTypes[name]
	return ok
}

// isJavaTypeVariable matches the conventional type-variable spelling: one
// upper-case letter, optionally followed by digits (T, E, K, V, T2).
func isJavaTypeVariable(name string) bool {
	if name == "" || name[0] < 'A' || name[0] > 'Z' {
		return false
	}
	for i := 1; i < len(name); i++ {
		if name[i] < '0' || name[i] > '9' {
			return false
		}
	}
	return true
}

// staticArgumentType returns the static type of a call's argument at idx, as
// an erased simple name, or "" when the call site does not establish it. It
// reads only the argument's own provenance: a declared variable, field or
// parameter type, or the class a constructor call creates. The result of any
// other call is unknown here even though its provenance records the receiver,
// because the receiver's type is not the value's type.
func staticArgumentType(call *FunctionCall, idx int) string {
	if idx < len(call.ArgumentSources) && len(call.ArgumentSources[idx]) > 0 {
		nodes := call.ArgumentSources[idx]
		if len(nodes) != 1 {
			return ""
		}
		return staticSourceNodeType(nodes[0], 0)
	}
	if idx >= len(call.Arguments) {
		return ""
	}
	return inferJavaArgumentTextType(call.Arguments[idx])
}

func staticSourceNodeType(node SourceNode, depth int) string {
	if node.DeclaredType != "" {
		return normalizeJavaTypeName(node.DeclaredType)
	}
	switch node.Type {
	case sourceNodeCallResult:
		if node.CallTarget != nil && BaseFunctionName(node.CallTarget.Name) == constructorMethodName {
			return normalizeJavaTypeName(node.CallTarget.Type)
		}
		return ""
	case sourceNodeValue:
		return inferJavaArgumentTextType(node.Value)
	case sourceNodeVariable:
		// An untyped local takes the type of the single value bound to it.
		if depth < hierarchyMaxDepth && len(node.SourceNodes) == 1 {
			return staticSourceNodeType(node.SourceNodes[0], depth+1)
		}
	}
	return ""
}
