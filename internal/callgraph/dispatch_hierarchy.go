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

// javaSupertypeAlternatives separates the possible fully qualified names of one
// extends/implements entry whose simple name an on-demand import leaves
// ambiguous (see resolveJavaSupertype).
const javaSupertypeAlternatives = "|"

// javaObjectType is the implicit root of every Java class hierarchy.
const javaObjectType = "java.lang.Object"

// subtypeRelation is the answer to "is A a subtype of B" when the hierarchy may
// be only partly known.
type subtypeRelation int

const (
	// subtypeUnknown: A's known ancestors do not include B, but some ancestor's
	// own supertypes are not recorded, so B may still be one of them.
	subtypeUnknown subtypeRelation = iota
	// subtypeYes: B is A or one of A's recorded ancestors.
	subtypeYes
	// subtypeNo: A's whole ancestry is recorded and B is not in it.
	subtypeNo
)

// dispatchHierarchy answers "is type A a subtype of type B" for the dispatch
// expansions, from every hierarchy the graph knows:
//
//   - graph.TypeHierarchy, the fully qualified parents indexed from bytecode
//     (Java) or dependency metadata (Python);
//   - graph.SourceSupertypes, the parser-resolved extends/implements clauses
//     of source-declared Java types, one entry per declared type even when it
//     names no supertype;
//   - FunctionDecl.OwnerBases, simple base names (Python, Node, and hand-built
//     graphs), used only for a type with no other record and resolved the way
//     the fragment export recovers source hierarchy: a same-package type wins,
//     otherwise a name unique across the graph.
//
// A type is "recorded" when one of these sources vouches for its complete list
// of direct supertypes. The expansions drop an edge only when the relation is
// subtypeNo, that is, when the candidate's whole ancestry is recorded and
// excludes the declared type. When it is subtypeUnknown they keep the edge,
// as name-and-arity matching did before, and mark it name_only.
//
// Go interfaces are satisfied structurally, so for the Go ecosystem
// implementsStructurally stands in for the nominal check.
type dispatchHierarchy struct {
	parents  map[string][]string
	children map[string][]string
	// simpleNameCount counts the known types sharing each simple name.
	simpleNameCount map[string]int
	// inheritedBy memoizes inheritedProviders per interface and method.
	inheritedBy     map[string]map[string]bool
	declaredMethods map[string]map[string][]*FunctionDecl
	recorded        map[string]bool
	ancestors       map[string]map[string]bool
	complete        map[string]bool

	// Go method sets, built on first use: owner key -> "name#arity" set.
	goMethodSets map[string]map[string]bool
	graph        *CallGraph
}

func newDispatchHierarchy(graph *CallGraph) *dispatchHierarchy {
	h := &dispatchHierarchy{
		parents:   make(map[string][]string),
		recorded:  make(map[string]bool),
		ancestors: make(map[string]map[string]bool),
		complete:  make(map[string]bool),
		graph:     graph,

		inheritedBy: make(map[string]map[string]bool),
	}

	typesBySimple, pkgByOwner, simpleBases, known := indexDeclaredOwners(graph)
	for owner := range graph.TypeHierarchy {
		known[normalizeHierarchyName(owner)] = true
	}
	for owner := range graph.SourceSupertypes {
		known[normalizeHierarchyName(owner)] = true
	}
	h.simpleNameCount = make(map[string]int, len(known))
	for owner := range known {
		h.simpleNameCount[simpleTypeName(owner)]++
	}

	for owner, bases := range graph.TypeHierarchy {
		h.record(normalizeHierarchyName(owner), bases, known)
	}
	for owner, bases := range graph.SourceSupertypes {
		h.record(normalizeHierarchyName(owner), bases, known)
	}
	for owner, bases := range simpleBases {
		if h.recorded[owner] {
			continue
		}
		resolved := make([]string, 0, len(bases))
		for _, base := range bases {
			if r := resolveSimpleBase(base, pkgByOwner[owner], typesBySimple); r != "" {
				resolved = append(resolved, r)
			}
		}
		h.addParents(owner, resolved)
		// Only a fully resolved base list vouches for the whole ancestry level.
		h.recorded[owner] = len(resolved) == len(bases)
	}
	h.indexChildren()
	return h
}

// indexDeclaredOwners indexes the types that own a declaration: by simple
// name, their package, the OwnerBases they declare, and the set of all of them.
func indexDeclaredOwners(graph *CallGraph) (typesBySimple map[string][]string, pkgByOwner map[string]string, simpleBases map[string][]string, known map[string]bool) {
	typesBySimple = make(map[string][]string)
	pkgByOwner = make(map[string]string)
	simpleBases = make(map[string][]string)
	known = make(map[string]bool)
	for _, decl := range graph.Functions {
		if decl == nil || decl.ID.Type == "" {
			continue
		}
		owner := declOwnerFQN(decl.ID)
		known[owner] = true
		if _, seen := pkgByOwner[owner]; !seen {
			pkgByOwner[owner] = decl.ID.Package
			simple := simpleTypeName(owner)
			typesBySimple[simple] = append(typesBySimple[simple], owner)
		}
		if len(decl.OwnerBases) > 0 && simpleBases[owner] == nil {
			simpleBases[owner] = decl.OwnerBases
		}
	}
	return typesBySimple, pkgByOwner, simpleBases, known
}

// record stores the supertypes a source vouches for. An entry listing
// alternatives keeps those naming a known type; when none does it keeps the
// first (Java's same-package default), which then reads as an unrecorded type.
func (h *dispatchHierarchy) record(owner string, bases []string, known map[string]bool) {
	if owner == "" {
		return
	}
	resolved := make([]string, 0, len(bases))
	certain := true
	for _, entry := range bases {
		alternatives := strings.Split(entry, javaSupertypeAlternatives)
		if h.simpleNameCount[simpleTypeName(strings.TrimSpace(stripGenericSuffix(alternatives[0])))] > 1 {
			// Several known types share the name, and which one the source
			// means depends on scoping the resolver does not model.
			certain = false
		}
		matched := 0
		for _, alt := range alternatives {
			if alt == javaUnresolvableSupertype {
				certain = false
				continue
			}
			if known[normalizeHierarchyName(strings.TrimSpace(stripGenericSuffix(alt)))] {
				resolved = append(resolved, alt)
				matched++
			}
		}
		switch {
		case matched == 0 && alternatives[0] != javaUnresolvableSupertype:
			resolved = append(resolved, alternatives[0])
		case matched > 1:
			// Several known types fit the name: each may be the parent, so
			// all are kept, but none may rule a subtype out.
			certain = false
		}
	}
	h.addParents(owner, resolved)
	// An uncertain entry leaves the owner unrecorded: relation can then
	// answer subtypeYes through the candidates, never subtypeNo.
	h.recorded[owner] = certain
}

func (h *dispatchHierarchy) indexChildren() {
	h.children = make(map[string][]string, len(h.parents))
	for owner, parents := range h.parents {
		for _, parent := range parents {
			h.children[parent] = append(h.children[parent], owner)
		}
	}
}

// inheritedProviders returns the classes that supply method (a "name#arity"
// key) to some recorded implementor of iface that does not declare it itself:
// for each implementor, the nearest ancestors that declare the method. Only
// those are real targets of an interface call; an ancestor whose method every
// implementor below it overrides is not (class Impl extends Base implements
// Hasher, with hash declared only on Base, makes Base.hash a target).
func (h *dispatchHierarchy) inheritedProviders(iface string, ifaceMethod *FunctionDecl) map[string]bool {
	iface = normalizeHierarchyName(iface)
	method := methodArityKey(ifaceMethod.ID.Name)
	// The full decorated name identifies the signature: same-arity interface
	// overloads carry their parameter types as a suffix (hash#1$byte[]), so
	// two of them never share a cache entry.
	memoKey := iface + "\x00" + ifaceMethod.ID.Name
	if set, ok := h.inheritedBy[memoKey]; ok {
		return set
	}
	declares := h.classMethodIndex()
	set := make(map[string]bool)
	seen := map[string]bool{iface: true}
	frontier := []string{iface}
	for depth := 0; depth < hierarchyMaxDepth && len(frontier) > 0; depth++ {
		var next []string
		for _, current := range frontier {
			for _, implementor := range h.children[current] {
				if seen[implementor] {
					continue
				}
				seen[implementor] = true
				next = append(next, implementor)
				if declaresOverride(declares[implementor][method], ifaceMethod) {
					continue
				}
				for _, provider := range h.nearestDeclaring(implementor, method, ifaceMethod, declares) {
					set[provider] = true
				}
			}
		}
		frontier = next
	}
	h.inheritedBy[memoKey] = set
	return set
}

// nearestDeclaring walks typeName's ancestors breadth-first and returns the
// closest level's classes that declare a method with ifaceMethod's signature.
func (h *dispatchHierarchy) nearestDeclaring(typeName, method string, ifaceMethod *FunctionDecl, declares map[string]map[string][]*FunctionDecl) []string {
	seen := map[string]bool{typeName: true}
	frontier := []string{typeName}
	for depth := 0; depth < hierarchyMaxDepth && len(frontier) > 0; depth++ {
		var next, found []string
		for _, current := range frontier {
			for _, parent := range h.parents[current] {
				if seen[parent] {
					continue
				}
				seen[parent] = true
				if declaresOverride(declares[parent][method], ifaceMethod) {
					found = append(found, parent)
				}
				next = append(next, parent)
			}
		}
		if len(found) > 0 {
			return found
		}
		frontier = next
	}
	return nil
}

// classMethodIndex maps each type to its methods with a body (interface
// declarations excluded), grouped by "name#arity" key. Built on first use.
func (h *dispatchHierarchy) classMethodIndex() map[string]map[string][]*FunctionDecl {
	if h.declaredMethods != nil {
		return h.declaredMethods
	}
	h.declaredMethods = make(map[string]map[string][]*FunctionDecl)
	for _, fn := range h.graph.Functions {
		if fn == nil || fn.ID.Type == "" || fn.OwnerType == ownerTypeInterface {
			continue
		}
		owner := declOwnerFQN(fn.ID)
		if h.declaredMethods[owner] == nil {
			h.declaredMethods[owner] = make(map[string][]*FunctionDecl)
		}
		key := methodArityKey(fn.ID.Name)
		h.declaredMethods[owner][key] = append(h.declaredMethods[owner][key], fn)
	}
	return h.declaredMethods
}

// declaresOverride reports whether one of decls has ifaceMethod's erased
// parameter types. A same-name, same-arity overload with other parameter
// types does not override it.
func declaresOverride(decls []*FunctionDecl, ifaceMethod *FunctionDecl) bool {
	for _, decl := range decls {
		if sameErasedParameters(decl.Parameters, ifaceMethod.Parameters) {
			return true
		}
	}
	return false
}

// relation classifies whether sub is a subtype of super.
func (h *dispatchHierarchy) relation(sub, super string) subtypeRelation {
	if h.isSubtype(sub, super) {
		return subtypeYes
	}
	if h.hierarchyComplete(normalizeHierarchyName(sub)) {
		return subtypeNo
	}
	return subtypeUnknown
}

// hierarchyComplete reports whether typeName and every one of its ancestors
// has a recorded list of direct supertypes.
func (h *dispatchHierarchy) hierarchyComplete(typeName string) bool {
	if done, ok := h.complete[typeName]; ok {
		return done
	}
	if typeName == javaObjectType {
		return true
	}
	// Provisionally complete, so a cyclic hierarchy terminates.
	h.complete[typeName] = true
	result := h.recorded[typeName]
	if result {
		for _, parent := range h.parents[typeName] {
			if !h.hierarchyComplete(parent) {
				result = false
				break
			}
		}
	}
	h.complete[typeName] = result
	return result
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
		if graph.SourceSupertypes[owner] == nil {
			graph.SourceSupertypes[owner] = []string{}
		}
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
	if existing == nil {
		existing = []string{}
	}
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

// mayHaveAncestorNamed reports whether a type whose simple name is sub can be
// passed where a type whose simple name is super is expected: some type named
// sub has an ancestor named super, or its ancestry is not fully recorded (or
// no type named sub is known at all), so nothing proves it cannot. The call
// site only knows erased simple names.
func (h *dispatchHierarchy) mayHaveAncestorNamed(sub, super string, typesBySimple map[string][]string) bool {
	owners := typesBySimple[sub]
	if len(owners) == 0 {
		return true
	}
	for _, owner := range owners {
		if !h.hierarchyComplete(owner) {
			return true
		}
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
	javaIntType     = "int"
	javaLongType    = "long"
	javaFloatType   = "float"
	javaDoubleType  = "double"
	javaLangString  = "java.lang.String"
	javaLangPrefix  = "java.lang."
	javaVoidType    = "void"
)

var javaPrimitiveWidening = map[string][]string{
	"byte":       {"short", "int", "long", "float", "double"},
	"short":      {"int", "long", "float", "double"},
	javaCharType: {"int", "long", "float", "double"},
	javaIntType:  {"long", "float", "double"},
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
	graph         *CallGraph
	// returnTypes maps a qualified method+arity key to the erased return
	// types its declarations share (see callReturnType). Built on first use.
	returnTypes map[string][]string
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
	return &overloadSelector{hierarchy: hierarchy, typesBySimple: typesBySimple, graph: graph}
}

// selectOverloads narrows candidates (keys of same-name, same-arity methods on
// one type) to the overloads the call site can invoke given the static
// argument types it records:
//
//  1. When every argument's type is known and some overloads declare exactly
//     those types, they are the most specific applicable methods and javac
//     picks among them, so only they are kept. An untyped argument never lets
//     an overload win by matching the typed ones alone, not even through an
//     Object parameter: its real type may make a more specific overload the
//     one javac picks.
//  2. Otherwise every overload whose parameters accept the recorded types is
//     kept (see assignable), minus those another applicable overload strictly
//     dominates (see pruneDominated).
//  3. When none is applicable the call site carries type information the graph
//     cannot reconcile (erasure, an unindexed supertype); every candidate is
//     kept, as before, rather than dropping the call.
//
// An argument whose type the call site does not record constrains nothing.
func (s *overloadSelector) selectOverloads(graph *CallGraph, call *FunctionCall, caller *FunctionDecl, candidates []string) []string {
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
		known, exactPositions, accepted := s.matchArguments(fn, call, caller)
		if known > 0 && exactPositions == len(fn.Parameters) {
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
		return s.pruneDominated(graph, call, caller, applicable)
	default:
		return candidates
	}
}

// pruneDominated drops an applicable overload that another applicable one is
// strictly more specific than whatever the untyped arguments turn out to be:
// the other declares exactly the recorded type at every typed position and the
// same parameter type as this one at every untyped position. javac would pick
// the other in every case, so this one is never the target.
func (s *overloadSelector) pruneDominated(graph *CallGraph, call *FunctionCall, caller *FunctionDecl, applicable []string) []string {
	if len(applicable) < 2 {
		return applicable
	}
	var typedExact []*FunctionDecl
	for _, key := range applicable {
		if fn := graph.Functions[key]; fn != nil && s.typedPositionsExact(fn, call, caller) {
			typedExact = append(typedExact, fn)
		}
	}
	if len(typedExact) == 0 {
		return applicable
	}
	kept := make([]string, 0, len(applicable))
	for _, key := range applicable {
		fn := graph.Functions[key]
		if fn == nil || s.typedPositionsExact(fn, call, caller) || !s.dominatedBy(fn, typedExact, call) {
			kept = append(kept, key)
		}
	}
	return kept
}

// typedPositionsExact reports whether fn declares exactly the recorded type at
// every argument position whose type is known.
func (s *overloadSelector) typedPositionsExact(fn *FunctionDecl, call *FunctionCall, caller *FunctionDecl) bool {
	for i := range fn.Parameters {
		if arg := stripGenericSuffix(s.staticArgumentType(call, i)); arg != "" && !s.exactAt(fn, call, i, caller) {
			return false
		}
	}
	return true
}

// exactAt reports whether the argument at position i has exactly fn's
// parameter type. Equal simple names are not enough for a reference type:
// both sides must resolve to the same fully qualified type, since
// com.other.Key is not com.acme.sec.Key. When either side's package cannot be
// resolved the position is not exact, so the overload does not win outright.
func (s *overloadSelector) exactAt(fn *FunctionDecl, call *FunctionCall, i int, caller *FunctionDecl) bool {
	param := fn.Parameters[i]
	arg := stripGenericSuffix(s.staticArgumentType(call, i))
	paramType := stripGenericSuffix(normalizeJavaTypeName(param.Type))
	if arg == "" || arg != paramType {
		return false
	}
	base := strings.TrimRight(arg, "[]")
	if isJavaPrimitive(base) {
		return true
	}
	argFQN := s.qualifiedArgumentType(call, i, caller)
	paramFQN := s.certainParameterType(fn, i)
	return argFQN != "" && argFQN == paramFQN
}

// certainParameterType returns the fully qualified type of fn's parameter i
// when it is certain, or "": written fully qualified in source, or a name
// certain by certainName in the declaring file.
func (s *overloadSelector) certainParameterType(fn *FunctionDecl, i int) string {
	param := fn.Parameters[i]
	if param.QualifiedInSource {
		return normalizeHierarchyName(param.QualifiedType)
	}
	base := javaParameterBaseType(normalizeJavaTypeName(param.Type))
	if param.QualifiedType == "" {
		return ""
	}
	return s.certainName(base, s.resolveQualified(param.QualifiedType, base, fn.ID.Package), fn)
}

// parameterUncertain reports whether fn's parameter i is a reference type
// whose meaning is not certain; such a parameter accepts any argument.
func (s *overloadSelector) parameterUncertain(fn *FunctionDecl, i int) bool {
	param := fn.Parameters[i]
	base := javaParameterBaseType(normalizeJavaTypeName(param.Type))
	if base == "" || isJavaPrimitive(base) || fn.FileTypeNamesAtRisk == nil || param.QualifiedInSource {
		return false
	}
	return s.certainParameterType(fn, i) == ""
}

// certainName decides whether a simple type name used in decl's file denotes
// one type beyond doubt, and returns it (or ""). It does so without modeling
// Java's scoping: the name is certain only when the file declares no type
// parameter or local class of that name, and at most one type of that simple
// name exists anywhere in the graph's type universe (source types, nested
// ones included, and indexed bytecode types). With two or more, any of them
// could be the one in scope. resolved is the import/package resolution of
// the name; when the universe holds exactly one type of that name and
// resolved names another, resolved is kept, which then simply fails to match.
func (s *overloadSelector) certainName(simple, resolved string, decl *FunctionDecl) string {
	if simple == "" || resolved == "" {
		return ""
	}
	if decl != nil && decl.FileTypeNamesAtRisk[simple] {
		return ""
	}
	if len(s.typesBySimple[simple]) > 1 {
		return ""
	}
	return resolved
}

// dominatedBy reports whether some overload in others has fn's parameter type
// at every position whose argument type is unknown.
func (s *overloadSelector) dominatedBy(fn *FunctionDecl, others []*FunctionDecl, call *FunctionCall) bool {
	for _, other := range others {
		if len(other.Parameters) != len(fn.Parameters) {
			continue
		}
		same := true
		for i := range fn.Parameters {
			if s.staticArgumentType(call, i) != "" {
				continue
			}
			if stripGenericSuffix(normalizeJavaTypeName(fn.Parameters[i].Type)) != stripGenericSuffix(normalizeJavaTypeName(other.Parameters[i].Type)) {
				same = false
				break
			}
		}
		if same {
			return true
		}
	}
	return false
}

// matchArguments compares fn's parameters with the call's recorded argument
// types: known counts arguments with a recorded type; exactPositions counts
// typed arguments equal to their parameter type; accepted is false when some
// recorded type cannot be passed to its parameter.
func (s *overloadSelector) matchArguments(fn *FunctionDecl, call *FunctionCall, caller *FunctionDecl) (known, exactPositions int, accepted bool) {
	accepted = true
	for i, param := range fn.Parameters {
		arg := stripGenericSuffix(s.staticArgumentType(call, i))
		paramType := stripGenericSuffix(normalizeJavaTypeName(param.Type))
		if arg == "" {
			continue
		}
		known++
		if s.exactAt(fn, call, i, caller) {
			exactPositions++
			continue
		}
		if s.parameterUncertain(fn, i) {
			continue
		}
		if arg != paramType && !s.argumentAssignable(call, i, caller, arg, paramType) {
			accepted = false
		}
	}
	return known, exactPositions, accepted
}

// javaStringSupertypes are the types a java.lang.String value can be passed as;
// String is final, so nothing else accepts it.
var javaStringSupertypes = map[string]bool{
	javaStringType: true, "Object": true, "CharSequence": true, "Comparable": true,
	"Serializable": true, "Constable": true, "ConstantDesc": true,
}

// argumentAssignable reports whether the argument at position i may be passed
// to a parameter of type param. An argument can rule an overload out only when
// its own type is certain in the caller's file (certainName, or a primitive or
// literal): a type parameter, a local class, an import of a type the graph
// never indexed or an inherited member type may all extend the parameter type
// without the graph knowing. Its ancestry must also be fully recorded.
func (s *overloadSelector) argumentAssignable(call *FunctionCall, i int, caller *FunctionDecl, arg, param string) bool {
	base := strings.TrimRight(arg, "[]")
	if isJavaTypeVariable(param) || param == "Object" {
		return true
	}
	if isJavaPrimitive(base) {
		return s.primitiveArgumentAssignable(arg, param)
	}
	argFQN := s.qualifiedArgumentType(call, i, caller)
	switch {
	case argFQN == "":
		return true
	case argFQN == javaLangString:
		return javaStringSupertypes[strings.TrimRight(param, "[]")] && !strings.HasSuffix(param, "[]")
	case strings.HasSuffix(arg, "[]") || strings.HasSuffix(param, "[]"):
		return true
	case isJavaPrimitive(param):
		return unboxedAssignable(arg, param)
	case len(s.typesBySimple[param]) == 0:
		// Nothing in the graph is named like the parameter: nothing proves
		// the argument is not one.
		return true
	}
	return s.recordedAncestorNamed(argFQN, param)
}

// primitiveArgumentAssignable decides a primitive (or primitive array)
// argument. A reference parameter type the graph knows nothing about and that
// is neither a wrapper, one of the wrappers' supertypes nor another java.lang
// type is never ruled out: it may be a platform supertype of the wrapper this
// check does not list.
func (s *overloadSelector) primitiveArgumentAssignable(arg, param string) bool {
	paramBase := strings.TrimRight(param, "[]")
	if !isJavaPrimitive(paramBase) && len(s.typesBySimple[paramBase]) == 0 && !javaBoxingTargets[paramBase] && !javaLangTypes[paramBase] {
		return true
	}
	return s.assignable(arg, param)
}

// recordedAncestorNamed reports whether argFQN may be passed as a type whose
// simple name is param: true when its ancestry is not fully recorded (nothing
// proves otherwise) or some recorded ancestor carries that name.
func (s *overloadSelector) recordedAncestorNamed(argFQN, param string) bool {
	if !s.knownType(argFQN) || !s.hierarchy.hierarchyComplete(argFQN) {
		return true
	}
	for ancestor := range s.hierarchy.ancestorSet(argFQN) {
		if simpleTypeName(ancestor) == param {
			return true
		}
	}
	return false
}

// javaLangTypes are the java.lang types a source file uses without importing.
var javaLangTypes = map[string]bool{
	"Object": true, "String": true, "CharSequence": true, "Number": true,
	"Integer": true, "Long": true, "Short": true, "Byte": true, "Character": true,
	"Boolean": true, "Double": true, "Float": true, "Void": true, "Class": true,
	"Iterable": true, "Comparable": true, "Runnable": true, "AutoCloseable": true,
	"Cloneable": true, "Throwable": true, "Exception": true, "RuntimeException": true,
	"Error": true, "StringBuilder": true, "StringBuffer": true, "Enum": true,
	"Record": true, "Thread": true, "ClassLoader": true, "Process": true,
}

// resolveQualified picks the fully qualified name a type written as simple in
// package pkg denotes. qualified is the parser's resolution, possibly listing
// alternatives; the first alternative naming a type the graph knows wins, a
// single alternative is trusted as is, and otherwise a java.lang type the file
// did not shadow is assumed. "" means the package cannot be told.
func (s *overloadSelector) resolveQualified(qualified, simple, pkg string) string {
	if qualified != "" {
		alternatives := strings.Split(qualified, javaSupertypeAlternatives)
		if len(alternatives) == 1 {
			return normalizeHierarchyName(alternatives[0])
		}
		// Alternatives are this package, then any on-demand imports, then
		// java.lang. A known type of this package wins; otherwise only a
		// java.lang type with no on-demand import that could supply the
		// name instead is certain.
		if first := normalizeHierarchyName(alternatives[0]); s.knownType(first) {
			return first
		}
		if len(alternatives) == 2 && javaLangTypes[simple] {
			return javaLangPrefix + simple
		}
		return ""
	}
	if pkg != "" && s.knownType(pkg+"."+simple) {
		return pkg + "." + simple
	}
	if javaLangTypes[simple] {
		return javaLangPrefix + simple
	}
	return ""
}

func (s *overloadSelector) knownType(fqn string) bool {
	for _, owner := range s.typesBySimple[simpleTypeName(fqn)] {
		if owner == fqn {
			return true
		}
	}
	return false
}

// qualifiedCallResultType resolves the fully qualified type a call produces:
// the class a constructor creates, or the callee's recorded return type,
// resolved through the callee file's imports. Either is kept only when
// certainName accepts the name.
func (s *overloadSelector) qualifiedCallResultType(target FunctionID, caller *FunctionDecl) string {
	if BaseFunctionName(target.Name) == constructorMethodName {
		fqn := declOwnerFQN(FunctionID{Package: target.Package, Type: target.Type})
		return s.certainName(simpleTypeName(fqn), fqn, caller)
	}
	fn := s.graph.Functions[target.String()]
	if fn == nil || fn.QualifiedReturnType == "" {
		return ""
	}
	base := javaParameterBaseType(normalizeJavaTypeName(fn.ReturnType))
	return s.certainName(base, s.resolveQualified(fn.QualifiedReturnType, base, fn.ID.Package), fn)
}

func callerPackageOf(caller *FunctionDecl) string {
	if caller == nil {
		return ""
	}
	return caller.ID.Package
}

// qualifiedArgumentType resolves the fully qualified static type of the
// argument at idx, or "" when its package cannot be told. A type name the
// caller's source left simple resolves against the caller's package.
func (s *overloadSelector) qualifiedArgumentType(call *FunctionCall, idx int, caller *FunctionDecl) string {
	if idx < len(call.ArgumentSources) && len(call.ArgumentSources[idx]) == 1 {
		return s.qualifiedSourceNodeType(call.ArgumentSources[idx][0], caller, 0)
	}
	if idx < len(call.Arguments) && javaLiteralType(call.Arguments[idx]) == javaStringType {
		return javaLangString
	}
	return ""
}

func (s *overloadSelector) qualifiedSourceNodeType(node SourceNode, caller *FunctionDecl, depth int) string {
	if node.DeclaredType != "" {
		base := javaParameterBaseType(node.DeclaredType)
		resolved := normalizeHierarchyName(base)
		if !strings.Contains(base, ".") {
			resolved = s.resolveQualified("", base, callerPackageOf(caller))
		}
		return s.certainName(simpleTypeName(base), resolved, caller)
	}
	switch node.Type {
	case sourceNodeCallResult:
		if node.CallTarget == nil {
			return ""
		}
		return s.qualifiedCallResultType(*node.CallTarget, caller)
	case sourceNodeValue, sourceNodeExpression:
		if s.staticSourceNodeType(node, depth) == javaStringType {
			return javaLangString
		}
	case sourceNodeVariable:
		if depth < hierarchyMaxDepth && len(node.SourceNodes) == 1 {
			return s.qualifiedSourceNodeType(node.SourceNodes[0], caller, depth+1)
		}
	}
	return ""
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
	if isJavaTypeVariable(param) || isJavaTypeVariable(arg) || len(s.typesBySimple[param]) == 0 {
		return true
	}
	return s.hierarchy.mayHaveAncestorNamed(arg, param, s.typesBySimple)
}

// primitiveAssignable covers widening (JLS 5.1.2) and boxing to the wrapper
// or one of its supertypes.
func primitiveAssignable(arg, param string) bool {
	if stringSliceContains(javaPrimitiveWidening[arg], param) || javaBoxedTypes[arg] == param {
		return true
	}
	switch param {
	case "Serializable", "Comparable", "Constable":
		return true
	case "Number":
		return arg != javaBooleanType && arg != javaCharType
	case "ConstantDesc":
		return arg == javaIntType || arg == javaLongType || arg == javaFloatType || arg == javaDoubleType
	}
	return false
}

// javaBoxingTargets are the reference types primitiveAssignable decides for a
// primitive argument: the wrappers and the interfaces and classes they extend.
var javaBoxingTargets = map[string]bool{
	"Boolean": true, "Byte": true, "Short": true, "Character": true, "Integer": true,
	"Long": true, "Float": true, "Double": true, "Number": true, "Serializable": true,
	"Comparable": true, "Constable": true, "ConstantDesc": true,
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
// parameter type, a literal, a string concatenation, the class a constructor
// call creates, or the return type the graph records for the called method.
// A call result is never typed from its receiver, whose type is not the
// value's type.
func (s *overloadSelector) staticArgumentType(call *FunctionCall, idx int) string {
	if idx < len(call.ArgumentSources) && len(call.ArgumentSources[idx]) > 0 {
		nodes := call.ArgumentSources[idx]
		if len(nodes) != 1 {
			return ""
		}
		return s.staticSourceNodeType(nodes[0], 0)
	}
	if idx >= len(call.Arguments) {
		return ""
	}
	return javaLiteralType(call.Arguments[idx])
}

func (s *overloadSelector) staticSourceNodeType(node SourceNode, depth int) string {
	if node.DeclaredType != "" {
		return normalizeJavaTypeName(node.DeclaredType)
	}
	switch node.Type {
	case sourceNodeCallResult:
		if node.CallTarget == nil {
			return ""
		}
		if BaseFunctionName(node.CallTarget.Name) == constructorMethodName {
			return normalizeJavaTypeName(node.CallTarget.Type)
		}
		return s.callReturnType(*node.CallTarget)
	case sourceNodeValue:
		return javaLiteralType(node.Value)
	case sourceNodeExpression:
		return javaExpressionType(node.Value)
	case sourceNodeVariable:
		// An untyped local takes the type of the single value bound to it.
		if depth < hierarchyMaxDepth && len(node.SourceNodes) == 1 {
			return s.staticSourceNodeType(node.SourceNodes[0], depth+1)
		}
	}
	return ""
}

// callReturnType returns the erased return type the graph records for target:
// its own declaration's, or the one every same-arity overload on its type and
// every resolver-indexed signature agree on. A disagreement, a type variable
// or void leaves the result unknown.
func (s *overloadSelector) callReturnType(target FunctionID) string {
	if s.graph == nil {
		return ""
	}
	if fn := s.graph.Functions[target.String()]; fn != nil {
		return strings.Trim(usableReturnType(fn.ReturnType), unusableReturnType)
	}
	if s.returnTypes == nil {
		s.returnTypes = make(map[string][]string)
		for _, fn := range s.graph.Functions {
			if fn == nil || fn.ID.Type == "" {
				continue
			}
			key := qualifiedMethodArityKey(fn.ID.Package, fn.ID.Type, fn.ID.Name)
			s.returnTypes[key] = appendUnique(s.returnTypes[key], usableReturnType(fn.ReturnType))
		}
	}
	key := qualifiedMethodArityKey(target.Package, target.Type, target.Name)
	types := s.returnTypes[key]
	for _, sig := range s.graph.ExternalMethodSignatures[ExternalMethodSignatureKey(target)] {
		types = appendUnique(types, usableReturnType(sig.ReturnType))
	}
	if len(types) != 1 {
		return ""
	}
	return strings.Trim(types[0], unusableReturnType)
}

// unusableReturnType stands for a return type that settles nothing (void, a
// type variable, none recorded), so it still counts as a disagreeing value.
const unusableReturnType = "\x00"

func usableReturnType(returnType string) string {
	t := stripGenericSuffix(normalizeJavaTypeName(returnType))
	if t == "" || t == javaVoidType || isJavaTypeVariable(t) {
		return unusableReturnType
	}
	return t
}

func appendUnique(values []string, v string) []string {
	if stringSliceContains(values, v) {
		return values
	}
	return append(values, v)
}

// javaLiteralType extends inferJavaArgumentTextType with the literal forms it
// does not type: char, long, float and double literals, and hexadecimal ints.
// `null` stays unknown: it fits every reference parameter equally.
func javaLiteralType(expr string) string {
	expr = strings.TrimSpace(expr)
	switch {
	case len(expr) >= 3 && expr[0] == '\'' && expr[len(expr)-1] == '\'':
		return javaCharType
	case javaNumericLiteral(expr, "lL") || javaHexLiteral(expr, true):
		return javaLongType
	case javaNumericLiteral(expr, "fF"):
		return "float"
	case javaNumericLiteral(expr, "dD") || (javaNumericLiteral(expr, "") && strings.ContainsAny(expr, ".eE") && !strings.HasPrefix(strings.TrimLeft(expr, "+-"), "0x")):
		return "double"
	case javaHexLiteral(expr, false):
		return javaIntType
	}
	return inferJavaArgumentTextType(expr)
}

// javaHexLiteral reports whether expr is a hexadecimal integer literal, with
// the long suffix when long is set and without it otherwise.
func javaHexLiteral(expr string, long bool) bool {
	body := strings.TrimLeft(expr, "+-")
	if !strings.HasPrefix(body, "0x") && !strings.HasPrefix(body, "0X") {
		return false
	}
	body = body[2:]
	hasSuffix := strings.HasSuffix(body, "L") || strings.HasSuffix(body, "l")
	if hasSuffix != long {
		return false
	}
	if long {
		body = body[:len(body)-1]
	}
	if body == "" {
		return false
	}
	for _, r := range body {
		isHex := r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r == '_'
		if !isHex {
			return false
		}
	}
	return true
}

// javaNumericLiteral reports whether expr is a decimal numeric literal ending
// in one of suffixes (or with no suffix when suffixes is empty).
func javaNumericLiteral(expr, suffixes string) bool {
	body := strings.TrimLeft(expr, "+-")
	if suffixes != "" {
		if body == "" || !strings.ContainsRune(suffixes, rune(body[len(body)-1])) {
			return false
		}
		body = body[:len(body)-1]
	}
	if body == "" || strings.HasPrefix(body, "0x") || strings.HasPrefix(body, "0X") {
		return false
	}
	digits := 0
	for i, r := range body {
		if r >= '0' && r <= '9' {
			digits++
			continue
		}
		if !javaNumericLiteralRune(body, i, r) {
			return false
		}
	}
	return digits > 0
}

// javaNumericLiteralRune accepts the non-digit characters a decimal literal
// may hold at position i: a point, an underscore, an exponent marker and the
// exponent's sign.
func javaNumericLiteralRune(body string, i int, r rune) bool {
	switch r {
	case '.', '_':
		return true
	case 'e', 'E':
		return i > 0
	case '+', '-':
		return i > 0 && (body[i-1] == 'e' || body[i-1] == 'E')
	}
	return false
}

// javaExpressionType types the one expression form whose type the text
// settles: a concatenation that starts or ends with a string literal is a
// String. A conditional is left unknown, since its branches may differ, and
// so is a sum whose string literal sits inside a call (s.indexOf("x") + 1).
func javaExpressionType(expr string) string {
	expr = strings.TrimSpace(expr)
	literalEdge := strings.HasPrefix(expr, "\"") || strings.HasSuffix(expr, "\"")
	if literalEdge && strings.Contains(expr, "+") && !strings.Contains(expr, "?") {
		return javaStringType
	}
	return ""
}
