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
	"strings"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/scanoss/crypto-finder/internal/callgraph/entrypoints"
)

// Entry points of Go code: what the runtime, net/http, a router, gRPC or
// cobra calls. The frameworks and the names they declare are the catalog's
// (entrypoints/go); this file recognizes the shapes: a registration call on a
// value from the framework's package, a handler field of a framework struct
// literal, an embedded framework type, a method with a framework interface's
// signature. init functions and package variable initializers are Go
// semantics and stay here.

const (
	goNodeInterpretedString = "interpreted_string_literal"
	goNodeStructType        = "struct_type"
	goNodeQualifiedType     = "qualified_type"
	goNodeMethodDecl        = "method_declaration"
	goNodeFunctionDecl      = "function_declaration"
	goNodeTypeDeclaration   = "type_declaration"
	goNodeVarDeclaration    = "var_declaration"
	goNodePackageIdentifier = "package_identifier"
	// goOriginDepth bounds how many declarations goEntryScope.origin follows.
	goOriginDepth = 8
)

// goOrigin is where a Go value comes from: an imported package (pkg), or a
// type the file declares (localType).
type goOrigin struct {
	pkg, localType string
	// typeName is the name a package-qualified type gives (Command for
	// cobra.Command), set only when the value's type is written that way.
	typeName string
}

// goEntryScope resolves the values of one file to their packages, through
// its imports and the declarations in scope.
type goEntryScope struct {
	analysis *FileAnalysis
	src      []byte
	// fields maps a struct type the file declares to its fields' types.
	fields map[string]map[string]*sitter.Node
	// packageVars maps a package-level variable the file declares to its
	// value, or its type when it has no value.
	packageVars map[string]*sitter.Node
}

// applyGoEntryRules marks the file's entry points: init functions and package
// variable initializers, which the runtime runs before main; methods with a
// catalog interface signature (ServeHTTP); and, as EntryRefs because they may
// be declared in another file of the package, registered handlers, handler
// fields and the methods of a type that embeds a catalog type.
func applyGoEntryRules(root *sitter.Node, src []byte, packagePath string, analysis *FileAnalysis) {
	scope := newGoEntryScope(root, src, analysis)
	for i := range analysis.Functions {
		decl := &analysis.Functions[i]
		switch {
		case decl.ID.Type == "" && (strings.HasPrefix(decl.ID.Name, "<init:") || strings.HasPrefix(decl.ID.Name, "<varinit:")):
			markEntry(decl, RootKindMain)
		case decl.ID.Type != "":
			if kind, ok := scope.interfaceMethodKind(decl); ok {
				markEntry(decl, kind)
			}
		}
	}
	scope.registeredHandlers(root, packagePath)
	scope.callbackReferences(root, packagePath)
}

func newGoEntryScope(root *sitter.Node, src []byte, analysis *FileAnalysis) *goEntryScope {
	s := &goEntryScope{analysis: analysis, src: src, fields: make(map[string]map[string]*sitter.Node), packageVars: make(map[string]*sitter.Node)}
	for i := 0; i < int(root.NamedChildCount()); i++ {
		decl := root.NamedChild(i)
		for j := 0; j < int(decl.NamedChildCount()); j++ {
			spec := decl.NamedChild(j)
			switch {
			case decl.Type() == goNodeTypeDeclaration && spec.Type() == goNodeTypeSpec:
				s.recordStructFields(spec)
			case decl.Type() == goNodeVarDeclaration && spec.Type() == goNodeVarSpec:
				s.recordVarSpec(spec, s.packageVars)
			}
		}
	}
	return s
}

func (s *goEntryScope) recordStructFields(spec *sitter.Node) {
	name := spec.ChildByFieldName("name")
	typ := spec.ChildByFieldName(goFieldType)
	if name == nil || typ == nil || typ.Type() != goNodeStructType || typ.NamedChildCount() == 0 {
		return
	}
	fields := make(map[string]*sitter.Node)
	list := typ.NamedChild(0)
	for i := 0; i < int(list.NamedChildCount()); i++ {
		field := list.NamedChild(i)
		fieldType := field.ChildByFieldName(goFieldType)
		if field.Type() != javaNodeFieldDeclaration || fieldType == nil {
			continue
		}
		for j := 0; j < int(field.NamedChildCount()); j++ {
			if id := field.NamedChild(j); id.Type() == goNodeFieldIdentifier {
				fields[id.Content(s.src)] = fieldType
			}
		}
	}
	s.fields[name.Content(s.src)] = fields
}

// recordVarSpec records each name a var spec declares with its value, or its
// type when it has no value.
func (s *goEntryScope) recordVarSpec(spec *sitter.Node, into map[string]*sitter.Node) {
	typ := spec.ChildByFieldName(goFieldType)
	values := spec.ChildByFieldName("value")
	index := 0
	for i := 0; i < int(spec.NamedChildCount()); i++ {
		id := spec.NamedChild(i)
		if id.Type() != goNodeIdentifier {
			continue
		}
		if value := goListElement(values, index); value != nil {
			into[id.Content(s.src)] = value
		} else if typ != nil {
			into[id.Content(s.src)] = typ
		}
		index++
	}
}

func goListElement(list *sitter.Node, index int) *sitter.Node {
	switch {
	case list == nil:
		return nil
	case list.Type() != goNodeExpressionList:
		if index == 0 {
			return list
		}
		return nil
	case index < int(list.NamedChildCount()):
		return list.NamedChild(index)
	}
	return nil
}

// origin returns where an expression's value comes from: http for
// http.NewServeMux(), chi for r where r := chi.NewRouter(), the local type
// api for signer where signer := &api{}.
func (s *goEntryScope) origin(expr *sitter.Node, depth int) goOrigin {
	if expr == nil || depth > goOriginDepth {
		return goOrigin{}
	}
	switch expr.Type() {
	case goNodeIdentifier:
		return s.identifierOrigin(expr, depth)
	case goNodeTypeIdentifier:
		return goOrigin{localType: expr.Content(s.src)}
	case goNodeSelectorExpression, goNodeQualifiedType:
		return s.selectorOrigin(expr, depth)
	case goNodeCallExpression:
		return s.origin(expr.ChildByFieldName(goFieldFunction), depth+1)
	case goNodeCompositeLiteral, goNodeGenericType:
		return s.origin(expr.ChildByFieldName(goFieldType), depth+1)
	case goNodeUnaryExpression:
		return s.origin(expr.ChildByFieldName("operand"), depth+1)
	case goNodePointerType, goNodeParenExpr:
		if expr.NamedChildCount() > 0 {
			return s.origin(expr.NamedChild(0), depth+1)
		}
	}
	return goOrigin{}
}

// identifierOrigin resolves a name to its declaration in the enclosing
// functions, else a package variable, else an import.
func (s *goEntryScope) identifierOrigin(id *sitter.Node, depth int) goOrigin {
	name := id.Content(s.src)
	for scope := id.Parent(); scope != nil; scope = scope.Parent() {
		switch scope.Type() {
		case goNodeFunctionDecl, goNodeMethodDecl, goNodeFuncLiteral:
			if declared, ok := s.localDeclaration(scope, name); ok {
				return s.origin(declared, depth+1)
			}
		}
	}
	if declared, ok := s.packageVars[name]; ok {
		return s.origin(declared, depth+1)
	}
	return goOrigin{pkg: s.analysis.Imports[name]}
}

// selectorOrigin resolves pkg.Name to the imported package, and x.field to
// the type of the field of x's type, or x's package for a value from one.
func (s *goEntryScope) selectorOrigin(expr *sitter.Node, depth int) goOrigin {
	operand := expr.ChildByFieldName(goFieldOperand)
	field := expr.ChildByFieldName(goFieldField)
	if expr.Type() == goNodeQualifiedType {
		operand, field = expr.ChildByFieldName("package"), expr.ChildByFieldName("name")
	}
	if operand == nil || field == nil {
		return goOrigin{}
	}
	if operand.Type() == goNodeIdentifier || operand.Type() == goNodePackageIdentifier {
		if pkg, ok := s.analysis.Imports[operand.Content(s.src)]; ok && !s.shadowed(operand) {
			if expr.Type() == goNodeQualifiedType {
				return goOrigin{pkg: pkg, typeName: field.Content(s.src)}
			}
			return goOrigin{pkg: pkg}
		}
	}
	owner := s.origin(operand, depth+1)
	if owner.localType != "" {
		return s.origin(s.fields[owner.localType][field.Content(s.src)], depth+1)
	}
	return goOrigin{pkg: owner.pkg}
}

// shadowed reports whether a name that an import binds is declared in an
// enclosing function.
func (s *goEntryScope) shadowed(id *sitter.Node) bool {
	for scope := id.Parent(); scope != nil; scope = scope.Parent() {
		switch scope.Type() {
		case goNodeFunctionDecl, goNodeMethodDecl, goNodeFuncLiteral:
			if _, ok := s.localDeclaration(scope, id.Content(s.src)); ok {
				return true
			}
		}
	}
	return false
}

// localDeclaration finds name among a function's receiver, parameters and
// variables, and returns its value or type.
func (s *goEntryScope) localDeclaration(fn *sitter.Node, name string) (*sitter.Node, bool) {
	for _, field := range []string{"receiver", "parameters"} {
		if typ, ok := s.parameterType(fn.ChildByFieldName(field), name); ok {
			return typ, true
		}
	}
	return s.bodyDeclaration(fn.ChildByFieldName("body"), name)
}

// bodyDeclaration finds a variable a function body declares, outside the
// function literals it holds, and returns its value or type.
func (s *goEntryScope) bodyDeclaration(node *sitter.Node, name string) (*sitter.Node, bool) {
	if node == nil {
		return nil, false
	}
	switch node.Type() {
	case goNodeShortVarDeclaration:
		left := node.ChildByFieldName(goFieldLeft)
		for i := 0; left != nil && i < int(left.NamedChildCount()); i++ {
			if left.NamedChild(i).Content(s.src) == name {
				return goListElement(node.ChildByFieldName(goFieldRight), i), true
			}
		}
	case goNodeVarSpec:
		vars := make(map[string]*sitter.Node)
		s.recordVarSpec(node, vars)
		if value, declared := vars[name]; declared {
			return value, true
		}
	case goNodeFuncLiteral:
		return nil, false
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		if value, found := s.bodyDeclaration(node.NamedChild(i), name); found {
			return value, true
		}
	}
	return nil, false
}

func (s *goEntryScope) parameterType(params *sitter.Node, name string) (*sitter.Node, bool) {
	for i := 0; params != nil && i < int(params.NamedChildCount()); i++ {
		param := params.NamedChild(i)
		if param.Type() != goNodeParameterDecl {
			continue
		}
		for j := 0; j < int(param.NamedChildCount()); j++ {
			if id := param.NamedChild(j); id.Type() == goNodeIdentifier && id.Content(s.src) == name {
				return param.ChildByFieldName(goFieldType), true
			}
		}
	}
	return nil, false
}

// interfaceMethodKind reports whether a method has the name and parameter
// types of a catalog interface method, each parameter type resolved through
// the file's imports: ServeHTTP(http.ResponseWriter, *http.Request).
func (s *goEntryScope) interfaceMethodKind(decl *FunctionDecl) (RootKind, bool) {
	entries := entryCatalog().Entries(entryLanguageGo, entrypoints.ShapeInterfaceMethod)
	for i := range entries {
		entry := &entries[i]
		if !entry.HasName(decl.ID.Name) || len(decl.Parameters) != len(entry.ParameterTypes) {
			continue
		}
		matches := true
		for j, want := range entry.ParameterTypes {
			matches = matches && s.parameterMatches(entry, decl.Parameters[j].Type, want)
		}
		if matches {
			return catalogEntryKind(entry), true
		}
	}
	return "", false
}

func (s *goEntryScope) parameterMatches(entry *entrypoints.Entry, written, want string) bool {
	pointer := strings.HasPrefix(want, "*")
	if strings.HasPrefix(written, "*") != pointer {
		return false
	}
	qualifier, name, ok := strings.Cut(strings.TrimPrefix(written, "*"), ".")
	return ok && name == strings.TrimPrefix(want, "*") && entry.Covers(s.analysis.Imports[qualifier])
}

// registeredHandlers records as EntryRefs the handlers the file passes to a
// catalog registration call or handler field, and the methods of the types
// that embed a catalog supertype.
func (s *goEntryScope) registeredHandlers(root *sitter.Node, packagePath string) {
	analysis := s.analysis
	var walk func(node *sitter.Node)
	walk = func(node *sitter.Node) {
		switch node.Type() {
		case goNodeCallExpression:
			if entry, ok := s.registration(node); ok {
				args := node.ChildByFieldName("arguments")
				for i := 0; i < int(args.NamedChildCount()); i++ {
					analysis.EntryRefs = s.appendHandlerRef(analysis.EntryRefs, args.NamedChild(i), packagePath, catalogEntryKind(&entry))
				}
			}
		case goNodeCompositeLiteral:
			s.handlerFields(node, packagePath)
		case goNodeAssignmentStmt:
			s.assignedHandlerFields(node, packagePath)
		case goNodeTypeSpec:
			s.embeddedSupertypes(node, packagePath)
		}
		for i := 0; i < int(node.NamedChildCount()); i++ {
			walk(node.NamedChild(i))
		}
	}
	walk(root)
}

// registration returns the catalog entry a call registers handlers with:
// http.HandleFunc("/x", h), mux.Handle("/x", h) on a ServeMux,
// r.Get("/x", h) on a chi router. The receiver must come from the entry's
// package.
func (s *goEntryScope) registration(call *sitter.Node) (entrypoints.Entry, bool) {
	function := call.ChildByFieldName(goFieldFunction)
	args := call.ChildByFieldName("arguments")
	if function == nil || args == nil || function.Type() != goNodeSelectorExpression {
		return entrypoints.Entry{}, false
	}
	field := function.ChildByFieldName(goFieldField)
	catalog := entryCatalog()
	if field == nil || !catalog.Named(entryLanguageGo, entrypoints.ShapeRegistrationCall, field.Content(s.src)) {
		return entrypoints.Entry{}, false
	}
	operand := function.ChildByFieldName(goFieldOperand)
	var pkg string
	if pkgPath, ok := s.analysis.Imports[operand.Content(s.src)]; ok && operand.Type() == goNodeIdentifier && !s.shadowed(operand) {
		pkg = pkgPath
	} else {
		pkg = s.origin(operand, 0).pkg
	}
	entry, ok := catalog.Match(entryLanguageGo, entrypoints.ShapeRegistrationCall, pkg, "", field.Content(s.src))
	if !ok || (entry.Path == entrypoints.PathRequired && !goRegistersPath(args)) {
		return entrypoints.Entry{}, false
	}
	return entry, true
}

// goRegistersPath reports whether a registration's first argument can be a
// path or a method (a literal, a constant, http.MethodGet, []string{...})
// followed by at least one more argument.
func goRegistersPath(args *sitter.Node) bool {
	if args.NamedChildCount() < 2 {
		return false
	}
	switch args.NamedChild(0).Type() {
	case goNodeInterpretedString, "raw_string_literal", goNodeIdentifier, goNodeSelectorExpression, goNodeCompositeLiteral:
		return true
	}
	return false
}

// handlerFields records the handlers of a catalog struct literal, as the
// RunE of &cobra.Command{RunE: run}.
func (s *goEntryScope) handlerFields(literal *sitter.Node, packagePath string) {
	typ := literal.ChildByFieldName(goFieldType)
	body := literal.ChildByFieldName("body")
	if typ == nil || body == nil || typ.Type() != goNodeQualifiedType {
		return
	}
	name := typ.ChildByFieldName("name")
	if name == nil {
		return
	}
	pkg := s.origin(typ, 0).pkg
	entries := entryCatalog().Entries(entryLanguageGo, entrypoints.ShapeHandlerField)
	for i := range entries {
		entry := &entries[i]
		if !entry.Covers(pkg) || !entry.HasType(name.Content(s.src)) {
			continue
		}
		for j := 0; j < int(body.NamedChildCount()); j++ {
			element := body.NamedChild(j)
			if element.Type() == "keyed_element" && element.NamedChildCount() == 2 && entry.HasName(element.NamedChild(0).Content(s.src)) {
				s.analysis.EntryRefs = s.appendHandlerRef(s.analysis.EntryRefs, element.NamedChild(1), packagePath, catalogEntryKind(entry))
			}
		}
	}
}

// embeddedSupertypes records the methods of a struct type that embeds a
// catalog type from an imported package: every exported method of a type
// embedding a generated gRPC Unimplemented...Server.
func (s *goEntryScope) embeddedSupertypes(spec *sitter.Node, packagePath string) {
	name := spec.ChildByFieldName("name")
	typ := spec.ChildByFieldName(goFieldType)
	if name == nil || typ == nil || typ.Type() != goNodeStructType || typ.NamedChildCount() == 0 {
		return
	}
	entries := entryCatalog().Entries(entryLanguageGo, entrypoints.ShapeSupertype)
	for _, embedded := range goEmbeddedQualifiedTypes(typ) {
		typeName := embedded.ChildByFieldName("name").Content(s.src)
		pkg := s.origin(embedded, 0).pkg
		for i := range entries {
			entry := &entries[i]
			if entry.Covers(pkg) && entry.HasType(typeName) {
				s.analysis.EntryRefs = append(s.analysis.EntryRefs, supertypeRefs(entry, FunctionID{Package: packagePath, Type: name.Content(s.src)})...)
			}
		}
	}
}

// goEmbeddedQualifiedTypes returns the embedded fields of a struct type that
// name a type of an imported package, as pb.UnimplementedKeysServer or
// *pb.UnimplementedKeysServer.
func goEmbeddedQualifiedTypes(typ *sitter.Node) []*sitter.Node {
	var out []*sitter.Node
	fields := typ.NamedChild(0)
	for i := 0; i < int(fields.NamedChildCount()); i++ {
		field := fields.NamedChild(i)
		embedded := field.ChildByFieldName(goFieldType)
		if field.Type() != javaNodeFieldDeclaration || field.ChildByFieldName("name") != nil || embedded == nil {
			continue
		}
		if embedded.Type() == goNodePointerType && embedded.NamedChildCount() > 0 {
			embedded = embedded.NamedChild(0)
		}
		if embedded.Type() == goNodeQualifiedType && embedded.ChildByFieldName("name") != nil {
			out = append(out, embedded)
		}
	}
	return out
}

// supertypeRefs names the methods of owner an entry makes entry points:
// every exported one for names "*", else the ones it names.
func supertypeRefs(entry *entrypoints.Entry, owner FunctionID) []EntryRef {
	kind := catalogEntryKind(entry)
	if entry.HasName(entrypoints.AnyName) {
		return []EntryRef{{Function: owner, AllExported: true, Kind: kind}}
	}
	refs := make([]EntryRef, 0, len(entry.Names))
	for _, name := range entry.Names {
		refs = append(refs, EntryRef{Function: FunctionID{Package: owner.Package, Type: owner.Type, Name: name}, Kind: kind})
	}
	return refs
}

// appendHandlerRef adds the function an argument names: a function of the
// package, an exported function of an imported package, or a method value
// whose receiver's type the file declares (signer.sign where signer :=
// &api{}), also through a conversion such as http.HandlerFunc(h). A method
// value whose receiver type cannot be resolved is dropped: matching the
// method by name alone would make every same-named method an entry point.
func (s *goEntryScope) appendHandlerRef(refs []EntryRef, arg *sitter.Node, packagePath string, kind RootKind) []EntryRef {
	if arg.Type() == "literal_element" && arg.NamedChildCount() == 1 {
		arg = arg.NamedChild(0)
	}
	switch arg.Type() {
	case goNodeIdentifier:
		return append(refs, EntryRef{Function: FunctionID{Package: packagePath, Name: arg.Content(s.src)}, Kind: kind})
	case goNodeSelectorExpression:
		operand := arg.ChildByFieldName(goFieldOperand)
		field := arg.ChildByFieldName(goFieldField)
		if operand == nil || field == nil {
			return refs
		}
		if imported, ok := s.analysis.Imports[operand.Content(s.src)]; ok && operand.Type() == goNodeIdentifier && !s.shadowed(operand) {
			return append(refs, EntryRef{Function: FunctionID{Package: imported, Name: field.Content(s.src)}, Kind: kind})
		}
		if owner := s.origin(operand, 0); owner.localType != "" {
			return append(refs, EntryRef{Function: FunctionID{Package: packagePath, Type: owner.localType, Name: field.Content(s.src)}, Kind: kind})
		}
	case goNodeCallExpression, goNodeTypeConversion:
		if inner := arg.ChildByFieldName("arguments"); inner != nil && inner.NamedChildCount() == 1 {
			return s.appendHandlerRef(refs, inner.NamedChild(0), packagePath, kind)
		}
	}
	return refs
}
