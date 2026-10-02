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

// A gRPC service is registered with the Register<Service>Server function
// protoc-gen-go-grpc generates, or Register<Service>HandlerServer for a
// grpc-gateway: pb.RegisterKeysServer(grpcServer, impl). The generated code
// calls the implementation's methods through the <Service>Server interface,
// so no call edge leads to them. The methods of the value registered are entry
// points; the other methods of its type are not.

const (
	goRegisterPrefix        = "Register"
	goHandlerServerSuffix   = "HandlerServer"
	goServerSuffix          = "Server"
	goContextType           = "context.Context"
	goErrorType             = "error"
	goServerValueDepth      = 8
	goMinRegistrationParams = 2
)

// goPredeclaredTypes are the types of the universe: no method of the
// application is declared on them.
var goPredeclaredTypes = map[string]bool{"any": true, "error": true, "string": true, "bool": true, "int": true, "byte": true}

// goServerValue is what a registered value resolves to: a type (pkg.typ), or
// a constructor function (pkg.ctor) that builds it.
type goServerValue struct {
	pkg, typ, ctor string
}

// serverRegistration records, as an EntryRef, the methods of the value a call
// passes to a catalog server registration. The call must name a function of an
// imported package; the server is its last argument (the second of
// RegisterKeysServer(s, srv), the third of RegisterKeysHandlerServer(ctx, mux,
// srv)). A value whose type cannot be resolved registers nothing.
func (s *goEntryScope) serverRegistration(call *sitter.Node) {
	args := call.ChildByFieldName("arguments")
	if args == nil || int(args.NamedChildCount()) < goMinRegistrationParams {
		return
	}
	pkg, name, entry, ok := s.registerCall(call)
	if !ok {
		return
	}
	service := strings.TrimPrefix(name, goRegisterPrefix)
	service = strings.TrimSuffix(strings.TrimSuffix(service, goHandlerServerSuffix), goServerSuffix)
	if service == "" {
		return
	}
	value := s.serverValue(args.NamedChild(int(args.NamedChildCount())-1), 0)
	ref := EntryRef{
		AllExported: true,
		Interface:   FunctionID{Package: pkg, Type: service + goServerSuffix},
		Kind:        catalogEntryKind(&entry),
	}
	switch {
	case value.pkg == ref.Interface.Package && value.typ == ref.Interface.Type:
		ref.Function = ref.Interface
		ref.Producers = true
	case value.typ != "":
		ref.Function = FunctionID{Package: value.pkg, Type: value.typ}
	case value.ctor != "":
		ref.Function = FunctionID{Package: value.pkg, Name: value.ctor}
		ref.Constructor = true
	default:
		return
	}
	s.analysis.EntryRefs = append(s.analysis.EntryRefs, ref)
}

// registerCall returns the imported package and the name of a call of a
// function of an imported package that a server_registration entry names.
func (s *goEntryScope) registerCall(call *sitter.Node) (pkg, name string, entry entrypoints.Entry, ok bool) {
	function := call.ChildByFieldName(goFieldFunction)
	if function == nil || function.Type() != goNodeSelectorExpression {
		return "", "", entry, false
	}
	operand := function.ChildByFieldName(goFieldOperand)
	field := function.ChildByFieldName(goFieldField)
	if operand == nil || field == nil || operand.Type() != goNodeIdentifier || s.shadowed(operand) {
		return "", "", entry, false
	}
	pkg, ok = s.analysis.Imports[operand.Content(s.src)]
	if !ok {
		return "", "", entry, false
	}
	name = field.Content(s.src)
	entry, ok = entryCatalog().Match(entryLanguageGo, entrypoints.ShapeServerRegistration, pkg, "", name)
	return pkg, name, entry, ok
}

// serverValue resolves an expression to the type of its value, or to the
// constructor that builds it: &impl{}, new(impl), a variable declared from
// either, a parameter or field typed *impl, NewImpl() and pkg.NewImpl().
func (s *goEntryScope) serverValue(expr *sitter.Node, depth int) goServerValue {
	if expr == nil || depth > goServerValueDepth {
		return goServerValue{}
	}
	switch expr.Type() {
	case goNodeParenExpr, goNodeUnaryExpression, goNodePointerType:
		return s.serverValue(firstNamedChild(expr), depth+1)
	case goNodeTypeIdentifier:
		if goPredeclaredTypes[expr.Content(s.src)] {
			return goServerValue{}
		}
		return goServerValue{pkg: s.packagePath, typ: expr.Content(s.src)}
	case goNodeQualifiedType:
		return s.qualifiedServerType(expr)
	case goNodeGenericType:
		return s.serverValue(expr.ChildByFieldName(goFieldType), depth+1)
	case goNodeCompositeLiteral:
		return s.serverValue(expr.ChildByFieldName(goFieldType), depth+1)
	case goNodeCallExpression:
		return s.constructorValue(expr, depth)
	case goNodeIdentifier:
		return s.identifierServerValue(expr, depth)
	case goNodeSelectorExpression:
		owner := s.origin(expr.ChildByFieldName(goFieldOperand), 0)
		field := expr.ChildByFieldName(goFieldField)
		if owner.localType == "" || field == nil {
			return goServerValue{}
		}
		return s.serverValue(s.fields[owner.localType][field.Content(s.src)], depth+1)
	}
	return goServerValue{}
}

func firstNamedChild(node *sitter.Node) *sitter.Node {
	if node.NamedChildCount() == 0 {
		return nil
	}
	return node.NamedChild(0)
}

func (s *goEntryScope) qualifiedServerType(expr *sitter.Node) goServerValue {
	qualifier, name := expr.ChildByFieldName("package"), expr.ChildByFieldName("name")
	if qualifier == nil || name == nil {
		return goServerValue{}
	}
	if pkg, ok := s.analysis.Imports[qualifier.Content(s.src)]; ok {
		return goServerValue{pkg: pkg, typ: name.Content(s.src)}
	}
	return goServerValue{}
}

// constructorValue resolves new(T), NewT() of the package and pkg.NewT() of an
// imported package. A method call, or any other callee, is unknown.
func (s *goEntryScope) constructorValue(call *sitter.Node, depth int) goServerValue {
	function := call.ChildByFieldName(goFieldFunction)
	if function == nil {
		return goServerValue{}
	}
	switch function.Type() {
	case goNodeIdentifier:
		name := function.Content(s.src)
		if name == goBuiltinNew {
			if args := call.ChildByFieldName("arguments"); args != nil && args.NamedChildCount() == 1 && !s.shadowed(function) {
				return s.serverValue(args.NamedChild(0), depth+1)
			}
			return goServerValue{}
		}
		if _, local := s.localDeclarationInScope(function); local {
			return goServerValue{}
		}
		return goServerValue{pkg: s.packagePath, ctor: name}
	case goNodeSelectorExpression:
		operand := function.ChildByFieldName(goFieldOperand)
		field := function.ChildByFieldName(goFieldField)
		if operand == nil || field == nil || operand.Type() != goNodeIdentifier || s.shadowed(operand) {
			return goServerValue{}
		}
		if pkg, ok := s.analysis.Imports[operand.Content(s.src)]; ok {
			return goServerValue{pkg: pkg, ctor: field.Content(s.src)}
		}
	}
	return goServerValue{}
}

// localDeclarationInScope reports whether name is declared in a function
// enclosing id, so that it is not the package-level function it spells.
func (s *goEntryScope) localDeclarationInScope(id *sitter.Node) (*sitter.Node, bool) {
	name := id.Content(s.src)
	for scope := id.Parent(); scope != nil; scope = scope.Parent() {
		switch scope.Type() {
		case goNodeFunctionDecl, goNodeMethodDecl, goNodeFuncLiteral:
			if declared, ok := s.localDeclaration(scope, name); ok {
				return declared, true
			}
		}
	}
	return nil, false
}

func (s *goEntryScope) identifierServerValue(id *sitter.Node, depth int) goServerValue {
	if declared, ok := s.localDeclarationInScope(id); ok {
		return s.serverValue(declared, depth+1)
	}
	if declared, ok := s.packageVars[id.Content(s.src)]; ok {
		return s.serverValue(declared, depth+1)
	}
	return goServerValue{}
}

// recordReturnedTypes sets, on each function the file declares, the types of
// the values it returns as &T{}, T{}, new(T) or a variable declared that way:
// the concrete types behind a constructor whose declared result is an
// interface.
func (s *goEntryScope) recordReturnedTypes(root *sitter.Node) {
	for i := 0; i < int(root.NamedChildCount()); i++ {
		node := root.NamedChild(i)
		if node.Type() != goNodeFunctionDecl || node.ChildByFieldName("body") == nil {
			continue
		}
		name := node.ChildByFieldName("name")
		if name == nil {
			continue
		}
		var types []string
		s.collectReturnedTypes(node.ChildByFieldName("body"), &types)
		if len(types) == 0 {
			continue
		}
		for j := range s.analysis.Functions {
			decl := &s.analysis.Functions[j]
			if decl.ID.Type == "" && decl.ID.Name == name.Content(s.src) && decl.StartLine == int(node.StartPoint().Row)+1 {
				decl.returnedTypes = types
			}
		}
	}
}

func (s *goEntryScope) collectReturnedTypes(node *sitter.Node, types *[]string) {
	switch node.Type() {
	case goNodeFuncLiteral:
		return
	case goNodeReturnStatement:
		results := []*sitter.Node{firstNamedChild(node)}
		if list := results[0]; list != nil && list.Type() == goNodeExpressionList {
			results = results[:0]
			for j := 0; j < int(list.NamedChildCount()); j++ {
				results = append(results, list.NamedChild(j))
			}
		}
		for _, expr := range results {
			if value := s.serverValue(expr, 0); value.typ != "" && value.pkg == s.packagePath {
				*types = append(*types, value.typ)
			}
		}
		return
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		s.collectReturnedTypes(node.NamedChild(i), types)
	}
}

// expandConstructorRefs replaces each constructor reference with a reference
// per concrete type the constructor builds: the types it returns as literals,
// and its declared result type when that is a type other than the interface.
func expandConstructorRefs(graph *CallGraph, refs []EntryRef) []EntryRef {
	out := make([]EntryRef, 0, len(refs))
	for i := range refs {
		ref := &refs[i]
		if ref.Producers {
			out = append(out, producerRefs(graph, ref)...)
			continue
		}
		if !ref.Constructor {
			out = append(out, *ref)
			continue
		}
		decl := graph.Functions[ref.Function.String()]
		if decl == nil {
			continue
		}
		seen := map[FunctionID]bool{}
		add := func(pkg, typ string) {
			id := FunctionID{Package: pkg, Type: strings.TrimPrefix(typ, "*")}
			if id.Type == "" || seen[id] {
				return
			}
			seen[id] = true
			out = append(out, EntryRef{Function: id, AllExported: true, Interface: ref.Interface, Kind: ref.Kind})
		}
		for _, typ := range decl.returnedTypes {
			add(decl.ID.Package, typ)
		}
		if pkg, typ := declaredResultType(decl); typ != "" {
			add(pkg, typ)
		}
	}
	return out
}

// producerRefs returns a reference per concrete type that a function declaring
// the registered interface as its result builds: the value registered is typed
// as the interface, as a parameter of the function that calls the register
// function is, and these functions are what make it.
func producerRefs(graph *CallGraph, ref *EntryRef) []EntryRef {
	var out []EntryRef
	seen := map[FunctionID]bool{}
	for _, decl := range graph.Functions {
		if decl.ID.Type != "" || len(decl.returnedTypes) == 0 {
			continue
		}
		if pkg, typ := declaredResultType(decl); pkg != ref.Interface.Package || typ != ref.Interface.Type {
			continue
		}
		for _, typ := range decl.returnedTypes {
			if id := (FunctionID{Package: decl.ID.Package, Type: typ}); !seen[id] {
				seen[id] = true
				out = append(out, EntryRef{Function: id, AllExported: true, Interface: ref.Interface, Kind: ref.Kind})
			}
		}
	}
	return out
}

// declaredResultType returns the package and name of the first result of a
// function: its own package for a bare name, else the import path the stored
// return type carries.
func declaredResultType(decl *FunctionDecl) (pkg, typ string) {
	result := strings.TrimSpace(decl.ReturnType)
	if strings.HasPrefix(result, "(") {
		result, _, _ = strings.Cut(strings.Trim(result, "()"), ",")
	}
	result = strings.TrimLeft(strings.TrimSpace(result), "*")
	if dot := strings.LastIndex(result, "."); dot > 0 {
		return result[:dot], result[dot+1:]
	}
	if result == goErrorType || strings.ContainsAny(result, " []{}()") {
		return "", ""
	}
	return decl.ID.Package, result
}

// serviceMethodFilter returns the test a method of a registered type must
// pass: its name is a method of the service interface when the graph declares
// it, else its signature is a gRPC handler's.
func serviceMethodFilter(declarations []*FunctionDecl, iface string) func(*FunctionDecl) bool {
	names := make(map[string]bool)
	for _, decl := range declarations {
		if decl.OwnerType == goOwnerInterface && decl.ID.Type == iface {
			names[decl.ID.Name] = true
		}
	}
	if len(names) > 0 {
		return func(decl *FunctionDecl) bool { return names[decl.ID.Name] }
	}
	return hasGRPCSignature
}

// hasGRPCSignature reports whether a method looks like a generated service
// method: unary (ctx context.Context, req *Req) (*Resp, error), or streaming
// ([req *Req,] stream Service_MethodServer) error.
func hasGRPCSignature(decl *FunctionDecl) bool {
	params := decl.Parameters
	results := splitGoResults(decl.ReturnType)
	switch {
	case len(params) == 2 && len(results) == 2:
		return params[0].Type == goContextType && strings.HasPrefix(params[1].Type, "*") &&
			strings.HasPrefix(results[0], "*") && results[1] == goErrorType
	case (len(params) == 1 || len(params) == 2) && len(results) == 1 && results[0] == goErrorType:
		stream := params[len(params)-1].Type
		return strings.Contains(stream, ".") && strings.HasSuffix(stream, goServerSuffix) &&
			(len(params) == 1 || strings.HasPrefix(params[0].Type, "*"))
	}
	return false
}

func splitGoResults(result string) []string {
	result = strings.TrimSpace(result)
	if result == "" {
		return nil
	}
	if strings.HasPrefix(result, "(") && strings.HasSuffix(result, ")") {
		result = result[1 : len(result)-1]
	}
	parts := strings.Split(result, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
