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
	"path/filepath"
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
// srv)). A value whose type cannot be resolved registers nothing, and neither
// does a registration with no evidence that it is a gRPC one (see
// acceptRegistrations).
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
	registrar := 0
	if strings.HasSuffix(name, goHandlerServerSuffix) {
		registrar = 1
	}
	if int(args.NamedChildCount()) <= registrar+1 {
		return
	}
	value := s.serverValue(args.NamedChild(int(args.NamedChildCount())-1), 0)
	ref := EntryRef{
		AllExported: true,
		Interface:   FunctionID{Package: pkg, Type: service + goServerSuffix},
		Kind:        catalogEntryKind(&entry),
	}
	ref.GRPCRegistrar, ref.RegistrarFunc, ref.RegistrarIndex = s.registrarEvidence(args.NamedChild(registrar))
	ref.FileImportsGRPC = s.registrarIsUntypedVariable(args.NamedChild(registrar))
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

const (
	goGRPCPackage      = "google.golang.org/grpc"
	goGatewayPackage   = "github.com/grpc-ecosystem/grpc-gateway"
	goSeveralProducers = 2
)

// goRegistrarType reports whether a type or constructor of pkg is what a
// generated register function takes first: a *grpc.Server or
// grpc.ServiceRegistrar, or a grpc-gateway runtime.ServeMux.
func goRegistrarType(pkg, typ, ctor string) bool {
	switch {
	case pkg == goGRPCPackage:
		return typ == "Server" || typ == "ServiceRegistrar" || ctor == "NewServer"
	case pkg == goGatewayPackage || strings.HasPrefix(pkg, goGatewayPackage+"/"):
		return typ == "ServeMux" || ctor == "NewServeMux"
	}
	return false
}

// registrarEvidence resolves the registrar argument of a register call. It
// says whether the argument is a gRPC server or gateway mux by its type
// here; otherwise, when it comes from a function, which function and which of
// its results, for the builder to read the declared result type.
func (s *goEntryScope) registrarEvidence(expr *sitter.Node) (confirmed bool, fn FunctionID, index int) {
	value := s.serverValue(expr, 0)
	if goRegistrarType(value.pkg, value.typ, value.ctor) {
		return true, FunctionID{}, 0
	}
	if expr != nil && expr.Type() == goNodeIdentifier {
		if call, position, ok := s.multiValueSource(expr); ok {
			if source := s.constructorValue(call, 0); source.ctor != "" {
				return false, FunctionID{Package: source.pkg, Name: source.ctor}, position
			}
		}
	}
	if value.ctor != "" {
		return false, FunctionID{Package: value.pkg, Name: value.ctor}, 0
	}
	return false, FunctionID{}, 0
}

// registrarIsUntypedVariable reports whether the registrar is a variable whose
// type is not known and the file imports google.golang.org/grpc, as in
// `listen, server, err := helper.Setup(); pb.RegisterXServer(server, impl)`.
func (s *goEntryScope) registrarIsUntypedVariable(expr *sitter.Node) bool {
	if expr == nil || expr.Type() != goNodeIdentifier || s.serverValue(expr, 0).typ != "" {
		return false
	}
	for _, path := range s.analysis.Imports {
		if path == goGRPCPackage {
			return true
		}
	}
	return false
}

// multiValueSource finds the declaration `a, b, err := f()` of the name in
// the functions enclosing id, and returns the call and the name's position.
func (s *goEntryScope) multiValueSource(id *sitter.Node) (*sitter.Node, int, bool) {
	name := id.Content(s.src)
	for scope := id.Parent(); scope != nil; scope = scope.Parent() {
		switch scope.Type() {
		case goNodeFunctionDecl, goNodeMethodDecl, goNodeFuncLiteral:
			if call, position := s.findMultiValue(scope.ChildByFieldName("body"), name); call != nil {
				return call, position, true
			}
		}
	}
	return nil, 0, false
}

func (s *goEntryScope) findMultiValue(node *sitter.Node, name string) (*sitter.Node, int) {
	if node == nil || node.Type() == goNodeFuncLiteral {
		return nil, 0
	}
	if node.Type() == goNodeShortVarDeclaration {
		left, right := node.ChildByFieldName(goFieldLeft), node.ChildByFieldName(goFieldRight)
		if left != nil && right != nil && right.Type() == goNodeExpressionList && right.NamedChildCount() == 1 &&
			right.NamedChild(0).Type() == goNodeCallExpression {
			for i := 0; i < int(left.NamedChildCount()); i++ {
				if left.NamedChild(i).Content(s.src) == name {
					return right.NamedChild(0), i
				}
			}
		}
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		if call, position := s.findMultiValue(node.NamedChild(i), name); call != nil {
			return call, position
		}
	}
	return nil, 0
}

// acceptRegistrations drops the service registrations with no evidence that
// they are gRPC ones, so a project's own httpx.RegisterHTTPServer(mux, srv)
// roots nothing. Evidence is any of: the generated interface <X>Server is in
// the graph; a generated file (*.pb.go) of the callee's package is; the
// registrar argument is a grpc.Server, grpc.ServiceRegistrar or gateway
// ServeMux, by its type in the file or by the declared result of the function
// it comes from.
func acceptRegistrations(graph *CallGraph, refs []EntryRef) []EntryRef {
	out := refs[:0:0]
	for i := range refs {
		ref := &refs[i]
		if ref.Interface == (FunctionID{}) || registrationEvidence(graph, ref) {
			out = append(out, *ref)
		}
	}
	return out
}

func registrationEvidence(graph *CallGraph, ref *EntryRef) bool {
	if ref.GRPCRegistrar {
		return true
	}
	resolved := false
	if decl := graph.Functions[ref.RegistrarFunc.String()]; ref.RegistrarFunc != (FunctionID{}) && decl != nil {
		resolved = true
		if registrarResultIsGRPC(decl, ref.RegistrarIndex) {
			return true
		}
	}
	if ref.FileImportsGRPC && !resolved {
		return true
	}
	for _, decl := range graph.Functions {
		if decl.ID.Package != ref.Interface.Package {
			continue
		}
		if (decl.OwnerType == goOwnerInterface && decl.ID.Type == ref.Interface.Type) || isGeneratedProtoFile(decl.FilePath) {
			return true
		}
	}
	return false
}

// registrarResultIsGRPC reads the declared result the registrar comes from.
func registrarResultIsGRPC(decl *FunctionDecl, index int) bool {
	results := splitGoResults(decl.ReturnType)
	if index >= len(results) {
		return false
	}
	result := strings.TrimLeft(results[index], "*")
	dot := strings.LastIndex(result, ".")
	return dot > 0 && goRegistrarType(result[:dot], result[dot+1:], "")
}

func isGeneratedProtoFile(path string) bool {
	return strings.HasSuffix(path, ".pb.go")
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

// expandConstructorRefs replaces each constructor reference, and each
// reference to the registered interface itself, with a reference per concrete
// type it stands for: the types a constructor returns as literals and its
// declared result type, or the types the producers of the interface build.
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
	var producers []*FunctionDecl
	for _, decl := range graph.Functions {
		if decl.ID.Type != "" || len(decl.returnedTypes) == 0 || isTestDeclaration(decl) || isDoubleProducer(decl) {
			continue
		}
		if pkg, typ := declaredResultType(decl); pkg == ref.Interface.Package && typ == ref.Interface.Type {
			producers = append(producers, decl)
		}
	}
	producers = calledProducers(graph, producers)
	var out []EntryRef
	seen := map[FunctionID]bool{}
	for _, decl := range producers {
		for _, typ := range decl.returnedTypes {
			if id := (FunctionID{Package: decl.ID.Package, Type: typ}); !seen[id] {
				seen[id] = true
				out = append(out, EntryRef{Function: id, AllExported: true, Interface: ref.Interface, Kind: ref.Kind})
			}
		}
	}
	return out
}

var goDoublePathSegments = map[string]bool{"mock": true, "mocks": true, "fake": true, "fakes": true, "testutil": true}

// isDoubleProducer recognizes a test double's constructor by its path or name.
func isDoubleProducer(decl *FunctionDecl) bool {
	for _, segment := range strings.Split(filepath.ToSlash(decl.FilePath), "/") {
		if goDoublePathSegments[segment] {
			return true
		}
	}
	for _, prefix := range []string{"newMock", "NewMock", "newFake", "NewFake"} {
		if strings.HasPrefix(decl.ID.Name, prefix) {
			return true
		}
	}
	return false
}

// calledProducers keeps the producers some function of the graph calls, when
// there are any: a service is built where the application calls its
// constructor. With none called, all are kept.
func calledProducers(graph *CallGraph, producers []*FunctionDecl) []*FunctionDecl {
	if len(producers) < goSeveralProducers {
		return producers
	}
	called := map[string]bool{}
	for _, decl := range graph.Functions {
		for i := range decl.Calls {
			called[decl.Calls[i].Callee.String()] = true
		}
	}
	var kept []*FunctionDecl
	for _, decl := range producers {
		if called[decl.ID.String()] {
			kept = append(kept, decl)
		}
	}
	if len(kept) == 0 {
		return producers
	}
	return kept
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
	service := strings.TrimSuffix(iface, goServerSuffix)
	names := make(map[string]bool)
	for _, decl := range declarations {
		if decl.OwnerType == goOwnerInterface && decl.ID.Type == iface {
			names[decl.ID.Name] = true
		}
	}
	if len(names) > 0 {
		return func(decl *FunctionDecl) bool { return names[decl.ID.Name] }
	}
	return func(decl *FunctionDecl) bool { return hasGRPCSignature(decl, service) }
}

// hasGRPCSignature reports whether a method looks like a generated service
// method: unary (ctx context.Context, req *Req) (*Resp, error), or streaming
// ([req *Req,] stream Service_MethodServer) error, the stream type named
// for the service.
func hasGRPCSignature(decl *FunctionDecl, service string) bool {
	params := decl.Parameters
	results := splitGoResults(decl.ReturnType)
	switch {
	case len(params) == 2 && len(results) == 2:
		return params[0].Type == goContextType && strings.HasPrefix(params[1].Type, "*") &&
			strings.HasPrefix(results[0], "*") && results[1] == goErrorType
	case (len(params) == 1 || len(params) == 2) && len(results) == 1 && results[0] == goErrorType:
		stream := params[len(params)-1].Type
		_, name, qualified := strings.Cut(stream[strings.LastIndex(stream, "/")+1:], ".")
		return qualified && strings.HasPrefix(name, service+"_") && strings.HasSuffix(name, goServerSuffix) &&
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
