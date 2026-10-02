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
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"unicode"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/scanoss/crypto-finder/internal/callgraph/entrypoints"
)

// Entry points of JavaScript and TypeScript code: what a web framework, React
// or Node itself calls, which no call expression in the application leads to.
// The frameworks and the names they declare are the catalog's
// (entrypoints/node); this file recognizes the shapes: a registration call on
// a receiver from the framework, an imported decorator, a file convention.
// The package.json main, module, exports and bin entries, require.main ===
// module and JSX are Node and React semantics and stay here.

const (
	nodeArgumentsNode       = "arguments"
	nodeStringNode          = "string"
	nodeTemplateString      = "template_string"
	nodeDefaultKeyword      = "default"
	nodeIfStatement         = "if_statement"
	nodeLexicalDeclaration  = "lexical_declaration"
	nodeVariableDeclaration = "variable_declaration"
	nodeRequiredParameter   = "required_parameter"
	nodeOptionalParameter   = "optional_parameter"
	nodeRequireFunction     = "require"
	nodeExpressionStatement = rustNodeExpressionStatement
	nodeForInStatement      = "for_in_statement"
	nodeShorthandPattern    = "shorthand_property_identifier_pattern"
	// nodeOriginDepth bounds how many assignments nodeOrigin follows.
	nodeOriginDepth = 8
)

// nodeEntryRefs lists the entry points one file declares or registers.
func nodeEntryRefs(root *sitter.Node, src []byte, filePath, modulePath string, bindings nodeBindings) []EntryRef {
	refs := nodeRegisteredHandlers(root, src, modulePath, bindings)
	exports, defaultExport := nodeModuleExports(root, src, modulePath)
	refs = append(refs, nodeFileConventionEntries(filePath, exports, defaultExport)...)
	role := nodePackageEntryRole(filePath)
	if role == nodeLibraryEntry {
		for _, id := range exports {
			refs = append(refs, EntryRef{Function: id, Kind: RootKindFrameworkEntry})
		}
	}
	if role != nodeNotAnEntry || nodeRunsAsMain(root, src) || nodeHasScriptShebang(filePath, src) {
		refs = append(refs, EntryRef{Function: FunctionID{Package: modulePath, Name: moduleInitMethodName}, Kind: RootKindMain})
	}
	return refs
}

// nodeRegisteredHandlers returns the functions the file registers with a
// framework router, and its methods with a framework entry decorator.
func nodeRegisteredHandlers(root *sitter.Node, src []byte, modulePath string, bindings nodeBindings) []EntryRef {
	var out []EntryRef
	var walk func(node *sitter.Node)
	walk = func(node *sitter.Node) {
		switch node.Type() {
		case nodeCallExpression:
			if entry, ok := nodeRouteRegistration(node, src, bindings); ok {
				for _, id := range nodeHandlerArguments(node, src, modulePath, bindings) {
					out = append(out, EntryRef{Function: id, Kind: catalogEntryKind(&entry)})
				}
			}
		case javaNodeClassDeclaration, nodeClassExpression:
			out = append(out, nodeDecoratedEntryMethods(node, src, modulePath, bindings)...)
		}
		for i := 0; i < int(node.NamedChildCount()); i++ {
			walk(node.NamedChild(i))
		}
	}
	walk(root)
	return out
}

// nodeRouteRegistration returns the catalog entry a call registers a handler
// with: app.get('/x', h), router.post(`/y`, h), app.use(h),
// app.route('/x').get(h). The receiver must come from the package the entry
// names, through the file's imports: app = express(), router =
// express.Router(), a parameter typed Express. A .get('/x', fn) on anything
// else, such as a cache, is not a route.
func nodeRouteRegistration(call *sitter.Node, src []byte, bindings nodeBindings) (entrypoints.Entry, bool) {
	function := call.ChildByFieldName("function")
	if function == nil || function.Type() != nodeMemberExpression {
		return entrypoints.Entry{}, false
	}
	property := function.ChildByFieldName("property")
	args := call.ChildByFieldName("arguments")
	if property == nil || args == nil || args.NamedChildCount() == 0 {
		return entrypoints.Entry{}, false
	}
	catalog := entryCatalog()
	method := property.Content(src)
	if !catalog.Named(entryLanguageNode, entrypoints.ShapeRegistrationCall, method) {
		return entrypoints.Entry{}, false
	}
	object := function.ChildByFieldName("object")
	entry, ok := catalog.Match(entryLanguageNode, entrypoints.ShapeRegistrationCall, nodeOrigin(object, src, bindings, 0), "", method)
	if !ok || (entry.Path == entrypoints.PathRequired && !nodeRegistersPath(args, object)) {
		return entrypoints.Entry{}, false
	}
	return entry, true
}

// nodeRegistersPath reports whether a registration names a path: as its
// first argument, or on the route it is chained to, as in
// app.route('/x').get(handler).
func nodeRegistersPath(args, object *sitter.Node) bool {
	if isNodeStringArgument(args.NamedChild(0)) {
		return true
	}
	if object == nil || object.Type() != nodeCallExpression {
		return false
	}
	inner := object.ChildByFieldName("arguments")
	return inner != nil && inner.NamedChildCount() > 0 && isNodeStringArgument(inner.NamedChild(0))
}

func isNodeStringArgument(node *sitter.Node) bool {
	return node != nil && (node.Type() == nodeStringNode || node.Type() == nodeTemplateString)
}

// nodeOrigin returns the npm package an expression's value comes from,
// through the file's imports and the declarations in scope: express for
// express(), express.Router(), app where const app = express(),
// require('fastify')({...}), or a parameter typed FastifyInstance. It
// returns "" for anything else.
func nodeOrigin(expr *sitter.Node, src []byte, bindings nodeBindings, depth int) string {
	if expr == nil || depth > nodeOriginDepth {
		return ""
	}
	switch expr.Type() {
	case goNodeIdentifier, "type_identifier":
		return nodeIdentifierOrigin(expr, expr.Content(src), src, bindings, depth)
	case nodeMemberExpression:
		return nodeOrigin(expr.ChildByFieldName("object"), src, bindings, depth+1)
	case nodeCallExpression:
		if module, ok := nodeRequiredModule(expr, src); ok {
			return module
		}
		return nodeOrigin(expr.ChildByFieldName("function"), src, bindings, depth+1)
	case "new_expression":
		return nodeOrigin(expr.ChildByFieldName("constructor"), src, bindings, depth+1)
	case "nested_type_identifier":
		return nodeOrigin(expr.ChildByFieldName("module"), src, bindings, depth+1)
	case "generic_type":
		return nodeOrigin(expr.ChildByFieldName("name"), src, bindings, depth+1)
	}
	if nodeValueWrappers[expr.Type()] && expr.NamedChildCount() > 0 {
		return nodeOrigin(expr.NamedChild(0), src, bindings, depth+1)
	}
	return ""
}

// nodeValueWrappers are the expressions whose value is their first child's.
var nodeValueWrappers = map[string]bool{
	"await_expression": true, rustNodeParenthesizedExpression: true, "as_expression": true,
	"non_null_expression": true, "satisfies_expression": true, "type_annotation": true,
}

// nodeRequiredModule returns the module of a require('module') call.
func nodeRequiredModule(call *sitter.Node, src []byte) (string, bool) {
	function := call.ChildByFieldName("function")
	args := call.ChildByFieldName("arguments")
	if function == nil || function.Type() != goNodeIdentifier || function.Content(src) != nodeRequireFunction ||
		args == nil || args.NamedChildCount() == 0 || args.NamedChild(0).Type() != nodeStringNode {
		return "", false
	}
	return unquoteNodeString(args.NamedChild(0).Content(src)), true
}

// nodeIdentifierOrigin resolves a name to the declaration in scope at at, or
// else to the module's import of it.
func nodeIdentifierOrigin(at *sitter.Node, name string, src []byte, bindings nodeBindings, depth int) string {
	for scope := at.Parent(); scope != nil; scope = scope.Parent() {
		if value, found := nodeScopeDeclaration(scope, name, src); found {
			return nodeOrigin(value, src, bindings, depth+1)
		}
	}
	return bindings[name].module
}

// nodeScopeDeclaration finds name among a scope's own declarations: the
// parameters of a function, the variables a block or the program declares.
// It returns what the declaration says about the value (the initializer, or
// a parameter's type annotation), nil when it says nothing.
func nodeScopeDeclaration(scope *sitter.Node, name string, src []byte) (*sitter.Node, bool) {
	switch scope.Type() {
	case "program", "statement_block":
		for i := 0; i < int(scope.NamedChildCount()); i++ {
			stmt := scope.NamedChild(i)
			if stmt.Type() == "export_statement" {
				stmt = stmt.ChildByFieldName("declaration")
			}
			if value, found := nodeDeclaratorValue(stmt, name, src); found {
				return value, true
			}
		}
	case nodeFunctionDeclaration, nodeFunctionExpression, nodeArrowFunction, nodeMethodDefinition, nodeGeneratorDeclaration:
		if param := scope.ChildByFieldName("parameter"); param != nil {
			return nil, param.Content(src) == name
		}
		return nodeParameterDeclaration(scope.ChildByFieldName("parameters"), name, src)
	}
	return nil, false
}

func nodeDeclaratorValue(stmt *sitter.Node, name string, src []byte) (*sitter.Node, bool) {
	if stmt == nil || (stmt.Type() != nodeLexicalDeclaration && stmt.Type() != nodeVariableDeclaration) {
		return nil, false
	}
	for i := 0; i < int(stmt.NamedChildCount()); i++ {
		declarator := stmt.NamedChild(i)
		id := declarator.ChildByFieldName("name")
		if declarator.Type() == nodeVariableDeclarator && id != nil && id.Type() == goNodeIdentifier && id.Content(src) == name {
			return declarator.ChildByFieldName("value"), true
		}
	}
	return nil, false
}

func nodeParameterDeclaration(params *sitter.Node, name string, src []byte) (*sitter.Node, bool) {
	if params == nil {
		return nil, false
	}
	for i := 0; i < int(params.NamedChildCount()); i++ {
		param := params.NamedChild(i)
		pattern := param
		switch param.Type() {
		case nodeRequiredParameter, nodeOptionalParameter:
			pattern = param.ChildByFieldName("pattern")
		case "assignment_pattern":
			pattern = param.ChildByFieldName("left")
		}
		if pattern == nil || pattern.Type() != goNodeIdentifier || pattern.Content(src) != name {
			continue
		}
		if param.Type() == nodeRequiredParameter || param.Type() == nodeOptionalParameter {
			return param.ChildByFieldName("type"), true
		}
		return nil, true
	}
	return nil, false
}

// nodeHandlerArguments returns the functions a route registration passes:
// inline functions, names of functions, members of an imported module, and
// the same one call deep, for a wrapper such as asyncHandler(fn).
func nodeHandlerArguments(call *sitter.Node, src []byte, modulePath string, bindings nodeBindings) []FunctionID {
	args := call.ChildByFieldName("arguments")
	var out []FunctionID
	for i := 0; i < int(args.NamedChildCount()); i++ {
		arg := args.NamedChild(i)
		if id, ok := nodeFunctionReference(arg, src, modulePath, bindings); ok {
			out = append(out, id)
			continue
		}
		if arg.Type() != nodeCallExpression {
			continue
		}
		if inner := arg.ChildByFieldName("arguments"); inner != nil {
			for j := 0; j < int(inner.NamedChildCount()); j++ {
				if id, ok := nodeFunctionReference(inner.NamedChild(j), src, modulePath, bindings); ok {
					out = append(out, id)
				}
			}
		}
	}
	return out
}

// nodeFunctionReference names the function an expression denotes: an inline
// function by the name its declaration gets, a name by what it binds, and a
// member of an imported module by its export.
func nodeFunctionReference(expr *sitter.Node, src []byte, modulePath string, bindings nodeBindings) (FunctionID, bool) {
	switch expr.Type() {
	case nodeArrowFunction, nodeFunctionExpression:
		return FunctionID{Package: modulePath, Name: nodeInlineFunctionName(expr, src)}, true
	case goNodeIdentifier:
		return nodeNamedReference(expr.Content(src), modulePath, bindings, nil), true
	case nodeMemberExpression:
		object := expr.ChildByFieldName("object")
		property := expr.ChildByFieldName("property")
		if object == nil || property == nil || object.Type() != goNodeIdentifier {
			return FunctionID{}, false
		}
		binding, ok := bindings.lookup(nil, object.Content(src))
		if !ok {
			return FunctionID{}, false
		}
		pkg, last := binding.qualify(property.Content(src))
		return FunctionID{Package: pkg, Name: last}, true
	}
	return FunctionID{}, false
}

// nodeInlineFunctionName is the name extractDeclarations gives a function
// expression: its own name, or where it starts.
func nodeInlineFunctionName(fn *sitter.Node, src []byte) string {
	if name := fn.ChildByFieldName("name"); name != nil {
		return name.Content(src)
	}
	return nodeAnonymousName(fn)
}

// nodeNamedReference resolves a name the way parseNodeCall resolves a call to
// it: through the module's imports unless locals shadow it, else to the
// module's own declaration.
func nodeNamedReference(name, modulePath string, bindings nodeBindings, locals map[string]bool) FunctionID {
	if binding, ok := bindings.lookup(locals, name); ok {
		pkg, last := binding.qualify()
		if last == "" {
			last = name
		}
		return FunctionID{Package: pkg, Name: last}
	}
	return FunctionID{Package: modulePath, Name: name}
}

// nodeDecoratedEntryMethods returns the methods of a class that carry a
// catalog entry decorator imported from its framework, as @Post() from
// @nestjs/common. tree-sitter puts a method's decorators before it in the
// class body.
func nodeDecoratedEntryMethods(class *sitter.Node, src []byte, modulePath string, bindings nodeBindings) []EntryRef {
	body := class.ChildByFieldName("body")
	name := class.ChildByFieldName("name")
	if body == nil || name == nil {
		return nil
	}
	var out []EntryRef
	var pending *entrypoints.Entry
	for i := 0; i < int(body.NamedChildCount()); i++ {
		member := body.NamedChild(i)
		switch member.Type() {
		case "decorator":
			if entry, ok := nodeDecoratorEntry(member, src, bindings); ok && pending == nil {
				pending = &entry
			}
		case nodeMethodDefinition:
			if method := member.ChildByFieldName("name"); pending != nil && method != nil {
				out = append(out, EntryRef{
					Function: FunctionID{Package: modulePath, Type: name.Content(src), Name: method.Content(src)},
					Kind:     catalogEntryKind(pending),
				})
			}
			pending = nil
		default:
			pending = nil
		}
	}
	return out
}

// nodeDecoratorEntry returns the catalog entry a decorator matches: the name
// it imports from the package, @Post() for import { Post } from
// '@nestjs/common', or a member of an imported namespace, @common.Post().
func nodeDecoratorEntry(decorator *sitter.Node, src []byte, bindings nodeBindings) (entrypoints.Entry, bool) {
	if decorator.NamedChildCount() == 0 {
		return entrypoints.Entry{}, false
	}
	expr := decorator.NamedChild(0)
	if expr.Type() == nodeCallExpression {
		expr = expr.ChildByFieldName("function")
	}
	if expr == nil {
		return entrypoints.Entry{}, false
	}
	var pkg, name string
	switch expr.Type() {
	case goNodeIdentifier:
		name = expr.Content(src)
		pkg = nodeIdentifierOrigin(expr, name, src, bindings, 0)
		if member := bindings[name].member; member != "" && member != nodeDefaultKeyword {
			name = member[strings.LastIndex(member, ".")+1:]
		}
	case nodeMemberExpression:
		property := expr.ChildByFieldName("property")
		if property == nil {
			return entrypoints.Entry{}, false
		}
		name = property.Content(src)
		pkg = nodeOrigin(expr.ChildByFieldName("object"), src, bindings, 0)
	default:
		return entrypoints.Entry{}, false
	}
	return entryCatalog().Match(entryLanguageNode, entrypoints.ShapeDecorator, pkg, "", name)
}

// nodeModuleExports returns the module's exported functions by exported name,
// and its default export. ES exports and CommonJS module.exports / exports.x
// assignments both count. A default export that wraps a function, as
// export default withAuth(Page), names the wrapped function.
func nodeModuleExports(root *sitter.Node, src []byte, modulePath string) (map[string]FunctionID, []FunctionID) {
	exports := make(map[string]FunctionID)
	var defaults []FunctionID
	for i := 0; i < int(root.NamedChildCount()); i++ {
		stmt := root.NamedChild(i)
		switch stmt.Type() {
		case "export_statement":
			defaults = append(defaults, nodeExportStatement(stmt, src, modulePath, exports)...)
		case nodeExpressionStatement:
			if stmt.NamedChildCount() > 0 && stmt.NamedChild(0).Type() == nodeAssignmentExpression {
				nodeCommonJSExport(stmt.NamedChild(0), src, modulePath, exports)
			}
		}
	}
	for _, id := range defaults {
		exports[nodeDefaultKeyword] = id
	}
	return exports, defaults
}

// nodeExportStatement records one ES export statement into exports and
// returns what it exports as default.
func nodeExportStatement(stmt *sitter.Node, src []byte, modulePath string, exports map[string]FunctionID) []FunctionID {
	isDefault := false
	for j := 0; j < int(stmt.ChildCount()); j++ {
		isDefault = isDefault || stmt.Child(j).Type() == nodeDefaultKeyword
	}
	var defaults []FunctionID
	if decl := stmt.ChildByFieldName("declaration"); decl != nil {
		for _, name := range nodeDeclaredFunctionNames(decl, src) {
			id := FunctionID{Package: modulePath, Name: name}
			exports[name] = id
			if isDefault {
				defaults = append(defaults, id)
			}
		}
	}
	if value := stmt.ChildByFieldName("value"); value != nil {
		defaults = append(defaults, nodeExportedValue(value, src, modulePath)...)
	}
	for j := 0; j < int(stmt.NamedChildCount()); j++ {
		if clause := stmt.NamedChild(j); clause.Type() == "export_clause" {
			nodeExportClause(clause, src, modulePath, exports)
		}
	}
	return defaults
}

func nodeDeclaredFunctionNames(decl *sitter.Node, src []byte) []string {
	switch decl.Type() {
	case nodeFunctionDeclaration, nodeGeneratorDeclaration:
		if name := decl.ChildByFieldName("name"); name != nil {
			return []string{name.Content(src)}
		}
	case nodeLexicalDeclaration, nodeVariableDeclaration:
		var names []string
		for i := 0; i < int(decl.NamedChildCount()); i++ {
			declarator := decl.NamedChild(i)
			name := declarator.ChildByFieldName("name")
			if declarator.Type() == nodeVariableDeclarator && name != nil && nodeAssignedFunction(declarator.ChildByFieldName("value")) != nil {
				names = append(names, name.Content(src))
			}
		}
		return names
	}
	return nil
}

func nodeExportedValue(value *sitter.Node, src []byte, modulePath string) []FunctionID {
	switch value.Type() {
	case goNodeIdentifier:
		return []FunctionID{{Package: modulePath, Name: value.Content(src)}}
	case nodeArrowFunction, nodeFunctionExpression:
		return []FunctionID{{Package: modulePath, Name: nodeInlineFunctionName(value, src)}}
	case nodeCallExpression:
		var out []FunctionID
		if args := value.ChildByFieldName("arguments"); args != nil {
			for i := 0; i < int(args.NamedChildCount()); i++ {
				out = append(out, nodeExportedValue(args.NamedChild(i), src, modulePath)...)
			}
		}
		return out
	}
	return nil
}

func nodeExportClause(clause *sitter.Node, src []byte, modulePath string, exports map[string]FunctionID) {
	for i := 0; i < int(clause.NamedChildCount()); i++ {
		spec := clause.NamedChild(i)
		name := spec.ChildByFieldName("name")
		if spec.Type() != "export_specifier" || name == nil {
			continue
		}
		exported := name.Content(src)
		if alias := spec.ChildByFieldName("alias"); alias != nil {
			exported = alias.Content(src)
		}
		exports[exported] = FunctionID{Package: modulePath, Name: name.Content(src)}
	}
}

// nodeCommonJSExport records module.exports = {a, b: c}, module.exports = fn,
// exports.x = ... and module.exports.x = ....
func nodeCommonJSExport(assign *sitter.Node, src []byte, modulePath string, exports map[string]FunctionID) {
	left := assign.ChildByFieldName("left")
	right := assign.ChildByFieldName("right")
	if left == nil || right == nil || left.Type() != nodeMemberExpression {
		return
	}
	target := left.Content(src)
	switch {
	case target == "module.exports" && right.Type() == nodeObjectLiteral:
		nodeCommonJSExportObject(right, src, modulePath, exports)
	case target == "module.exports":
		for _, id := range nodeExportedValue(right, src, modulePath) {
			exports[nodeDefaultKeyword] = id
		}
	case strings.HasPrefix(target, "exports.") || strings.HasPrefix(target, "module.exports."):
		if name, _ := nodeAssignmentTarget(left, src); name != "" {
			if id, ok := nodeCommonJSExportValue(right, name, src, modulePath); ok {
				exports[name] = id
			}
		}
	}
}

// nodeCommonJSExportObject records module.exports = {a, b: c, d() {}}.
func nodeCommonJSExportObject(object *sitter.Node, src []byte, modulePath string, exports map[string]FunctionID) {
	for i := 0; i < int(object.NamedChildCount()); i++ {
		member := object.NamedChild(i)
		if member.Type() == "shorthand_property_identifier" {
			exports[member.Content(src)] = FunctionID{Package: modulePath, Name: member.Content(src)}
			continue
		}
		key := member.ChildByFieldName("key")
		if member.Type() != "pair" || key == nil {
			continue
		}
		name := unquoteNodeString(key.Content(src))
		if id, ok := nodeCommonJSExportValue(member.ChildByFieldName("value"), name, src, modulePath); ok {
			exports[name] = id
		}
	}
}

// nodeCommonJSExportValue names the function a CommonJS export stores under
// name: the function a name refers to, or the function expression, which
// extractDeclarations declares under that name.
func nodeCommonJSExportValue(value *sitter.Node, name string, src []byte, modulePath string) (FunctionID, bool) {
	switch {
	case value == nil:
		return FunctionID{}, false
	case value.Type() == goNodeIdentifier:
		return FunctionID{Package: modulePath, Name: value.Content(src)}, true
	case nodeAssignedFunction(value) != nil:
		return FunctionID{Package: modulePath, Name: name}, true
	}
	return FunctionID{}, false
}

// nodeFileConventionEntries returns the exports a framework calls because of
// where the file is, as the POST of a Next.js app/**/route.ts. An entry
// counts only when the nearest package.json declares its package, so an
// app/ or pages/ directory of a project without Next.js is nothing special.
func nodeFileConventionEntries(filePath string, exports map[string]FunctionID, defaults []FunctionID) []EntryRef {
	entries := entryCatalog().Entries(entryLanguageNode, entrypoints.ShapeFileConvention)
	if len(entries) == 0 {
		return nil
	}
	manifest := nearestNodeManifest(filepath.Dir(filePath))
	if manifest == nil {
		return nil
	}
	slashed := "/" + filepath.ToSlash(filePath)
	base := filepath.Base(slashed)
	stem := strings.TrimSuffix(base, filepath.Ext(base))
	var out []EntryRef
	for i := range entries {
		entry := &entries[i]
		if !manifest.declaresAny(entry.From) ||
			(entry.Directory != "" && !strings.Contains(slashed, "/"+entry.Directory+"/")) ||
			(len(entry.Files) > 0 && !slices.Contains(entry.Files, stem)) {
			continue
		}
		kind := catalogEntryKind(entry)
		for _, name := range entry.Names {
			if name == nodeDefaultKeyword {
				for _, id := range defaults {
					out = append(out, EntryRef{Function: id, Kind: kind})
				}
			} else if id, ok := exports[name]; ok {
				out = append(out, EntryRef{Function: id, Kind: kind})
			}
		}
	}
	return out
}

// nodeRunsAsMain reports whether the module runs as a program when Node
// starts it directly: if (require.main === module).
func nodeRunsAsMain(root *sitter.Node, src []byte) bool {
	for i := 0; i < int(root.NamedChildCount()); i++ {
		stmt := root.NamedChild(i)
		if stmt.Type() != nodeIfStatement {
			continue
		}
		condition := stmt.ChildByFieldName("condition")
		if condition == nil {
			continue
		}
		text := strings.Join(strings.Fields(condition.Content(src)), "")
		text = strings.Trim(text, "()")
		switch text {
		case "require.main===module", "require.main==module", "module===require.main", "module==require.main":
			return true
		}
	}
	return false
}

type nodeEntryRole int

const (
	nodeNotAnEntry nodeEntryRole = iota
	// nodeProgramEntry is a bin script: Node runs it as a program.
	nodeProgramEntry
	// nodeLibraryEntry is the module package.json main, module or exports
	// names: loading the package runs it, and its exports are what other
	// code calls.
	nodeLibraryEntry
)

// nodePackageEntryRole reports whether filePath is an entry of the nearest
// package.json. A manifest names built output as often as source
// ("main": "dist/index.js"), so dist/, build/, lib/ and out/ also match the
// same path under src/ and at the package root, and any extension matches.
func nodePackageEntryRole(filePath string) nodeEntryRole {
	manifest := nearestNodeManifest(filepath.Dir(filePath))
	if manifest == nil {
		return nodeNotAnEntry
	}
	rel, err := filepath.Rel(manifest.dir, filePath)
	if err != nil {
		return nodeNotAnEntry
	}
	rel = filepath.ToSlash(rel)
	stem := strings.TrimSuffix(rel, filepath.Ext(rel))
	// A target written with an extension of a file that exists is recorded
	// under its full path, so its same-stem sibling is not an entry.
	switch {
	case manifest.bins[rel], manifest.scripts[rel], manifest.bins[stem], manifest.scripts[stem]:
		return nodeProgramEntry
	case manifest.mains[rel], manifest.mains[stem]:
		return nodeLibraryEntry
	}
	return nodeNotAnEntry
}

type nodeManifest struct {
	dir   string
	mains map[string]bool
	bins  map[string]bool
	// scripts are the files a "scripts" command runs with node, tsx, ts-node,
	// bun or deno.
	scripts map[string]bool
	// deps are the packages the manifest declares in dependencies,
	// devDependencies, peerDependencies or optionalDependencies.
	deps map[string]bool
}

func (m *nodeManifest) declaresAny(packages []string) bool {
	for _, pkg := range packages {
		if m.deps[pkg] {
			return true
		}
	}
	return false
}

// nodeManifests caches nearestNodeManifest per directory; nil means none.
var nodeManifests sync.Map

func nearestNodeManifest(dir string) *nodeManifest {
	if cached, ok := nodeManifests.Load(dir); ok {
		if manifest, typed := cached.(*nodeManifest); typed {
			return manifest
		}
		return nil
	}
	var manifest *nodeManifest
	if data, err := os.ReadFile(filepath.Join(dir, "package.json")); err == nil {
		manifest = parseNodeManifest(dir, data)
	} else if parent := filepath.Dir(dir); parent != dir && filepath.Base(dir) != "node_modules" {
		manifest = nearestNodeManifest(parent)
	}
	nodeManifests.Store(dir, manifest)
	return manifest
}

func parseNodeManifest(dir string, data []byte) *nodeManifest {
	var fields struct {
		Main    string          `json:"main"`
		Module  string          `json:"module"`
		Exports json.RawMessage `json:"exports"`
		Bin     json.RawMessage `json:"bin"`
		Scripts map[string]any  `json:"scripts"`

		Dependencies         map[string]json.RawMessage `json:"dependencies"`
		DevDependencies      map[string]json.RawMessage `json:"devDependencies"`
		PeerDependencies     map[string]json.RawMessage `json:"peerDependencies"`
		OptionalDependencies map[string]json.RawMessage `json:"optionalDependencies"`
	}
	manifest := &nodeManifest{dir: dir, mains: map[string]bool{}, bins: map[string]bool{}, scripts: map[string]bool{}, deps: map[string]bool{}}
	if json.Unmarshal(data, &fields) != nil {
		return manifest
	}
	for _, deps := range []map[string]json.RawMessage{fields.Dependencies, fields.DevDependencies, fields.PeerDependencies, fields.OptionalDependencies} {
		for name := range deps {
			manifest.deps[name] = true
		}
	}
	var mains []string
	for _, entry := range []string{fields.Main, fields.Module} {
		if entry != "" {
			mains = append(mains, entry)
		}
	}
	mains = append(mains, nodeManifestPaths(fields.Exports)...)
	if len(mains) == 0 {
		mains = []string{"index"}
	}
	for _, entry := range mains {
		manifest.record(manifest.mains, entry)
	}
	for _, entry := range nodeManifestPaths(fields.Bin) {
		manifest.record(manifest.bins, entry)
	}
	manifest.addScripts(fields.Scripts)
	return manifest
}

// addScripts records the files the "scripts" commands run with a JavaScript
// or TypeScript runtime.
func (m *nodeManifest) addScripts(scripts map[string]any) {
	for _, value := range scripts {
		command, isString := value.(string)
		if !isString {
			continue
		}
		for _, target := range nodeScriptTargets(command) {
			m.record(m.scripts, target)
		}
	}
}

// record marks the file a manifest entry names in set. An entry written with
// a source extension that exists as written is exactly that file; otherwise
// (built output the tree does not hold, or no extension) it is every source
// file nodeSourceCandidates says it can denote.
func (m *nodeManifest) record(set map[string]bool, entry string) {
	clean := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(entry)), "./")
	if isNodeSourceExtension(filepath.Ext(clean)) && !strings.Contains(clean, "*") {
		if info, err := os.Stat(filepath.Join(m.dir, filepath.FromSlash(clean))); err == nil && !info.IsDir() {
			set[clean] = true
			return
		}
	}
	for _, candidate := range nodeSourceCandidates(entry) {
		set[candidate] = true
	}
}

// nodeManifestPaths collects the file paths of an exports or bin field: a
// string, or an object of strings and nested condition objects. Type
// declaration entries are skipped.
func nodeManifestPaths(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return []string{single}
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return nil
	}
	var out []string
	for key, value := range object {
		if key == "types" || key == "typings" {
			continue
		}
		out = append(out, nodeManifestPaths(value)...)
	}
	return out
}

// nodeBuildOutputDirs are the directories a manifest names built output in.
var nodeBuildOutputDirs = map[string]bool{
	"dist": true, "build": true, "lib": true, "out": true, "esm": true, "cjs": true, "es": true,
}

// nodeSourceCandidates returns the extension-less paths, relative to the
// package, whose source file a manifest entry can denote.
func nodeSourceCandidates(entry string) []string {
	entry = strings.TrimPrefix(filepath.ToSlash(filepath.Clean(entry)), "./")
	if entry == "" || entry == "." || strings.Contains(entry, "*") {
		return nil
	}
	if ext := filepath.Ext(entry); ext != "" && !strings.ContainsFunc(ext[1:], func(r rune) bool { return !unicode.IsLetter(r) }) {
		entry = strings.TrimSuffix(entry, ext)
	}
	out := []string{entry, entry + "/index"}
	if first, rest, ok := strings.Cut(entry, "/"); ok && nodeBuildOutputDirs[first] {
		out = append(out, "src/"+rest, rest)
	}
	if !strings.Contains(entry, "/") {
		out = append(out, "src/"+entry)
	}
	return out
}

// nodeImplicitCalls returns what a function body calls without a call
// expression of its own: each component its JSX renders, each function it
// writes inline as an argument (a callback runs when the call it is passed to
// runs), and each handler a JSX attribute names. Route handlers are left out:
// the router calls them, and nodeEntryRefs makes them entry points.
func nodeImplicitCalls(body *sitter.Node, src []byte, filePath, packagePath string, imports nodeBindings, locals map[string]bool) []FunctionCall {
	var out []FunctionCall
	add := func(node *sitter.Node, callee FunctionID) {
		call := FunctionCall{
			Callee:   callee,
			Raw:      callee.Name,
			FilePath: filePath,
			Line:     int(node.StartPoint().Row) + 1,
			StartCol: int(node.StartPoint().Column) + 1,
			EndCol:   int(node.EndPoint().Column) + 1,
		}
		out = append(out, call)
	}
	var walk func(node *sitter.Node)
	walk = func(node *sitter.Node) {
		if node == nil {
			return
		}
		if isNodeNestedScope(node.Type()) {
			if isNodeInlineCallback(node, src, imports) {
				add(node, FunctionID{Package: packagePath, Name: nodeInlineFunctionName(node, src)})
			}
			return
		}
		switch node.Type() {
		case "jsx_opening_element", "jsx_self_closing_element":
			if name := node.ChildByFieldName("name"); name != nil && name.Type() == goNodeIdentifier && isExportedName(name.Content(src)) {
				add(node, nodeNamedReference(name.Content(src), packagePath, imports, locals))
			}
		case "jsx_expression":
			if parent := node.Parent(); parent != nil && parent.Type() == "jsx_attribute" &&
				node.NamedChildCount() == 1 && node.NamedChild(0).Type() == goNodeIdentifier {
				add(node, nodeNamedReference(node.NamedChild(0).Content(src), packagePath, imports, locals))
			}
		}
		for i := 0; i < int(node.ChildCount()); i++ {
			walk(node.Child(i))
		}
	}
	walk(body)
	return out
}

// isNodeInlineCallback reports whether fn is a function expression written as
// a call argument or a JSX attribute value, other than a route handler.
func isNodeInlineCallback(fn *sitter.Node, src []byte, bindings nodeBindings) bool {
	if fn.Type() != nodeArrowFunction && fn.Type() != nodeFunctionExpression {
		return false
	}
	parent := fn.Parent()
	if parent == nil {
		return false
	}
	switch parent.Type() {
	case "jsx_expression":
		return true
	case nodeArgumentsNode:
	default:
		return false
	}
	call := parent.Parent()
	if call == nil {
		return false
	}
	if _, route := nodeRouteRegistration(call, src, bindings); route {
		return false
	}
	// asyncHandler(fn) inside app.get('/x', ...)
	if outer := call.Parent(); outer != nil && outer.Type() == nodeArgumentsNode {
		if registration := outer.Parent(); registration != nil {
			_, route := nodeRouteRegistration(registration, src, bindings)
			return !route
		}
	}
	return true
}
