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
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/scanoss/crypto-finder/internal/callgraph/entrypoints"
)

// Entry points of Python code: what a web framework, a task queue, a CLI
// framework or the interpreter calls. The frameworks and the names they
// declare are the catalog's (entrypoints/python); this file recognizes the
// shapes: a decorator from the framework, a URL pattern call, a method of a
// class whose base comes from the framework. The __main__ guard and the
// console scripts a project manifest names are Python semantics and stay
// here.

const (
	pythonDecoratedDefinition = "decorated_definition"
	pythonAttribute           = "attribute"
)

// pythonEntryScope is what one file's names are bound to: the module a
// module-level name's value comes from, through the file's imports.
type pythonEntryScope struct {
	analysis *FileAnalysis
	// origins maps a module-level name to the module its value comes from:
	// app = Flask(__name__) binds app to flask.Flask, and a function a click
	// decorator makes, def cli() under @click.group(), binds cli to click.
	origins map[string]string
	// bases maps a class the file declares to its bases as written.
	bases map[string][]string
}

// applyPythonEntryRules marks the file's entry points: functions with a
// catalog decorator, the catalog methods of a class-based view, the module a
// __main__ guard runs, and the console_scripts functions of the project
// manifest. Views a URL pattern names by reference may live in another
// module, so they become EntryRefs.
func applyPythonEntryRules(root *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis) {
	scope := &pythonEntryScope{analysis: analysis, origins: make(map[string]string), bases: make(map[string][]string)}
	for i := range analysis.Functions {
		if decl := &analysis.Functions[i]; decl.ID.Type != "" && decl.FilePath == filePath {
			scope.bases[decl.ID.Type] = decl.OwnerBases
		}
	}
	kinds := make(map[int]RootKind)
	scope.bindModuleNames(root, src)
	scope.decoratedEntries(root, src, kinds)
	module := pythonModuleDottedPath(filePath, packagePath)
	scripts := pythonConsoleScripts(filePath)[module]
	runsAsMain := pythonHasMainGuard(root, src)
	for i := range analysis.Functions {
		decl := &analysis.Functions[i]
		if decl.FilePath != filePath {
			continue
		}
		switch {
		case decl.ID.Name == moduleInitMethodName && runsAsMain:
			markEntry(decl, RootKindMain)
		case decl.ID.Type == "" && scripts[decl.ID.Name]:
			markEntry(decl, RootKindMain)
		case kinds[decl.StartLine] != "":
			markEntry(decl, kinds[decl.StartLine])
		case decl.ID.Type != "":
			if kind, ok := scope.supertypeEntryKind(decl.ID.Type, decl.ID.Name, map[string]bool{}); ok {
				markEntry(decl, kind)
			}
		}
	}
	analysis.EntryRefs = append(analysis.EntryRefs, scope.registeredViews(root, src, module)...)
}

// nameOrigin returns the module a name's value comes from: the module an
// import names (with the imported name for a from-import, so from flask
// import Flask gives flask.Flask), else a module-level binding.
func (s *pythonEntryScope) nameOrigin(name string) string {
	if module, ok := s.analysis.Imports[name]; ok {
		if s.analysis.FromImports[name] {
			return module + "." + pythonImportedName(s.analysis, name)
		}
		return module
	}
	return s.origins[name]
}

// exprOrigin returns the module an expression's value comes from: a name, an
// attribute of one (flask.Flask), or a call of either (Flask(__name__)).
func (s *pythonEntryScope) exprOrigin(expr *sitter.Node, src []byte) string {
	if expr == nil {
		return ""
	}
	switch expr.Type() {
	case goNodeIdentifier:
		return s.nameOrigin(expr.Content(src))
	case pythonAttribute:
		if object := s.exprOrigin(expr.ChildByFieldName("object"), src); object != "" {
			if attribute := expr.ChildByFieldName("attribute"); attribute != nil {
				return object + "." + attribute.Content(src)
			}
		}
	case pythonNodeCall:
		return s.exprOrigin(expr.ChildByFieldName("function"), src)
	}
	return ""
}

// target returns the module and name a decorator or callee denotes: for
// @app.route the origin of app and route, for a bare @shared_task the module
// it is imported from and the name it has there.
func (s *pythonEntryScope) target(expr *sitter.Node, src []byte) (module, name string) {
	if expr != nil && expr.Type() == pythonNodeCall {
		expr = expr.ChildByFieldName("function")
	}
	if expr == nil {
		return "", ""
	}
	switch expr.Type() {
	case goNodeIdentifier:
		local := expr.Content(src)
		if !s.analysis.FromImports[local] {
			return "", ""
		}
		return s.analysis.Imports[local], pythonImportedName(s.analysis, local)
	case pythonAttribute:
		attribute := expr.ChildByFieldName("attribute")
		if attribute == nil {
			return "", ""
		}
		return s.exprOrigin(expr.ChildByFieldName("object"), src), attribute.Content(src)
	}
	return "", ""
}

// bindModuleNames records, in source order, the origin of each module-level
// assignment and of each function a catalog decorator makes, so a later
// @app.get or @cli.command resolves.
func (s *pythonEntryScope) bindModuleNames(root *sitter.Node, src []byte) {
	for i := 0; i < int(root.NamedChildCount()); i++ {
		stmt := root.NamedChild(i)
		switch stmt.Type() {
		case nodeExpressionStatement:
			if stmt.NamedChildCount() > 0 && stmt.NamedChild(0).Type() == "assignment" {
				s.bindAssignment(stmt.NamedChild(0), src)
			}
		case pythonDecoratedDefinition:
			s.bindDecoratedFunction(stmt, src)
		}
	}
}

// bindAssignment binds name = value to the origin of value.
func (s *pythonEntryScope) bindAssignment(assign *sitter.Node, src []byte) {
	left := assign.ChildByFieldName("left")
	if left == nil || left.Type() != goNodeIdentifier {
		return
	}
	if origin := s.exprOrigin(assign.ChildByFieldName("right"), src); origin != "" {
		s.origins[left.Content(src)] = origin
	}
}

// bindDecoratedFunction binds a function a catalog decorator makes to the
// decorator's module: def cli() under @click.group() is a click group, so
// @cli.command() is a click command.
func (s *pythonEntryScope) bindDecoratedFunction(decorated *sitter.Node, src []byte) {
	definition := decorated.ChildByFieldName("definition")
	if definition == nil || definition.Type() != pythonNodeFunctionDefinition {
		return
	}
	name := definition.ChildByFieldName("name")
	if module, _, ok := s.decoratorEntry(decorated, src); ok && name != nil {
		s.origins[name.Content(src)] = module
	}
}

// decoratedEntries records, by the line of the def, each function a catalog
// decorator makes an entry point, at any depth.
func (s *pythonEntryScope) decoratedEntries(node *sitter.Node, src []byte, kinds map[int]RootKind) {
	if node.Type() == pythonDecoratedDefinition {
		definition := node.ChildByFieldName("definition")
		if definition != nil && definition.Type() == pythonNodeFunctionDefinition {
			if _, kind, ok := s.decoratorEntry(node, src); ok {
				kinds[int(definition.StartPoint().Row)+1] = kind
			}
		}
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		s.decoratedEntries(node.NamedChild(i), src, kinds)
	}
}

// decoratorEntry returns the first decorator of a decorated definition that
// the catalog names for the module it comes from.
func (s *pythonEntryScope) decoratorEntry(decorated *sitter.Node, src []byte) (string, RootKind, bool) {
	catalog := entryCatalog()
	for i := 0; i < int(decorated.NamedChildCount()); i++ {
		decorator := decorated.NamedChild(i)
		if decorator.Type() != "decorator" || decorator.NamedChildCount() == 0 {
			continue
		}
		module, name := s.target(decorator.NamedChild(0), src)
		if entry, ok := catalog.Match(entryLanguagePython, entrypoints.ShapeDecorator, module, "", name); ok {
			return module, catalogEntryKind(&entry), true
		}
	}
	return "", "", false
}

// supertypeEntryKind reports whether method of class is one a framework
// dispatcher calls: a catalog method of a class whose base, directly or
// through a class of the same file, is a catalog type (a Django View, a
// Flask MethodView).
func (s *pythonEntryScope) supertypeEntryKind(class, method string, seen map[string]bool) (RootKind, bool) {
	catalog := entryCatalog()
	if seen[class] || !catalog.Named(entryLanguagePython, entrypoints.ShapeSupertype, method) {
		return "", false
	}
	seen[class] = true
	for _, base := range s.bases[class] {
		module, typeName := s.baseType(base)
		if entry, ok := catalog.Match(entryLanguagePython, entrypoints.ShapeSupertype, module, typeName, method); ok {
			return catalogEntryKind(&entry), true
		}
		if _, local := s.bases[base]; local {
			if kind, ok := s.supertypeEntryKind(base, method, seen); ok {
				return kind, true
			}
		}
	}
	return "", false
}

// baseType resolves a base class as written to its module and name:
// View from django.views import View is django.views and View, and
// generic.ListView from django.views import generic is django.views.generic
// and ListView.
func (s *pythonEntryScope) baseType(base string) (module, typeName string) {
	dot := strings.LastIndex(base, ".")
	if dot < 0 {
		if !s.analysis.FromImports[base] {
			return "", ""
		}
		return s.analysis.Imports[base], pythonImportedName(s.analysis, base)
	}
	head, rest, _ := strings.Cut(base[:dot], ".")
	module = s.nameOrigin(head)
	if module != "" && rest != "" {
		module += "." + rest
	}
	return module, base[dot+1:]
}

// pythonHasMainGuard reports an `if __name__ == "__main__":` at module level.
func pythonHasMainGuard(root *sitter.Node, src []byte) bool {
	for i := 0; i < int(root.NamedChildCount()); i++ {
		stmt := root.NamedChild(i)
		if stmt.Type() != nodeIfStatement {
			continue
		}
		condition := stmt.ChildByFieldName("condition")
		if condition == nil {
			continue
		}
		text := strings.ReplaceAll(strings.Join(strings.Fields(condition.Content(src)), ""), "'", `"`)
		text = strings.Trim(text, "()")
		if text == `__name__=="__main__"` || text == `"__main__"==__name__` {
			return true
		}
	}
	return false
}

// registeredViews returns the views a catalog registration call names by
// reference, as Django's path("x/", views.index) or path("x/", index). The
// call must come from the framework (from django.urls import path), and its
// first argument must be the pattern.
func (s *pythonEntryScope) registeredViews(root *sitter.Node, src []byte, module string) []EntryRef {
	catalog := entryCatalog()
	var refs []EntryRef
	var walk func(node *sitter.Node)
	walk = func(node *sitter.Node) {
		if node.Type() == pythonNodeCall {
			refs = append(refs, s.registrationRefs(catalog, node, src, module)...)
		}
		for i := 0; i < int(node.NamedChildCount()); i++ {
			walk(node.NamedChild(i))
		}
	}
	walk(root)
	return refs
}

func (s *pythonEntryScope) registrationRefs(catalog *entrypoints.Catalog, call *sitter.Node, src []byte, module string) []EntryRef {
	args := call.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() < 2 {
		return nil
	}
	callee, name := s.target(call.ChildByFieldName("function"), src)
	entry, ok := catalog.Match(entryLanguagePython, entrypoints.ShapeRegistrationCall, callee, "", name)
	if !ok || (entry.Path == entrypoints.PathRequired && args.NamedChild(0).Type() != nodeStringNode) {
		return nil
	}
	var refs []EntryRef
	for i := 1; i < int(args.NamedChildCount()); i++ {
		if ref, found := s.viewReference(args.NamedChild(i), src, module); found {
			ref.Kind = catalogEntryKind(&entry)
			refs = append(refs, ref)
		}
	}
	return refs
}

// viewReference names the function an argument refers to: a name of the
// module or one it imports, or an attribute of an imported module.
func (s *pythonEntryScope) viewReference(view *sitter.Node, src []byte, module string) (EntryRef, bool) {
	analysis := s.analysis
	ref := EntryRef{Module: true}
	switch view.Type() {
	case goNodeIdentifier:
		target := view.Content(src)
		ref.Function = FunctionID{Package: module, Name: target}
		if imported, ok := analysis.Imports[target]; ok {
			ref.Function = FunctionID{Package: imported, Name: pythonImportedName(analysis, target)}
		}
	case pythonAttribute:
		object := view.ChildByFieldName("object")
		attribute := view.ChildByFieldName("attribute")
		if object == nil || attribute == nil || object.Type() != goNodeIdentifier {
			return EntryRef{}, false
		}
		imported, ok := analysis.Imports[object.Content(src)]
		if !ok {
			return EntryRef{}, false
		}
		if analysis.FromImports[object.Content(src)] {
			// from . import views: the module is a member of the package.
			imported += "." + pythonImportedName(analysis, object.Content(src))
		}
		ref.Function = FunctionID{Package: imported, Name: attribute.Content(src)}
	default:
		return EntryRef{}, false
	}
	return ref, true
}

// pythonConsoleScripts maps each module the nearest project manifest names
// as a console or GUI script to the functions it names: [project.scripts],
// [project.gui-scripts] and [tool.poetry.scripts] in pyproject.toml,
// console_scripts in setup.cfg, and "name = module:function" strings in
// setup.py.
func pythonConsoleScripts(filePath string) map[string]map[string]bool {
	return nearestPythonManifest(filepath.Dir(filePath))
}

var (
	pythonManifests sync.Map
	// pythonScriptEntry matches `name = "module:function"` and its unquoted
	// setup.cfg form.
	pythonScriptEntry = regexp.MustCompile(`^\s*["']?[\w.-]+["']?\s*=\s*["']?([\w.]+)\s*:\s*(\w+)`)
	// pythonSetupPyEntry matches a "name = module:function" string literal.
	pythonSetupPyEntry = regexp.MustCompile(`["']\s*[\w.-]+\s*=\s*([\w.]+)\s*:\s*(\w+)`)
)

func nearestPythonManifest(dir string) map[string]map[string]bool {
	if cached, ok := pythonManifests.Load(dir); ok {
		if scripts, typed := cached.(map[string]map[string]bool); typed {
			return scripts
		}
		return nil
	}
	scripts, found := readPythonManifests(dir)
	if !found {
		if parent := filepath.Dir(dir); parent != dir {
			scripts = nearestPythonManifest(parent)
		}
	}
	pythonManifests.Store(dir, scripts)
	return scripts
}

func readPythonManifests(dir string) (map[string]map[string]bool, bool) {
	scripts := make(map[string]map[string]bool)
	add := func(module, function string) {
		if scripts[module] == nil {
			scripts[module] = make(map[string]bool)
		}
		scripts[module][function] = true
	}
	found := false
	for _, name := range []string{"pyproject.toml", "setup.cfg"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		found = true
		inScripts := false
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "[") {
				inScripts = pythonScriptSection(trimmed)
				continue
			}
			if !inScripts {
				continue
			}
			if m := pythonScriptEntry.FindStringSubmatch(strings.TrimPrefix(trimmed, "console_scripts =")); m != nil {
				add(m[1], m[2])
			}
		}
	}
	if data, err := os.ReadFile(filepath.Join(dir, "setup.py")); err == nil {
		found = true
		for _, m := range pythonSetupPyEntry.FindAllStringSubmatch(string(data), -1) {
			add(m[1], m[2])
		}
	}
	return scripts, found
}

func pythonScriptSection(header string) bool {
	switch strings.ReplaceAll(header, " ", "") {
	case "[project.scripts]", "[project.gui-scripts]", "[tool.poetry.scripts]",
		`[project.entry-points."console_scripts"]`, "[project.entry-points.console_scripts]",
		"[options.entry_points]":
		return true
	}
	return false
}
