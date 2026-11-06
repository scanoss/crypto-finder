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
	"context"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	treec "github.com/smacker/go-tree-sitter/c"
	treecpp "github.com/smacker/go-tree-sitter/cpp"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/java"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/python"
	"github.com/smacker/go-tree-sitter/rust"
	"github.com/smacker/go-tree-sitter/typescript/tsx"
	"github.com/smacker/go-tree-sitter/typescript/typescript"
)

// entry_mentions.go counts the references source code makes to a function
// by name, for the rule that keeps an uncalled function a root when anything
// refers to it (entry_scope.go).
//
// A reference is an identifier the language parser reads in code. A name
// inside a comment, or inside a string literal that holds more than the name
// ("/fingerprint?data=hello", a log message), is not one. A string literal
// that is exactly the name is, since that is how reflection looks a function
// up (getattr(m, "f"), getMethod("f"), exports["f"]).
//
// A qualified reference (liba.fingerprint, liba::fingerprint) counts unless
// its qualifier is a plain name that the file imports from a module, package
// or class no application function of that name is declared in. When the
// qualifier is anything else (a local variable, self, an expression, a name
// the file does not import), the reference may be to this function, so it
// counts. Rust also reads a qualifier the file does not import as the crate or
// module it names, since a path needs no import there.
//
// A file whose language has no parser here, or that does not parse, is
// counted the old way: every identifier-shaped word, strings and comments
// included.

// mentionLanguage is a language mentions are read with.
type mentionLanguage struct {
	grammar *sitter.Language
	// imports maps each name a file binds by import to the path it imports.
	imports func(root *sitter.Node, src []byte) map[string]string
	// qualifier returns the qualifier of a qualified reference whose member
	// is leaf, or nil when leaf is not such a member.
	qualifier func(leaf *sitter.Node) *sitter.Node
	// bareQualifiers reads a qualifier the file does not import as the path
	// it names (a Rust crate or module).
	bareQualifiers bool
}

const (
	sitterIdentifier        = "identifier"
	sitterImportDeclaration = "import_declaration"
	sitterImportSpec        = "import_spec"
	sitterScopedUseList     = "scoped_use_list"
	sitterUseList           = "use_list"
	tsxExtension            = ".tsx"
)

var nodeMember = fieldQualifier(nodeMemberExpression, "property", "object")

func mentionLanguageFor(file string) *mentionLanguage {
	ext := strings.ToLower(filepath.Ext(file))
	switch ext {
	case ".go":
		return &mentionLanguage{grammar: golang.GetLanguage(), imports: goImportBindings, qualifier: fieldQualifier("selector_expression", "field", "operand")}
	case ".py", ".pyi":
		return &mentionLanguage{grammar: python.GetLanguage(), imports: pythonImportBindings, qualifier: fieldQualifier("attribute", "attribute", "object")}
	case ".java":
		return &mentionLanguage{grammar: java.GetLanguage(), imports: javaImportBindings, qualifier: javaQualifier}
	case ".rs":
		return &mentionLanguage{grammar: rust.GetLanguage(), imports: rustUseBindings, qualifier: fieldQualifier(rustNodeScopedIdentifier, "name", "path"), bareQualifiers: true}
	case ".c", ".h":
		return &mentionLanguage{grammar: treec.GetLanguage()}
	case ".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".h++":
		return &mentionLanguage{grammar: treecpp.GetLanguage()}
	}
	if !slices.Contains(nodeSourceExtensions, ext) {
		return nil
	}
	grammar := javascript.GetLanguage()
	switch {
	case ext == tsxExtension:
		grammar = tsx.GetLanguage()
	case strings.HasSuffix(ext, "ts"):
		grammar = typescript.GetLanguage()
	}
	return &mentionLanguage{grammar: grammar, imports: nodeImportBindings, qualifier: nodeMember}
}

// mentionCounter counts references to a set of function names.
type mentionCounter struct {
	names map[string]bool
	// homes maps each name to the module keys of the application functions
	// declaring it: file stems, package and type name segments. A qualified
	// reference whose qualifier imports a path ending in none of them names
	// another module's function.
	homes    map[string]map[string]bool
	mentions map[string]int
}

func newMentionCounter(names map[string]bool, decls []*FunctionDecl) *mentionCounter {
	homes := map[string]map[string]bool{}
	for _, decl := range decls {
		name := BaseFunctionName(decl.ID.Name)
		if !names[name] {
			continue
		}
		if homes[name] == nil {
			homes[name] = map[string]bool{}
		}
		for _, key := range moduleKeys(decl) {
			homes[name][key] = true
		}
	}
	return &mentionCounter{names: names, homes: homes, mentions: map[string]int{}}
}

// moduleKeys names the places a qualifier can point at to reach decl: its
// file, its file's directory (a package, or the module of an index.js,
// __init__.py or mod.rs), each segment of its package and of its type.
func moduleKeys(decl *FunctionDecl) []string {
	var keys []string
	if decl.FilePath != "" {
		keys = append(keys,
			strings.TrimSuffix(filepath.Base(decl.FilePath), filepath.Ext(decl.FilePath)),
			filepath.Base(filepath.Dir(decl.FilePath)))
	}
	keys = append(keys, pathSegments(decl.ID.Package)...)
	keys = append(keys, pathSegments(decl.ID.Type)...)
	return keys
}

var pathSeparators = regexp.MustCompile(`[./:\\]+`)

func pathSegments(path string) []string {
	var out []string
	for _, segment := range pathSeparators.Split(path, -1) {
		if segment != "" {
			out = append(out, segment)
		}
	}
	return out
}

var goMajorVersionSuffix = regexp.MustCompile(`^v\d+$`)

// lastPathSegment is the module, package or class an import path ends in:
// "./liba.js" and "pkg.liba" read liba, "example.com/x/v2" reads x.
func lastPathSegment(path string) string {
	path = strings.Trim(path, "\"'`")
	for _, ext := range append(nodeSourceExtensions, ".py") {
		path = strings.TrimSuffix(path, ext)
	}
	path = strings.TrimSuffix(path, "/index")
	segments := pathSegments(path)
	for len(segments) > 1 && goMajorVersionSuffix.MatchString(segments[len(segments)-1]) {
		segments = segments[:len(segments)-1]
	}
	if len(segments) == 0 {
		return ""
	}
	return segments[len(segments)-1]
}

// countRaw counts every identifier-shaped word of src, strings and comments
// included: configuration files, and source no parser here reads.
func (c *mentionCounter) countRaw(src []byte) {
	for _, word := range identifierPattern.FindAll(src, -1) {
		if c.names[string(word)] {
			c.mentions[string(word)]++
		}
	}
}

// containsName reports whether any of the names occurs in src as a word.
func (c *mentionCounter) containsName(src []byte) bool {
	for _, word := range identifierPattern.FindAll(src, -1) {
		if c.names[string(word)] {
			return true
		}
	}
	return false
}

// countSource counts the references of one source file.
func (c *mentionCounter) countSource(file string, src []byte) {
	if !c.containsName(src) {
		return
	}
	lang := mentionLanguageFor(file)
	if lang == nil {
		c.countRaw(src)
		return
	}
	parser := sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(lang.grammar)
	tree, err := parser.ParseCtx(context.Background(), nil, src)
	if err != nil || tree == nil {
		c.countRaw(src)
		return
	}
	defer tree.Close()
	root := tree.RootNode()
	var imports map[string]string
	if lang.imports != nil {
		imports = lang.imports(root, src)
	}
	c.walk(root, src, lang, imports)
}

func (c *mentionCounter) walk(node *sitter.Node, src []byte, lang *mentionLanguage, imports map[string]string) {
	kind := node.Type()
	if node.ChildCount() == 0 {
		if isIdentifierNode(kind) {
			name := node.Content(src)
			if c.names[name] && !c.foreignMember(node, src, lang, imports, name) {
				c.mentions[name]++
			}
		}
		return
	}
	if isStringNode(kind) {
		if name := stringLiteralValue(node.Content(src)); c.names[name] {
			c.mentions[name]++
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		c.walk(node.Child(i), src, lang, imports)
	}
}

// isIdentifierNode reports a tree-sitter leaf that names something:
// identifier, field_identifier, property_identifier, type_identifier and the
// other *_identifier kinds. Comments and string contents are other kinds.
func isIdentifierNode(kind string) bool {
	return kind == sitterIdentifier || strings.HasSuffix(kind, "_identifier")
}

func isStringNode(kind string) bool {
	switch kind {
	case nodeStringNode, cNodeStringLiteral, goNodeInterpretedString, rustNodeRawStringLiteral, "template_string":
		return true
	default:
		return false
	}
}

// stringLiteralValue strips a literal's prefix letters (r, b, f, u) and its
// quotes.
func stringLiteralValue(text string) string {
	text = strings.TrimLeft(text, "rRbBuUfF")
	for _, quote := range []string{`"""`, `'''`, `"`, `'`, "`"} {
		if len(text) >= 2*len(quote) && strings.HasPrefix(text, quote) && strings.HasSuffix(text, quote) {
			return text[len(quote) : len(text)-len(quote)]
		}
	}
	return text
}

// foreignMember reports a qualified reference whose qualifier is a name the
// file imports from a path no application function called name lives in.
func (c *mentionCounter) foreignMember(leaf *sitter.Node, src []byte, lang *mentionLanguage, imports map[string]string, name string) bool {
	if lang.qualifier == nil {
		return false
	}
	qualifier := lang.qualifier(leaf)
	if qualifier == nil || qualifier.Type() != sitterIdentifier {
		return false
	}
	text := qualifier.Content(src)
	path, imported := imports[text]
	if !imported {
		if !lang.bareQualifiers || text == rustSelfType {
			return false
		}
		path = text
	}
	segment := lastPathSegment(path)
	return segment != "" && !c.homes[name][segment]
}

// fieldQualifier reads a qualified reference from a node of kind whose
// member field holds the leaf and whose qualifier field holds the qualifier.
func fieldQualifier(kind, member, qualifier string) func(*sitter.Node) *sitter.Node {
	return func(leaf *sitter.Node) *sitter.Node {
		parent := leaf.Parent()
		if parent == nil || parent.Type() != kind {
			return nil
		}
		if field := parent.ChildByFieldName(member); field == nil || !sameNode(field, leaf) {
			return nil
		}
		return parent.ChildByFieldName(qualifier)
	}
}

// javaQualifier reads Liba.fingerprint(..), Liba.fingerprint and
// Liba::fingerprint.
func javaQualifier(leaf *sitter.Node) *sitter.Node {
	parent := leaf.Parent()
	if parent == nil {
		return nil
	}
	switch parent.Type() {
	case javaNodeMethodInvocation:
		return fieldQualifier(javaNodeMethodInvocation, "name", "object")(leaf)
	case "field_access":
		return fieldQualifier("field_access", "field", "object")(leaf)
	case "method_reference":
		if parent.NamedChildCount() == 2 && sameNode(parent.NamedChild(1), leaf) {
			return parent.NamedChild(0)
		}
	}
	return nil
}

func sameNode(a, b *sitter.Node) bool {
	return a.StartByte() == b.StartByte() && a.EndByte() == b.EndByte() && a.Type() == b.Type()
}

// pythonImportBindings reads import a.b (binds a), import a.b as c,
// from m import n and from m import n as c.
func pythonImportBindings(root *sitter.Node, src []byte) map[string]string {
	out := map[string]string{}
	for _, stmt := range nodesOfKind(root, "import_statement", "import_from_statement") {
		module := stmt.ChildByFieldName("module_name")
		for i := 0; i < int(stmt.NamedChildCount()); i++ {
			child := stmt.NamedChild(i)
			if module != nil && sameNode(child, module) {
				continue
			}
			binding, path := pythonImportBinding(child, src)
			switch {
			case binding == "":
				continue
			case module != nil:
				path = module.Content(src) + "." + path
			case child.Type() == pythonNodeDottedName:
				binding = strings.SplitN(path, ".", 2)[0]
				path = binding
			}
			out[binding] = path
		}
	}
	return out
}

// pythonImportBinding reads one imported name: a dotted_name binds itself,
// an aliased_import its alias.
func pythonImportBinding(node *sitter.Node, src []byte) (binding, path string) {
	switch node.Type() {
	case pythonNodeDottedName:
		return node.Content(src), node.Content(src)
	case "aliased_import":
		if name, alias := node.ChildByFieldName("name"), node.ChildByFieldName("alias"); name != nil && alias != nil {
			return alias.Content(src), name.Content(src)
		}
	}
	return "", ""
}

// nodeImportBindings reads ES imports and const x = require("m").
func nodeImportBindings(root *sitter.Node, src []byte) map[string]string {
	out := map[string]string{}
	for _, stmt := range nodesOfKind(root, "import_statement") {
		source := stmt.ChildByFieldName("source")
		if source == nil {
			continue
		}
		module := stringLiteralValue(source.Content(src))
		for i := 0; i < int(stmt.NamedChildCount()); i++ {
			if clause := stmt.NamedChild(i); clause.Type() == nodeImportClause {
				readImportClause(clause, src, module, out)
			}
		}
	}
	for _, decl := range nodesOfKind(root, "lexical_declaration", "variable_declaration") {
		for i := 0; i < int(decl.NamedChildCount()); i++ {
			declarator := decl.NamedChild(i)
			name, value := declarator.ChildByFieldName("name"), declarator.ChildByFieldName("value")
			if declarator.Type() != "variable_declarator" || name == nil || value == nil || name.Type() != sitterIdentifier {
				continue
			}
			if module, ok := requireTarget(value, src); ok {
				out[name.Content(src)] = module
			}
		}
	}
	return out
}

// readImportClause reads import x, import * as x and import {a, b as c}.
func readImportClause(clause *sitter.Node, src []byte, module string, out map[string]string) {
	for j := 0; j < int(clause.NamedChildCount()); j++ {
		part := clause.NamedChild(j)
		switch part.Type() {
		case sitterIdentifier:
			out[part.Content(src)] = module
		case "namespace_import":
			for k := 0; k < int(part.NamedChildCount()); k++ {
				if id := part.NamedChild(k); id.Type() == sitterIdentifier {
					out[id.Content(src)] = module
				}
			}
		case "named_imports":
			for k := 0; k < int(part.NamedChildCount()); k++ {
				readImportSpecifier(part.NamedChild(k), src, module, out)
			}
		}
	}
}

// readImportSpecifier binds a in {a} and c in {a as c} to module/a.
func readImportSpecifier(spec *sitter.Node, src []byte, module string, out map[string]string) {
	name, alias := spec.ChildByFieldName("name"), spec.ChildByFieldName("alias")
	if spec.Type() != nodeImportSpecifier || name == nil {
		return
	}
	binding := name
	if alias != nil {
		binding = alias
	}
	out[binding.Content(src)] = module + "/" + name.Content(src)
}

// requireTarget reads require("m"), also as require("m").x.
func requireTarget(value *sitter.Node, src []byte) (string, bool) {
	for value.Type() == nodeMemberExpression {
		value = value.ChildByFieldName("object")
		if value == nil {
			return "", false
		}
	}
	if value.Type() != nodeCallExpression {
		return "", false
	}
	fn, args := value.ChildByFieldName("function"), value.ChildByFieldName("arguments")
	if fn == nil || args == nil || fn.Content(src) != nodeRequireFunction || args.NamedChildCount() == 0 {
		return "", false
	}
	if arg := args.NamedChild(0); arg.Type() == nodeStringNode {
		return stringLiteralValue(arg.Content(src)), true
	}
	return "", false
}

// goImportBindings reads import "a/b" and import x "a/b".
func goImportBindings(root *sitter.Node, src []byte) map[string]string {
	out := map[string]string{}
	for _, spec := range nodesOfKind(root, sitterImportSpec) {
		path := spec.ChildByFieldName("path")
		if path == nil {
			continue
		}
		module := stringLiteralValue(path.Content(src))
		binding := lastPathSegment(module)
		if name := spec.ChildByFieldName("name"); name != nil {
			binding = name.Content(src)
		}
		if binding != "_" && binding != "." && binding != "" {
			out[binding] = module
		}
	}
	return out
}

// javaImportBindings reads single-type imports: import a.b.Liba binds Liba.
func javaImportBindings(root *sitter.Node, src []byte) map[string]string {
	out := map[string]string{}
	for _, decl := range nodesOfKind(root, sitterImportDeclaration) {
		text := strings.TrimSpace(decl.Content(src))
		if strings.HasPrefix(text, "import static ") || strings.Contains(text, "*") {
			continue
		}
		path := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(text, "import")), ";"))
		if binding := lastPathSegment(path); binding != "" {
			out[binding] = path
		}
	}
	return out
}

// rustUseBindings reads use a::b, use a::b as c and use a::{b, c as d}.
func rustUseBindings(root *sitter.Node, src []byte) map[string]string {
	out := map[string]string{}
	for _, decl := range nodesOfKind(root, "use_declaration") {
		if arg := decl.ChildByFieldName("argument"); arg != nil {
			bindRustUse(arg, src, "", out)
		}
	}
	return out
}

func bindRustUse(node *sitter.Node, src []byte, prefix string, out map[string]string) {
	join := func(path string) string {
		if prefix == "" {
			return path
		}
		return prefix + "::" + path
	}
	switch node.Type() {
	case rustNodeIdentifier:
		out[node.Content(src)] = join(node.Content(src))
	case rustNodeScopedIdentifier:
		if name := node.ChildByFieldName("name"); name != nil {
			out[name.Content(src)] = join(node.Content(src))
		}
	case "use_as_clause":
		if path, alias := node.ChildByFieldName("path"), node.ChildByFieldName("alias"); path != nil && alias != nil {
			out[alias.Content(src)] = join(path.Content(src))
		}
	case sitterScopedUseList:
		next := prefix
		if path := node.ChildByFieldName("path"); path != nil {
			next = join(path.Content(src))
		}
		if list := node.ChildByFieldName("list"); list != nil {
			bindRustUse(list, src, next, out)
		}
	case sitterUseList:
		for i := 0; i < int(node.NamedChildCount()); i++ {
			bindRustUse(node.NamedChild(i), src, prefix, out)
		}
	}
}

// nodesOfKind returns the outermost nodes of the given kinds in the tree.
func nodesOfKind(root *sitter.Node, kinds ...string) []*sitter.Node {
	want := map[string]bool{}
	for _, kind := range kinds {
		want[kind] = true
	}
	var out []*sitter.Node
	var visit func(*sitter.Node)
	visit = func(node *sitter.Node) {
		if want[node.Type()] {
			out = append(out, node)
			return
		}
		for i := 0; i < int(node.NamedChildCount()); i++ {
			visit(node.NamedChild(i))
		}
	}
	visit(root)
	return out
}
