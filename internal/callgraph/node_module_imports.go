// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"path/filepath"
	"slices"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

const (
	nodeImportStatement  = "import_statement"
	nodeImportClause     = "import_clause"
	nodeExportClauseKind = "export_clause"
	nodeTypeKeyword      = ownerTypeType
)

// nodeModuleImportCollector gathers the project modules one module loads.
type nodeModuleImportCollector struct {
	root                  *sitter.Node
	typescript            bool
	src                   []byte
	filePath, packagePath string
	modulePath            string
	seen                  map[string]bool
	calls                 []FunctionCall
}

// nodeModuleImportReferences returns one reference per project module that the
// module at root loads when its top level runs: `import './x'`,
// `import a from './x'`, `export ... from './x'`, `export * from './x'` and a
// top-level `require('./x')`. Loading a module runs its top level, so the
// importer's <module> reaches the imported <module> with certainty.
//
// A type-only import is erased at compile time and loads nothing. A dynamic
// import() and a require inside a function run only when that function does,
// so neither is the module's call. A package specifier names no project file
// and is left out, as is a module importing itself.
func nodeModuleImportReferences(root *sitter.Node, src []byte, filePath, packagePath, modulePath string) []FunctionCall {
	c := &nodeModuleImportCollector{
		root: root, typescript: nodeIsTypeScriptFile(filePath),
		src: src, filePath: filePath, packagePath: packagePath, modulePath: modulePath,
		seen: make(map[string]bool),
	}
	c.walk(root)
	return c.calls
}

func (c *nodeModuleImportCollector) walk(node *sitter.Node) {
	if node == nil || isNodeNestedScope(node.Type()) {
		return
	}
	switch node.Type() {
	case nodeImportStatement, nodeExportKind:
		if source := node.ChildByFieldName("source"); source != nil {
			if !nodeIsTypeOnlyModuleStatement(node) && !c.erased(node) {
				c.add(node, source)
			}
			return
		}
	case nodeCallExpression:
		if specifier := c.requireSpecifier(node); specifier != nil {
			c.add(node, specifier)
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		c.walk(node.Child(i))
	}
}

// requireSpecifier returns the argument of a `require(..)` call.
func (c *nodeModuleImportCollector) requireSpecifier(call *sitter.Node) *sitter.Node {
	function, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if function == nil || args == nil || args.NamedChildCount() != 1 {
		return nil
	}
	if function.Type() != goNodeIdentifier || function.Content(c.src) != nodeRequireFunction {
		return nil
	}
	return args.NamedChild(0)
}

func (c *nodeModuleImportCollector) add(node, specifier *sitter.Node) {
	if specifier.Type() != nodeStringNode {
		return
	}
	target, ok := resolveNodeRelativeModule(c.filePath, c.packagePath, unquoteNodeString(specifier.Content(c.src)))
	if !ok || target == c.modulePath || c.seen[target] {
		return
	}
	c.seen[target] = true
	callee := FunctionID{Package: target, Name: moduleInitMethodName}
	c.calls = append(c.calls, FunctionCall{
		Callee:    callee,
		Raw:       callee.Name,
		FilePath:  c.filePath,
		Line:      int(node.StartPoint().Row) + 1,
		StartCol:  int(node.StartPoint().Column) + 1,
		EndCol:    int(node.EndPoint().Column) + 1,
		Reference: true,
	})
}

// nodeIsTypeOnlyModuleStatement reports `import type ...` and `export type ...
// from`, which TypeScript erases.
func nodeIsTypeOnlyModuleStatement(node *sitter.Node) bool {
	for i := 0; i < int(node.ChildCount()); i++ {
		switch child := node.Child(i); child.Type() {
		case nodeTypeKeyword:
			if !child.IsNamed() {
				return true
			}
		case nodeImportClause, nodeExportClauseKind, nodeStringNode:
			return false
		}
	}
	return false
}

func nodeIsTypeScriptFile(filePath string) bool {
	return slices.Contains(nodeSourceExtensions[:4], strings.ToLower(filepath.Ext(filePath)))
}

// erased reports a statement TypeScript drops without loading the module: every
// specifier carries the inline `type` keyword, or, in a TypeScript file, every
// binding the statement introduces is used only where a type is written. A
// bare `import './x'` introduces no binding and is never erased. A name used
// as `typeof X` in a type counts as a value use, which keeps the edge.
func (c *nodeModuleImportCollector) erased(node *sitter.Node) bool {
	specifiers, values := nodeModuleBindings(node, c.src)
	if specifiers == 0 {
		return false
	}
	if len(values) == 0 {
		return true
	}
	if !c.typescript || node.Type() != nodeImportStatement {
		return false
	}
	for _, name := range values {
		if c.usedAsValue(name, node) {
			return false
		}
	}
	return true
}

// nodeModuleBindings counts the specifiers of an import or export statement and
// returns the local names of those without the inline `type` keyword.
func nodeModuleBindings(node *sitter.Node, src []byte) (specifiers int, values []string) {
	var collect func(n *sitter.Node)
	collect = func(n *sitter.Node) {
		switch n.Type() {
		case "import_specifier", "export_specifier":
			specifiers++
			if nodeHasInlineTypeKeyword(n) {
				return
			}
			name := n.ChildByFieldName("name")
			if alias := n.ChildByFieldName("alias"); alias != nil {
				name = alias
			}
			if name != nil {
				values = append(values, name.Content(src))
			}
			return
		case goNodeIdentifier:
			if parent := n.Parent(); parent != nil && (parent.Type() == nodeImportClause || parent.Type() == "namespace_import") {
				specifiers++
				values = append(values, n.Content(src))
			}
			return
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			collect(n.Child(i))
		}
	}
	collect(node)
	return specifiers, values
}

func nodeHasInlineTypeKeyword(specifier *sitter.Node) bool {
	for i := 0; i < int(specifier.ChildCount()); i++ {
		if child := specifier.Child(i); child.Type() == nodeTypeKeyword && !child.IsNamed() {
			return true
		}
	}
	return false
}

// usedAsValue reports an identifier named name outside the import statement.
// Type positions use type_identifier nodes, so an identifier is a value use.
func (c *nodeModuleImportCollector) usedAsValue(name string, statement *sitter.Node) bool {
	var found bool
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		if found || n == nil || n == statement {
			return
		}
		if n.Type() == goNodeIdentifier && n.Content(c.src) == name {
			found = true
			return
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			walk(n.Child(i))
		}
	}
	walk(c.root)
	return found
}
