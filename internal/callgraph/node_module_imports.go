// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
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
			if !nodeIsTypeOnlyModuleStatement(node) {
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
