// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	sitter "github.com/smacker/go-tree-sitter"

	"github.com/scanoss/crypto-finder/internal/callgraph/entrypoints"
)

// goCallbackAPIs lists the standard and well-known library APIs that call a
// function argument, keyed by the package path and the function or method
// name. A method is keyed by the package of the value it is called on
// (sync.Once.Do is "sync.Do"): a value of that package with that method is
// the one type that declares it.
var goCallbackAPIs = map[string]callbackAPI{
	"sort.Slice":                       positional(1),
	"sort.SliceStable":                 positional(1),
	"sort.Search":                      positional(1),
	"slices.SortFunc":                  positional(1),
	"slices.SortStableFunc":            positional(1),
	"slices.IndexFunc":                 positional(1),
	"slices.ContainsFunc":              positional(1),
	"time.AfterFunc":                   positional(1),
	"context.AfterFunc":                positional(1),
	"runtime.SetFinalizer":             positional(1),
	"sync.OnceFunc":                    positional(0),
	"sync.Do":                          positional(0),
	"path/filepath.Walk":               positional(1),
	"path/filepath.WalkDir":            positional(1),
	"io/fs.WalkDir":                    positional(2),
	"golang.org/x/sync/errgroup.Go":    positional(0),
	"golang.org/x/sync/errgroup.TryGo": positional(0),
}

// callbackReferences gives each function that passes a function it declares
// to a callback-invoking API a reference edge to it. `go fn()` and
// `defer fn()` are calls already, and a function literal argument is part of
// its enclosing function. An argument that is not a bare function name or
// `pkg.Func` of an imported package (a method value, a variable, a call
// result) gets no edge.
func (s *goEntryScope) callbackReferences(root *sitter.Node, packagePath string) {
	var walk func(node *sitter.Node)
	walk = func(node *sitter.Node) {
		if node.Type() == goNodeCallExpression {
			s.callbackReference(node, packagePath)
		}
		for i := 0; i < int(node.NamedChildCount()); i++ {
			walk(node.NamedChild(i))
		}
	}
	walk(root)
}

func (s *goEntryScope) callbackReference(call *sitter.Node, packagePath string) {
	function := call.ChildByFieldName(goFieldFunction)
	args := call.ChildByFieldName("arguments")
	if function == nil || args == nil || function.Type() != goNodeSelectorExpression {
		return
	}
	operand := function.ChildByFieldName(goFieldOperand)
	field := function.ChildByFieldName(goFieldField)
	if operand == nil || field == nil {
		return
	}
	var pkg string
	if imported, ok := s.analysis.Imports[operand.Content(s.src)]; ok && operand.Type() == goNodeIdentifier && !s.shadowed(operand) {
		pkg = imported
	} else {
		pkg = s.origin(operand, 0).pkg
	}
	api, ok := goCallbackAPIs[pkg+"."+field.Content(s.src)]
	if pkg == "" || !ok {
		return
	}
	registrar := s.enclosingDecl(call)
	if registrar == nil {
		return
	}
	site := FunctionCall{
		FilePath: registrar.FilePath,
		Line:     int(call.StartPoint().Row) + 1,
		StartCol: int(call.StartPoint().Column) + 1,
		EndCol:   int(call.EndPoint().Column) + 1,
	}
	for i := 0; i < int(args.NamedChildCount()); i++ {
		if !positionTaken(api, i) {
			continue
		}
		arg := args.NamedChild(i)
		if target, ok := s.callbackTarget(arg, packagePath); ok {
			registrar.ImplicitCalls = appendCallbackReference(registrar.ImplicitCalls, callbackReference(&site, target, arg.Content(s.src)))
		}
	}
}

func positionTaken(api callbackAPI, position int) bool {
	for _, p := range api.positions {
		if p == position {
			return true
		}
	}
	return false
}

// enclosingDecl is the declaration of the function or method whose body holds
// node, or nil at package level.
func (s *goEntryScope) enclosingDecl(node *sitter.Node) *FunctionDecl {
	for scope := node.Parent(); scope != nil; scope = scope.Parent() {
		if scope.Type() != goNodeFunctionDecl && scope.Type() != goNodeMethodDecl {
			continue
		}
		line := int(scope.StartPoint().Row) + 1
		for i := range s.analysis.Functions {
			if decl := &s.analysis.Functions[i]; decl.StartLine == line && decl.EndLine == int(scope.EndPoint().Row)+1 {
				return decl
			}
		}
		return nil
	}
	return nil
}

// callbackTarget resolves a callback argument to the function it names.
func (s *goEntryScope) callbackTarget(arg *sitter.Node, packagePath string) (FunctionID, bool) {
	switch arg.Type() {
	case goNodeIdentifier:
		if s.shadowed(arg) {
			return FunctionID{}, false
		}
		return FunctionID{Package: packagePath, Name: arg.Content(s.src)}, true
	case goNodeSelectorExpression:
		operand := arg.ChildByFieldName(goFieldOperand)
		field := arg.ChildByFieldName(goFieldField)
		if operand == nil || field == nil || operand.Type() != goNodeIdentifier || s.shadowed(operand) {
			return FunctionID{}, false
		}
		if imported, ok := s.analysis.Imports[operand.Content(s.src)]; ok {
			return FunctionID{Package: imported, Name: field.Content(s.src)}, true
		}
	}
	return FunctionID{}, false
}

// assignedHandlerFields records the handlers a statement assigns to the
// handler fields of a catalog struct: cmd.RunE = run, the assignment form of
// &cobra.Command{RunE: run}.
func (s *goEntryScope) assignedHandlerFields(assign *sitter.Node, packagePath string) {
	left := assign.ChildByFieldName(goFieldLeft)
	right := assign.ChildByFieldName(goFieldRight)
	if left == nil || right == nil {
		return
	}
	entries := entryCatalog().Entries(entryLanguageGo, entrypoints.ShapeHandlerField)
	for i := 0; i < int(left.NamedChildCount()); i++ {
		target := left.NamedChild(i)
		value := goListElement(right, i)
		if target.Type() != goNodeSelectorExpression || value == nil {
			continue
		}
		owner := s.origin(target.ChildByFieldName(goFieldOperand), 0)
		field := target.ChildByFieldName(goFieldField)
		if field == nil || owner.pkg == "" || owner.typeName == "" {
			continue
		}
		for j := range entries {
			if entry := &entries[j]; entry.Covers(owner.pkg) && entry.HasType(owner.typeName) && entry.HasName(field.Content(s.src)) {
				s.analysis.EntryRefs = s.appendHandlerRef(s.analysis.EntryRefs, value, packagePath, catalogEntryKind(entry))
			}
		}
	}
}
