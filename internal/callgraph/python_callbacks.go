// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// pythonCallbackAPIs lists the callback-invoking APIs, by the callee the
// parser resolves for the registering call, with the arguments they take a
// function in.
var pythonCallbackAPIs = map[string]callbackAPI{
	"threading.Thread":                          {positions: []int{1}, keywords: []string{"target"}},
	"threading.Timer":                           {positions: []int{1}, keywords: []string{"function"}},
	"multiprocessing.Process":                   {positions: []int{1}, keywords: []string{"target"}},
	"atexit.register":                           positional(0),
	"signal.signal":                             positional(1),
	"functools.reduce":                          positional(0),
	"django.db.migrations.RunPython":            {positions: []int{0, 1}, keywords: []string{"code", "reverse_code"}},
	"django.db.migrations.operations.RunPython": {positions: []int{0, 1}, keywords: []string{"code", "reverse_code"}},
}

// pythonBuiltinCallbackAPIs are the builtins that call a function argument.
var pythonBuiltinCallbackAPIs = map[string]callbackAPI{
	"map":    positional(0),
	"filter": positional(0),
	"sorted": {keywords: []string{"key"}},
	"min":    {keywords: []string{"key"}},
	"max":    {keywords: []string{"key"}},
}

// pythonExecutorClasses build the executors and pools whose methods run a
// function argument.
var pythonExecutorClasses = map[string]bool{
	"concurrent.futures.ThreadPoolExecutor":  true,
	"concurrent.futures.ProcessPoolExecutor": true,
	"multiprocessing.Pool":                   true,
	"multiprocessing.pool.ThreadPool":        true,
}

var pythonExecutorMethods = map[string]callbackAPI{
	"submit":         positional(0),
	"map":            positional(0),
	"apply":          positional(0),
	"apply_async":    positional(0),
	"imap":           positional(0),
	"imap_unordered": positional(0),
	"starmap":        positional(0),
}

// addPythonCallbackReferences gives each declaration of the file a reference
// edge to every function it registers as a callback.
func addPythonCallbackReferences(analysis *FileAnalysis) {
	executors, declared := pythonCallbackScope(analysis)
	for i := range analysis.Functions {
		decl := &analysis.Functions[i]
		bound := make(map[string]bool, len(decl.Parameters)+len(decl.boundNames))
		for _, param := range decl.Parameters {
			bound[param.Name] = true
		}
		for name := range decl.boundNames {
			bound[name] = true
		}
		for j := range decl.Calls {
			call := &decl.Calls[j]
			api, ok := pythonCallbackAPI(call, analysis, declared, executors, bound)
			if !ok {
				continue
			}
			for _, arg := range callbackArguments(call.Arguments, api) {
				if target, ok := pythonCallbackTarget(arg, decl, analysis, bound); ok {
					decl.ImplicitCalls = appendCallbackReference(decl.ImplicitCalls, callbackReference(call, target, arg))
				}
			}
		}
	}
}

// pythonCallbackScope returns the variables the file binds to an executor or
// pool (file-wide: a variable bound to an executor in one function counts in
// every function of the file, which only matters for a call that also names a
// known executor method), and the module-level functions it declares (a declared `map` is not
// the builtin).
func pythonCallbackScope(analysis *FileAnalysis) (executors, declared map[string]bool) {
	executors = make(map[string]bool)
	declared = make(map[string]bool)
	for i := range analysis.Functions {
		decl := &analysis.Functions[i]
		if decl.ID.Type == "" {
			declared[decl.ID.Name] = true
		}
		for j := range decl.Calls {
			if call := &decl.Calls[j]; call.AssignedVar != "" && pythonExecutorClasses[pythonCallbackKey(call)] {
				executors[call.AssignedVar] = true
			}
		}
	}
	return executors, declared
}

// pythonCallbackKey names a call's callee as its dotted path, a constructor
// by its class: threading.Thread however the file imports it.
func pythonCallbackKey(call *FunctionCall) string {
	if call.Callee.Name == constructorMethodName && call.Callee.Type != "" {
		return call.Callee.Package + "." + call.Callee.Type
	}
	return call.Callee.String()
}

func pythonCallbackAPI(call *FunctionCall, analysis *FileAnalysis, declared, executors, bound map[string]bool) (callbackAPI, bool) {
	if api, ok := pythonCallbackAPIs[pythonCallbackKey(call)]; ok {
		return api, true
	}
	if call.Callee.Package == analysis.PackagePath && call.Callee.Type == "" && call.Raw == call.Callee.Name && !declared[call.Raw] && !bound[call.Raw] {
		api, ok := pythonBuiltinCallbackAPIs[call.Raw]
		return api, ok
	}
	if receiver, method, ok := strings.Cut(call.Raw, "."); ok && executors[receiver] {
		api, ok := pythonExecutorMethods[method]
		return api, ok
	}
	return callbackAPI{}, false
}

// pythonCallbackTarget resolves a callback argument to the function it names:
// a bare name (a function of the module, or an imported one), `module.fn` of
// an imported module, or `self.method`. Anything else, a call result, a
// lambda, or a name the function binds (a parameter, a local, a loop or
// comprehension variable, a nested def), names no function.
func pythonCallbackTarget(arg string, decl *FunctionDecl, analysis *FileAnalysis, bound map[string]bool) (FunctionID, bool) {
	object, name, qualified := strings.Cut(arg, ".")
	switch {
	case !qualified:
		if !callbackIdentifier.MatchString(arg) || bound[arg] {
			return FunctionID{}, false
		}
		if pkg, ok := analysis.Imports[arg]; ok {
			if analysis.ImportedTypes[arg] {
				return FunctionID{}, false
			}
			return FunctionID{Package: pkg, Name: pythonImportedName(analysis, arg)}, true
		}
		return FunctionID{Package: analysis.PackagePath, Name: arg}, true
	case !callbackIdentifier.MatchString(object) || !callbackIdentifier.MatchString(name) || bound[object] && object != pythonSelfObjectName:
		return FunctionID{}, false
	case object == pythonSelfObjectName:
		if decl.ID.Type == "" {
			return FunctionID{}, false
		}
		return FunctionID{Package: decl.ID.Package, Type: decl.ID.Type, Name: name}, true
	}
	pkg, ok := analysis.Imports[object]
	if !ok || analysis.ImportedTypes[object] {
		return FunctionID{}, false
	}
	if analysis.FromImports[object] {
		pkg += "." + pythonImportedName(analysis, object)
	}
	return FunctionID{Package: pkg, Name: name}, true
}

const (
	pythonNodeDefaultParameter  = "default_parameter"
	pythonNodeTuplePattern      = "tuple_pattern"
	pythonNodeTypedParameter    = "typed_parameter"
	pythonNodeTypedDefaultParam = "typed_default_parameter"
)

// pythonBoundNames collects every name a function definition binds anywhere
// in its span, nested functions, lambdas and comprehensions included: its
// parameters, assignment, loop, `with` and `except` targets, walrus targets,
// and the names of nested definitions, classes and imports. Closure calls are
// attributed to the enclosing function, so a name any scope inside binds may
// not be the module-level function of that name.
func pythonBoundNames(fn *sitter.Node, src []byte) map[string]bool {
	names := make(map[string]bool)
	pythonBoundParameterNames(fn.ChildByFieldName("parameters"), src, names)
	for i := 0; i < int(fn.NamedChildCount()); i++ {
		pythonCollectBindings(fn.NamedChild(i), src, names)
	}
	return names
}

func pythonCollectBindings(node *sitter.Node, src []byte, names map[string]bool) {
	switch node.Type() {
	case "assignment", "augmented_assignment", javaNodeForStatement, "for_in_clause":
		pythonTargetNames(node.ChildByFieldName("left"), src, names)
	case "named_expression":
		pythonTargetNames(node.ChildByFieldName("name"), src, names)
	case "as_pattern":
		pythonTargetNames(node.ChildByFieldName("alias"), src, names)
	case "function_definition", "class_definition":
		pythonTargetNames(node.ChildByFieldName("name"), src, names)
		pythonBoundParameterNames(node.ChildByFieldName("parameters"), src, names)
	case "lambda":
		pythonBoundParameterNames(node.ChildByFieldName("parameters"), src, names)
	case "aliased_import":
		pythonTargetNames(node.ChildByFieldName("alias"), src, names)
	case "import_statement", "import_from_statement":
		for i := 0; i < int(node.NamedChildCount()); i++ {
			if child := node.NamedChild(i); child.Type() == "dotted_name" && child.NamedChildCount() > 0 {
				names[child.NamedChild(0).Content(src)] = true
			}
		}
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		pythonCollectBindings(node.NamedChild(i), src, names)
	}
}

// pythonTargetNames records the names an assignment-like target binds; an
// attribute or a subscript binds none.
func pythonTargetNames(node *sitter.Node, src []byte, names map[string]bool) {
	if node == nil {
		return
	}
	switch node.Type() {
	case goNodeIdentifier:
		names[node.Content(src)] = true
	case "attribute", "subscript":
	default:
		for i := 0; i < int(node.NamedChildCount()); i++ {
			pythonTargetNames(node.NamedChild(i), src, names)
		}
	}
}

// pythonBoundParameterNames records the names a parameter list binds, not the
// default values it reads.
func pythonBoundParameterNames(params *sitter.Node, src []byte, names map[string]bool) {
	for i := 0; params != nil && i < int(params.NamedChildCount()); i++ {
		switch child := params.NamedChild(i); child.Type() {
		case goNodeIdentifier, "list_splat_pattern", "dictionary_splat_pattern", pythonNodeTypedParameter, pythonNodeTuplePattern:
			pythonTargetNames(child, src, names)
		case pythonNodeDefaultParameter, pythonNodeTypedDefaultParam:
			pythonTargetNames(child.ChildByFieldName("name"), src, names)
		}
	}
}
