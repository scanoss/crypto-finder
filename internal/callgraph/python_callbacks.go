// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "strings"

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
		params := make(map[string]bool, len(decl.Parameters))
		for _, param := range decl.Parameters {
			params[param.Name] = true
		}
		for j := range decl.Calls {
			call := &decl.Calls[j]
			api, ok := pythonCallbackAPI(call, analysis, declared, executors)
			if !ok {
				continue
			}
			for _, arg := range callbackArguments(call.Arguments, api) {
				if target, ok := pythonCallbackTarget(arg, decl, analysis, params); ok {
					decl.ImplicitCalls = appendCallbackReference(decl.ImplicitCalls, callbackReference(call, target, arg))
				}
			}
		}
	}
}

// pythonCallbackScope returns the variables the file binds to an executor or
// pool, and the module-level functions it declares (a declared `map` is not
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

func pythonCallbackAPI(call *FunctionCall, analysis *FileAnalysis, declared, executors map[string]bool) (callbackAPI, bool) {
	if api, ok := pythonCallbackAPIs[pythonCallbackKey(call)]; ok {
		return api, true
	}
	if call.Callee.Package == analysis.PackagePath && call.Callee.Type == "" && call.Raw == call.Callee.Name && !declared[call.Raw] {
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
// lambda or a parameter, names no function.
func pythonCallbackTarget(arg string, decl *FunctionDecl, analysis *FileAnalysis, params map[string]bool) (FunctionID, bool) {
	object, name, qualified := strings.Cut(arg, ".")
	switch {
	case !qualified:
		if !callbackIdentifier.MatchString(arg) || params[arg] {
			return FunctionID{}, false
		}
		if pkg, ok := analysis.Imports[arg]; ok {
			if analysis.ImportedTypes[arg] {
				return FunctionID{}, false
			}
			return FunctionID{Package: pkg, Name: pythonImportedName(analysis, arg)}, true
		}
		return FunctionID{Package: analysis.PackagePath, Name: arg}, true
	case !callbackIdentifier.MatchString(object) || !callbackIdentifier.MatchString(name) || params[object]:
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
