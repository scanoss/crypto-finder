// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// nodeGlobalCallbackAPIs are the globals that call a function argument.
var nodeGlobalCallbackAPIs = map[string]callbackAPI{
	"setTimeout":       positional(0),
	"setInterval":      positional(0),
	"setImmediate":     positional(0),
	"queueMicrotask":   positional(0),
	"process.nextTick": positional(0),
}

// nodeMethodCallbackAPIs are the Array, Promise and event emitter methods that
// call a function argument. `find`, `some`, `every` and `sort` are left out: as method names they are likelier a domain or repository method than an Array one. The receiver is usually of a type the parser
// cannot know (`items.map(fn)`), so they match by method name and argument
// position. That is sound for the edge recorded: the registrar passes a
// declared function to a method that runs the function it is given. An
// imported object (`_.map(xs, fn)`, `Promise.race`) is not matched.
var nodeMethodCallbackAPIs = map[string]callbackAPI{
	"map": positional(0), "forEach": positional(0), "filter": positional(0),
	"reduce": positional(0), "reduceRight": positional(0), "flatMap": positional(0),
	"then": positional(0, 1), "catch": positional(0), "finally": positional(0),
	"addEventListener": positional(1),
	"on":               positional(1), "once": positional(1), "addListener": positional(1),
	"prependListener": positional(1),
}

// nodeElectronIPCAPIs are the methods of Electron's ipcMain that call a
// handler.
var nodeElectronIPCAPIs = map[string]callbackAPI{
	"handle": positional(1), "handleOnce": positional(1), "on": positional(1), "once": positional(1),
}

// nodeCallbackReferences returns a reference to each declared function the
// body hands to a callback-invoking API: a bare name, `module.fn` of an
// imported module, or `this.method`. Functions written inline are
// declarations of their own, reached by nodeImplicitCalls, and a name the
// function itself binds (a parameter, a local) names no declared function.
func nodeCallbackReferences(body *sitter.Node, src []byte, filePath, packagePath, owner string, imports nodeBindings, locals, own map[string]bool) []FunctionCall {
	var out []FunctionCall
	var walk func(node *sitter.Node)
	walk = func(node *sitter.Node) {
		if node == nil || isNodeNestedScope(node.Type()) {
			return
		}
		if api, args, ok := nodeCallbackCall(node, src, imports, own); ok {
			site := FunctionCall{
				FilePath: filePath,
				Line:     int(node.StartPoint().Row) + 1,
				StartCol: int(node.StartPoint().Column) + 1,
				EndCol:   int(node.EndPoint().Column) + 1,
			}
			for i := 0; i < int(args.NamedChildCount()); i++ {
				if !positionTaken(api, i) {
					continue
				}
				arg := args.NamedChild(i)
				if target, ok := nodeCallbackTarget(arg, src, packagePath, owner, imports, locals, own); ok {
					out = appendCallbackReference(out, callbackReference(&site, target, arg.Content(src)))
				}
			}
		}
		for i := 0; i < int(node.ChildCount()); i++ {
			walk(node.Child(i))
		}
	}
	walk(body)
	return out
}

// nodeCallbackCall returns the callback API a call or `new` expression
// invokes, and its argument list.
func nodeCallbackCall(node *sitter.Node, src []byte, imports nodeBindings, own map[string]bool) (callbackAPI, *sitter.Node, bool) {
	switch node.Type() {
	case nodeCallExpression:
	case "new_expression":
		constructor := node.ChildByFieldName("constructor")
		args := node.ChildByFieldName("arguments")
		if constructor != nil && args != nil && constructor.Content(src) == "Promise" && nodeIsGlobal("Promise", imports, own) {
			return positional(0), args, true
		}
		return callbackAPI{}, nil, false
	default:
		return callbackAPI{}, nil, false
	}
	function := node.ChildByFieldName("function")
	args := node.ChildByFieldName(nodeArgumentsNode)
	if function == nil || args == nil {
		return callbackAPI{}, nil, false
	}
	switch function.Type() {
	case goNodeIdentifier:
		name := function.Content(src)
		api, ok := nodeGlobalCallbackAPIs[name]
		return api, args, ok && nodeIsGlobal(name, imports, own)
	case nodeMemberExpression:
		api, ok := nodeMemberCallbackAPI(function, src, imports, own)
		return api, args, ok
	}
	return callbackAPI{}, nil, false
}

// nodeMemberCallbackAPI returns the callback API a method call invokes.
func nodeMemberCallbackAPI(function *sitter.Node, src []byte, imports nodeBindings, own map[string]bool) (callbackAPI, bool) {
	object := function.ChildByFieldName("object")
	property := function.ChildByFieldName("property")
	if object == nil || property == nil {
		return callbackAPI{}, false
	}
	objectText, method := object.Content(src), property.Content(src)
	first, _ := splitNodeMemberObject(objectText)
	if first == "ipcMain" {
		binding, imported := imports.lookup(own, first)
		api, ok := nodeElectronIPCAPIs[method]
		return api, ok && imported && binding.module == "electron"
	}
	if api, ok := nodeGlobalCallbackAPIs[objectText+"."+method]; ok {
		return api, nodeIsGlobal(first, imports, own)
	}
	if _, imported := imports.lookup(own, first); imported {
		return callbackAPI{}, false
	}
	api, ok := nodeMethodCallbackAPIs[method]
	return api, ok
}

func nodeIsGlobal(name string, imports nodeBindings, own map[string]bool) bool {
	return !own[name] && !nodeIsImported(name, imports)
}

func nodeIsImported(name string, imports nodeBindings) bool {
	binding, ok := imports[name]
	return ok && binding.module != ""
}

// nodeCallbackTarget resolves a callback argument to the function it names.
func nodeCallbackTarget(arg *sitter.Node, src []byte, packagePath, owner string, imports nodeBindings, locals, own map[string]bool) (FunctionID, bool) {
	for arg != nil && nodeIsTransparentWrapper(arg.Type()) {
		if arg.NamedChildCount() == 0 {
			return FunctionID{}, false
		}
		arg = arg.NamedChild(0)
	}
	if arg == nil {
		return FunctionID{}, false
	}
	switch arg.Type() {
	case goNodeIdentifier:
		name := arg.Content(src)
		if own[name] {
			return FunctionID{}, false
		}
		return nodeNamedReference(name, packagePath, imports, locals), true
	case nodeMemberExpression:
		return nodeMemberCallbackTarget(arg, src, packagePath, owner, imports, own)
	}
	return FunctionID{}, false
}

// nodeIsTransparentWrapper reports the expressions that only annotate the
// value inside them: `fn as Handler`, `fn!`, `(fn)`.
func nodeIsTransparentWrapper(nodeType string) bool {
	switch nodeType {
	case "as_expression", "satisfies_expression", "non_null_expression", javaNodeParenthesizedExpr:
		return true
	}
	return false
}

// nodeMemberCallbackTarget resolves `this.method` and `module.fn`.
func nodeMemberCallbackTarget(arg *sitter.Node, src []byte, packagePath, owner string, imports nodeBindings, own map[string]bool) (FunctionID, bool) {
	object := arg.ChildByFieldName("object")
	property := arg.ChildByFieldName("property")
	if object == nil || property == nil || property.Type() != "property_identifier" {
		return FunctionID{}, false
	}
	name := property.Content(src)
	if object.Type() == "this" {
		if owner == "" {
			return FunctionID{}, false
		}
		return FunctionID{Package: packagePath, Type: owner, Name: name}, true
	}
	first, suffix := splitNodeMemberObject(object.Content(src))
	if binding, ok := imports.lookup(own, first); ok && !strings.ContainsAny(object.Content(src), "()[]") {
		pkg, _ := binding.qualify(suffix, name)
		return FunctionID{Package: pkg, Name: name}, true
	}
	return FunctionID{}, false
}
