// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// pythonRuntimeCall marks os.getenv(name[, default]) and
// os.environ.get(name[, default]), with the name passed positionally.
func pythonRuntimeCall(node *sitter.Node, call *FunctionCall) *runtimeRef {
	target := call.Callee.Package + "." + call.Callee.Name
	if call.Callee.Type != "" || (target != "os.getenv" && target != "os.environ.get") {
		return nil
	}
	args := pythonArgumentListChild(node)
	if args == nil || args.NamedChildCount() < 1 || args.NamedChildCount() > 2 ||
		args.NamedChild(0).Symbol() == pythonSyms.keywordArgument || len(call.ArgumentSources) == 0 {
		return nil
	}
	return newRuntimeRef(RuntimeSourceEnv, call.ArgumentSources[0])
}

// pythonRuntimeSubscript is the source of os.environ[name] or sys.argv[i],
// with the module imported under the name the expression spells.
func (p *PythonParser) pythonRuntimeSubscript(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, bindings pythonBindings, fw *pythonFileWalk, depth int) []SourceNode {
	value, index := node.ChildByFieldName("value"), node.ChildByFieldName("subscript")
	if value == nil || index == nil || node.NamedChildCount() != 2 {
		return nil
	}
	ref := pythonNamedValueRef(value.Content(src), analysis, bindings, fw)
	if ref == nil {
		return nil
	}
	var runtime *runtimeRef
	var key []SourceNode
	switch ref.tiers[0][0] {
	case "os.environ":
		key = p.pythonArgumentSourceFor(index, src, filePath, analysis, bindings, fw, depth)
		runtime = newRuntimeRef(RuntimeSourceEnv, key)
	case "sys.argv":
		if index.Symbol() != pythonSyms.integer {
			return nil
		}
		runtime = &runtimeRef{kind: RuntimeSourceArgv, key: runtimeKey(RuntimeSourceArgv, index.Content(src))}
	default:
		return nil
	}
	return []SourceNode{{
		Type:        sourceNodeExpression,
		Value:       strings.TrimSpace(node.Content(src)),
		Location:    &SourceLocation{FilePath: filePath, Line: int(node.StartPoint().Row) + 1},
		SourceNodes: key,
		runtime:     runtime,
	}}
}

// pythonRuntimeShape reports that value is spelled like a runtime read
// pythonRuntimeCall or pythonRuntimeSubscript may mark. Only the use site,
// which resolves imports, decides that it is one.
func pythonRuntimeShape(value *sitter.Node, src []byte) bool {
	switch value.Symbol() {
	case pythonSyms.subscript:
		target := value.ChildByFieldName("value")
		if target == nil {
			return false
		}
		text := target.Content(src)
		return text == "environ" || text == "argv" || strings.HasSuffix(text, ".environ") || strings.HasSuffix(text, ".argv")
	case pythonSyms.call:
		fn := value.ChildByFieldName("function")
		if fn == nil {
			return false
		}
		text := fn.Content(src)
		return text == "getenv" || strings.HasSuffix(text, ".getenv") || strings.HasSuffix(text, "environ.get")
	}
	return false
}
