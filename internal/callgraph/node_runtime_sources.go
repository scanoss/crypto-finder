// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import sitter "github.com/smacker/go-tree-sitter"

// nodeRuntimeSource is the source of process.env.NAME, process.env[name] or
// process.argv[i], when the file declares nothing named process.
func (p *NodeParser) nodeRuntimeSource(node *sitter.Node, depth int) []SourceNode {
	x := p.values
	object := unwrapNodeValue(node.ChildByFieldName("object"))
	if object == nil || object.Type() != nodeMemberExpression || x.disabled || len(x.decls["process"]) > 0 {
		return nil
	}
	root, path := nodeMemberChain(object, x.src)
	if root == nil || root.Content(x.src) != "process" || len(path) != 1 {
		return nil
	}
	runtime, key := p.nodeRuntimeRead(node, path[0], depth)
	if runtime == nil {
		return nil
	}
	return []SourceNode{{
		Type:        sourceNodeExpression,
		Value:       node.Content(x.src),
		Location:    x.location(node),
		SourceNodes: key,
		runtime:     runtime,
	}}
}

// nodeRuntimeRead is the read node makes of process.<member>, with the
// sources of a computed key.
func (p *NodeParser) nodeRuntimeRead(node *sitter.Node, member string, depth int) (*runtimeRef, []SourceNode) {
	x := p.values
	computed := node.Type() == nodeSubscriptExpression
	env := member == "env"
	switch {
	case env && !computed:
		property := node.ChildByFieldName("property")
		if property == nil || property.Type() != nodePropertyIdentifier {
			return nil, nil
		}
		return &runtimeRef{kind: RuntimeSourceEnv, key: property.Content(x.src)}, nil
	case env:
		var key []SourceNode
		if index := node.ChildByFieldName("index"); index != nil && depth < nodeValueMaxDepth {
			key = p.nodeValueSource(index, depth+1)
		}
		return newRuntimeRef(RuntimeSourceEnv, key), key
	case member == "argv" && computed:
		index := unwrapNodeValue(node.ChildByFieldName("index"))
		if index == nil || index.Type() != nodeNumberNode {
			return nil, nil
		}
		return &runtimeRef{kind: RuntimeSourceArgv, key: runtimeKey(RuntimeSourceArgv, index.Content(x.src))}, nil
	}
	return nil, nil
}
