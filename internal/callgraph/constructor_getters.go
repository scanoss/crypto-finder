// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

// ctorGetterRef marks a call of a zero-argument method on a receiver whose
// construction the parser saw: `new Holder("x").getAlg()`, or `h.get_alg()`
// where the function binds `h` once, to `Holder("x")`. The method is looked up
// on the constructed class itself, so an override in a subclass or a receiver
// of another runtime type never borrows the value.
type ctorGetterRef struct {
	constructor FunctionID
	method      string
	arguments   []ctorArgument
}

// ctorArgument is one argument of the construction, as written at the call.
type ctorArgument struct {
	// keyword is the parameter a keyword argument names, empty when positional.
	keyword string
	// splat marks `*args` or `**kwargs`, which fills no provable position.
	splat   bool
	sources []SourceNode
}

// foldConstructorGetters rewrites every call a ctorGetterRef marks, when the
// method returns a field set from constructor parameter k, into the field with
// argument k's sources: the FIELD{VALUE} shape a same-class final field has.
// It runs once every file is parsed, since the class may be declared in a file
// parsed after the call.
func foldConstructorGetters(graph *CallGraph) {
	if graph == nil {
		return
	}
	for _, fn := range graph.Functions {
		fn.ReturnSources = foldConstructorGetterNodes(graph, fn.ReturnSources)
		for i := range fn.Calls {
			for j, sources := range fn.Calls[i].ArgumentSources {
				fn.Calls[i].ArgumentSources[j] = foldConstructorGetterNodes(graph, sources)
			}
		}
		if fn.InferredReturn != nil {
			fn.InferredReturn.Provenance = foldConstructorGetterNodes(graph, fn.InferredReturn.Provenance)
		}
	}
}

func foldConstructorGetterNodes(graph *CallGraph, nodes []SourceNode) []SourceNode {
	for i := range nodes {
		nodes[i].SourceNodes = foldConstructorGetterNodes(graph, nodes[i].SourceNodes)
		ref := nodes[i].getter
		nodes[i].getter = nil
		if ref == nil {
			continue
		}
		ctor := graph.Functions[ref.constructor.String()]
		method := graph.Functions[FunctionID{Package: ref.constructor.Package, Type: ref.constructor.Type, Name: ref.method}.String()]
		field, param, ok := constructorFieldParameter(method, ctor)
		if !ok {
			continue
		}
		slot, ok := ctorArgumentSlot(ref.arguments, param.ParameterIndex, param.Name)
		if !ok || len(ref.arguments[slot].sources) == 0 {
			continue
		}
		nodes[i] = SourceNode{
			Type:         sourceNodeField,
			Name:         nodes[i].Value,
			DeclaredType: field.DeclaredType,
			Location:     param.Location,
			SourceNodes:  foldConstructorGetterNodes(graph, ref.arguments[slot].sources),
			Flow:         nodes[i].Flow,
		}
	}
	return nodes
}

// constructorFieldParameter reports the constructor parameter whose value
// method returns: method's one return source is a field, and that field's one
// source is a parameter of ctor assigned inside ctor's body. Parsers emit that
// shape only for a field no other code writes.
func constructorFieldParameter(method, ctor *FunctionDecl) (field, param SourceNode, ok bool) {
	if method == nil || ctor == nil || len(method.ReturnSources) != 1 {
		return SourceNode{}, SourceNode{}, false
	}
	field = method.ReturnSources[0]
	if field.Type != sourceNodeField || len(field.SourceNodes) != 1 {
		return SourceNode{}, SourceNode{}, false
	}
	param = field.SourceNodes[0]
	loc := param.Location
	if param.Type != sourceNodeParameter || loc == nil || loc.FilePath != ctor.FilePath ||
		loc.Line < ctor.StartLine || loc.Line > ctor.EndLine ||
		param.ParameterIndex < 0 || param.ParameterIndex >= len(ctor.Parameters) ||
		ctor.Parameters[param.ParameterIndex].Name != param.Name {
		return SourceNode{}, SourceNode{}, false
	}
	return field, param, true
}

// ctorArgumentSlot is the argument that fills the parameter declared at index
// with name: the keyword argument naming it, else the argument at index when
// every argument up to it is positional.
func ctorArgumentSlot(args []ctorArgument, index int, name string) (int, bool) {
	for i := range args {
		if name != "" && args[i].keyword == name {
			return i, true
		}
	}
	if index < 0 || index >= len(args) {
		return 0, false
	}
	for i := 0; i <= index; i++ {
		if args[i].keyword != "" || args[i].splat {
			return 0, false
		}
	}
	return index, true
}
