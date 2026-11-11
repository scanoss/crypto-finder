// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

// maxNamedValueDepth bounds how many `A = B` hops a reference is followed
// before it is left unresolved.
const maxNamedValueDepth = 8

// NamedValue is a string a name in source denotes wherever it is used, in any
// file: a Java `static final` String constant, a Java enum constant's name(),
// a Python module string constant or Enum member. Parsers record it under the
// fully qualified name a use spells (owner type or module path plus the
// member, then any accessor such as ".name()" or ".value"); the graph is per
// ecosystem, so keys of different languages never meet.
type NamedValue struct {
	// Value is the string literal, quotes included. Empty when the
	// declaration names another value.
	Value        string
	DeclaredType string
	FilePath     string
	Line         int
	// ref is the value an initializer like `A = B` names.
	ref *nameRef
	// ambiguous marks a key that two source files declare differently.
	ambiguous bool
}

// nameRef is a name in source that may denote a NamedValue, carried with the
// keys it could resolve to. The keys come in precedence tiers, the way the
// language's scoping orders them; the first tier with a recorded value
// decides, and two matches within one tier leave it unresolved.
type nameRef struct {
	expr  string
	tiers [][]string
	// placeholder marks a node that exists only to carry the ref, so the fold
	// drops it when the ref resolves to nothing.
	placeholder bool
}

func newNameRef(expr string, tiers [][]string) *nameRef {
	if len(tiers) == 0 {
		return nil
	}
	return &nameRef{expr: expr, tiers: tiers}
}

// withAccessor turns a ref to a member into a ref to the value an accessor of
// that member yields, e.g. `Algo.EC` into `Algo.EC.name()`.
func (r *nameRef) withAccessor(expr, accessor string) *nameRef {
	if r == nil {
		return nil
	}
	tiers := make([][]string, len(r.tiers))
	for i, tier := range r.tiers {
		tiers[i] = make([]string, len(tier))
		for j, key := range tier {
			tiers[i][j] = key + accessor
		}
	}
	return &nameRef{expr: expr, tiers: tiers, placeholder: r.placeholder}
}

func recordNamedValue(analysis *FileAnalysis, key string, value NamedValue) {
	if analysis.NamedValues == nil {
		analysis.NamedValues = make(map[string]NamedValue)
	}
	analysis.NamedValues[key] = value
}

// mergeNamedValues adds one file's values to the graph. A key that another
// file already declares with a different value becomes ambiguous.
func mergeNamedValues(graph *CallGraph, analysis *FileAnalysis) {
	if len(analysis.NamedValues) == 0 {
		return
	}
	if graph.NamedValues == nil {
		graph.NamedValues = make(map[string]NamedValue, len(analysis.NamedValues))
	}
	for key, value := range analysis.NamedValues {
		existing, ok := graph.NamedValues[key]
		if !ok {
			graph.NamedValues[key] = value
			continue
		}
		if existing.ref == nil && value.ref == nil && existing.Value == value.Value {
			continue
		}
		existing.ambiguous = true
		graph.NamedValues[key] = existing
	}
}

// foldNamedValues rewrites every source node whose name resolves to exactly
// one recorded value into the shape a same-class final field already has: a
// FIELD at the declaration with the literal as its one VALUE child. It runs
// once every file is parsed, since the declaring file may be parsed after the
// one using the name.
func foldNamedValues(graph *CallGraph) {
	if graph == nil {
		return
	}
	for _, fn := range graph.Functions {
		fn.ReturnSources = foldNamedValueNodes(fn.ReturnSources, graph.NamedValues)
		for i := range fn.Calls {
			for j, sources := range fn.Calls[i].ArgumentSources {
				fn.Calls[i].ArgumentSources[j] = foldNamedValueNodes(sources, graph.NamedValues)
			}
		}
		if fn.InferredReturn != nil {
			fn.InferredReturn.Provenance = foldNamedValueNodes(fn.InferredReturn.Provenance, graph.NamedValues)
		}
	}
}

func foldNamedValueNodes(nodes []SourceNode, values map[string]NamedValue) []SourceNode {
	if len(nodes) == 0 {
		return nodes
	}
	kept := nodes[:0]
	for i := range nodes {
		node := nodes[i]
		node.SourceNodes = foldNamedValueNodes(node.SourceNodes, values)
		ref := node.nameRef
		node.nameRef = nil
		if ref != nil {
			if value, ok := resolveNamedValue(values, ref, 0, nil); ok {
				node = SourceNode{
					Type:         sourceNodeField,
					Name:         ref.expr,
					DeclaredType: value.DeclaredType,
					Location:     &SourceLocation{FilePath: value.FilePath, Line: value.Line},
					SourceNodes:  []SourceNode{{Type: sourceNodeValue, Value: value.Value}},
					Flow:         node.Flow,
				}
			} else if ref.placeholder {
				continue
			}
		}
		kept = append(kept, node)
	}
	if len(kept) == 0 {
		return nil
	}
	return kept
}

// resolveNamedValue returns the value ref denotes, with the literal of the
// final link when its initializer names another value.
func resolveNamedValue(values map[string]NamedValue, ref *nameRef, depth int, visiting map[string]bool) (NamedValue, bool) {
	key, ok := ref.lookup(values)
	if !ok {
		return NamedValue{}, false
	}
	value := values[key]
	if value.ambiguous {
		return NamedValue{}, false
	}
	if value.ref == nil {
		return value, value.Value != ""
	}
	if depth >= maxNamedValueDepth || visiting[key] {
		return NamedValue{}, false
	}
	if visiting == nil {
		visiting = make(map[string]bool)
	}
	visiting[key] = true
	target, ok := resolveNamedValue(values, value.ref, depth+1, visiting)
	if !ok {
		return NamedValue{}, false
	}
	value.Value = target.Value
	return value, true
}

func (r *nameRef) lookup(values map[string]NamedValue) (string, bool) {
	for _, tier := range r.tiers {
		match := ""
		for _, key := range tier {
			if _, ok := values[key]; !ok || key == match {
				continue
			}
			if match != "" {
				return "", false
			}
			match = key
		}
		if match != "" {
			return match, true
		}
	}
	return "", false
}
