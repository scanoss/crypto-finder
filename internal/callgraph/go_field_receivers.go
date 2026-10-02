package callgraph

import "strings"

// mergeGoStructFields folds one file's struct field types into the graph. Two
// declarations of the same struct that disagree on a field's type (build-tag
// variants) leave that field untyped, so a call through it never resolves.
func mergeGoStructFields(graph *CallGraph, fields map[string]map[string]GoFieldType, packagePath string) {
	for structName, byField := range fields {
		key := packagePath + "." + structName
		if graph.goStructFields == nil {
			graph.goStructFields = make(map[string]map[string]GoFieldType)
		}
		merged := graph.goStructFields[key]
		if merged == nil {
			merged = make(map[string]GoFieldType)
			graph.goStructFields[key] = merged
		}
		for name, ft := range byField {
			if prev, seen := merged[name]; seen && prev != ft {
				merged[name] = GoFieldType{}
				continue
			}
			merged[name] = ft
		}
	}
}

// resolveGoFieldReceiverCalls types each Go call made through a struct field
// (`r.cache.Get()`) from the field's declared type, so the ordinary caller
// index and interface fan-out apply: a concrete field links exactly to the
// method, an interface field links to the interface method and from there to
// its implementers. A field the graph has no unambiguous type for leaves the
// call untyped, exactly as before.
func resolveGoFieldReceiverCalls(graph *CallGraph, ecosystem string) {
	if ecosystem != ecosystemGo || len(graph.goStructFields) == 0 {
		return
	}
	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			resolveGoFieldReceiverCall(graph, &fn.Calls[i])
		}
	}
}

func resolveGoFieldReceiverCall(graph *CallGraph, call *FunctionCall) {
	if call.FieldReceiver == nil || call.Callee.Type != "" {
		return
	}
	owner := call.FieldReceiver.Owner
	structKey := owner.Package + "." + strings.TrimLeft(owner.Type, "*")
	ft, ok := graph.goStructFields[structKey][call.FieldReceiver.Name]
	if !ok || ft.Type == "" {
		return
	}
	target := FunctionID{Package: ft.Package, Type: ft.Type, Name: call.Callee.Name}
	if _, declared := graph.Functions[target.String()]; !declared {
		toggled := "*" + ft.Type
		if strings.HasPrefix(ft.Type, "*") {
			toggled = ft.Type[1:]
		}
		other := FunctionID{Package: ft.Package, Type: toggled, Name: call.Callee.Name}
		if _, declared := graph.Functions[other.String()]; declared {
			target = other
		}
	}
	call.Callee = target
}
