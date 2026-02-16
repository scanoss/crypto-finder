package callgraph

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// GraphMetadata holds summary information about a call graph.
type GraphMetadata struct {
	Ecosystem     string `json:"ecosystem"`
	RootModule    string `json:"root_module"`
	FunctionCount int    `json:"function_count"`
	EdgeCount     int    `json:"edge_count"`
}

// jsonOutput is the top-level JSON structure for the callgraph command.
type jsonOutput struct {
	Metadata  GraphMetadata            `json:"metadata"`
	Functions map[string]*jsonFunction `json:"functions"`
	Callers   map[string][]string      `json:"callers"`
}

// jsonFunction represents a single function in JSON output.
type jsonFunction struct {
	Package   string     `json:"package"`
	Type      string     `json:"type"`
	Name      string     `json:"name"`
	File      string     `json:"file"`
	StartLine int        `json:"start_line"`
	EndLine   int        `json:"end_line"`
	Calls     []jsonCall `json:"calls"`
}

// jsonCall represents a single outgoing call in JSON output.
type jsonCall struct {
	Callee string `json:"callee"`
	File   string `json:"file"`
	Line   int    `json:"line"`
}

// FormatJSON serializes the call graph to JSON with metadata.
func FormatJSON(graph *CallGraph, metadata GraphMetadata) ([]byte, error) {
	if graph == nil {
		return nil, fmt.Errorf("nil call graph")
	}

	functions := make(map[string]*jsonFunction, len(graph.Functions))

	for key, fn := range graph.Functions {
		calls := make([]jsonCall, len(fn.Calls))
		for i, c := range fn.Calls {
			calls[i] = jsonCall{
				Callee: c.Callee.String(),
				File:   c.FilePath,
				Line:   c.Line,
			}
		}
		functions[key] = &jsonFunction{
			Package:   fn.ID.Package,
			Type:      fn.ID.Type,
			Name:      fn.ID.Name,
			File:      fn.FilePath,
			StartLine: fn.StartLine,
			EndLine:   fn.EndLine,
			Calls:     calls,
		}
	}

	out := jsonOutput{
		Metadata:  metadata,
		Functions: functions,
		Callers:   graph.Callers,
	}

	return json.MarshalIndent(out, "", "  ")
}

// FormatDOT serializes the call graph in Graphviz DOT format.
func FormatDOT(graph *CallGraph) ([]byte, error) {
	if graph == nil {
		return nil, fmt.Errorf("nil call graph")
	}

	var b strings.Builder

	b.WriteString("digraph callgraph {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  node [shape=box, style=filled, fillcolor=\"#e8e8e8\"];\n\n")

	// Group functions by package for subgraph clusters
	pkgFunctions := make(map[string][]string)
	for key, fn := range graph.Functions {
		pkgFunctions[fn.ID.Package] = append(pkgFunctions[fn.ID.Package], key)
	}

	// Sort packages for deterministic output
	pkgs := make([]string, 0, len(pkgFunctions))
	for pkg := range pkgFunctions {
		pkgs = append(pkgs, pkg)
	}
	sort.Strings(pkgs)

	for _, pkg := range pkgs {
		keys := pkgFunctions[pkg]
		sort.Strings(keys)

		// Use short label: last segment of the package path
		label := pkg
		if idx := strings.LastIndex(pkg, "/"); idx != -1 {
			label = pkg[idx+1:]
		} else if idx := strings.LastIndex(pkg, "."); idx != -1 {
			label = pkg[idx+1:]
		}

		fmt.Fprintf(&b, "  subgraph %q {\n", "cluster_"+pkg)
		fmt.Fprintf(&b, "    label=%q;\n", label)
		for _, key := range keys {
			fn := graph.Functions[key]
			nodeLabel := fn.ID.Name
			if fn.ID.Type != "" {
				nodeLabel = fn.ID.Type + "." + fn.ID.Name
			}
			fmt.Fprintf(&b, "    %q [label=%q];\n", key, nodeLabel)
		}
		b.WriteString("  }\n\n")
	}

	// Edges
	sortedKeys := make([]string, 0, len(graph.Functions))
	for key := range graph.Functions {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Strings(sortedKeys)

	for _, callerKey := range sortedKeys {
		fn := graph.Functions[callerKey]
		for _, call := range fn.Calls {
			calleeKey := call.Callee.String()
			// Shorten file label to basename:line
			fileLabel := call.FilePath
			if idx := strings.LastIndex(fileLabel, "/"); idx != -1 {
				fileLabel = fileLabel[idx+1:]
			}
			edgeLabel := fmt.Sprintf("%s:%d", fileLabel, call.Line)
			fmt.Fprintf(&b, "  %q -> %q [label=%q];\n", callerKey, calleeKey, edgeLabel)
		}
	}

	b.WriteString("}\n")
	return []byte(b.String()), nil
}

// FormatText serializes the call graph as human-readable text.
func FormatText(graph *CallGraph) ([]byte, error) {
	if graph == nil {
		return nil, fmt.Errorf("nil call graph")
	}

	var b strings.Builder

	edgeCount := 0
	for _, fn := range graph.Functions {
		edgeCount += len(fn.Calls)
	}

	fmt.Fprintf(&b, "Call Graph: %d functions, %d edges\n\n", len(graph.Functions), edgeCount)

	// Sort functions for deterministic output
	keys := make([]string, 0, len(graph.Functions))
	for key := range graph.Functions {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		fn := graph.Functions[key]
		fmt.Fprintf(&b, "%s (%s:%d-%d)\n", key, fn.FilePath, fn.StartLine, fn.EndLine)
		for _, call := range fn.Calls {
			fmt.Fprintf(&b, "  → %s (%s:%d)\n", call.Callee.String(), call.FilePath, call.Line)
		}
		b.WriteString("\n")
	}

	return []byte(b.String()), nil
}

// FormatTraceText formats trace results as human-readable text.
func FormatTraceText(chains []CallChain, target string) string {
	if len(chains) == 0 {
		return fmt.Sprintf("No callers found for %s\n", target)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Callers of %s:\n\n", target)

	for i, chain := range chains {
		if i > 0 {
			b.WriteString("\n")
		}
		for depth, step := range chain.Steps {
			indent := strings.Repeat("  ", depth)
			arrow := ""
			if depth > 0 {
				arrow = "→ "
			}
			fmt.Fprintf(&b, "%s%s%s (%s:%d)\n", indent, arrow, step.Function.String(), step.FilePath, step.Line)
		}
	}

	return b.String()
}
