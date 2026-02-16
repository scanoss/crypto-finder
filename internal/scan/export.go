package scan

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
)

// ExportCallGraph formats and writes the crypto-scoped call graph to a file.
func ExportCallGraph(path, format string, result *engine.DepScanResult) error {
	if result == nil {
		return fmt.Errorf("cannot export call graph: dep scan result is nil")
	}
	if result.CallGraph == nil {
		return fmt.Errorf("cannot export call graph: result.CallGraph is nil")
	}

	metadata := callgraph.GraphMetadata{
		Ecosystem:     result.Ecosystem,
		RootModule:    result.RootModule,
		FunctionCount: len(result.CallGraph.Functions),
		EdgeCount:     countCallGraphEdges(result.CallGraph),
	}

	var data []byte
	var err error
	switch format {
	case "json":
		data, err = callgraph.FormatJSON(result.CallGraph, metadata)
	case "dot":
		data, err = callgraph.FormatDOT(result.CallGraph)
	case "text":
		data, err = callgraph.FormatText(result.CallGraph)
	default:
		return fmt.Errorf("unsupported call graph format %q (supported: json, dot, text)", format)
	}
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("failed to write call graph to %s: %w", path, err)
	}

	log.Info().
		Str("file", path).
		Str("format", format).
		Int("functions", metadata.FunctionCount).
		Int("edges", metadata.EdgeCount).
		Msg("Exported crypto call graph")

	return nil
}

// countCallGraphEdges counts the total number of call edges in a call graph.
func countCallGraphEdges(graph *callgraph.CallGraph) int {
	count := 0
	for _, fn := range graph.Functions {
		count += len(fn.Calls)
	}
	return count
}
