package dependency

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/rs/zerolog/log"
)

// goModule represents the JSON output of `go list -m -json`.
type goModule struct {
	Path    string `json:"Path"`
	Version string `json:"Version"`
	Dir     string `json:"Dir"`
	Main    bool   `json:"Main"`
}

// GoResolver resolves Go module dependencies using the `go` tool.
type GoResolver struct{}

// NewGoResolver creates a new Go dependency resolver.
func NewGoResolver() *GoResolver {
	return &GoResolver{}
}

// Ecosystem returns "go".
func (r *GoResolver) Ecosystem() string {
	return "go"
}

// Resolve uses `go list -m -json all` to resolve all transitive dependencies
// for the Go project at targetDir.
func (r *GoResolver) Resolve(ctx context.Context, targetDir string) (*ResolveResult, error) {
	modules, err := r.goListModules(ctx, targetDir)
	if err != nil {
		return nil, fmt.Errorf("failed to list Go modules in %s: %w", targetDir, err)
	}

	result := &ResolveResult{
		Dependencies: make([]Dependency, 0, len(modules)),
		Graph:        make(map[string][]string),
	}

	for _, m := range modules {
		if m.Main {
			result.RootModule = m.Path
			continue
		}

		// Skip modules without a directory (e.g., not yet downloaded)
		if m.Dir == "" {
			log.Debug().Str("module", m.Path).Str("version", m.Version).Msg("Skipping module without local directory")
			continue
		}

		result.Dependencies = append(result.Dependencies, Dependency{
			Module:  m.Path,
			Version: m.Version,
			Dir:     m.Dir,
		})
	}

	// Build dependency graph using `go mod graph`
	graph, err := r.goModGraph(ctx, targetDir)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to build dependency graph, call chain tracing may be limited")
	} else {
		result.Graph = graph
	}

	log.Info().
		Int("count", len(result.Dependencies)).
		Str("root", result.RootModule).
		Msg("Resolved Go dependencies")

	return result, nil
}

// goListModules runs `go list -m -json all` and parses the streamed JSON output.
// The output is a stream of JSON objects (not a JSON array), so we decode them one by one.
func (r *GoResolver) goListModules(ctx context.Context, dir string) ([]goModule, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-m", "-json", "all")
	cmd.Dir = dir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go list -m -json all: %w\nstderr: %s", err, stderr.String())
	}

	modules := make([]goModule, 0, 32)
	decoder := json.NewDecoder(&stdout)
	for decoder.More() {
		var m goModule
		if err := decoder.Decode(&m); err != nil {
			return nil, fmt.Errorf("failed to decode go list output: %w", err)
		}
		modules = append(modules, m)
	}

	return modules, nil
}

// goModGraph runs `go mod graph` and parses the output into an adjacency list.
// Each line of output is: "module@version module@version" (parent -> dependency).
func (r *GoResolver) goModGraph(ctx context.Context, dir string) (map[string][]string, error) {
	cmd := exec.CommandContext(ctx, "go", "mod", "graph")
	cmd.Dir = dir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go mod graph: %w\nstderr: %s", err, stderr.String())
	}

	graph := make(map[string][]string)
	for _, line := range strings.Split(stdout.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		// Strip version from module paths for cleaner lookup
		parent := stripVersion(parts[0])
		child := stripVersion(parts[1])
		graph[parent] = append(graph[parent], child)
	}

	return graph, nil
}

// stripVersion removes the @version suffix from a module path.
// "golang.org/x/crypto@v0.17.0" -> "golang.org/x/crypto".
func stripVersion(moduleAtVersion string) string {
	if idx := strings.LastIndex(moduleAtVersion, "@"); idx != -1 {
		return moduleAtVersion[:idx]
	}
	return moduleAtVersion
}
