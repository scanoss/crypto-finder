package dependency

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
)

// goModule represents the module fields in `go list` JSON output.
type goModule struct {
	Path    string `json:"Path"`
	Version string `json:"Version"`
	Dir     string `json:"Dir"`
	Main    bool   `json:"Main"`
	// packageDirs are the directories of the module's packages in the
	// import closure. goListModules fills it; go list never does.
	packageDirs []string
}

// goPackage holds the fields goListModules requests from `go list -deps`.
type goPackage struct {
	ImportPath string    `json:"ImportPath"`
	Dir        string    `json:"Dir"`
	Module     *goModule `json:"Module"`
	Error      *struct {
		Err string `json:"Err"`
	} `json:"Error"`
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

// CanResolve reports whether targetDir is a directory inside a Go module or
// workspace. `go list` searches upward from its working directory
// for the nearest go.mod, or the go.work that stands in for one at a workspace
// root, so a package directory below the module root resolves the whole module
// and the precondition searches the same way. A file target answers false
// because Resolve runs the go tool with targetDir as its working directory.
func (r *GoResolver) CanResolve(targetDir string) bool {
	dir, err := filepath.Abs(targetDir)
	if err != nil {
		return false
	}
	if info, statErr := os.Stat(dir); statErr != nil || !info.IsDir() {
		return false
	}
	for {
		if fileExists(filepath.Join(dir, "go.mod")) || fileExists(filepath.Join(dir, "go.work")) {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// Resolve inventories the modules in the production import closure of the Go
// project at targetDir: the modules that provide a package imported, directly
// or transitively, by a non-test package of a main module.
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
			Module:      m.Path,
			Version:     m.Version,
			Dir:         m.Dir,
			PackageDirs: m.packageDirs,
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

// goListModules returns the main modules, then each module that provides a
// package in their non-test import closure, once, with the directories of
// those packages. Requirements reached only from tests, build-tagged tool
// files or nothing at all never enter it.
func (r *GoResolver) goListModules(ctx context.Context, dir string) ([]goModule, error) {
	modules, err := goList[goModule](ctx, dir, "-m", "-json")
	if err != nil {
		return nil, err
	}

	// -e keeps a package that fails to load, such as a directory mixing two
	// package names, from discarding the closure of every package that loads.
	// Each main module's directory is listed because `./...` matches nothing
	// at a go.work root and only a subtree below a module root.
	args := []string{"-e", "-deps", "-json=ImportPath,Dir,Module,Error"}
	for _, m := range modules {
		if m.Dir == "" {
			return nil, fmt.Errorf("go list -m: main module %s has no directory", m.Path)
		}
		args = append(args, filepath.Join(m.Dir, "..."))
	}
	packages, err := goList[goPackage](ctx, dir, args...)
	if err != nil {
		return nil, err
	}

	index := make(map[string]int)
	failed := 0
	for _, p := range packages {
		if p.Error != nil {
			failed++
			log.Debug().Str("package", p.ImportPath).Str("error", p.Error.Err).Msg("Go package failed to load")
		}
		if p.Module == nil || p.Module.Main {
			continue
		}
		i, seen := index[p.Module.Path]
		if !seen {
			i = len(modules)
			index[p.Module.Path] = i
			modules = append(modules, *p.Module)
		}
		// A package the go tool could not find has no directory.
		if p.Dir != "" {
			modules[i].packageDirs = append(modules[i].packageDirs, p.Dir)
		}
	}
	for _, i := range index {
		slices.Sort(modules[i].packageDirs)
		modules[i].packageDirs = slices.Compact(modules[i].packageDirs)
	}
	if failed > 0 {
		log.Warn().Int("packages", failed).Msg("Go packages failed to load; modules imported only through them are not inventoried")
	}

	return modules, nil
}

// goList runs `go list` with args and decodes its output, a stream of JSON
// objects rather than one array.
func goList[T any](ctx context.Context, dir string, args ...string) ([]T, error) {
	args = append([]string{"list"}, args...)
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go %s: %w\nstderr: %s", strings.Join(args, " "), err, stderr.String())
	}

	var out []T
	decoder := json.NewDecoder(&stdout)
	for decoder.More() {
		var v T
		if err := decoder.Decode(&v); err != nil {
			return nil, fmt.Errorf("failed to decode go list output: %w", err)
		}
		out = append(out, v)
	}
	return out, nil
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
