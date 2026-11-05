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
	// files are the Go files the host build compiles in the module's
	// packages in the import closure, nil when none of them has a directory.
	// goListModules fills it; go list never does.
	files []string
}

// goPackage holds the fields goListModules requests from `go list -deps`.
// GoFiles and CgoFiles are the Go files the build compiles once build
// constraints, GOOS, GOARCH, tags and CGO_ENABLED have been applied, relative
// to Dir. Only Go files are taken: a Go dependency scan runs only Go rules
// and the Go call graph parses only Go files, so the package's C, assembly
// and other files would add targets no rule or parser reads.
type goPackage struct {
	ImportPath string    `json:"ImportPath"`
	Dir        string    `json:"Dir"`
	GoFiles    []string  `json:"GoFiles"`
	CgoFiles   []string  `json:"CgoFiles"`
	Imports    []string  `json:"Imports"`
	Module     *goModule `json:"Module"`
	Error      *struct {
		Err string `json:"Err"`
	} `json:"Error"`
}

// compiledFiles returns the absolute paths of the Go files the build compiles.
func (p *goPackage) compiledFiles() []string {
	files := make([]string, 0, len(p.GoFiles)+len(p.CgoFiles))
	for _, name := range slices.Concat(p.GoFiles, p.CgoFiles) {
		files = append(files, filepath.Join(p.Dir, name))
	}
	return files
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
	modules, graph, err := r.goListModules(ctx, targetDir)
	if err != nil {
		return nil, fmt.Errorf("failed to list Go modules in %s: %w", targetDir, err)
	}

	result := &ResolveResult{
		Dependencies: make([]Dependency, 0, len(modules)),
		Graph:        graph,
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
			Files:   m.files,
		})
	}

	log.Info().
		Int("count", len(result.Dependencies)).
		Str("root", result.RootModule).
		Msg("Resolved Go dependencies")

	return result, nil
}

// goListModules returns the main modules, then each module that provides a
// package in their non-test import closure, once, with the Go files the
// build compiles in those packages. Requirements reached only from tests,
// build-tagged tool files or nothing at all never enter it.
//
// It also returns the module import graph of that closure: each module that
// provides a package, mapped to the other modules its packages import. Unlike
// the requirement graph (go mod graph), it names the module that imports the
// next one: since Go 1.17 a go.mod lists every module its build needs, so a
// module requires, // indirect, modules only its dependencies import.
func (r *GoResolver) goListModules(ctx context.Context, dir string) ([]goModule, map[string][]string, error) {
	modules, err := goList[goModule](ctx, dir, "-m", "-json")
	if err != nil {
		return nil, nil, err
	}

	// -e keeps a package that fails to load, such as a directory mixing two
	// package names, from discarding the closure of every package that loads.
	// Each main module's directory is listed because `./...` matches nothing
	// at a go.work root and only a subtree below a module root.
	args := []string{"-e", "-deps", "-json=ImportPath,Dir,GoFiles,CgoFiles,Imports,Module,Error"}
	for _, m := range modules {
		if m.Dir == "" {
			return nil, nil, fmt.Errorf("go list -m: main module %s has no directory", m.Path)
		}
		args = append(args, filepath.Join(m.Dir, "..."))
	}
	packages, err := goList[goPackage](ctx, dir, args...)
	if err != nil {
		return nil, nil, err
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
		// One that compiles no file for this build still limits the scan.
		if p.Dir != "" {
			if modules[i].files == nil {
				modules[i].files = []string{}
			}
			modules[i].files = append(modules[i].files, p.compiledFiles()...)
		}
	}
	for _, i := range index {
		slices.Sort(modules[i].files)
		modules[i].files = slices.Compact(modules[i].files)
	}
	if failed > 0 {
		log.Warn().Int("packages", failed).Msg("Go packages failed to load; modules imported only through them are not inventoried")
	}

	return modules, moduleImportGraph(packages), nil
}

// moduleImportGraph maps each module that provides one of packages to the
// other modules whose packages its packages import, in first-import order.
// A module whose packages import no other module maps to an empty list.
func moduleImportGraph(packages []goPackage) map[string][]string {
	owner := make(map[string]string, len(packages))
	for _, p := range packages {
		if p.Module != nil {
			owner[p.ImportPath] = p.Module.Path
		}
	}
	graph := make(map[string][]string)
	for _, p := range packages {
		if p.Module == nil {
			continue
		}
		from := p.Module.Path
		if graph[from] == nil {
			graph[from] = []string{}
		}
		for _, imported := range p.Imports {
			if to := owner[imported]; to != "" && to != from && !slices.Contains(graph[from], to) {
				graph[from] = append(graph[from], to)
			}
		}
	}
	return graph
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
