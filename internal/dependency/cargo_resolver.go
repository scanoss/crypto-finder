package dependency

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
)

// cargoMetadata represents the JSON output of `cargo metadata --format-version=1`.
type cargoMetadata struct {
	Packages      []cargoPackage `json:"packages"`
	Resolve       cargoResolve   `json:"resolve"`
	WorkspaceRoot string         `json:"workspace_root"`
}

// cargoPackage represents a single package in cargo metadata output.
type cargoPackage struct {
	Name         string  `json:"name"`
	Version      string  `json:"version"`
	ManifestPath string  `json:"manifest_path"`
	Source       *string `json:"source"` // nil = local/workspace crate
}

// cargoResolve represents the dependency graph in cargo metadata output.
type cargoResolve struct {
	Nodes []cargoResolveNode `json:"nodes"`
}

// cargoResolveNode represents a single node in the cargo resolve graph.
type cargoResolveNode struct {
	ID   string            `json:"id"`
	Deps []cargoResolveDep `json:"deps"`
}

// cargoResolveDep represents a dependency edge in the resolve graph.
type cargoResolveDep struct {
	Pkg string `json:"pkg"`
}

// CargoResolver resolves Rust/Cargo dependencies using `cargo metadata`.
type CargoResolver struct{}

// NewCargoResolver creates a new Cargo dependency resolver.
func NewCargoResolver() *CargoResolver {
	return &CargoResolver{}
}

// Ecosystem returns "rust".
func (r *CargoResolver) Ecosystem() string {
	return "rust"
}

// Resolve uses `cargo metadata --format-version=1` to resolve all dependencies
// for the Rust project at targetDir.
func (r *CargoResolver) Resolve(ctx context.Context, targetDir string) (*ResolveResult, error) {
	meta, err := r.cargoMetadata(ctx, targetDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get cargo metadata in %s: %w", targetDir, err)
	}

	result := &ResolveResult{
		Dependencies: make([]Dependency, 0, len(meta.Packages)),
		Graph:        make(map[string][]string),
	}

	// Build a lookup from package ID prefix to package name for graph building
	pkgByID := make(map[string]string)

	for _, pkg := range meta.Packages {
		if pkg.Source == nil {
			// Local/workspace crate — treat as user code
			dir := filepath.Dir(pkg.ManifestPath)
			result.WorkspaceMembers = append(result.WorkspaceMembers, WorkspaceMember{
				Name: pkg.Name,
				Dir:  dir,
			})
			if result.RootModule == "" {
				result.RootModule = pkg.Name
			}
			continue
		}

		dir := filepath.Dir(pkg.ManifestPath)
		result.Dependencies = append(result.Dependencies, Dependency{
			Module:  pkg.Name,
			Version: pkg.Version,
			Dir:     dir,
		})
	}

	// Build ID→name mapping for resolve graph
	for _, node := range meta.Resolve.Nodes {
		name := cargoPackageNameFromID(node.ID)
		pkgByID[node.ID] = name
	}

	// Build dependency graph from resolve nodes
	for _, node := range meta.Resolve.Nodes {
		parentName := pkgByID[node.ID]
		if parentName == "" {
			continue
		}
		for _, dep := range node.Deps {
			childName := pkgByID[dep.Pkg]
			if childName == "" {
				childName = cargoPackageNameFromID(dep.Pkg)
			}
			result.Graph[parentName] = append(result.Graph[parentName], childName)
		}
	}

	log.Info().
		Int("count", len(result.Dependencies)).
		Str("root", result.RootModule).
		Msg("Resolved Cargo dependencies")

	return result, nil
}

// cargoMetadata runs `cargo metadata --format-version=1` and parses the JSON output.
func (r *CargoResolver) cargoMetadata(ctx context.Context, dir string) (*cargoMetadata, error) {
	cmd := exec.CommandContext(ctx, "cargo", "metadata", "--format-version=1",
		"--manifest-path", filepath.Join(dir, "Cargo.toml"))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("cargo metadata: %w\nstderr: %s", err, stderr.String())
	}

	var meta cargoMetadata
	if err := json.Unmarshal(stdout.Bytes(), &meta); err != nil {
		return nil, fmt.Errorf("failed to parse cargo metadata output: %w", err)
	}

	return &meta, nil
}

// cargoPackageNameFromID extracts the package name from a cargo package ID.
// IDs look like: "ring 0.17.8 (registry+https://github.com/rust-lang/crates.io-index)"
// or in newer formats: "ring@0.17.8" or just "ring 0.17.8".
func cargoPackageNameFromID(id string) string {
	// Handle "name@version" format
	if idx := strings.Index(id, "@"); idx != -1 {
		return id[:idx]
	}
	// Handle "name version (...)" format
	if idx := strings.Index(id, " "); idx != -1 {
		return id[:idx]
	}
	return id
}
