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

	result := newCargoResolveResult(meta)
	pkgByID := cargoPackageNamesByNodeID(meta.Resolve.Nodes)
	populateCargoGraph(result, meta.Resolve.Nodes, pkgByID)

	log.Info().
		Int("count", len(result.Dependencies)).
		Str("root", result.RootModule).
		Msg("Resolved Cargo dependencies")

	return result, nil
}

func newCargoResolveResult(meta *cargoMetadata) *ResolveResult {
	result := &ResolveResult{
		Dependencies:   make([]Dependency, 0, len(meta.Packages)),
		Graph:          make(map[string][]string),
		VersionedGraph: make(map[string][]Ref),
	}

	for _, pkg := range meta.Packages {
		appendCargoPackage(result, pkg)
	}

	return result
}

func appendCargoPackage(result *ResolveResult, pkg cargoPackage) {
	dir := filepath.Dir(pkg.ManifestPath)
	if pkg.Source == nil {
		result.WorkspaceMembers = append(result.WorkspaceMembers, WorkspaceMember{
			Name: pkg.Name,
			Dir:  dir,
		})
		if result.RootModule == "" {
			result.RootModule = pkg.Name
		}
		return
	}

	result.Dependencies = append(result.Dependencies, Dependency{
		Module:  pkg.Name,
		Version: pkg.Version,
		Dir:     dir,
	})
}

func cargoPackageNamesByNodeID(nodes []cargoResolveNode) map[string]string {
	pkgByID := make(map[string]string, len(nodes))
	for _, node := range nodes {
		ref := cargoPackageRefFromID(node.ID)
		pkgByID[node.ID] = ref.Module
	}
	return pkgByID
}

func populateCargoGraph(result *ResolveResult, nodes []cargoResolveNode, pkgByID map[string]string) {
	for _, node := range nodes {
		parentRef := cargoPackageRefFromID(node.ID)
		parentName := parentRef.Module
		if parentName == "" {
			continue
		}
		appendCargoDependencies(result, parentRef, parentName, node.Deps, pkgByID)
	}
}

func appendCargoDependencies(
	result *ResolveResult,
	parentRef Ref,
	parentName string,
	deps []cargoResolveDep,
	pkgByID map[string]string,
) {
	parentKey := parentRef.Key()
	for _, dep := range deps {
		childRef, childName := resolveCargoDependencyTarget(dep, pkgByID)
		result.Graph[parentName] = append(result.Graph[parentName], childName)
		if parentKey != "" && childRef.Module != "" {
			result.VersionedGraph[parentKey] = append(result.VersionedGraph[parentKey], childRef)
		}
	}
}

func resolveCargoDependencyTarget(dep cargoResolveDep, pkgByID map[string]string) (Ref, string) {
	childRef := cargoPackageRefFromID(dep.Pkg)
	childName := childRef.Module
	if childName == "" {
		childName = pkgByID[dep.Pkg]
	}
	if childName == "" {
		childName = cargoPackageNameFromID(dep.Pkg)
	}
	return childRef, childName
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

// cargoPackageRefFromID extracts the package name and version from a cargo package ID.
// Current Cargo emits package IDs like:
//   - "path+file:///tmp/app#app@0.1.0"
//   - "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0"
//
// Older formats may look like:
//   - "ring 0.17.8 (registry+https://github.com/rust-lang/crates.io-index)"
//   - "ring@0.17.8"
func cargoPackageRefFromID(id string) Ref {
	if hashIdx := strings.LastIndex(id, "#"); hashIdx != -1 && hashIdx+1 < len(id) {
		id = id[hashIdx+1:]
	}

	if atIdx := strings.LastIndex(id, "@"); atIdx != -1 {
		return Ref{
			Module:  id[:atIdx],
			Version: id[atIdx+1:],
		}
	}

	fields := strings.Fields(id)
	if len(fields) >= 2 {
		return Ref{
			Module:  fields[0],
			Version: fields[1],
		}
	}

	return Ref{Module: id}
}

// cargoPackageNameFromID extracts the package name from a cargo package ID.
// IDs look like: "ring 0.17.8 (registry+https://github.com/rust-lang/crates.io-index)"
// or in newer formats: "ring@0.17.8" or just "ring 0.17.8".
func cargoPackageNameFromID(id string) string {
	return cargoPackageRefFromID(id).Module
}
