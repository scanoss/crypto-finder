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
	Packages         []cargoPackage `json:"packages"`
	Resolve          cargoResolve   `json:"resolve"`
	WorkspaceMembers []string       `json:"workspace_members"`
	WorkspaceRoot    string         `json:"workspace_root"`
}

// cargoPackage represents a single package in cargo metadata output.
type cargoPackage struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	Version      string  `json:"version"`
	ManifestPath string  `json:"manifest_path"`
	Source       *string `json:"source"` // nil = local/workspace crate
}

// cargoResolve represents the dependency graph in cargo metadata output.
type cargoResolve struct {
	Root  string             `json:"root"`
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
	workspaceMemberIDs, workspaceMemberFallbacks := cargoWorkspaceMemberSets(meta.WorkspaceMembers)
	result.RootModule = cargoRootModuleName(meta.Resolve.Root, meta.Packages)
	if result.RootModule == "" {
		result.RootModule = cargoFallbackRootModule(meta.WorkspaceMembers, meta.Packages)
	}

	for _, pkg := range meta.Packages {
		appendCargoPackage(result, pkg, workspaceMemberIDs, workspaceMemberFallbacks)
	}

	return result
}

func appendCargoPackage(result *ResolveResult, pkg cargoPackage, workspaceMemberIDs, workspaceMemberFallbacks map[string]struct{}) {
	dir := filepath.Dir(pkg.ManifestPath)
	if isCargoWorkspacePackage(pkg, workspaceMemberIDs, workspaceMemberFallbacks) {
		result.WorkspaceMembers = append(result.WorkspaceMembers, WorkspaceMember{
			Name: pkg.Name,
			Dir:  dir,
		})
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
//
// A `path+` or `git+` ID may also name the package only by its LOCATION, with
// the fragment carrying just a version or just a git revision:
//   - "path+file:///abs/path/to/crate#0.8.4"
//   - "git+https://github.com/foo/bar#<40-hex sha>"
//
// Reading the fragment as the name left Module set to "0.8.4" and to the commit
// sha respectively — a version and a revision standing where a crate name
// belongs, which no coordinate can be matched against. The name then comes from
// the path's last segment or the repository's, exactly as cargo's own
// PackageIdSpec derives it, and the fragment is classified: a leading digit with
// a "." in it is a version, anything else is a revision and leaves Version
// empty rather than inventing one.
func cargoPackageRefFromID(id string) Ref {
	location, fragment := id, ""
	if hashIdx := strings.LastIndex(id, "#"); hashIdx != -1 && hashIdx+1 < len(id) {
		location, fragment = id[:hashIdx], id[hashIdx+1:]
		id = fragment
	}

	if atIdx := strings.LastIndex(id, "@"); atIdx != -1 {
		return Ref{
			Module:  id[:atIdx],
			Version: id[atIdx+1:],
		}
	}

	// Only the location forms whose fragment is allowed to omit the name. A
	// plain `registry+` ID always spells the name out, so its handling is
	// unchanged.
	if fragment != "" && (strings.HasPrefix(location, "path+") || strings.HasPrefix(location, "git+")) {
		if name := cargoNameFromLocation(location); name != "" {
			ref := Ref{Module: name}
			if cargoFragmentIsVersion(fragment) {
				ref.Version = fragment
			}
			return ref
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

// cargoNameFromLocation derives a crate name from a `path+` or `git+` package
// ID's location: the last path segment, with any query string and a repository's
// ".git" suffix removed.
func cargoNameFromLocation(location string) string {
	if queryIdx := strings.IndexByte(location, '?'); queryIdx != -1 {
		location = location[:queryIdx]
	}
	location = strings.TrimRight(location, "/")
	if slashIdx := strings.LastIndexByte(location, '/'); slashIdx != -1 {
		location = location[slashIdx+1:]
	}
	location = strings.TrimSuffix(location, ".git")
	// A location that reduced to the scheme itself, or to nothing, names no
	// crate; the caller keeps its existing fallbacks rather than guessing.
	if location == "" || strings.Contains(location, "+") || strings.Contains(location, ":") {
		return ""
	}
	return location
}

// cargoFragmentIsVersion reports whether a name-less package ID fragment is a
// version rather than a git revision. Cargo writes a semver there, or a commit
// hash; a hash carries no ".".
func cargoFragmentIsVersion(fragment string) bool {
	if fragment == "" || fragment[0] < '0' || fragment[0] > '9' {
		return false
	}
	return strings.Contains(fragment, ".")
}

// cargoPackageNameFromID extracts the package name from a cargo package ID.
// IDs look like: "ring 0.17.8 (registry+https://github.com/rust-lang/crates.io-index)"
// or in newer formats: "ring@0.17.8" or just "ring 0.17.8".
func cargoPackageNameFromID(id string) string {
	return cargoPackageRefFromID(id).Module
}

func cargoWorkspaceMemberSets(workspaceMembers []string) (map[string]struct{}, map[string]struct{}) {
	memberIDs := make(map[string]struct{}, len(workspaceMembers))
	memberFallbacks := make(map[string]struct{}, len(workspaceMembers))
	for _, memberID := range workspaceMembers {
		if memberID == "" {
			continue
		}
		memberIDs[memberID] = struct{}{}
		if ref := cargoPackageRefFromID(memberID); ref.Module != "" {
			memberFallbacks[ref.Key()] = struct{}{}
		}
	}
	return memberIDs, memberFallbacks
}

func isCargoWorkspacePackage(pkg cargoPackage, workspaceMemberIDs, workspaceMemberFallbacks map[string]struct{}) bool {
	if pkg.ID != "" {
		_, ok := workspaceMemberIDs[pkg.ID]
		return ok
	}

	if len(workspaceMemberFallbacks) == 0 {
		return false
	}

	_, ok := workspaceMemberFallbacks[Ref{Module: pkg.Name, Version: pkg.Version}.Key()]
	return ok
}

func cargoRootModuleName(rootID string, packages []cargoPackage) string {
	if rootID == "" {
		return ""
	}

	for _, pkg := range packages {
		if pkg.ID != "" && pkg.ID == rootID {
			return pkg.Name
		}
	}

	rootRef := cargoPackageRefFromID(rootID)
	if rootRef.Module == "" {
		return ""
	}
	for _, pkg := range packages {
		if cargoPackageMatchesRef(pkg, rootRef) {
			return pkg.Name
		}
	}
	return rootRef.Module
}

func cargoFallbackRootModule(workspaceMembers []string, packages []cargoPackage) string {
	if len(workspaceMembers) == 0 {
		return ""
	}

	firstMember := workspaceMembers[0]
	for _, pkg := range packages {
		if pkg.ID != "" && pkg.ID == firstMember {
			return pkg.Name
		}
	}

	memberRef := cargoPackageRefFromID(firstMember)
	if memberRef.Module == "" {
		return ""
	}
	for _, pkg := range packages {
		if cargoPackageMatchesRef(pkg, memberRef) {
			return pkg.Name
		}
	}
	return memberRef.Module
}

func cargoPackageMatchesRef(pkg cargoPackage, ref Ref) bool {
	if pkg.Name == "" || pkg.Name != ref.Module {
		return false
	}
	return ref.Version == "" || pkg.Version == "" || pkg.Version == ref.Version
}
