// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/failure"
)

const ecosystemRust = "rust"

// cargoManifest is the manifest of a Rust package or workspace, and cargoLock
// the lock file that pins its closure.
const (
	cargoManifest = "Cargo.toml"
	cargoLock     = "Cargo.lock"
)

// ErrCargoLockMissing is the cause of a resolution of a project with no
// Cargo.lock: its closure is not pinned, and the resolver never writes one
// into the project (cargo metadata runs with --locked).
var ErrCargoLockMissing = errors.New("no Cargo.lock")

// cargoMetadata is the part of `cargo metadata --format-version 1` the
// resolver reads.
type cargoMetadata struct {
	Packages         []cargoPackage `json:"packages"`
	Resolve          cargoResolve   `json:"resolve"`
	WorkspaceMembers []string       `json:"workspace_members"`
}

type cargoPackage struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	Version      string        `json:"version"`
	ManifestPath string        `json:"manifest_path"`
	Source       *string       `json:"source"` // nil = a path package
	Targets      []cargoTarget `json:"targets"`
}

type cargoTarget struct {
	Name string   `json:"name"`
	Kind []string `json:"kind"`
}

type cargoResolve struct {
	Root  string             `json:"root"`
	Nodes []cargoResolveNode `json:"nodes"`
}

type cargoResolveNode struct {
	ID   string            `json:"id"`
	Deps []cargoResolveDep `json:"deps"`
}

type cargoResolveDep struct {
	Pkg      string         `json:"pkg"`
	DepKinds []cargoDepKind `json:"dep_kinds"`
}

// cargoDepKind is one way a package depends on another: Kind is null for a
// normal dependency, "dev" or "build" otherwise.
type cargoDepKind struct {
	Kind *string `json:"kind"`
}

// cargoLibraryKinds are the target kinds of a library other crates link
// against and name in source.
var cargoLibraryKinds = []string{"lib", "rlib", "dylib", "proc-macro"}

// libraryName returns the name source code uses for the package's library:
// its library target's name, which `[lib] name` sets and which otherwise is
// the package name with each "-" turned into "_". A package the metadata
// lists no targets for gets that default; one with targets but no library
// (a binary-only crate) gets "", as nothing can name it in source.
func (pkg cargoPackage) libraryName() string {
	if len(pkg.Targets) == 0 {
		return strings.ReplaceAll(pkg.Name, "-", "_")
	}
	for _, target := range pkg.Targets {
		for _, kind := range target.Kind {
			if slices.Contains(cargoLibraryKinds, kind) && target.Name != "" {
				return target.Name
			}
		}
	}
	return ""
}

// importPath is the package's Dependency.ImportPath or
// WorkspaceMember.ImportPath: its library name when that differs from its
// package name, else "".
func (pkg cargoPackage) importPath() string {
	if name := pkg.libraryName(); name != pkg.Name {
		return name
	}
	return ""
}

// registry reports whether the package comes from a crates registry: the
// only packages the API names by a package URL (pkg:cargo/<name>@<version>).
func (pkg cargoPackage) registry() bool {
	return pkg.Source != nil && (strings.HasPrefix(*pkg.Source, "registry+") || strings.HasPrefix(*pkg.Source, "sparse+"))
}

// normalDependency reports whether the edge is a production dependency: some
// dep_kind of it is null. A package metadata does not report kinds for (an
// old cargo) counts as normal.
func (dep cargoResolveDep) normalDependency() bool {
	if len(dep.DepKinds) == 0 {
		return true
	}
	for _, kind := range dep.DepKinds {
		if kind.Kind == nil {
			return true
		}
	}
	return false
}

// CargoResolver reads a Rust project's pinned closure with
// `cargo metadata --format-version 1 --locked`, which reads Cargo.lock and
// never rewrites it. The production closure is what the workspace members
// reach through normal dependencies: dev-dependencies and build-dependencies
// (and what only they pull in) are left out. A path crate inside the project
// (the scan root, else the resolved directory) is the project's own code, and
// one outside it a local dependency (Dependency.Local) analyzed from its
// directory. A git dependency has no registry package URL and is carried as
// unpinned. Cargo's own source directory (registry/src, or vendor/) is the
// dependency's Dir when present.
type CargoResolver struct {
	cargoHome string
	offline   bool
	scanRoot  string
}

// SetScanRoot names the scanned tree: a path crate inside it is the project's
// own code.
func (r *CargoResolver) SetScanRoot(dir string) {
	r.scanRoot = dir
}

// SetOffline makes cargo run with --offline as well as --locked: it reads
// only the crate sources already in Cargo's registry cache or vendor/, and
// never reaches a registry. A crate missing from them fails the resolution:
// run cargo fetch or cargo vendor first.
func (r *CargoResolver) SetOffline(offline bool) {
	r.offline = offline
}

// NewCargoResolver creates a Cargo resolver over the registry CARGO_HOME
// names (else ~/.cargo).
func NewCargoResolver() *CargoResolver {
	return &CargoResolver{cargoHome: cargoHomeDir()}
}

func cargoHomeDir() string {
	if home := os.Getenv("CARGO_HOME"); home != "" {
		return home
	}
	if user, err := os.UserHomeDir(); err == nil {
		return filepath.Join(user, ".cargo")
	}
	return ""
}

// Ecosystem returns "rust".
func (r *CargoResolver) Ecosystem() string {
	return ecosystemRust
}

// CanResolve reports whether targetDir has the Cargo.toml `cargo metadata
// --manifest-path` is pointed at.
func (r *CargoResolver) CanResolve(targetDir string) bool {
	return fileExists(filepath.Join(targetDir, cargoManifest))
}

// Resolve reads the pinned production closure of the project at targetDir.
func (r *CargoResolver) Resolve(ctx context.Context, targetDir string) (*ResolveResult, error) {
	if !cargoLockPresent(targetDir) {
		return nil, failure.Wrap(ErrCargoLockMissing, failure.CodeDependencyResolutionFailed, failure.StageDependency,
			fmt.Sprintf("read the Cargo dependency closure of %s: run cargo generate-lockfile", targetDir),
			failure.WithDetail("target_dir", targetDir))
	}
	meta, err := cargoMetadataOf(ctx, targetDir, r.offline)
	if err != nil {
		return nil, failure.New(failure.CodeDependencyResolutionFailed, failure.StageDependency,
			fmt.Sprintf("read the Cargo dependency closure of %s: %v", targetDir, err), failure.WithDetail("target_dir", targetDir))
	}
	result := r.closure(targetDir, meta)
	log.Debug().Str("root", result.RootModule).Int("dependencies", len(result.Dependencies)).
		Int("unpinned", len(result.Unpinned)).Msg("Resolved the Cargo dependency closure")
	return result, nil
}

// cargoLockPresent reports whether a Cargo.lock sits in dir or a directory
// above it: a workspace member's lock is its workspace root's.
func cargoLockPresent(dir string) bool {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	for {
		if fileExists(filepath.Join(abs, cargoLock)) {
			return true
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return false
		}
		abs = parent
	}
}

// cargoMetadataOf runs cargo metadata against the lock file as it is: --locked
// fails rather than update it.
func cargoMetadataOf(ctx context.Context, dir string, offline bool) (*cargoMetadata, error) {
	// The working directory changes below, so a relative target must not.
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	args := []string{"metadata", "--format-version", "1", "--locked", "--manifest-path", filepath.Join(dir, cargoManifest)}
	if offline {
		args = append(args, "--offline")
	}
	cmd := exec.CommandContext(ctx, "cargo", args...) // #nosec G204 -- fixed arguments; dir is the scan target.
	// Cargo reads .cargo/config.toml (source replacement, a vendor/
	// directory) from its working directory, not from the manifest's.
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("cargo metadata: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var meta cargoMetadata
	if err := json.Unmarshal(stdout.Bytes(), &meta); err != nil {
		return nil, fmt.Errorf("parse cargo metadata output: %w", err)
	}
	return &meta, nil
}

// closure builds the result from the metadata: workspace members, then the
// registry packages reachable from them through normal dependencies.
func (r *CargoResolver) closure(targetDir string, meta *cargoMetadata) *ResolveResult {
	result := &ResolveResult{
		Source:         cargoLock,
		Graph:          map[string][]string{},
		VersionedGraph: map[string][]Ref{},
	}
	pkgs := make(map[string]cargoPackage, len(meta.Packages))
	for _, pkg := range meta.Packages {
		pkgs[pkg.ID] = pkg
	}
	members := make(map[string]bool, len(meta.WorkspaceMembers))
	for _, id := range meta.WorkspaceMembers {
		members[id] = true
	}
	nodes := make(map[string][]cargoResolveDep, len(meta.Resolve.Nodes))
	for _, node := range meta.Resolve.Nodes {
		nodes[node.ID] = node.Deps
	}
	result.RootModule = pkgs[meta.Resolve.Root].Name
	for _, id := range meta.WorkspaceMembers {
		pkg, ok := pkgs[id]
		if !ok {
			continue
		}
		if result.RootModule == "" {
			result.RootModule = pkg.Name
		}
		result.WorkspaceMembers = append(result.WorkspaceMembers, WorkspaceMember{
			Name: pkg.Name, ImportPath: pkg.importPath(), Dir: filepath.Dir(pkg.ManifestPath),
		})
	}

	c := cargoWalk{
		root: projectDir(targetDir, r.scanRoot), pkgs: pkgs, members: members, nodes: nodes,
		edges: map[string][]string{}, direct: map[string]bool{}, unpinned: map[string]bool{}, visited: map[string]bool{},
	}
	for _, id := range meta.WorkspaceMembers {
		c.visit(id)
	}
	c.build(r, targetDir, result)
	return result
}

// cargoWalk is the traversal of the production closure: every normal edge
// from a member (or a path crate inside root, which counts as one) to a
// registry, git or local path crate, before a version is chosen for a crate
// locked at several.
type cargoWalk struct {
	// root is the project: the scan root, else the resolved directory. A
	// path crate inside it is the project's own code, one outside it a local
	// dependency.
	root     string
	pkgs     map[string]cargoPackage
	members  map[string]bool
	nodes    map[string][]cargoResolveDep
	edges    map[string][]string
	direct   map[string]bool
	unpinned map[string]bool
	visited  map[string]bool
	// registry lists the registry packages reached, in first-seen order.
	registry []string
	// git lists the git packages reached: unpinned, but their dependencies
	// are part of the closure.
	git []string
	// pathMembers are the path crates outside the workspace but inside root,
	// taken as members.
	pathMembers []string
	// local lists the path crates outside root reached: local dependencies.
	local []string
}

// visit follows the normal dependencies of id. Members are the application:
// their registry children are the direct dependencies.
func (c *cargoWalk) visit(id string) {
	if c.visited[id] {
		return
	}
	c.visited[id] = true
	for _, dep := range c.nodes[id] {
		if !dep.normalDependency() {
			continue
		}
		child, ok := c.pkgs[dep.Pkg]
		if !ok || c.members[dep.Pkg] {
			continue
		}
		switch {
		case child.registry():
			if !c.visited[dep.Pkg] {
				c.registry = append(c.registry, dep.Pkg)
			}
			c.direct[dep.Pkg] = c.direct[dep.Pkg] || c.members[id]
		case child.Source == nil && isWithin(filepath.Dir(child.ManifestPath), c.root):
			// A path crate inside the project is its own code, as a workspace
			// member is.
			c.members[dep.Pkg] = true
			c.pathMembers = append(c.pathMembers, dep.Pkg)
		case child.Source == nil:
			// A path crate outside the project is a local dependency: its
			// code is its directory, and its registry children are transitive.
			if !c.visited[dep.Pkg] {
				c.local = append(c.local, dep.Pkg)
			}
		default:
			// A git crate has no registry package URL: it is unpinned, and its
			// registry children are transitive.
			if !c.visited[dep.Pkg] {
				c.git = append(c.git, dep.Pkg)
			}
		}
		c.edges[id] = append(c.edges[id], dep.Pkg)
		c.visit(dep.Pkg)
	}
}

// versionLess orders crate versions by semver: numeric dot-separated fields,
// a pre-release below its release, build metadata ignored.
func versionLess(a, b string) bool {
	core := func(v string) (nums []int, pre string) {
		v, _, _ = strings.Cut(v, "+")
		v, pre, _ = strings.Cut(v, "-")
		for _, field := range strings.Split(v, ".") {
			n, err := strconv.Atoi(field)
			if err != nil {
				n = 0
			}
			nums = append(nums, n)
		}
		return nums, pre
	}
	an, apre := core(a)
	bn, bpre := core(b)
	for i := 0; i < len(an) || i < len(bn); i++ {
		var x, y int
		if i < len(an) {
			x = an[i]
		}
		if i < len(bn) {
			y = bn[i]
		}
		if x != y {
			return x < y
		}
	}
	switch {
	case apre == bpre:
		return false
	case apre == "":
		return false
	case bpre == "":
		return true
	}
	return apre < bpre
}

// choose picks the one version of each crate the request names: the version
// a member declares directly (the highest of them), else the highest.
func (c *cargoWalk) choose() map[string]string {
	chosen := map[string]string{}
	better := func(name, id string) bool {
		current, ok := chosen[name]
		if !ok {
			return true
		}
		if c.direct[id] != c.direct[current] {
			return c.direct[id]
		}
		return versionLess(c.pkgs[current].Version, c.pkgs[id].Version)
	}
	for _, id := range c.registry {
		if name := c.pkgs[id].Name; better(name, id) {
			chosen[name] = id
		}
	}
	return chosen
}

// build fills result from the walk: the chosen versions reachable from the
// members, the versions left out (OtherVersions), and the crates only a
// version left out requires (UnderOtherVersions).
func (c *cargoWalk) build(r *CargoResolver, targetDir string, result *ResolveResult) {
	for _, id := range c.pathMembers {
		pkg := c.pkgs[id]
		result.WorkspaceMembers = append(result.WorkspaceMembers, WorkspaceMember{
			Name: pkg.Name, ImportPath: pkg.importPath(), Dir: filepath.Dir(pkg.ManifestPath),
		})
	}
	chosen := c.choose()
	redirect := func(id string) string {
		if pkg := c.pkgs[id]; pkg.registry() {
			return chosen[pkg.Name]
		}
		return id
	}
	reached := c.reach(redirect)
	for _, id := range c.git {
		if !c.unpinned[c.pkgs[id].Name] && reached[id] {
			c.unpinned[c.pkgs[id].Name] = true
			result.Unpinned = append(result.Unpinned, UnpinnedDependency{Module: c.pkgs[id].Name, Manifest: cargoManifest})
		}
	}
	dependency := func(id string) Dependency {
		pkg := c.pkgs[id]
		return Dependency{Module: pkg.Name, ImportPath: pkg.importPath(), Version: pkg.Version, Dir: r.sourceDir(targetDir, pkg)}
	}
	for _, id := range c.local {
		if pkg := c.pkgs[id]; reached[id] {
			result.Dependencies = append(result.Dependencies, Dependency{
				Module: pkg.Name, ImportPath: pkg.importPath(), Version: pkg.Version, Dir: filepath.Dir(pkg.ManifestPath), Local: true,
			})
		}
	}
	for _, id := range c.registry {
		switch {
		case chosen[c.pkgs[id].Name] != id:
			result.OtherVersions = append(result.OtherVersions, dependency(id))
		case reached[id]:
			result.Dependencies = append(result.Dependencies, dependency(id))
		default:
			result.UnderOtherVersions = append(result.UnderOtherVersions, dependency(id))
		}
	}
	c.fillGraph(result, reached, redirect)
	for _, list := range [][]Dependency{result.Dependencies, result.OtherVersions, result.UnderOtherVersions} {
		sort.Slice(list, func(i, j int) bool {
			if list[i].Module != list[j].Module {
				return list[i].Module < list[j].Module
			}
			return list[i].Version < list[j].Version
		})
	}
	sort.Slice(result.Unpinned, func(i, j int) bool { return result.Unpinned[i].Module < result.Unpinned[j].Module })
}

// reach returns the nodes the members reach, each edge taken to the chosen
// version of its crate: a version left out is never reached.
func (c *cargoWalk) reach(redirect func(string) string) map[string]bool {
	reached := map[string]bool{}
	queue := make([]string, 0, len(c.members))
	for id := range c.members {
		if c.visited[id] {
			queue = append(queue, id)
		}
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, child := range c.edges[id] {
			if to := redirect(child); !reached[to] && !c.members[to] {
				reached[to] = true
				queue = append(queue, to)
			}
		}
	}
	return reached
}

// fillGraph writes the name-keyed Graph and the versioned graph from the
// edges between reached nodes, each edge pointing at the chosen version.
func (c *cargoWalk) fillGraph(result *ResolveResult, reached map[string]bool, redirect func(string) string) {
	for id, children := range c.edges {
		if !c.members[id] && !reached[id] {
			continue
		}
		parent := c.pkgs[id]
		for _, child := range children {
			to := redirect(child)
			if !reached[to] {
				continue
			}
			target := c.pkgs[to]
			result.Graph[parent.Name] = appendUnique(result.Graph[parent.Name], target.Name)
			if c.members[id] {
				if target.registry() || target.Source == nil {
					result.DirectDependencies = addSorted(result.DirectDependencies, target.Name)
				}
				continue
			}
			ref := Ref{Module: parent.Name, Version: parent.Version}
			result.VersionedGraph[ref.Key()] = appendRef(result.VersionedGraph[ref.Key()], Ref{Module: target.Name, Version: target.Version})
		}
	}
	for parent, children := range result.Graph {
		sort.Strings(children)
		result.Graph[parent] = children
	}
	for parent, refs := range result.VersionedGraph {
		sort.Slice(refs, func(i, j int) bool { return refs[i].Key() < refs[j].Key() })
		result.VersionedGraph[parent] = refs
	}
}

// sourceDir is the extracted source of a registry package: the directory of
// its manifest when cargo has it (the registry cache, or a vendor directory
// source replacement points at), else a vendor/ directory of the project or
// a registry cache of CARGO_HOME. "" when none holds it.
func (r *CargoResolver) sourceDir(targetDir string, pkg cargoPackage) string {
	if dir := filepath.Dir(pkg.ManifestPath); pkg.ManifestPath != "" && fileExists(filepath.Join(dir, cargoManifest)) {
		return dir
	}
	candidates := []string{
		filepath.Join(targetDir, "vendor", pkg.Name+"-"+pkg.Version),
		filepath.Join(targetDir, "vendor", pkg.Name),
	}
	if r.cargoHome != "" {
		registries, err := filepath.Glob(filepath.Join(r.cargoHome, "registry", "src", "*"))
		if err != nil {
			log.Debug().Err(err).Msg("Cargo registry cache not listed")
		}
		for _, registry := range registries {
			candidates = append(candidates, filepath.Join(registry, pkg.Name+"-"+pkg.Version))
		}
	}
	for _, dir := range candidates {
		if cargoManifestHasVersion(filepath.Join(dir, cargoManifest), pkg.Version) {
			return dir
		}
	}
	return ""
}

// cargoManifestHasVersion reports whether the manifest at path declares
// version: a vendor directory without the version in its name holds one
// version of the crate, which may not be the locked one.
func cargoManifestHasVersion(path, version string) bool {
	data, err := os.ReadFile(path) // #nosec G304 -- a crate manifest under the project's vendor/ or Cargo's registry.
	if err != nil {
		return false
	}
	return bytes.Contains(data, []byte(`version = "`+version+`"`))
}
