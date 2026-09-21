package dependency

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"
)

const (
	ecosystemNode   = "node"
	npmManifest     = "package.json"
	npmLockfile     = "package-lock.json"
	npmModulesDir   = "node_modules"
	npmModulesSlash = npmModulesDir + "/"
)

// npmManifestFile is the subset of package.json this resolver reads.
type npmManifestFile struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Dependencies map[string]string `json:"dependencies"`
}

// npmLockFile covers both lockfile shapes npm has shipped. A v2 lockfile carries
// BOTH fields for backwards compatibility, so `packages` is preferred wherever it
// is present: it is keyed by install path and therefore already answers the
// question `dependencies` needs a tree walk to answer.
type npmLockFile struct {
	Name            string                    `json:"name"`
	Version         string                    `json:"version"`
	LockfileVersion int                       `json:"lockfileVersion"`
	Packages        map[string]npmLockPackage `json:"packages"`
	Dependencies    map[string]npmLockV1Entry `json:"dependencies"`
}

// npmLockPackage is one entry of a v2/v3 `packages` map. The key is the install
// path; `Dependencies` maps a name to a SEMVER RANGE, never to a resolved
// version, which is why edges are resolved through the install tree below.
type npmLockPackage struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Dependencies map[string]string `json:"dependencies"`
	// Peer and optional dependencies are real edges. Reading only `dependencies`
	// loses the bridge package on a user -> crypto path, and a chain that has to
	// cross a peer edge cannot be built at all.
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	Dev                  bool              `json:"dev"`
	// Optional marks a package npm may legitimately not install. The platform
	// packages of esbuild, rollup, swc and sharp are optional and gated by os and
	// cpu, so a healthy linux-x64 install is missing most of them BY DESIGN.
	Optional bool `json:"optional"`
	// Link marks a node_modules entry that is a symlink to a workspace member.
	// It carries no version of its own: the real entry is keyed by the member's
	// own path elsewhere in the same map.
	Link bool `json:"link"`
}

// npmLockV1Entry is one entry of a v1 `dependencies` map, which nests instead of
// keying by path.
type npmLockV1Entry struct {
	Version string `json:"version"`
	Dev     bool   `json:"dev"`
	// npm 5.0 and 5.1 wrote `"requires": true` here instead of a map. Typing
	// this as map[string]string made the whole scan fail on a lockfile the code
	// deliberately claims to support, so the shape is decoded leniently and a
	// non-object is read as no edges.
	Requires     json.RawMessage           `json:"requires"`
	Optional     bool                      `json:"optional"`
	Dependencies map[string]npmLockV1Entry `json:"dependencies"`
}

// requireMap decodes the v1 `requires` field, tolerating the boolean npm 5.0
// and 5.1 emitted.
func (e npmLockV1Entry) requireMap() map[string]string {
	if len(e.Requires) == 0 {
		return nil
	}
	out := map[string]string{}
	if err := json.Unmarshal(e.Requires, &out); err != nil {
		return nil
	}
	return out
}

// NpmResolver resolves Node dependencies from package-lock.json and the
// node_modules tree npm has already installed.
//
// Unlike the cargo, go and java resolvers it runs no tool: npm puts dependency
// sources on disk at install time, so resolution is reading the lockfile and
// pointing at directories that are already there. That is also the constraint —
// without an install there is nothing to point at, and this resolver fails
// rather than return dependencies whose Dir is empty.
type NpmResolver struct{}

// NewNpmResolver creates a new npm dependency resolver.
func NewNpmResolver() *NpmResolver {
	return &NpmResolver{}
}

// Ecosystem returns "node".
func (r *NpmResolver) Ecosystem() string {
	return ecosystemNode
}

// CanResolve reports whether targetDir has the root package.json Resolve reads.
func (r *NpmResolver) CanResolve(targetDir string) bool {
	return fileExists(filepath.Join(targetDir, npmManifest))
}

// Resolve reads package.json and package-lock.json at targetDir and maps every
// production dependency to the directory npm installed it in.
func (r *NpmResolver) Resolve(_ context.Context, targetDir string) (*ResolveResult, error) {
	manifest, err := readNpmManifest(targetDir)
	if err != nil {
		return nil, err
	}
	lock, err := readNpmLockfile(targetDir)
	if err != nil {
		return nil, err
	}

	packages, workspacePaths, rootDeps := npmPackagesByInstallPath(manifest, lock)

	result := &ResolveResult{
		RootModule:     npmRootModule(manifest, lock),
		Dependencies:   make([]Dependency, 0, len(packages)),
		Graph:          make(map[string][]string),
		VersionedGraph: make(map[string][]Ref),
	}

	appendNpmWorkspaceMembers(result, targetDir, workspacePaths)
	resolved, absent := appendNpmDependencies(result, targetDir, packages)

	// An absent OPTIONAL package is not a defect: npm gates the platform
	// packages of esbuild, rollup, swc and sharp on os and cpu, so a healthy
	// linux-x64 tree is missing most of them by design. An absent DEV package is
	// not a defect either, since `npm install --omit=dev` is ordinary. Counting
	// those made the warning fire on every real project, which is the same as
	// having no warning at all. What does mean the install is incomplete is an
	// absent REQUIRED production package.
	if len(absent.required) > 0 {
		return nil, fmt.Errorf(
			"npm resolver: %d required %s in %s are in %s but not installed under %s (%s): run `npm install` before scanning",
			len(absent.required), npmPluralPackages(len(absent.required)), targetDir, npmLockfile,
			npmModulesDir, strings.Join(npmSampleNames(absent.required), ", "),
		)
	}
	if len(result.Dependencies) == 0 && len(packages) > 0 {
		return nil, fmt.Errorf(
			"npm resolver: %s in %s lists %d dependencies and none are installed under %s: run `npm install` before scanning",
			npmLockfile, targetDir, len(packages), npmModulesDir,
		)
	}
	if len(absent.dev) > 0 {
		log.Debug().
			Int("dev", len(absent.dev)).
			Int("optional", len(absent.optional)).
			Str("target", targetDir).
			Msg("Dev or optional npm packages in the lockfile are not installed, which is expected")
	}

	// The graph is built from what RESOLVED, plus the workspace members and the
	// root. Walking the lockfile instead put nodes in the graph for packages
	// that are not on disk at all.
	populateNpmGraph(result, packages, workspacePaths, resolved, rootDeps, manifest)

	log.Info().
		Int("count", len(result.Dependencies)).
		Str("root", result.RootModule).
		Msg("Resolved npm dependencies")

	return result, nil
}

func readNpmManifest(targetDir string) (*npmManifestFile, error) {
	raw, err := os.ReadFile(filepath.Join(targetDir, npmManifest))
	if err != nil {
		return nil, fmt.Errorf("npm resolver: read %s in %s: %w", npmManifest, targetDir, err)
	}
	manifest := &npmManifestFile{}
	if err := json.Unmarshal(raw, manifest); err != nil {
		return nil, fmt.Errorf("npm resolver: parse %s in %s: %w", npmManifest, targetDir, err)
	}
	return manifest, nil
}

func readNpmLockfile(targetDir string) (*npmLockFile, error) {
	raw, err := os.ReadFile(filepath.Join(targetDir, npmLockfile))
	if err != nil {
		return nil, fmt.Errorf(
			"npm resolver: read %s in %s: %w: a lockfile is the only record of which versions are installed",
			npmLockfile, targetDir, err,
		)
	}
	lock := &npmLockFile{}
	if err := json.Unmarshal(raw, lock); err != nil {
		return nil, fmt.Errorf("npm resolver: parse %s in %s: %w", npmLockfile, targetDir, err)
	}
	return lock, nil
}

func npmRootModule(manifest *npmManifestFile, lock *npmLockFile) string {
	if manifest.Name != "" {
		return manifest.Name
	}
	return lock.Name
}

// npmPackagesByInstallPath reduces either lockfile shape to one path-keyed map,
// and returns the root's own direct dependency names alongside it. Dev-only
// packages are dropped: they are build tooling that never ships, and walking
// them multiplies the scanned tree without adding anything a consumer runs.
func npmPackagesByInstallPath(
	manifest *npmManifestFile,
	lock *npmLockFile,
) (packages, workspacePaths map[string]npmLockPackage, rootDeps []string) {
	packages = make(map[string]npmLockPackage)
	workspacePaths = make(map[string]npmLockPackage)

	if len(lock.Packages) > 0 {
		for installPath, pkg := range lock.Packages {
			if installPath == "" {
				rootDeps = sortedKeys(pkg.Dependencies)
				continue
			}
			if pkg.Link {
				// A link entry is the symlink npm drops in node_modules for a
				// workspace member. Its target is already keyed by its own path,
				// and the entry itself has no version, so taking it would report
				// the same source twice and once without a coordinate.
				continue
			}
			if !strings.HasPrefix(installPath, npmModulesSlash) {
				// A path outside node_modules is the user's OWN package in a
				// workspace, not something installed for them.
				workspacePaths[installPath] = pkg
				continue
			}
			packages[installPath] = pkg
		}
		if len(rootDeps) == 0 {
			rootDeps = sortedKeys(manifest.Dependencies)
		}
		return packages, workspacePaths, rootDeps
	}

	collectNpmV1Entries("", lock.Dependencies, packages)
	return packages, workspacePaths, sortedKeys(manifest.Dependencies)
}

// collectNpmV1Entries flattens the nested v1 shape into install paths, which is
// exactly what the v2 `packages` map states directly.
func collectNpmV1Entries(prefix string, entries map[string]npmLockV1Entry, out map[string]npmLockPackage) {
	for name, entry := range entries {
		installPath := path.Join(prefix, npmModulesDir, name)
		out[installPath] = npmLockPackage{
			Name:         name,
			Version:      entry.Version,
			Dependencies: entry.requireMap(),
			Dev:          entry.Dev,
			Optional:     entry.Optional,
		}
		collectNpmV1Entries(installPath, entry.Dependencies, out)
	}
}

// npmAbsent separates the packages a lockfile names but the tree does not hold,
// because the three kinds mean different things.
type npmAbsent struct {
	required []string
	dev      []string
	optional []string
}

// appendNpmDependencies records one Dependency per installed package. It returns
// the set of install paths that actually resolved — the graph is built from that
// rather than from the lockfile — and what was absent, classified.
func appendNpmDependencies(
	result *ResolveResult,
	targetDir string,
	packages map[string]npmLockPackage,
) (map[string]struct{}, npmAbsent) {
	resolved := make(map[string]struct{}, len(packages))
	var absent npmAbsent
	for _, installPath := range sortedPackagePaths(packages) {
		pkg := packages[installPath]
		dir := filepath.Join(targetDir, filepath.FromSlash(installPath))
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			name := npmModuleName(installPath, pkg)
			switch {
			case pkg.Optional:
				absent.optional = append(absent.optional, name)
			case pkg.Dev:
				absent.dev = append(absent.dev, name)
			default:
				absent.required = append(absent.required, name)
			}
			continue
		}
		resolved[installPath] = struct{}{}
		result.Dependencies = append(result.Dependencies, Dependency{
			Module:  npmModuleName(installPath, pkg),
			Version: pkg.Version,
			Dir:     dir,
		})
	}
	return resolved, absent
}

func npmPluralPackages(n int) string {
	if n == 1 {
		return "package"
	}
	return "packages"
}

// npmSampleNames keeps an error message actionable without pasting a whole tree
// into it.
func npmSampleNames(names []string) []string {
	const sampleLimit = 5
	if len(names) <= sampleLimit {
		return names
	}
	return append(append([]string{}, names[:sampleLimit]...), "...")
}

// appendNpmWorkspaceMembers records the user's own packages. They are source the
// consumer wrote, so attributing them to an external coordinate would put author
// code under a dependency's name.
func appendNpmWorkspaceMembers(result *ResolveResult, targetDir string, workspacePaths map[string]npmLockPackage) {
	for _, installPath := range sortedPackagePaths(workspacePaths) {
		pkg := workspacePaths[installPath]
		dir := filepath.Join(targetDir, filepath.FromSlash(installPath))
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			continue
		}
		result.WorkspaceMembers = append(result.WorkspaceMembers, WorkspaceMember{
			Name: npmModuleName(installPath, pkg),
			Dir:  dir,
		})
	}
}

// npmEdgeSources returns every declared edge of a package. peerDependencies and
// optionalDependencies are real edges: a bridge package reached only through a
// peer edge is invisible without them, and the chain that crosses it cannot be
// built.
func npmEdgeSources(pkg npmLockPackage) []string {
	names := map[string]struct{}{}
	for _, m := range []map[string]string{pkg.Dependencies, pkg.PeerDependencies, pkg.OptionalDependencies} {
		for name := range m {
			names[name] = struct{}{}
		}
	}
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// populateNpmGraph walks the packages that RESOLVED, the workspace members and
// the root. A workspace member is a graph parent like any other: its own
// dependencies are edges the consumer wrote, and omitting them left every
// dependency of a member as an orphan with no path from the root.
func populateNpmGraph(
	result *ResolveResult,
	packages map[string]npmLockPackage,
	workspacePaths map[string]npmLockPackage,
	resolved map[string]struct{},
	rootDeps []string,
	manifest *npmManifestFile,
) {
	lookup := func(fromPath, name string) (npmLockPackage, string, bool) {
		return npmResolveEdge(packages, resolved, fromPath, name)
	}

	if result.RootModule != "" {
		rootKey := npmVersionedKey(result.RootModule, manifest.Version)
		for _, name := range rootDeps {
			if target, targetPath, ok := lookup("", name); ok {
				appendNpmEdge(result, result.RootModule, rootKey, npmModuleName(targetPath, target), target.Version)
			}
		}
	}

	for _, installPath := range sortedPackagePaths(workspacePaths) {
		pkg := workspacePaths[installPath]
		parent := npmModuleName(installPath, pkg)
		parentKey := npmVersionedKey(parent, pkg.Version)
		for _, name := range npmEdgeSources(pkg) {
			if target, targetPath, ok := lookup(installPath, name); ok {
				appendNpmEdge(result, parent, parentKey, npmModuleName(targetPath, target), target.Version)
			}
		}
	}

	for _, installPath := range sortedPackagePaths(packages) {
		if _, ok := resolved[installPath]; !ok {
			continue
		}
		pkg := packages[installPath]
		parent := npmModuleName(installPath, pkg)
		parentKey := npmVersionedKey(parent, pkg.Version)
		for _, name := range npmEdgeSources(pkg) {
			if target, targetPath, ok := lookup(installPath, name); ok {
				appendNpmEdge(result, parent, parentKey, npmModuleName(targetPath, target), target.Version)
			}
		}
	}
}

func appendNpmEdge(result *ResolveResult, parent, parentKey, childName, childVersion string) {
	result.Graph[parent] = append(result.Graph[parent], childName)
	result.VersionedGraph[parentKey] = append(result.VersionedGraph[parentKey], Ref{
		Module:  childName,
		Version: childVersion,
	})
}

// npmResolveEdge applies node's own resolution order: a dependency is looked up
// in the depender's own node_modules first, then in each ancestor's, ending at
// the root. That walk is what makes a nested copy resolve to the nested copy —
// guessing `node_modules/<name>` reports the hoisted one for both, and the two
// are different source.
//
// It returns the install PATH as well as the package, because the caller must
// name the child by the package it resolved to. `name` here is the key from the
// depender's dependency map, which for an aliased install
// (`"foo": "npm:bar@1"`) is the ALIAS. Naming the edge after it produced a child
// no Dependency carried, so the edge joined nothing.
//
// A target that did not resolve on disk is not an edge: it would put a node in
// the graph for source that cannot be parsed.
func npmResolveEdge(
	packages map[string]npmLockPackage,
	resolved map[string]struct{},
	fromPath, name string,
) (npmLockPackage, string, bool) {
	prefix := fromPath
	for {
		candidate := path.Join(prefix, npmModulesDir, name)
		if pkg, ok := packages[candidate]; ok {
			if _, live := resolved[candidate]; live {
				return pkg, candidate, true
			}
			return npmLockPackage{}, "", false
		}
		if prefix == "" {
			return npmLockPackage{}, "", false
		}
		idx := strings.LastIndex(prefix, npmModulesSlash)
		if idx < 0 {
			// A workspace member's path holds no node_modules segment at all, so
			// the next place node looks is the root.
			prefix = ""
			continue
		}
		prefix = strings.TrimSuffix(prefix[:idx], "/")
	}
}

// npmModuleName reads the package name off its install path, which holds the
// scope as its own segment (`node_modules/@noble/hashes`). The lockfile's own
// `name` field is preferred when present, since an aliased install
// (`"foo": "npm:bar@1"`) makes the path the alias rather than the package.
func npmModuleName(installPath string, pkg npmLockPackage) string {
	if pkg.Name != "" {
		return pkg.Name
	}
	idx := strings.LastIndex(installPath, npmModulesSlash)
	if idx < 0 {
		return installPath
	}
	return installPath[idx+len(npmModulesSlash):]
}

func npmVersionedKey(module, version string) string {
	return Ref{Module: module, Version: version}.Key()
}

// sortedPackagePaths keeps resolution deterministic, and orders shallow installs
// before the copies nested under them.
func sortedPackagePaths(packages map[string]npmLockPackage) []string {
	paths := make([]string, 0, len(packages))
	for installPath := range packages {
		paths = append(paths, installPath)
	}
	sort.Slice(paths, func(i, j int) bool {
		di, dj := strings.Count(paths[i], npmModulesSlash), strings.Count(paths[j], npmModulesSlash)
		if di != dj {
			return di < dj
		}
		return paths[i] < paths[j]
	})
	return paths
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
