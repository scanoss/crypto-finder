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
	Dev          bool              `json:"dev"`
	// Link marks a node_modules entry that is a symlink to a workspace member.
	// It carries no version of its own: the real entry is keyed by the member's
	// own path elsewhere in the same map.
	Link bool `json:"link"`
}

// npmLockV1Entry is one entry of a v1 `dependencies` map, which nests instead of
// keying by path.
type npmLockV1Entry struct {
	Version      string                    `json:"version"`
	Dev          bool                      `json:"dev"`
	Requires     map[string]string         `json:"requires"`
	Dependencies map[string]npmLockV1Entry `json:"dependencies"`
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
	missing := appendNpmDependencies(result, targetDir, packages)
	if len(result.Dependencies) == 0 && len(packages) > 0 {
		return nil, fmt.Errorf(
			"npm resolver: %s lists %d dependencies but none are installed under %s in %s: run `npm install` before scanning",
			npmLockfile, len(packages), npmModulesDir, targetDir,
		)
	}
	if missing > 0 {
		log.Warn().
			Int("missing", missing).
			Int("resolved", len(result.Dependencies)).
			Str("target", targetDir).
			Msg("Some npm dependencies in the lockfile are not installed and were skipped")
	}

	populateNpmGraph(result, packages, rootDeps)

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
			if pkg.Dev || pkg.Link {
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
		if entry.Dev {
			continue
		}
		installPath := path.Join(prefix, npmModulesDir, name)
		out[installPath] = npmLockPackage{
			Name:         name,
			Version:      entry.Version,
			Dependencies: entry.Requires,
		}
		collectNpmV1Entries(installPath, entry.Dependencies, out)
	}
}

// appendNpmDependencies records one Dependency per installed package and returns
// how many the lockfile named but the tree does not hold.
func appendNpmDependencies(result *ResolveResult, targetDir string, packages map[string]npmLockPackage) int {
	missing := 0
	for _, installPath := range sortedPackagePaths(packages) {
		pkg := packages[installPath]
		dir := filepath.Join(targetDir, filepath.FromSlash(installPath))
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			missing++
			continue
		}
		result.Dependencies = append(result.Dependencies, Dependency{
			Module:  npmModuleName(installPath, pkg),
			Version: pkg.Version,
			Dir:     dir,
		})
	}
	return missing
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

func populateNpmGraph(result *ResolveResult, packages map[string]npmLockPackage, rootDeps []string) {
	if result.RootModule != "" {
		for _, name := range rootDeps {
			target, ok := npmResolveEdge(packages, "", name)
			if !ok {
				continue
			}
			appendNpmEdge(result, result.RootModule, npmVersionedKey(result.RootModule, ""), name, target.Version)
		}
	}

	for _, installPath := range sortedPackagePaths(packages) {
		pkg := packages[installPath]
		parent := npmModuleName(installPath, pkg)
		parentKey := npmVersionedKey(parent, pkg.Version)
		for _, name := range sortedKeys(pkg.Dependencies) {
			target, ok := npmResolveEdge(packages, installPath, name)
			if !ok {
				continue
			}
			appendNpmEdge(result, parent, parentKey, name, target.Version)
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
func npmResolveEdge(packages map[string]npmLockPackage, fromPath, name string) (npmLockPackage, bool) {
	prefix := fromPath
	for {
		candidate := path.Join(prefix, npmModulesDir, name)
		if pkg, ok := packages[candidate]; ok {
			return pkg, true
		}
		if prefix == "" {
			return npmLockPackage{}, false
		}
		idx := strings.LastIndex(prefix, npmModulesSlash)
		if idx < 0 {
			return npmLockPackage{}, false
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
