package dependency

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/scanoss/crypto-finder/internal/skip"
)

// rootManifests names the files whose presence makes a directory a RESOLUTION
// ROOT for an ecosystem, meaning the directory that ecosystem's resolver must
// be pointed at. That is a narrower question than "which ecosystem is this",
// which scan.DetectEcosystem answers.
//
// The absence of an ecosystem is the design, not an oversight. "python" is
// deliberately missing: PipResolver resolves from the interpreter or venv
// associated with the target rather than from a manifest, so a Python tree
// with no root manifest already resolves today, and fanning out would run the
// same interpreter query once per subdirectory for the same answer.
var rootManifests = map[string][]string{
	"go":          {"go.mod"},
	ecosystemJava: {"pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"},
	"rust":        {"Cargo.toml"},
	// Node needs BOTH. NpmResolver.Resolve reads package.json and then
	// package-lock.json and errors without either, and a bare package.json
	// holding {"type":"module"} is ordinary source layout, not a module root.
	ecosystemNode: {npmManifest, npmLockfile},
}

// rootManifestsAllRequired lists the ecosystems whose entry in rootManifests
// must ALL be present rather than any one of them.
var rootManifestsAllRequired = map[string]bool{ecosystemNode: true}

// rootDiscoveryIgnoredDirs are pruned on top of skip.DefaultDirMatcher(). A
// manifest under one of these names a fixture, not a module of the repository
// under scan: this repository's own two pom.xml files both live under
// testdata/projects/.
var rootDiscoveryIgnoredDirs = []string{"test", "tests", "__tests__", "testdata", "fixtures"}

const (
	// maxRootDiscoveryDepth bounds how far below the scan root a manifest can
	// sit and still name a top-level module. Independent modules live near the
	// top (services/<name>, apps/<name>/api); deeper than this a Java tree is
	// src/main/java/... and a manifest there is a fixture. An immediate child
	// of the scan root is depth 1.
	maxRootDiscoveryDepth = 4
	// maxRootDiscoveryWalk bounds walk cost on a wide pathological tree. Same
	// value and role as skip.maxBuiltOutputWalk.
	maxRootDiscoveryWalk = 50000
	// maxResolutionRoots bounds PROCESS EXECUTION, not reading. One root is one
	// mvn/gradle/npm/cargo/go invocation plus, for Maven, a source-jar pass.
	// Real service directories hold roughly 3 to 12 modules.
	maxResolutionRoots = 16
)

// rootDiscoveryBounds carries the caps for one discovery so a test can bind
// them without a shared variable.
type rootDiscoveryBounds struct {
	maxRoots   int
	maxDepth   int
	maxEntries int
}

// discoveredRoot is one directory the walk qualified, with the facts needed to
// order it, cap it and report it.
type discoveredRoot struct {
	// Dir is the absolute, cleaned path to the directory.
	Dir string
	// Rel is the slash-separated path relative to the scan root, which is the
	// name this root is reported under.
	Rel string
	// Depth counts levels below the scan root; an immediate child is 1.
	Depth int
}

// RootDiscovery is the outcome of one bounded downward walk.
type RootDiscovery struct {
	// Searched is false when the gate stayed closed, either because the
	// ecosystem is not manifest-rooted or because the scan root already holds a
	// manifest. Roots is then nil.
	Searched bool
	// Roots are the discovered resolution roots, shallowest first then lexical,
	// capped at maxResolutionRoots.
	Roots []discoveredRoot
	// Found is how many roots qualified before the cap was applied.
	Found int
	// Truncated reports that Found exceeded the cap.
	Truncated bool
	// Abandoned reports that the entry cap stopped the walk early.
	Abandoned bool
	// Unreadable counts directories skipped because they could not be read.
	Unreadable int
}

// rootWalk is the WalkDir state for one discovery.
type rootWalk struct {
	root      string
	ecosystem string
	bounds    rootDiscoveryBounds
	skipDirs  skip.SkipMatcher
	found     []discoveredRoot
	seen      int
	out       RootDiscovery
}

// HasRootManifest reports whether dir holds the file or files that make it a
// resolution root for ecosystem. It is always false for an ecosystem absent
// from rootManifests.
func HasRootManifest(dir, ecosystem string) bool {
	manifests, ok := rootManifests[ecosystem]
	if !ok {
		return false
	}
	if rootManifestsAllRequired[ecosystem] {
		for _, name := range manifests {
			if !fileExists(filepath.Join(dir, name)) {
				return false
			}
		}
		return true
	}
	for _, name := range manifests {
		if fileExists(filepath.Join(dir, name)) {
			return true
		}
	}
	return false
}

// ResolutionRoots answers where the resolver for ecosystem must be pointed for
// the tree at targetDir. A closed gate, meaning Searched false and Roots nil,
// says that today's single Resolve(targetDir) is correct and nothing changed.
func ResolutionRoots(targetDir, ecosystem string) RootDiscovery {
	return resolutionRoots(targetDir, ecosystem, rootDiscoveryBounds{
		maxRoots:   maxResolutionRoots,
		maxDepth:   maxRootDiscoveryDepth,
		maxEntries: maxRootDiscoveryWalk,
	})
}

func resolutionRoots(targetDir, ecosystem string, bounds rootDiscoveryBounds) RootDiscovery {
	if _, ok := rootManifests[ecosystem]; !ok {
		return RootDiscovery{}
	}
	root := filepath.Clean(targetDir)
	if HasRootManifest(root, ecosystem) {
		return RootDiscovery{}
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return RootDiscovery{}
	}

	walk := rootWalk{
		root:      root,
		ecosystem: ecosystem,
		bounds:    bounds,
		skipDirs:  skip.DefaultDirMatcher(),
	}
	// visit returns only fs.SkipDir or fs.SkipAll, so a non-nil error here
	// would be a WalkDir defect rather than an unreadable directory, which
	// visit records on the walk itself.
	if err := filepath.WalkDir(root, walk.visit); err != nil {
		return RootDiscovery{}
	}

	out := walk.out
	out.Searched = true
	out.Found = len(walk.found)
	sort.Slice(walk.found, func(i, j int) bool {
		if walk.found[i].Depth != walk.found[j].Depth {
			return walk.found[i].Depth < walk.found[j].Depth
		}
		return walk.found[i].Rel < walk.found[j].Rel
	})
	if len(walk.found) > bounds.maxRoots {
		out.Truncated = true
		walk.found = walk.found[:bounds.maxRoots]
	}
	out.Roots = walk.found
	return out
}

// visit is the WalkDir callback. An unreadable directory is skipped and
// counted rather than fatal, which diverges from skip.BuiltOutputOnlySource,
// where a partial answer would wrongly remove an exclusion. Here a partial
// answer is strictly more coverage than the zero shipped before this walk
// existed.
func (w *rootWalk) visit(path string, d fs.DirEntry, err error) error {
	if err != nil {
		w.out.Unreadable++
		return fs.SkipDir
	}
	if !d.IsDir() {
		return nil
	}
	w.seen++
	if w.seen > w.bounds.maxEntries {
		w.out.Abandoned = true
		return fs.SkipAll
	}
	rel, relErr := filepath.Rel(w.root, path)
	if relErr != nil {
		w.out.Unreadable++
		return fs.SkipDir
	}
	if rel == "." {
		return nil
	}
	// The matcher is given the directory's own name, not its path. A gitignore
	// pattern matches any segment, so an absolute path would skip every
	// directory under a scan root that merely SITS in one, and
	// /home/me/build/myproject would discover nothing at all.
	if w.skipDirs.ShouldSkip(d.Name(), true) || slices.Contains(rootDiscoveryIgnoredDirs, d.Name()) {
		return fs.SkipDir
	}
	slashRel := filepath.ToSlash(rel)
	depth := 1 + strings.Count(slashRel, "/")
	if HasRootManifest(path, w.ecosystem) {
		w.found = append(w.found, discoveredRoot{Dir: path, Rel: slashRel, Depth: depth})
		// A qualifying root is never descended into. Its own resolver owns its
		// declared sub-modules (Maven <modules>, npm workspace lockfile keys,
		// cargo metadata members), and descending would resolve them twice and
		// parse one directory under two import paths.
		return fs.SkipDir
	}
	if depth >= w.bounds.maxDepth {
		return fs.SkipDir
	}
	return nil
}

// RootResolution pairs a discovered root with what its resolver returned.
type RootResolution struct {
	Root   discoveredRoot
	Result *ResolveResult
}

// MergeRootResolutions folds per-root results into the one ResolveResult the
// pipeline consumes. Each discovered root becomes a WorkspaceMember of the
// scan root, which has no module identity of its own and is named by its
// directory.
//
// RootModule may never be empty. scan.exportUserPackages returns a nil stop-set
// for an empty RootModule, which makes every finding report reachability
// not_applicable, and occurrenceSourceSubject hashes every non-dependency
// finding against it. The directory-name fallback is the convention
// internal/scan/root_module.go:24 already documents for DetectRootModule;
// internal/dependency cannot import internal/scan, because internal/scan
// imports this package.
func MergeRootResolutions(scanRoot string, resolutions []RootResolution) *ResolveResult {
	out := &ResolveResult{
		RootModule:     filepath.Base(filepath.Clean(scanRoot)),
		Graph:          map[string][]string{},
		VersionedGraph: map[string][]Ref{},
	}
	for _, r := range resolutions {
		if r.Result == nil {
			continue
		}
		out.WorkspaceMembers = append(out.WorkspaceMembers, mergedMembers(r)...)
		out.Dependencies = append(out.Dependencies, r.Result.Dependencies...)
		mergeGraph(out.Graph, r.Result.Graph)
		mergeVersionedGraph(out.VersionedGraph, r.Result.VersionedGraph)
	}
	sortGraph(out.Graph)
	sortVersionedGraph(out.VersionedGraph)
	return out
}

// mergedMembers is what one resolved root contributes to the merged member
// list. A child that reported its own members is REPLACED by them:
// collectPackageSets gives a member no ExcludeDirs, so listing both an
// aggregator and its sub-modules would parse one directory under two import
// paths. The aggregator's own files stay covered by the scan-root PackageDir,
// which carries ExcludeDirs for every member.
func mergedMembers(r RootResolution) []WorkspaceMember {
	if len(r.Result.WorkspaceMembers) > 0 {
		return r.Result.WorkspaceMembers
	}
	// The name is the child's PLAIN RootModule, a Maven groupId and never a
	// decorated form. owningModule feeds that string to mavenRootAliasRefs,
	// which prefix-matches it against versioned graph keys.
	name := r.Result.RootModule
	if name == "" {
		name = filepath.Base(r.Root.Dir)
	}
	return []WorkspaceMember{{Name: name, Dir: r.Root.Dir}}
}

func mergeGraph(dst, src map[string][]string) {
	for parent, children := range src {
		existing := dst[parent]
		for _, child := range children {
			if !slices.Contains(existing, child) {
				existing = append(existing, child)
			}
		}
		dst[parent] = existing
	}
}

func mergeVersionedGraph(dst, src map[string][]Ref) {
	for parent, refs := range src {
		existing := dst[parent]
		for _, ref := range refs {
			if !slices.ContainsFunc(existing, func(have Ref) bool { return have.Key() == ref.Key() }) {
				existing = append(existing, ref)
			}
		}
		dst[parent] = existing
	}
}

func sortGraph(graph map[string][]string) {
	for parent := range graph {
		slices.Sort(graph[parent])
	}
}

func sortVersionedGraph(graph map[string][]Ref) {
	for parent := range graph {
		slices.SortFunc(graph[parent], func(a, b Ref) int {
			return strings.Compare(a.Key(), b.Key())
		})
	}
}
