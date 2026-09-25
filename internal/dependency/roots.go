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
	// go.work is here because a workspace root carries no go.mod of its own and
	// `go list -m -json all` resolves from it.
	"go":          {"go.mod", "go.work"},
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

// ecosystemsResolvingUpward names the ecosystems whose toolchain locates its
// own manifest by searching the scan root's ancestors. GoResolver sets only
// cmd.Dir and lets `go list` walk up, so a directory inside a module resolves
// today with no manifest of its own and must not be treated as manifest-less.
var ecosystemsResolvingUpward = map[string]bool{"go": true}

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
	// maxRootDiscoveryWalk bounds walk cost on a wide pathological tree. It
	// counts DIRECTORIES, not entries: visit returns on a file before the
	// counter moves, unlike skip.builtOutputScan, which counts every entry.
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

// rootWalk is the WalkDir state for one discovery. It consults two matchers
// because they are asked different questions. skipDirs is asked about a bare
// directory NAME, since a gitignore pattern matches any segment and an absolute
// path would make a scan root that merely sits below a directory called build
// prune its whole tree. userSkip is asked about the path RELATIVE to the scan
// root, because a user pattern is path-shaped (third_party/**) and cannot match
// a bare name; a relative path never contains the scan root's ancestry, so it
// is immune to that problem.
type rootWalk struct {
	root      string
	ecosystem string
	bounds    rootDiscoveryBounds
	skipDirs  skip.SkipMatcher
	userSkip  skip.SkipMatcher
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

// hasRootManifestAbove reports whether a strict ancestor of dir carries a root
// manifest for ecosystem. It stops at the filesystem root.
func hasRootManifestAbove(dir, ecosystem string) bool {
	for {
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		if HasRootManifest(parent, ecosystem) {
			return true
		}
		dir = parent
	}
}

// absoluteScanRoot is the one form of the scan root that discovery and merging
// both work from. A relative target would otherwise name the merged result ".",
// and that string reaches scan_metadata.root_module and the occurrence-key
// subject, so the same tree scanned as "." and by absolute path would produce
// different occurrence keys. Symlinks are resolved because filepath.WalkDir
// hands entries straight from ReadDir and never follows one, so a scan root
// like ./current -> releases/2026-09 would walk nothing at all.
func absoluteScanRoot(scanRoot string) string {
	abs, err := filepath.Abs(scanRoot)
	if err != nil {
		return filepath.Clean(scanRoot)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return abs
	}
	return resolved
}

// ResolutionRoots answers where the resolver for ecosystem must be pointed for
// the tree at targetDir. A closed gate, meaning Searched false and Roots nil,
// says that today's single Resolve(targetDir) is correct and nothing changed.
// skipPatterns are the scan's own exclusions; a directory they cover is never
// discovered, because resolving a root runs that ecosystem's build tool there.
func ResolutionRoots(targetDir, ecosystem string, skipPatterns []string) RootDiscovery {
	return resolutionRoots(targetDir, ecosystem, skipPatterns, rootDiscoveryBounds{
		maxRoots:   maxResolutionRoots,
		maxDepth:   maxRootDiscoveryDepth,
		maxEntries: maxRootDiscoveryWalk,
	})
}

func resolutionRoots(targetDir, ecosystem string, skipPatterns []string, bounds rootDiscoveryBounds) RootDiscovery {
	if _, ok := rootManifests[ecosystem]; !ok {
		return RootDiscovery{}
	}
	root := absoluteScanRoot(targetDir)
	if HasRootManifest(root, ecosystem) {
		return RootDiscovery{}
	}
	if ecosystemsResolvingUpward[ecosystem] && hasRootManifestAbove(root, ecosystem) {
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
	if len(skipPatterns) > 0 {
		walk.userSkip = skip.NewGitIgnoreMatcher(skipPatterns)
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
//
// A symlinked directory BELOW the scan root is not a discoverable module root:
// WalkDir hands it over as a non-directory entry and never follows it. Only the
// scan root itself is dereferenced, by absoluteScanRoot.
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
	if w.skipDirs.ShouldSkip(d.Name(), true) || slices.Contains(rootDiscoveryIgnoredDirs, d.Name()) {
		return fs.SkipDir
	}
	slashRel := filepath.ToSlash(rel)
	if w.userSkip != nil && w.userSkip.ShouldSkip(slashRel, true) {
		return fs.SkipDir
	}
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
// scan root, which has no module identity of its own: its RootModule is empty,
// never its directory name, so the same tree scanned from two differently
// named directories keeps one set of symbols and occurrence keys.
// scan.exportUserPackages still classifies reachability for an empty root,
// from the packages of the functions that live under the project tree.
func MergeRootResolutions(resolutions []RootResolution) *ResolveResult {
	out := &ResolveResult{
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
