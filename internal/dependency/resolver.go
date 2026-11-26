// Package dependency provides interfaces and implementations for resolving
// project dependencies to their source code locations on disk.
package dependency

import (
	"context"
	"path/filepath"
)

const ecosystemJava = "java"

// Dependency represents a single resolved dependency with its source location.
type Dependency struct {
	// Module is the dependency coordinate (e.g., "golang.org/x/crypto",
	// "org.example:lib", or the Python distribution name "argon2-cffi").
	Module string
	// ImportPath is the source namespace when it differs from Module. Python
	// resolvers use it for distribution/import-root pairs such as
	// argon2-cffi/argon2, and leave it empty for a distribution rooted at
	// site-packages, whose packages keep their own names; other ecosystems
	// leave it empty.
	ImportPath string
	// Version is the resolved version (e.g., "v0.17.0" or "1.2.3").
	Version string
	// Dir is the absolute filesystem path to the dependency source code.
	Dir string
	// Files, when non-nil, limits the dependency's source to these absolute,
	// clean, sorted regular files under Dir. Go lists the Go files the host
	// build compiles (go list GoFiles and CgoFiles) in each package a program
	// imports: the only files it links. Python lists the files a
	// distribution installed into a namespace directory it shares with other
	// distributions (google/, say), and, for a distribution rooted at
	// site-packages because it installed several top-level packages or a
	// module file, the files of each of them. Nil means every file under Dir.
	Files []string
	// CompiledArtifactPath is the absolute path to the compiled artifact used for
	// type-only indexing when source scanning is unavailable or incomplete.
	CompiledArtifactPath string
	// SourceArchivePath is the absolute path to the downloaded source archive when
	// available. The extracted source directory in Dir remains the preferred scan input.
	SourceArchivePath string
	// Markers, for a Python dependency, are the PEP 508 environment markers
	// under which the lock or environment installs it, as written: the
	// entry's own markers where the format writes them per package, else
	// the markers of the requirements that pull it in when every one of
	// them carries one. Empty means unconditional. The closure is the union of all
	// marker branches; the markers are kept for display, not evaluated.
	Markers []string
	// Extras, for a Python dependency, are its extras the lock or environment
	// enables (requests[socks]), sorted. Their requirements are in the
	// closure under the same union policy.
	Extras []string
	// Local marks a dependency whose source of truth is a directory outside
	// the project that its manifest points at (a Go replace directory, a
	// Cargo path crate), not a registry release. Dir holds its code and
	// Version is the version the manifest names, which no registry need
	// publish with that code. An offline scan mines it from Dir; the API
	// knows only published versions, so an online scan carries it as
	// unpinned (see LocalAsUnpinned).
	Local bool
}

// Ref identifies a dependency edge target without requiring a source directory.
type Ref struct {
	// Module is the dependency coordinate without version (e.g., "org.example:lib").
	Module string
	// Version is the resolved version for this edge target.
	Version string
}

// Key returns the canonical coordinate for this dependency reference.
func (d Ref) Key() string {
	if d.Module == "" {
		return ""
	}
	if d.Version == "" {
		return d.Module
	}
	return d.Module + "@" + d.Version
}

// WorkspaceMember represents a local/workspace crate or module that is part of the
// user's project (not an external dependency).
type WorkspaceMember struct {
	// Name is the module/crate name (e.g., "rustls", "rustls-webpki")
	Name string
	// ImportPath is the source namespace when it differs from Name: a Cargo
	// member's library name (my_core for package my-core).
	ImportPath string
	// Dir is the absolute filesystem path to the member's source root
	Dir string
}

// SourceNamespace is the name the member's code is reached by in source:
// ImportPath, or Name when that is empty.
func (m WorkspaceMember) SourceNamespace() string {
	if m.ImportPath != "" {
		return m.ImportPath
	}
	return m.Name
}

// ResolveResult holds the complete dependency resolution output.
type ResolveResult struct {
	// RootModule is the root module path (e.g., "github.com/myorg/myproject")
	RootModule string
	// WorkspaceMembers lists all local workspace members (for monorepo/workspace projects).
	// When non-empty, all members are treated as user code for call chain tracing.
	WorkspaceMembers []WorkspaceMember
	// Dependencies is the flat list of all resolved dependencies
	Dependencies []Dependency
	// Graph maps each module path to its direct dependency module paths (adjacency list)
	Graph map[string][]string
	// ImportGraph, set by the Go resolver, maps each module of the production
	// import closure to the modules its packages import. Dependency paths
	// follow it instead of Graph, the requirement graph, where a go.mod lists
	// modules only its dependencies import.
	ImportGraph map[string][]string
	// DirectDependencies, for a Graph with no application node, names the
	// modules the project's manifests declare: the application's children.
	// The pip resolver sets it from requirements.txt and pyproject.toml.
	DirectDependencies []string
	// VersionedGraph maps each parent node key to its direct dependency targets with versions preserved.
	// Parent keys should use the same canonical coordinate form as Ref.Key() when a version is known.
	VersionedGraph map[string][]Ref
	// Source names what the closure was read from: a lock file's name, or
	// the site-packages directory of an installed environment. Set by the
	// Python resolver.
	Source string
	// Unpinned lists the declared dependencies with no pinned version (a
	// range, or no version at all). They have no closure, and the API cannot
	// answer for them: their findings are unknown, reason unpinned.
	Unpinned []UnpinnedDependency
	// OtherVersions lists the versions of a package the closure holds at
	// several (npm nests a copy under the package that needs it) that the
	// request leaves out: it takes one version per package URL, and the closure
	// keeps the one the project's own code loads. Edges to them point at the
	// kept version.
	OtherVersions []Dependency
	// UnderOtherVersions lists the packages only a version in OtherVersions
	// requires: the request leaves them out too, as no requested package
	// leads to them and their verdicts would read unreachable while the
	// project loads them.
	UnderOtherVersions []Dependency
	// OmittedEdges holds the dependency edges a tree resolver resolved but
	// left out of VersionedGraph, keyed the same way: a parent declares a
	// child that the closure resolves at another position of the tree (Maven
	// prints such a child once, and elsewhere only as "omitted for duplicate"
	// or "omitted for conflict"). Each child carries the version the closure
	// selected. The parent's code still calls the child, so the project
	// reachability request names these edges too; dependency paths do not
	// use them.
	OmittedEdges map[string][]Ref
}

// ReasonUnpinned is the reachability reason of a declared dependency without
// a pinned version.
const ReasonUnpinned = "unpinned"

// UnpinnedDependency is a declared dependency whose version the client cannot
// pin.
type UnpinnedDependency struct {
	// Module is the dependency name (PEP 503 normalised for Python).
	Module string
	// Specifier is the version constraint as written; empty for none.
	Specifier string
	// Marker is the requirement's environment marker as written.
	Marker string
	// Manifest is the file that declares it.
	Manifest string
}

// LocalAsUnpinned moves the local dependencies (Dependency.Local) of r to
// Unpinned, the specifier naming the directory relative to target, and
// returns them: the API holds only published versions, so a request to it
// cannot name them. Edges to them stay; a request names only the
// dependencies left.
func (r *ResolveResult) LocalAsUnpinned(target string) []Dependency {
	var local []Dependency
	kept := r.Dependencies[:0]
	for _, dep := range r.Dependencies {
		if !dep.Local {
			kept = append(kept, dep)
			continue
		}
		local = append(local, dep)
		r.Unpinned = append(r.Unpinned, UnpinnedDependency{
			Module:    dep.Module,
			Specifier: "path " + filepath.ToSlash(relOr(absoluteScanRoot(target), dep.Dir)),
			Manifest:  r.Source,
		})
	}
	r.Dependencies = kept
	return local
}

// ScanRootConfigurer is a resolver that tells a local dependency directory
// from the project's own code: a directory inside the scan root is the
// project's code even when Resolve is given a module root below it, as a scan
// root without a manifest resolves each module root it holds.
type ScanRootConfigurer interface {
	SetScanRoot(dir string)
}

// Resolver resolves a project's dependencies to filesystem paths.
type Resolver interface {
	// Resolve returns all dependencies for the project at targetDir.
	Resolve(ctx context.Context, targetDir string) (*ResolveResult, error)
	// Ecosystem returns the name of the ecosystem (e.g., "go", "python", "java", "rust")
	Ecosystem() string
	// CanResolve reports whether targetDir carries the inputs this resolver
	// needs. It is a cheap filesystem precondition, not a promise that Resolve
	// will succeed: a present but malformed manifest still fails in Resolve. A
	// resolver that reads the ambient environment rather than a manifest
	// reports true unconditionally.
	CanResolve(targetDir string) bool
}
