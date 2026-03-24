// Package dependency provides interfaces and implementations for resolving
// project dependencies to their source code locations on disk.
package dependency

import "context"

// Dependency represents a single resolved dependency with its source location.
type Dependency struct {
	// Module is the import path (e.g., "golang.org/x/crypto")
	Module string
	// Version is the resolved version (e.g., "v0.17.0")
	Version string
	// Dir is the absolute filesystem path to the dependency source code
	Dir string
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
	// Dir is the absolute filesystem path to the member's source root
	Dir string
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
	// VersionedGraph maps each parent node key to its direct dependency targets with versions preserved.
	// Parent keys should use the same canonical coordinate form as Ref.Key() when a version is known.
	VersionedGraph map[string][]Ref
}

// Resolver resolves a project's dependencies to filesystem paths.
type Resolver interface {
	// Resolve returns all dependencies for the project at targetDir.
	Resolve(ctx context.Context, targetDir string) (*ResolveResult, error)
	// Ecosystem returns the name of the ecosystem (e.g., "go", "python", "rust")
	Ecosystem() string
}
