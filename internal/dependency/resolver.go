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
}

// Resolver resolves a project's dependencies to filesystem paths.
type Resolver interface {
	// Resolve returns all dependencies for the project at targetDir, up to maxDepth.
	// A maxDepth of 0 means only direct dependencies; -1 means unlimited.
	Resolve(ctx context.Context, targetDir string, maxDepth int) (*ResolveResult, error)
	// Ecosystem returns the name of the ecosystem (e.g., "go", "python", "rust")
	Ecosystem() string
}
