// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"

	"github.com/scanoss/crypto-finder/internal/failure"
)

const ecosystemNode = "node"

// npmLocks are the lock files the npm resolver reads, in the order the first
// one present decides the closure: npm itself prefers a shrinkwrap to a
// package-lock.json.
var npmLocks = []string{"npm-shrinkwrap.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}

// NpmResolver resolves a JavaScript or TypeScript project's pinned npm
// closure from its lock file (package-lock.json or npm-shrinkwrap.json of
// lockfileVersion 2 and 3, yarn.lock, pnpm-lock.yaml), read with the
// resolver the other SCANOSS tools share. Nothing runs and nothing is
// downloaded: a project without a lock file has no closure (package.json
// ranges are never resolved), and dev-only packages are left out. A
// dependency installed under node_modules carries its directory.
type NpmResolver struct{}

// NewNpmResolver returns the npm resolver.
func NewNpmResolver() *NpmResolver {
	return &NpmResolver{}
}

// Ecosystem returns "node".
func (r *NpmResolver) Ecosystem() string {
	return ecosystemNode
}

// CanResolve reports whether targetDir holds an npm, yarn or pnpm lock file.
func (r *NpmResolver) CanResolve(targetDir string) bool {
	return npmLockName(targetDir) != ""
}

// npmLockName is the lock file of dir that decides its closure, or "".
func npmLockName(dir string) string {
	for _, name := range npmLocks {
		if fileExists(filepath.Join(dir, name)) {
			return name
		}
	}
	return ""
}

// Resolve reads the lock file of targetDir into the pinned runtime closure.
func (r *NpmResolver) Resolve(ctx context.Context, targetDir string) (*ResolveResult, error) {
	lock := npmLockName(targetDir)
	if lock == "" {
		return nil, npmFailure(targetDir, "no npm, yarn or pnpm lock file")
	}
	graph, err := readLockfile(ctx, targetDir, lock)
	if err != nil {
		return nil, npmFailure(targetDir, fmt.Sprintf("%s: %v", lock, err))
	}
	for _, root := range graph.Roots {
		if root.Status == resolve.StatusUnknown {
			detail := fmt.Sprintf("%s: %s %s", lock, root.Reason, root.Detail)
			if root.Reason == resolve.ReasonUnsupportedVersion {
				return nil, failure.Wrap(ErrUnsupportedNpmLock, failure.CodeDependencyResolutionFailed, failure.StageDependency,
					fmt.Sprintf("read the npm dependency closure of %s: %s", targetDir, detail), failure.WithDetail("target_dir", targetDir))
			}
			return nil, npmFailure(targetDir, detail)
		}
	}
	result := npmClosure(lock, graph, npmHoistedVersions(targetDir, lock))
	result.RootModule = npmPackageName(targetDir)
	installed := indexInstalledNpm(filepath.Join(targetDir, "node_modules"))
	for i := range result.Dependencies {
		dep := &result.Dependencies[i]
		dep.Dir = installed[Ref{Module: dep.Module, Version: dep.Version}.Key()]
	}
	return result, nil
}

// ErrUnsupportedNpmLock is the cause of a resolution that read a lock file
// version the shared parser does not read (npm 6, lockfileVersion 1).
var ErrUnsupportedNpmLock = errors.New("unsupported npm lock file version")

func npmFailure(dir, detail string) error {
	return failure.New(failure.CodeDependencyResolutionFailed, failure.StageDependency,
		fmt.Sprintf("read the npm dependency closure of %s: %s", dir, detail), failure.WithDetail("target_dir", dir))
}

// npmClosure reads the runtime closure out of the lock's graph: the members
// of every root (a workspace has one per member) that some root reaches
// outside its dev dependencies, the edges between them, and which are
// declared. A local node is the project's own package, not a dependency; a
// member with no registry package URL or version is unpinned.
func npmClosure(source string, graph resolve.Graph, hoisted map[string]string) *ResolveResult {
	c := &npmCollector{
		source: source,
		result: &ResolveResult{Source: source, Graph: map[string][]string{}, VersionedGraph: map[string][]Ref{}},
		nodes:  make(map[resolve.NodeID]resolve.Node, len(graph.Nodes)),
		refs:   map[resolve.NodeID]Ref{},
		kept:   map[Ref]bool{},
		direct: map[string]bool{},
		seen:   map[string]bool{},

		hoisted:   hoisted,
		directRef: map[Ref]bool{},
		incoming:  map[Ref]int{},
	}
	for _, node := range graph.Nodes {
		c.nodes[node.ID] = node
		if module, ok := npmModuleOf(node.PURL); ok && node.Version != "" && !node.Local {
			c.refs[node.ID] = Ref{Module: module, Version: node.Version}
		}
	}
	for i := range graph.Roots {
		c.addRoot(&graph.Roots[i])
	}
	return c.finish()
}

// npmCollector accumulates the closure over the roots of a lock's graph.
type npmCollector struct {
	source string
	result *ResolveResult
	nodes  map[resolve.NodeID]resolve.Node
	refs   map[resolve.NodeID]Ref
	kept   map[Ref]bool
	direct map[string]bool
	seen   map[string]bool

	// hoisted, directRef and incoming choose among the versions of a package.
	hoisted   map[string]string
	directRef map[Ref]bool
	incoming  map[Ref]int
}

func (c *npmCollector) addRoot(root *resolve.Root) {
	for _, member := range root.Members {
		node := c.nodes[member.ID]
		if member.Dev || node.Local {
			continue
		}
		ref, pinned := c.refs[member.ID]
		if !pinned {
			c.addUnpinned(node)
			continue
		}
		c.kept[ref] = true
		c.direct[ref.Module] = c.direct[ref.Module] || member.Direct
		c.directRef[ref] = c.directRef[ref] || member.Direct
	}
	for _, edge := range root.Edges {
		from, fromOK := c.refs[edge.From]
		to, toOK := c.refs[edge.To]
		if fromOK && toOK && from != to {
			c.result.VersionedGraph[from.Key()] = appendRef(c.result.VersionedGraph[from.Key()], to)
			c.incoming[to]++
		}
	}
}

func (c *npmCollector) addUnpinned(node resolve.Node) {
	name := npmNodeName(node)
	if name == "" || c.seen[name] {
		return
	}
	c.seen[name] = true
	c.result.Unpinned = append(c.result.Unpinned, UnpinnedDependency{Module: name, Manifest: c.source})
}

func (c *npmCollector) finish() *ResolveResult {
	result := c.result
	redirect := c.chooseVersions()
	for ref := range c.kept {
		result.Dependencies = append(result.Dependencies, Dependency{Module: ref.Module, Version: ref.Version})
	}
	sort.Slice(result.Dependencies, func(i, j int) bool {
		a, b := result.Dependencies[i], result.Dependencies[j]
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		return a.Version < b.Version
	})
	droppedEdges := map[Ref][]Ref{}
	for other := range redirect {
		droppedEdges[other] = result.VersionedGraph[other.Key()]
	}
	npmTrimEdges(result, c.kept, redirect)
	for module, declared := range c.direct {
		if declared {
			result.DirectDependencies = append(result.DirectDependencies, module)
		}
	}
	sort.Strings(result.DirectDependencies)
	sort.Slice(result.Unpinned, func(i, j int) bool { return result.Unpinned[i].Module < result.Unpinned[j].Module })
	npmDropUnderOtherVersions(result, droppedEdges)
	return result
}

// npmTrimEdges keeps the edges between kept dependencies (a dev-only package
// is no child) and fills the name-keyed Graph the dependency paths read.
func npmTrimEdges(result *ResolveResult, kept map[Ref]bool, redirect map[Ref]Ref) {
	for from, children := range result.VersionedGraph {
		parent := refOfKey(from)
		var out []Ref
		if kept[parent] {
			for _, child := range children {
				if to, moved := redirect[child]; moved {
					child = to
				}
				if kept[child] && child != parent {
					out = appendRef(out, child)
				}
			}
		}
		if len(out) == 0 {
			delete(result.VersionedGraph, from)
			continue
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
		result.VersionedGraph[from] = out
		for _, child := range out {
			result.Graph[parent.Module] = appendUnique(result.Graph[parent.Module], child.Module)
		}
	}
	for _, children := range result.Graph {
		sort.Strings(children)
	}
}

// refOfKey is the Ref of a "module@version" key; a scoped module keeps its
// leading "@".
func refOfKey(key string) Ref {
	i := strings.LastIndex(key, "@")
	if i <= 0 {
		return Ref{Module: key}
	}
	return Ref{Module: key[:i], Version: key[i+1:]}
}

func appendRef(list []Ref, ref Ref) []Ref {
	for _, r := range list {
		if r == ref {
			return list
		}
	}
	return append(list, ref)
}

// npmModuleOf names an npm package URL's package the way npm does:
// "@scope/name" for a scoped one. It reports false for another package type.
func npmModuleOf(raw string) (string, bool) {
	p, err := packageurl.FromString(raw)
	if err != nil || p.Type != packageurl.TypeNPM || p.Name == "" {
		return "", false
	}
	if p.Namespace == "" {
		return p.Name, true
	}
	return p.Namespace + "/" + p.Name, true
}

// npmNodeName is a name for a node that has no registry version, for the
// unpinned list.
func npmNodeName(node resolve.Node) string {
	if module, ok := npmModuleOf(node.PURL); ok {
		return module
	}
	if p, err := packageurl.FromString(node.PURL); err == nil {
		return p.Name
	}
	return ""
}

// npmPackageName is the "name" of dir's package.json, or "".
func npmPackageName(dir string) string {
	name, _ := readPackageNameVersion(filepath.Join(dir, "package.json"))
	return name
}

func readPackageNameVersion(path string) (name, version string) {
	data, err := os.ReadFile(path) // #nosec G304 -- the scan target's own package.json, or an installed package's.
	if err != nil {
		return "", ""
	}
	var manifest struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(data, &manifest) != nil {
		return "", ""
	}
	return strings.TrimSpace(manifest.Name), strings.TrimSpace(manifest.Version)
}
