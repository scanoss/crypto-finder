// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

// artifact_scope.go keeps a name_only dispatch guess inside the artifacts
// that could hold the subtype it guesses.
//
// A name_only edge links a call to a same-named method whose class may be a
// subtype of the receiver's type: its ancestry is only partly recorded, so
// nothing proves it is not. The namespace root used to be the only other
// bound, and a root like org.apache spans dozens of unrelated artifacts, so a
// call on a tika-core class could land in commons-math3.
//
// A class can only extend a type its artifact compiles against. So the guess
// is kept only when the candidate's artifact is the receiver type's artifact,
// is the scanned project (which compiles against every resolved dependency),
// or depends on the receiver type's artifact in the resolved dependency graph.
// A proven subtype (interface_dispatch) is never filtered: its recorded
// ancestry already is the evidence.

// projectArtifact identifies the scanned project's own packages: every
// package without a dependency version.
const projectArtifact = "\x00project"

// artifactScope records which artifact declares each type and which
// artifacts each one depends on.
type artifactScope struct {
	// typeArtifact maps a declaring type (declOwnerFQN) to its artifact. A
	// type two artifacts declare maps to "": its artifact is unknown.
	typeArtifact map[string]string
	// requires is the resolved dependency graph: artifact -> direct
	// dependencies. Nil when the scan resolved no graph.
	requires map[string][]string
	// closure memoizes each artifact's transitive dependencies.
	closure map[string]map[string]bool
}

func newArtifactScope(requires map[string][]string) *artifactScope {
	return &artifactScope{
		typeArtifact: make(map[string]string),
		requires:     requires,
		closure:      make(map[string]map[string]bool),
	}
}

// artifactOf names a package's artifact: its dependency coordinate, or the
// project for a package without a version.
func artifactOf(pkg PackageDir) string {
	if pkg.Version == "" {
		return projectArtifact
	}
	if pkg.DistributionName != "" {
		return pkg.DistributionName
	}
	return pkg.ImportPath
}

// record notes that artifact declares fn's type.
func (s *artifactScope) record(fn *FunctionDecl, artifact string) {
	if s == nil || artifact == "" {
		return
	}
	owner := declOwnerFQN(fn.ID)
	existing, seen := s.typeArtifact[owner]
	switch {
	case !seen:
		s.typeArtifact[owner] = artifact
	case existing != artifact:
		s.typeArtifact[owner] = ""
	}
}

// mayExtend reports whether a type declared by sub's artifact can be a
// subtype of super. Unknown artifacts allow it, which keeps a graph built
// without artifact information as it was.
func (s *artifactScope) mayExtend(sub, super string) bool {
	if s == nil {
		return true
	}
	subArtifact, superArtifact := s.typeArtifact[sub], s.typeArtifact[super]
	switch {
	case subArtifact == "" || superArtifact == "":
		return true
	case subArtifact == superArtifact, subArtifact == projectArtifact:
		return true
	case superArtifact == projectArtifact:
		return false
	}
	return s.dependsOn(subArtifact)[superArtifact]
}

// related reports whether either type can be the other's subtype.
func (s *artifactScope) related(a, b string) bool {
	return s.mayExtend(a, b) || s.mayExtend(b, a)
}

// dependsOn returns artifact's transitive dependencies.
func (s *artifactScope) dependsOn(artifact string) map[string]bool {
	if deps, ok := s.closure[artifact]; ok {
		return deps
	}
	deps := make(map[string]bool)
	queue := append([]string(nil), s.requires[artifact]...)
	for len(queue) > 0 {
		next := queue[0]
		queue = queue[1:]
		if deps[next] || next == artifact {
			continue
		}
		deps[next] = true
		queue = append(queue, s.requires[next]...)
	}
	s.closure[artifact] = deps
	return deps
}
