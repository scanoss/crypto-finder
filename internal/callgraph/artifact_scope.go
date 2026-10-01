// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "strings"

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

// compilesAgainst reports whether code of user's artifact can name used:
// the type user can extend, or call. Unknown artifacts allow it, which keeps
// a graph built without artifact information as it was.
func (s *artifactScope) compilesAgainst(user, used string) bool {
	if s == nil {
		return true
	}
	userArtifact, usedArtifact := s.typeArtifact[user], s.typeArtifact[used]
	switch {
	case userArtifact == "" || usedArtifact == "":
		return true
	case userArtifact == usedArtifact, userArtifact == projectArtifact:
		return true
	case usedArtifact == projectArtifact:
		return false
	}
	return s.dependsOn(userArtifact)[usedArtifact]
}

// related reports whether either type can be the other's subtype.
func (s *artifactScope) related(a, b string) bool {
	return s.compilesAgainst(a, b) || s.compilesAgainst(b, a)
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

// artifactNameFor names pkg's artifact as the ecosystem spells it. Python
// distribution names compare in PEP 503 form.
func artifactNameFor(ecosystem string, pkg PackageDir) string {
	name := artifactOf(pkg)
	if ecosystem == ecosystemPython && name != projectArtifact {
		return normalizePythonDistribution(name)
	}
	return name
}

// newArtifactScopeFor builds the scope of a scan from its resolved dependency
// graph, normalizing Python names on the graph's side the way artifactNameFor
// does on the packages' side.
func newArtifactScopeFor(ecosystem string, requires map[string][]string) *artifactScope {
	if ecosystem == ecosystemPython {
		requires = normalizePythonRequires(requires)
	}
	return newArtifactScope(requires)
}

// normalizePythonDistribution returns name in its PEP 503 normalized form:
// lowercase, with each run of "-", "_" and "." collapsed to one "-". pip names
// a distribution by its metadata name (Foo_Bar) and lists its requirements
// as the raw strings other packages wrote (foo-bar), so the two sides of the
// dependency graph only compare equal after this.
func normalizePythonDistribution(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	separator := false
	for _, r := range strings.ToLower(name) {
		if r == '-' || r == '_' || r == '.' {
			separator = true
			continue
		}
		if separator {
			b.WriteByte('-')
			separator = false
		}
		b.WriteRune(r)
	}
	if separator {
		b.WriteByte('-')
	}
	return b.String()
}

// normalizePythonRequires returns requires with every key and dependency in
// PEP 503 form. A nil graph stays nil.
func normalizePythonRequires(requires map[string][]string) map[string][]string {
	if requires == nil {
		return nil
	}
	out := make(map[string][]string, len(requires))
	for name, deps := range requires {
		key := normalizePythonDistribution(name)
		normalized := out[key]
		for _, dep := range deps {
			normalized = append(normalized, normalizePythonDistribution(dep))
		}
		out[key] = normalized
	}
	return out
}
