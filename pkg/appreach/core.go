// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"context"

	packageurl "github.com/package-url/packageurl-go"
	core "github.com/scanoss/reach/appreach"
)

// The application-reachability core lives in reach
// (github.com/scanoss/reach/appreach): closure parsing, the dependency-graph
// splice, the stitch policy and the verdicts. This package keeps its names,
// so its callers compile unchanged, and adds what is crypto-finder's own: the
// request and response, findings, conditioned rules and PQC.

type (
	// Dependency is one member of the project's pinned dependency closure.
	Dependency = core.Dependency
	// Limits bounds one project request.
	Limits = core.Limits
	// Pins is the request's dependency closure, keyed by canonical
	// versionless purl, in request order.
	Pins = core.Pins
	// RunError is a failed run: the stage that failed (stitch, hydrate or
	// render) and its error. A canceled or expired ctx fails as the stitch
	// stage with ctx's error.
	RunError = core.RunError
)

// DefaultLimits are the limits the API starts with.
var DefaultLimits = core.DefaultLimits

// Root is the stitch root standing for the client's project.
var Root = core.Root

// Reachability verdicts.
const (
	VerdictReachable   = core.VerdictReachable
	VerdictUnreachable = core.VerdictUnreachable
	VerdictUnknown     = core.VerdictUnknown
)

// Reasons an unknown verdict carries (reachability_reason).
const (
	// ReasonAmbiguousDispatch: the project reaches the finding only through an
	// interface call with several implementations in the closure.
	ReasonAmbiguousDispatch = core.ReasonAmbiguousDispatch
	// ReasonUnresolvedDispatch: only through a call linked by name.
	ReasonUnresolvedDispatch = core.ReasonUnresolvedDispatch
	// ReasonSearchCapped: the route search hit a cap before it could decide.
	ReasonSearchCapped = core.ReasonSearchCapped
	// ReasonNoContainingFunction: the finding sits outside any function (a
	// field or static initializer), so no call can reach it.
	ReasonNoContainingFunction = core.ReasonNoContainingFunction
	// ReasonDependencyEntryPointOnly: the project reaches a function that the
	// dependency's mine-time entry-point index says reaches the finding, but
	// the stitch holds no route of calls to it.
	ReasonDependencyEntryPointOnly = core.ReasonDependencyEntryPointOnly
	// ReasonDependencyWithoutGraph: every dependency path from the project to
	// the finding's dependency crosses a dependency with no graph, whose
	// calls are therefore not in the graph.
	ReasonDependencyWithoutGraph = core.ReasonDependencyWithoutGraph
	// ReasonNotAnnotated: the dependency's stored findings report holds the
	// finding but its crypto annotation does not, so the stitch never saw it.
	ReasonNotAnnotated = "finding_not_annotated"
	// ReasonUnpinned: the client could not pin the dependency's version (a
	// range, no lock). It never reaches the API, which needs a version; the
	// client reports the dependency without findings under this reason.
	ReasonUnpinned = "unpinned"
)

// ErrInvalidPurl is returned for a purl that does not parse, names no package, or misses a
// namespace its ecosystem requires.
var ErrInvalidPurl = core.ErrInvalidPurl

// ParsePurl validates and canonicalizes a PURL. Its String() is the form the
// miners store components under.
func ParsePurl(s string) (packageurl.PackageURL, error) { return core.ParsePurl(s) }

// PurlToModule converts a purl to crypto-finder's module id (see
// core.PurlToModule).
func PurlToModule(purl string) string { return core.PurlToModule(purl) }

// EcosystemForPurl is crypto-finder's ecosystem name for a purl's type.
func EcosystemForPurl(purl string) string { return core.EcosystemForPurl(purl) }

// PyPIVersion is version in its PEP 440 normal form (1.0.0-RC1 -> 1.0.0rc1,
// v2.0.post -> 2.0.post0, 01.02 -> 1.2). A version PEP 440 cannot parse (a
// legacy release) is returned trimmed, as written.
func PyPIVersion(version string) string { return core.PyPIVersion(version) }

// PyPIVersionsEqual reports whether two versions name one release under PEP
// 440's comparison, where the release's trailing zeros do not count (1.0 ==
// 1.0.0). Versions PEP 440 cannot parse are equal only as written.
func PyPIVersionsEqual(a, b string) bool { return core.PyPIVersionsEqual(a, b) }

// DepPrefixedPath is a dependency file's path as the stitch names it:
// module@version/path.
func DepPrefixedPath(filePath, module, version string) string {
	return core.DepPrefixedPath(filePath, module, version)
}

// ComputeFindingID is the finding id the stitch gives a crypto operation
// (graphfrag's own, which is unexported).
func ComputeFindingID(path string, startLine int, ruleID string) string {
	return core.ComputeFindingID(path, startLine, ruleID)
}

// StitchWithContext runs the stitch on its own goroutine so ctx's deadline
// can abort a pathologically large graph walk.
func StitchWithContext(ctx context.Context, root ComponentKey, deps DependencyGraph, fragments map[ComponentKey]Fragment, opts StitchOptions) (*Result, error) {
	return core.StitchWithContext(ctx, root, deps, fragments, opts)
}

// IsProducerGraph reports whether raw is a structural graph-fragment document
// rather than another stored graph form.
func IsProducerGraph(raw []byte) bool { return core.IsProducerGraph(raw) }

// DecodeProducerGraph turns a structural graph-fragment document into the
// structural half of a Fragment, as gf.DecodeFragment decodes it, so it
// carries the entry kinds and supertypes.
func DecodeProducerGraph(k ComponentKey, raw []byte) (*Fragment, error) {
	return core.DecodeProducerGraph(k, raw)
}
