// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"slices"
	"strings"

	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/engine"
	scanutil "github.com/scanoss/crypto-finder/internal/scan"
)

// Skip reasons of the dependency phase that are not about a manifest. The
// manifest ones live in the dependency package.
const (
	depSkipEcosystemUnknown     = "ecosystem_unknown"
	depSkipResolverUnavailable  = "resolver_unavailable"
	depSkipParserUnavailable    = "parser_unavailable"
	depSkipCallgraphUnavailable = "callgraph_unavailable"
	depSkipNotRequested         = "not_requested"

	// progressStatusCompleted is the status of a phase that finished.
	progressStatusCompleted = "completed"
)

// dependencyEcosystemSkip names an ecosystem the dependency phase saw in the
// target but did not resolve, and why. Reason is a dependency-phase skip
// reason.
type dependencyEcosystemSkip struct {
	Ecosystem string `json:"ecosystem"`
	Reason    string `json:"reason"`
}

// autoDependencyEcosystems is what --dep-ecosystem auto found in a target.
type autoDependencyEcosystems struct {
	// resolvable lists, in candidate order, the ecosystems whose resolver has
	// something to read at or below the target.
	resolvable []string
	// skipped lists every other candidate, in candidate order, with the
	// reason it is not resolved.
	skipped []dependencyEcosystemSkip
	// fallback is the ecosystem auto mode picked before it checked which
	// ecosystems can be resolved: the dominant language, else the first
	// manifest. It is used, with the skip that follows from it, when no
	// candidate is resolvable.
	fallback string
	// manifests lists the ecosystems a manifest at the target names
	// (scan.DetectEcosystems).
	manifests []string
}

// reportedSkips is the part of skipped a completed dependencies event
// reports in ecosystems_skipped: the ecosystems the target carries something
// for that the phase left unresolved. A candidate that only a language hint
// named, with nothing its resolver could read (manifest_absent) or no
// resolver at all (resolver_unavailable, C and C++), is not a gap in the
// dependency coverage: there were no dependencies to resolve. Reporting it
// read, to a consumer, as if the Node dependencies of a Flask application
// with some browser JavaScript and no package.json had gone unchecked. The
// same reasons are reported when a manifest for the ecosystem sits at the
// target, such as a requirements.txt with no Python interpreter to read.
func (a autoDependencyEcosystems) reportedSkips() []dependencyEcosystemSkip {
	out := make([]dependencyEcosystemSkip, 0, len(a.skipped))
	for _, skip := range a.skipped {
		nothingToResolve := skip.Reason == dependency.SkipReasonManifestAbsent || skip.Reason == depSkipResolverUnavailable
		if nothingToResolve && !slices.Contains(a.manifests, skip.Ecosystem) {
			continue
		}
		out = append(out, skip)
	}
	return out
}

// primary is the ecosystem the dependency phase resolves first: the first
// resolvable candidate, else the fallback.
func (a autoDependencyEcosystems) primary() string {
	if len(a.resolvable) > 0 {
		return a.resolvable[0]
	}
	return a.fallback
}

// secondary lists the resolvable ecosystems after the primary one. Auto mode
// resolves them too, each beside the primary.
func (a autoDependencyEcosystems) secondary() []string {
	if len(a.resolvable) < 2 {
		return nil
	}
	return a.resolvable[1:]
}

// dependencyEcosystemOutcome is what a completed dependency phase resolved:
// one result per ecosystem, the primary first, and the ecosystems it saw but
// did not resolve.
type dependencyEcosystemOutcome struct {
	resolved []*engine.DepScanResult
	skipped  []dependencyEcosystemSkip
}

// primaryWithAdditional returns the primary result, the first resolved
// ecosystem, carrying every other resolved ecosystem that built a call graph
// in AdditionalEcosystems, so each of their findings resolves against the
// dependency-aware graph of its own language. Each ecosystem scanned on top
// of the report the one before it returned, so the last report holds the
// findings of all of them; every result names it.
//
// An ecosystem that resolved no dependencies builds no call graph and is left
// out: the source-only graph an export builds for an additional ecosystem
// covers its findings, as it did before.
func (o dependencyEcosystemOutcome) primaryWithAdditional() *engine.DepScanResult {
	final := o.resolved[len(o.resolved)-1].Report
	primary := o.resolved[0]
	for _, result := range o.resolved {
		result.Report = final
		if result != primary && result.CallGraph != nil {
			primary.AdditionalEcosystems = append(primary.AdditionalEcosystems, result)
		}
	}
	return primary
}

// progressDetails is the details object of the completed dependencies event:
// the counters and outcome lists summed over every resolved ecosystem, the
// resolved ecosystems, primary first, and the skipped ones sorted by
// ecosystem. ecosystems_skipped is always present, empty when none was.
func (o dependencyEcosystemOutcome) progressDetails() map[string]any {
	details := engine.AggregateProgressDetails(o.resolved)
	ecosystems := make([]string, 0, len(o.resolved))
	for _, result := range o.resolved {
		ecosystems = append(ecosystems, result.Ecosystem)
	}
	skipped := append([]dependencyEcosystemSkip{}, o.skipped...)
	slices.SortStableFunc(skipped, func(a, b dependencyEcosystemSkip) int {
		return strings.Compare(a.Ecosystem, b.Ecosystem)
	})
	details["ecosystems"] = ecosystems
	details["ecosystems_skipped"] = skipped
	return details
}

// planAutoDependencyEcosystems orders the ecosystems a target may resolve
// dependencies for and keeps those its resolver can read.
//
// The candidates are the ecosystems of the language hints, in hint order
// (dominant language first), then every other ecosystem a manifest at the
// target names, in scan.DetectEcosystems' precedence. A candidate is
// resolvable when the registry has a resolver for it, and the resolver can
// read the target or a module root below it. The dominant language alone no
// longer decides: a Flask application whose browser JavaScript outnumbers its
// Python files, with a requirements.txt and no package.json, resolves Python.
//
// Python is the one resolver that needs no manifest, since it reads the
// installed packages of an interpreter, which is found on PATH on most hosts.
// It is therefore resolvable only with a Python manifest at the target, or
// when it is the fallback, which it would have resolved before.
//
// explicitLanguages says languageHints came from --languages rather than
// detection. The user then chose the languages to scan, so a manifest only
// adds candidates for those languages' ecosystems: --languages java on a root
// that also carries a package.json and a requirements.txt resolves Java alone,
// as it did before auto mode looked at manifests.
func planAutoDependencyEcosystems(target string, languageHints []string, explicitLanguages bool, registry *dependency.Registry, skipPatterns []string) autoDependencyEcosystems {
	fallback := ecosystemFromHints(target, languageHints)
	if fallback == "" {
		fallback = scanutil.DetectEcosystem(target)
	}
	manifests := scanutil.DetectEcosystems(target)
	plan := autoDependencyEcosystems{fallback: fallback, manifests: manifests}
	candidateManifests := manifests
	if explicitLanguages {
		candidateManifests = manifestsForLanguages(target, languageHints, manifests)
	}
	for _, ecosystem := range dependencyEcosystemCandidates(target, languageHints, candidateManifests, fallback) {
		reason := dependencyEcosystemSkipReason(target, ecosystem, registry, skipPatterns)
		if reason == "" && ecosystem == ecosystemPython && ecosystem != fallback && !slices.Contains(manifests, ecosystemPython) {
			reason = dependency.SkipReasonManifestAbsent
		}
		if reason != "" {
			plan.skipped = append(plan.skipped, dependencyEcosystemSkip{Ecosystem: ecosystem, Reason: reason})
			continue
		}
		plan.resolvable = append(plan.resolvable, ecosystem)
	}
	return plan
}

// manifestsForLanguages keeps the manifest ecosystems that one of the
// explicitly requested languages maps to.
func manifestsForLanguages(target string, languages, manifests []string) []string {
	var out []string
	for _, ecosystem := range manifests {
		for _, language := range languages {
			if ecosystemFromHint(target, language) == ecosystem {
				out = append(out, ecosystem)
				break
			}
		}
	}
	return out
}

// dependencyEcosystemCandidates lists, without repeats, the ecosystems of the
// language hints in hint order, then the manifest ecosystems, then the
// fallback when neither named it.
func dependencyEcosystemCandidates(target string, languageHints, manifests []string, fallback string) []string {
	var out []string
	add := func(ecosystem string) {
		if ecosystem != "" && !slices.Contains(out, ecosystem) {
			out = append(out, ecosystem)
		}
	}
	for _, hint := range languageHints {
		// ecosystemFromHint walks the target for a C++ header on a "c" hint.
		// Neither C nor C++ has a resolver, so the fallback's answer stands
		// in rather than walking the tree once per hint.
		if hint == "c" && fallback == ecosystemCPP {
			add(ecosystemCPP)
			continue
		}
		if hint == "c" {
			add("c")
			continue
		}
		add(ecosystemFromHint(target, hint))
	}
	for _, ecosystem := range manifests {
		add(ecosystem)
	}
	add(fallback)
	return out
}

// dependencyEcosystemSkipReason is why the dependency phase cannot resolve
// ecosystem for target, or "" when it can. It is the same test, and the same
// reason, the phase applies to the ecosystem it picked.
func dependencyEcosystemSkipReason(target, ecosystem string, registry *dependency.Registry, skipPatterns []string) string {
	resolver, err := registry.Get(ecosystem)
	if err != nil {
		return depSkipResolverUnavailable
	}
	if !dependencyEcosystemResolvable(resolver, target, ecosystem, skipPatterns) {
		return dependency.UnresolvableSkipReason(target, ecosystem)
	}
	return ""
}

// dependencyEcosystemResolvable reports whether resolver can read target, or
// a module root discovered below it.
//
// Gated on target rather than targetDir because the dependency scanner hands
// the resolver opts.ScanOptions.Target. Gating on the containing directory
// lets a file target pass and then abort inside the resolver.
//
// A target the resolver cannot read is not necessarily a target with nothing
// to resolve. A monorepo carries its manifests in the module directories below
// the root, and the dependency scanner resolves each of those.
func dependencyEcosystemResolvable(resolver dependency.Resolver, target, ecosystem string, skipPatterns []string) bool {
	return resolver.CanResolve(target) || len(dependency.ResolutionRoots(target, ecosystem, skipPatterns).Roots) > 0
}

// dependencySkipDetails is the details object of a skipped dependencies
// event: the reason, and the ecosystem the reason is about when one was
// picked.
func dependencySkipDetails(reason, ecosystem string) map[string]any {
	details := map[string]any{"reason": reason}
	if ecosystem != "" && reason != depSkipEcosystemUnknown && reason != depSkipNotRequested {
		details["ecosystem"] = ecosystem
	}
	return details
}
