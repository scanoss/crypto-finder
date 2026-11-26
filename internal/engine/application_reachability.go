// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package engine

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/scanoss/reach/graphfrag"
	"github.com/scanoss/reach/purl"

	apiclient "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// Application reachability is the client side of the client-server split: the
// client resolves its project's pinned dependency closure to compiled
// artifacts, builds the project's one typed graph with those artifacts as
// type-only packages, and sends its call sites into the closure to the API in
// one request. The API, which holds every dependency version's mined graph and
// findings, answers which dependency findings the project reaches. No
// dependency source is fetched, scanned or parsed on the client.

// ApplicationClosure is a project's pinned dependency closure.
type ApplicationClosure struct {
	Ecosystem string
	Target    string
	Resolved  *dependency.ResolveResult
	// Paths holds each dependency's shortest route from the application,
	// keyed as DepScanResult.DependencyPaths is.
	Paths map[string]dependency.Path
}

// ResolveApplicationClosure resolves the project at target with resolver, which
// should be set to resolve compiled artifacts only (see
// dependency.CompiledArtifactsConfigurer), the way a dependency scan resolves
// its scan root: the module roots below target when target holds no manifest.
func ResolveApplicationClosure(ctx context.Context, resolver dependency.Resolver, target string, skipPatterns []string) (*ApplicationClosure, error) {
	resolved, dirs, err := resolveScanRoot(ctx, resolver, target, skipPatterns)
	if err != nil {
		return nil, err
	}
	ecosystem := resolver.Ecosystem()
	resolved.Dependencies = canonicalDependencies(resolved.Dependencies)
	// The server holds every dependency's graph, so no route is "without
	// source" from where the verdict is decided.
	parsed := make(map[string]bool, 2*len(resolved.Dependencies))
	for _, dep := range resolved.Dependencies {
		parsed[dep.Module] = true
		parsed[dependency.Ref{Module: dep.Module, Version: dep.Version}.Key()] = true
	}
	paths := dependency.ResolvedPaths(dependency.SharedGraphs(ctx, dirs, ecosystem), resolved, ecosystem, parsed)
	return &ApplicationClosure{Ecosystem: ecosystem, Target: target, Resolved: resolved, Paths: paths}, nil
}

// CompiledArtifacts lists the compiled artifact of every dependency that has
// one, in closure order: the type-only packages of the project's graph.
func (c *ApplicationClosure) CompiledArtifacts() []string {
	var out []string
	for _, dep := range c.Resolved.Dependencies {
		if dep.CompiledArtifactPath != "" && !slices.Contains(out, dep.CompiledArtifactPath) {
			out = append(out, dep.CompiledArtifactPath)
		}
	}
	return out
}

// Request builds the /reachability/application request: every pinned dependency
// with its direct flag and the dependencies it requires in the resolved tree,
// and the project's call sites into them, taken from project, the project's
// graph fragment, without those of the unreachable functions (see CallSites).
// maxChains bounds the call chains per finding the API returns; 0 asks for
// none.
func (c *ApplicationClosure) Request(project *graphfrag.GraphFragmentExport, unreachable map[string]bool, maxChains int) (*apiclient.ApplicationReachabilityRequest, error) {
	deps := c.requestDependencies()
	if len(deps) == 0 {
		return nil, fmt.Errorf("no dependency of the closure has a package URL")
	}
	request := &apiclient.ApplicationReachabilityRequest{
		SchemaVersion: apiclient.ApplicationReachabilitySchemaVersion,
		Dependencies:  deps,
		CallSites:     CallSites(project, unreachable),
	}
	if maxChains > 0 {
		request.IncludeCallChains = true
		request.MaxChainsPerFinding = maxChains
	}
	return request, nil
}

func (c *ApplicationClosure) requestDependencies() []apiclient.ApplicationDependency { //nolint:gocognit,gocyclo // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
	versions := make(map[string]string, len(c.Resolved.Dependencies))
	deps := make([]apiclient.ApplicationDependency, 0, len(c.Resolved.Dependencies))
	index := make(map[string]int, len(c.Resolved.Dependencies))
	for _, dep := range c.Resolved.Dependencies {
		p := purl.Dependency(c.Ecosystem, dep.Module, "")
		if p == "" || dep.Version == "" {
			log.Warn().Str("module", dep.Module).Str("version", dep.Version).Msg("Dependency has no package URL or version; left out of the reachability request")
			continue
		}
		if pinned, ok := versions[p]; ok {
			// The API takes one version per purl. A multi-module project
			// can resolve two; the first keeps its place.
			if pinned != dep.Version {
				log.Warn().Str("purl", p).Str("version", dep.Version).Str("kept", pinned).Msg("Dependency resolved at two versions; the reachability request pins the first")
			}
			continue
		}
		versions[p] = dep.Version
		index[p] = len(deps)
		deps = append(deps, apiclient.ApplicationDependency{Purl: p, Version: dep.Version, Markers: dep.Markers, Extras: dep.Extras})
	}
	anyPath := false
	for _, dep := range c.Resolved.Dependencies {
		p := purl.Dependency(c.Ecosystem, dep.Module, "")
		i, ok := index[p]
		if !ok || versions[p] != dep.Version {
			continue
		}
		if path, found := c.path(dep); found {
			anyPath = true
			deps[i].Direct = deps[i].Direct || len(path.Steps) == 1
		}
		key := dependency.Ref{Module: dep.Module, Version: dep.Version}.Key()
		for _, child := range slices.Concat(c.Resolved.VersionedGraph[key], c.Resolved.OmittedEdges[key]) {
			cp := purl.Dependency(c.Ecosystem, child.Module, "")
			if _, pinned := index[cp]; !pinned || cp == p || slices.Contains(deps[i].Requires, cp) {
				continue
			}
			deps[i].Requires = append(deps[i].Requires, cp)
		}
	}
	if !anyPath {
		// Without a resolved tree the client cannot tell which
		// dependencies the project declares; it declares them all, so the
		// API resolves the project's calls against every one of them.
		for i := range deps {
			deps[i].Direct = true
		}
	}
	return deps
}

func (c *ApplicationClosure) path(dep dependency.Dependency) (dependency.Path, bool) {
	if path, ok := c.Paths[dependency.Ref{Module: dep.Module, Version: dep.Version}.Key()]; ok && len(path.Steps) > 0 {
		return path, true
	}
	path, ok := c.Paths[dep.Module]
	return path, ok && len(path.Steps) > 0
}

// CallSites projects a project's graph fragment to what the API reads of it:
// the functions that call into a dependency, their external calls, and the
// supertypes of the project's types and its ServiceLoader registrations.
//
// The API takes every function it is sent as a root of the walk into the
// dependencies, so which functions are sent decides the verdicts. unreachable
// names, by function key (the key of the project's call graph, which is
// GraphFragmentFunction.Key and GraphFragmentExternal.CallerKey), the
// functions the project's own reachability reads unreachable: dead code. Their
// calls are left out, so a dependency called only from dead code is not
// reported as reachable. A nil set leaves nothing out.
func CallSites(project *graphfrag.GraphFragmentExport, unreachable map[string]bool) *graphfrag.GraphFragmentExport {
	if project == nil {
		return &graphfrag.GraphFragmentExport{SchemaVersion: graphfrag.SchemaVersion}
	}
	calls := project.ExternalCalls
	if len(unreachable) > 0 {
		calls = make([]graphfrag.GraphFragmentExternal, 0, len(project.ExternalCalls))
		for i := range project.ExternalCalls {
			if !unreachable[project.ExternalCalls[i].CallerKey] {
				calls = append(calls, project.ExternalCalls[i])
			}
		}
	}
	callers := make(map[string]bool, len(calls))
	for i := range calls {
		callers[calls[i].CallerKey] = true
	}
	out := &graphfrag.GraphFragmentExport{
		SchemaVersion: project.SchemaVersion,
		ScanMetadata: graphfrag.GraphFragmentScanMetadata{
			Ecosystem:        project.ScanMetadata.Ecosystem,
			RootModule:       project.ScanMetadata.RootModule,
			GraphAlgoVersion: project.ScanMetadata.GraphAlgoVersion,
			ExternalCalls:    len(calls),
		},
		ExternalCalls:    calls,
		Supertypes:       project.Supertypes,
		ServiceProviders: project.ServiceProviders,
	}
	for _, fn := range project.Functions {
		if callers[fn.Key] {
			out.Functions = append(out.Functions, fn)
		}
	}
	out.ScanMetadata.FunctionCount = len(out.Functions)
	return out
}

// ApplicationReachabilityOutcome counts what an answer added to the report.
type ApplicationReachabilityOutcome struct {
	// Dependencies is how many dependencies the answer covers, and
	// DependenciesWithFindings how many of them have a finding.
	Dependencies             int
	DependenciesWithFindings int
	// DependenciesWithout lists, in answer order, the dependencies the API
	// holds no reachability data for: their findings are missing.
	DependenciesWithout []DependencyWithout
	Findings            int
	Reachable           int
	Unknown             int
	Unreachable         int
}

// DependencyWithout names a dependency the API answered without data, and
// the API's info code for it, or a declared dependency the client could not
// pin (Reason DependencyWithoutUnpinned, with its specifier and marker as
// written).
type DependencyWithout struct {
	Module    string   `json:"module"`
	Version   string   `json:"version"`
	PURL      string   `json:"purl,omitempty"`
	Reason    string   `json:"reason"`
	InfoCode  string   `json:"error_code,omitempty"`
	Specifier string   `json:"specifier,omitempty"`
	Markers   []string `json:"markers,omitempty"`
	// OfflineFallback, for a dependency without data that the scan's
	// offline fallback could not answer either, says why.
	OfflineFallback string `json:"offline_fallback,omitempty"`
}

// Reasons of a DependencyWithout.
const (
	DependencyWithoutReachabilityData = "no_reachability_data"
	// DependencyWithoutUnpinned: a declared dependency with no pinned
	// version (a range, no lock). No request names it, so its findings are
	// unknown to the scan.
	DependencyWithoutUnpinned = dependency.ReasonUnpinned
	// DependencyWithoutOtherVersion: a version of a package the closure holds
	// at several; the request names the one the project loads, as it takes
	// one version per package URL.
	DependencyWithoutOtherVersion = "other_version_requested"
	// DependencyWithoutUnderOtherVersion: a package only a version listed
	// other_version_requested requires. No requested package leads to it,
	// so the request leaves it out rather than serve it as unreachable.
	DependencyWithoutUnderOtherVersion = "under_other_version"
)

// AddUnpinned lists the closure's unpinned declared dependencies among the
// dependencies without data, after those of the answer.
func AddUnpinned(outcome *ApplicationReachabilityOutcome, closure *ApplicationClosure) {
	for _, other := range closure.Resolved.OtherVersions {
		without := DependencyWithout{Module: other.Module, Version: other.Version, Reason: DependencyWithoutOtherVersion}
		if p := purl.Dependency(closure.Ecosystem, other.Module, ""); p != "" {
			without.PURL = p
		}
		outcome.DependenciesWithout = append(outcome.DependenciesWithout, without)
		outcome.Dependencies++
	}
	for _, under := range closure.Resolved.UnderOtherVersions {
		without := DependencyWithout{Module: under.Module, Version: under.Version, Reason: DependencyWithoutUnderOtherVersion}
		if p := purl.Dependency(closure.Ecosystem, under.Module, ""); p != "" {
			without.PURL = p
		}
		outcome.DependenciesWithout = append(outcome.DependenciesWithout, without)
		outcome.Dependencies++
	}
	for _, u := range closure.Resolved.Unpinned {
		without := DependencyWithout{Module: u.Module, Reason: DependencyWithoutUnpinned, Specifier: u.Specifier}
		if p := purl.Dependency(closure.Ecosystem, u.Module, ""); p != "" {
			without.PURL = p
		}
		if u.Marker != "" {
			without.Markers = []string{u.Marker}
		}
		outcome.DependenciesWithout = append(outcome.DependenciesWithout, without)
		outcome.Dependencies++
	}
}

// MergeApplicationReachability adds every dependency finding of answer to report,
// as a dependency scan reports them (source dependency, dependency_info, file
// paths relative to the dependency), each asset carrying the API's verdict in
// Served. It assigns finding ids and returns the result the callgraph export
// reads: project's graph with the closure's dependencies and paths.
func MergeApplicationReachability(report *entities.InterimReport, project *DepScanResult, closure *ApplicationClosure, answer *apiclient.ApplicationReachability) (*DepScanResult, ApplicationReachabilityOutcome) { //nolint:gocognit // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
	outcome := ApplicationReachabilityOutcome{Dependencies: len(answer.Dependencies)}
	merged := &entities.InterimReport{
		Version:  report.Version,
		Tool:     report.Tool,
		Rules:    report.Rules,
		Findings: append(make([]entities.Finding, 0, len(report.Findings)), report.Findings...),
	}
	enrichDirectFindingPURLs(merged, closure.Target, closure.Resolved, closure.Ecosystem)
	environment := pythonEnvironment(closure)
	for i := range answer.Dependencies {
		dep := &answer.Dependencies[i]
		if dep.InfoCode != "READY" {
			outcome.DependenciesWithout = append(outcome.DependenciesWithout, DependencyWithout{
				Module:   dependencyInfoOf(closure.Ecosystem, dep.Purl, dep.Version).Module,
				Version:  dep.Version,
				PURL:     dep.Purl,
				Reason:   DependencyWithoutReachabilityData,
				InfoCode: dep.InfoCode,
			})
		}
		withFindings := false
		for _, file := range dep.Findings {
			finding := entities.Finding{Language: file.Language}
			info := file.DependencyInfo
			if info == nil {
				info = dependencyInfoOf(closure.Ecosystem, dep.Purl, dep.Version)
			}
			if env, ok := environment[dep.Purl]; ok && (len(env.Markers) > 0 || len(env.Extras) > 0) {
				withEnv := *info
				withEnv.Markers, withEnv.Extras = env.Markers, env.Extras
				info = &withEnv
			}
			finding.FilePath = strings.TrimPrefix(file.FilePath, info.Module+"@"+info.Version+"/")
			info = packageNamed(closure.Ecosystem, dep.Purl, info)
			for _, served := range file.CryptographicAssets {
				asset := served.Asset
				asset.FindingID = ""
				assetInfo := asset.DependencyInfo
				if assetInfo == nil {
					assetInfo = info
				}
				attributeDependencyAsset(&asset, packageNamed(closure.Ecosystem, dep.Purl, assetInfo))
				asset.Served = &entities.ServedReachability{
					Reachability: served.Reachability,
					Reason:       served.ReachabilityReason,
					CallChains:   served.CallChains,
					Analysis:     served.Analysis,
				}
				switch served.Reachability {
				case graphfrag.ReachabilityReachable:
					outcome.Reachable++
				case graphfrag.ReachabilityUnknown:
					outcome.Unknown++
				default:
					outcome.Unreachable++
				}
				outcome.Findings++
				finding.CryptographicAssets = append(finding.CryptographicAssets, asset)
			}
			if len(finding.CryptographicAssets) > 0 {
				merged.Findings = append(merged.Findings, finding)
				withFindings = true
			}
		}
		if withFindings {
			outcome.DependenciesWithFindings++
		}
	}
	EnsureFindingSources(merged)
	AssignFindingIDs(merged)

	result := closure.Project(project)
	result.Report = merged
	return result, outcome
}

// Project is project, the result holding the project's own graph, named as
// the scan's result is: with the closure's ecosystem, dependencies and paths.
// The call graph export classifies the project's findings against this
// result, and the reachability of the project's call sites is read from it
// too, so both see the same user packages.
func (c *ApplicationClosure) Project(project *DepScanResult) *DepScanResult {
	result := *project
	result.Ecosystem = c.Ecosystem
	// The module the resolver names, as a dependency scan's result and a
	// project without dependencies name it; occurrence keys of first-party
	// findings hash it.
	result.RootModule = c.Resolved.RootModule
	result.Dependencies = slices.Clone(c.Resolved.Dependencies)
	result.DependencyPaths = c.Paths
	return &result
}

// pythonEnvironment maps each Python dependency of the closure that the
// lock installs only under some environment markers, or with extras, to its
// dependency (by versionless purl), so its findings name them. Nil for
// another ecosystem.
func pythonEnvironment(closure *ApplicationClosure) map[string]dependency.Dependency {
	if closure.Ecosystem != ecosystemPython {
		return nil
	}
	out := make(map[string]dependency.Dependency)
	for _, dep := range closure.Resolved.Dependencies {
		if len(dep.Markers) == 0 && len(dep.Extras) == 0 {
			continue
		}
		if p := purl.Dependency(closure.Ecosystem, dep.Module, ""); p != "" {
			if _, seen := out[p]; !seen {
				out[p] = dep
			}
		}
	}
	return out
}

// packageNamed returns info with its module set to the package name the
// dependency's purl carries. A Rust crate's graph names it by its library name
// (acme_sign), which source paths need for stitching, but a report names a
// dependency the same way its purl does (acme-sign). Only the report's module
// changes; info is returned as it is when it already agrees or names another
// package.
func packageNamed(ecosystem, versionless string, info *entities.DependencyInfo) *entities.DependencyInfo {
	if ecosystem != ecosystemRust || info == nil {
		return info
	}
	named := dependencyInfoOf(ecosystem, versionless, info.Version)
	if named.Module == info.Module || named.Module == "" || !strings.HasPrefix(info.PURL, versionless+"@") {
		return info
	}
	renamed := *info
	renamed.Module = named.Module
	return &renamed
}

// dependencyInfoOf is the dependency_info of a finding the API served without
// one.
func dependencyInfoOf(ecosystem, versionless, version string) *entities.DependencyInfo {
	module := versionless
	switch ecosystem {
	case "java":
		if _, rest, ok := strings.Cut(versionless, "pkg:maven/"); ok {
			module = strings.Replace(rest, "/", ":", 1)
		}
	case "python":
		if rest, ok := strings.CutPrefix(versionless, "pkg:pypi/"); ok && rest != "" {
			module = rest
		}
	case "go":
		if rest, ok := strings.CutPrefix(versionless, "pkg:golang/"); ok && rest != "" {
			module = rest
		}
	case "rust":
		if rest, ok := strings.CutPrefix(versionless, "pkg:cargo/"); ok && rest != "" {
			module = rest
		}
	case "node":
		if rest, ok := strings.CutPrefix(versionless, "pkg:npm/"); ok && rest != "" {
			module = strings.Replace(rest, "%40", "@", 1)
		}
	}
	return &entities.DependencyInfo{Module: module, Version: version, PURL: versionless + "@" + version}
}
