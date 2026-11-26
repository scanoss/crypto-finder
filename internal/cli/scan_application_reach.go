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

package cli

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scanoss/reach/javaruntime"
	"github.com/scanoss/reach/perf"
	"github.com/scanoss/reach/skip"

	api "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/config"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/rules"
	scanutil "github.com/scanoss/crypto-finder/internal/scan"
	"github.com/scanoss/crypto-finder/internal/scanner/cards"
	"github.com/scanoss/crypto-finder/internal/utils"
)

const (
	// applicationReachabilityTimeout bounds the one request: the API stitches the
	// whole closure for it.
	applicationReachabilityTimeout = 10 * time.Minute
	// depSkipEcosystemNotSupported: the target declares dependencies only in
	// an ecosystem this version does not resolve (any but Java, Python, Go,
	// JavaScript/TypeScript, Rust, Ruby and C#).
	depSkipEcosystemNotSupported = "ecosystem_not_supported"
)

var scanApplicationReachabilityMaxChains int

func init() {
	scanCmd.Flags().IntVar(&scanApplicationReachabilityMaxChains, "dependency-reachability-max-chains", 1,
		"With --scan-dependencies: call chains per dependency finding the SCANOSS API returns for --export-callgraph (0: none)")
}

// applicationReachabilityPlan is a dependency scan's resolved closure. Its
// compiled JARs type the project's one call graph, so the plan is made
// before detection builds it.
type applicationReachabilityPlan struct {
	closure *engine.ApplicationClosure
	graphs  *graphStore
	// resolver is the Java resolver; nil for a Python closure.
	resolver *dependency.JavaResolver
}

// dependencySkip says why a dependency scan resolves nothing: the progress
// skip reason and the ecosystem it is about.
type dependencySkip struct {
	reason, ecosystem string
}

// planApplicationReachability resolves the pinned dependency closure of the
// target in the scan's language: for Java its Maven or Gradle build, to
// compiled JARs added to the type-only JARs of the scan's graphs; for Python
// its lock, pinned requirements or installed environment (no JAR, no
// subprocess); for Go its go.mod; for JavaScript/TypeScript its lock file; for Rust its Cargo.lock through cargo metadata. A Java target without a Java build manifest is skipped,
// naming the other ecosystem it declares dependencies in, if any; a Python
// target without a Python manifest, lock or environment is skipped.
func planApplicationReachability(ctx context.Context, graphs *graphStore, target, language string, ensureJavaRuntime func() (javaruntime.Config, error), skipPatterns []string) (*applicationReachabilityPlan, dependencySkip, error) {
	if language == ecosystemPython {
		return planPythonReachability(ctx, graphs, target, skipPatterns)
	}
	if language == ecosystemGo {
		return planGoReachability(ctx, graphs, target, skipPatterns)
	}
	if language == ecosystemNode {
		return planNodeReachability(ctx, graphs, target, skipPatterns)
	}
	if language == ecosystemRust {
		return planRustReachability(ctx, graphs, target, skipPatterns)
	}
	if language == ecosystemRuby {
		return planRubyReachability(ctx, graphs, target, skipPatterns)
	}
	if language == ecosystemCSharp {
		return planCSharpReachability(ctx, graphs, target, skipPatterns)
	}
	if language != ecosystemJava {
		// A scanned ecosystem this version resolves no dependencies of.
		log.Warn().Str("ecosystem", language).
			Msg("Dependency scanning does not support the " + language + " ecosystem in this version; its dependencies are not scanned")
		return nil, dependencySkip{reason: depSkipEcosystemNotSupported, ecosystem: language}, nil
	}
	resolver := dependency.NewJavaResolver()
	if !resolver.CanResolve(target) && len(dependency.ResolutionRoots(target, ecosystemJava, skipPatterns).Roots) == 0 {
		for _, ecosystem := range scanutil.DetectEcosystems(target) {
			if ecosystem != ecosystemJava {
				log.Warn().Str("ecosystem", ecosystem).
					Msg("Dependency scanning of a Java target supports Java (Maven, Gradle) only in this version; the " + ecosystem + " dependencies are not scanned")
				return nil, dependencySkip{reason: depSkipEcosystemNotSupported, ecosystem: ecosystem}, nil
			}
		}
		log.Warn().Str("target", target).Msg("No Java build manifest at or below the scan target, skipping the dependency scan")
		return nil, dependencySkip{reason: dependency.SkipReasonManifestAbsent, ecosystem: ecosystemJava}, nil
	}
	javaRuntime, err := ensureJavaRuntime()
	if err != nil {
		return nil, dependencySkip{}, err
	}
	resolver.SetJavaRuntime(javaRuntime)
	resolver.SetCompiledArtifactsOnly(true)
	span := perf.Start("dependencies.resolve")
	closure, err := engine.ResolveApplicationClosure(ctx, resolver, target, skipPatterns)
	span.End()
	if err != nil {
		return nil, dependencySkip{}, failure.WrapUnknown(err, failure.CodeDependencyResolutionFailed, failure.StageDependency, "dependency resolution failed")
	}
	jars := closure.CompiledArtifacts()
	log.Info().
		Int("dependencies", len(closure.Resolved.Dependencies)).
		Int("compiled_jars", len(jars)).
		Msg("Resolved the pinned dependency closure for application reachability")
	graphs.addTypeJARs(jars)
	return &applicationReachabilityPlan{closure: closure, graphs: graphs, resolver: resolver}, dependencySkip{}, nil
}

// planPythonReachability resolves a Python target's pinned closure with the
// Python resolver: the first of a lock (uv, poetry, Pipfile, pdm, pylock),
// fully pinned requirements, the installed environment (.venv, venv,
// VIRTUAL_ENV) and the declared requirements. Declared requirements without
// a pin have no closure: they are carried as unpinned.
func planPythonReachability(ctx context.Context, graphs *graphStore, target string, skipPatterns []string) (*applicationReachabilityPlan, dependencySkip, error) {
	resolver := dependency.NewPythonResolver()
	if !resolver.CanResolve(target) && len(dependency.ResolutionRoots(target, ecosystemPython, skipPatterns).Roots) == 0 {
		log.Warn().Str("target", target).Msg("No Python manifest, lock or environment at or below the scan target, skipping the dependency scan")
		return nil, dependencySkip{reason: dependency.SkipReasonManifestAbsent, ecosystem: ecosystemPython}, nil
	}
	span := perf.Start("dependencies.resolve")
	closure, err := engine.ResolveApplicationClosure(ctx, resolver, target, skipPatterns)
	span.End()
	if err != nil {
		return nil, dependencySkip{}, failure.WrapUnknown(err, failure.CodeDependencyResolutionFailed, failure.StageDependency, "dependency resolution failed")
	}
	log.Info().
		Str("source", closure.Resolved.Source).
		Int("dependencies", len(closure.Resolved.Dependencies)).
		Int("unpinned", len(closure.Resolved.Unpinned)).
		Msg("Resolved the pinned Python dependency closure for application reachability")
	return &applicationReachabilityPlan{closure: closure, graphs: graphs}, dependencySkip{}, nil
}

// planGoReachability resolves a Go target's pinned closure from its go.mod
// (files only: nothing is downloaded); a replacement by a directory outside
// the module is a local dependency (dependency.Dependency.Local).
func planGoReachability(ctx context.Context, graphs *graphStore, target string, skipPatterns []string) (*applicationReachabilityPlan, dependencySkip, error) {
	resolver := dependency.NewGoResolver()
	if !resolver.CanResolve(target) && len(dependency.ResolutionRoots(target, ecosystemGo, skipPatterns).Roots) == 0 {
		log.Warn().Str("target", target).Msg("No go.mod at or below the scan target, skipping the dependency scan")
		return nil, dependencySkip{reason: dependency.SkipReasonManifestAbsent, ecosystem: ecosystemGo}, nil
	}
	span := perf.Start("dependencies.resolve")
	closure, err := engine.ResolveApplicationClosure(ctx, resolver, target, skipPatterns)
	span.End()
	if err != nil {
		return nil, dependencySkip{}, failure.WrapUnknown(err, failure.CodeDependencyResolutionFailed, failure.StageDependency, "dependency resolution failed")
	}
	log.Info().
		Int("dependencies", len(closure.Resolved.Dependencies)).
		Int("unpinned", len(closure.Resolved.Unpinned)).
		Msg("Resolved the pinned Go dependency closure for application reachability")
	return &applicationReachabilityPlan{closure: closure, graphs: graphs}, dependencySkip{}, nil
}

// planNodeReachability resolves a JavaScript or TypeScript target's pinned
// closure from its lock file (package-lock.json, npm-shrinkwrap.json,
// yarn.lock or pnpm-lock.yaml; files only, nothing runs or downloads). A
// target with no lock file is skipped: package.json ranges are never
// resolved.
func planNodeReachability(ctx context.Context, graphs *graphStore, target string, skipPatterns []string) (*applicationReachabilityPlan, dependencySkip, error) {
	resolver := dependency.NewNpmResolver()
	if !resolver.CanResolve(target) && len(dependency.ResolutionRoots(target, ecosystemNode, skipPatterns).Roots) == 0 {
		log.Warn().Str("target", target).Msg("No npm, yarn or pnpm lock file at or below the scan target, skipping the dependency scan")
		return nil, dependencySkip{reason: dependency.SkipReasonManifestAbsent, ecosystem: ecosystemNode}, nil
	}
	span := perf.Start("dependencies.resolve")
	closure, err := engine.ResolveApplicationClosure(ctx, resolver, target, skipPatterns)
	span.End()
	if errors.Is(err, dependency.ErrUnsupportedNpmLock) {
		// An npm 6 lock skips the npm dependencies only: the scan's other
		// ecosystems keep theirs.
		log.Warn().Err(err).Msg("An npm lock file is lockfileVersion 1 (npm 6), which this version does not read; the npm dependencies are not scanned. Regenerate it with npm 7 or later")
		return nil, dependencySkip{reason: dependency.SkipReasonUnsupportedLockfile, ecosystem: ecosystemNode}, nil
	}
	if err != nil {
		return nil, dependencySkip{}, failure.WrapUnknown(err, failure.CodeDependencyResolutionFailed, failure.StageDependency, "dependency resolution failed")
	}
	log.Info().
		Str("source", closure.Resolved.Source).
		Int("dependencies", len(closure.Resolved.Dependencies)).
		Int("unpinned", len(closure.Resolved.Unpinned)).
		Msg("Resolved the pinned npm dependency closure for application reachability")
	return &applicationReachabilityPlan{closure: closure, graphs: graphs}, dependencySkip{}, nil
}

// planRustReachability resolves a Rust target's pinned production closure
// with `cargo metadata --locked` (Cargo.lock as it is: nothing is written or
// downloaded by this client). A target whose Cargo.lock is absent has no
// pinned closure and is skipped.
func planRustReachability(ctx context.Context, graphs *graphStore, target string, skipPatterns []string) (*applicationReachabilityPlan, dependencySkip, error) {
	resolver := dependency.NewCargoResolver()
	// An offline scan must not reach a registry: crates not already fetched fail it.
	resolver.SetOffline(scanOffline)
	if !resolver.CanResolve(target) && len(dependency.ResolutionRoots(target, ecosystemRust, skipPatterns).Roots) == 0 {
		log.Warn().Str("target", target).Msg("No Cargo.toml at or below the scan target, skipping the dependency scan")
		return nil, dependencySkip{reason: dependency.SkipReasonManifestAbsent, ecosystem: ecosystemRust}, nil
	}
	span := perf.Start("dependencies.resolve")
	closure, err := engine.ResolveApplicationClosure(ctx, resolver, target, skipPatterns)
	span.End()
	if errors.Is(err, dependency.ErrCargoLockMissing) {
		log.Warn().Err(err).Msg("A Rust project has no Cargo.lock, so its closure is not pinned; its dependencies are not scanned. Run cargo generate-lockfile and commit the lock")
		return nil, dependencySkip{reason: dependency.SkipReasonManifestAbsent, ecosystem: ecosystemRust}, nil
	}
	if err != nil {
		return nil, dependencySkip{}, failure.WrapUnknown(err, failure.CodeDependencyResolutionFailed, failure.StageDependency, "dependency resolution failed")
	}
	log.Info().
		Str("source", closure.Resolved.Source).
		Int("dependencies", len(closure.Resolved.Dependencies)).
		Int("unpinned", len(closure.Resolved.Unpinned)).
		Msg("Resolved the pinned Cargo dependency closure for application reachability")
	return &applicationReachabilityPlan{closure: closure, graphs: graphs}, dependencySkip{}, nil
}

// cardsLanguageOf is the cards scanner's language option for ecosystem. An
// ecosystem with no scanned cards language fails: it is never matched with
// another language's rules.
func cardsLanguageOf(ecosystem string) (string, error) {
	lang, ok := cards.ForEcosystem(ecosystem)
	if !ok || !lang.IsScanned() {
		return "", failure.New(
			failure.CodeLanguageNotSupported,
			failure.StageScan,
			fmt.Sprintf("the cards engine has no scanned language for the %q ecosystem", ecosystem),
			failure.WithDetail("languages", ecosystem),
		)
	}
	return lang.Name, nil
}

// planApplicationReachabilities resolves the closure of every scanned ecosystem
// that has something to resolve, in ecosystem order, so the first plan is
// the primary ecosystem's. With no plan it returns why the dependency scan
// resolves nothing: the first ecosystem's skip, unless that skip names
// another ecosystem the scan resolves itself.
func planApplicationReachabilities(ctx context.Context, graphs *graphStore, target string, ecosystems []string, ensureJavaRuntime func() (javaruntime.Config, error), skipPatterns []string) ([]*applicationReachabilityPlan, dependencySkip, error) {
	var plans []*applicationReachabilityPlan
	var skips []dependencySkip
	for _, ecosystem := range ecosystems {
		plan, planSkip, err := planApplicationReachability(ctx, graphs, target, ecosystem, ensureJavaRuntime, skipPatterns)
		if err != nil {
			return nil, dependencySkip{}, err
		}
		if plan != nil {
			plans = append(plans, plan)
			continue
		}
		skips = append(skips, planSkip)
	}
	if len(plans) > 0 {
		return plans, dependencySkip{}, nil
	}
	for _, skip := range skips {
		if skip.reason == depSkipEcosystemNotSupported && slices.Contains(ecosystems, skip.ecosystem) {
			continue
		}
		return nil, skip, nil
	}
	return nil, skips[0], nil
}

// runApplicationReachability is the dependency phase of a application reachability
// scan, one progress phase for every planned ecosystem. Per ecosystem: the
// project's graph (built once, by the detector or here), its call sites
// into the closure, one request to the API, and the API's dependency
// findings and verdicts merged into the report. Each further ecosystem runs
// on the report the previous one returned, so findings accumulate, and its
// result joins the first's AdditionalEcosystems, as auto mode on main
// resolves every ecosystem with a manifest (#902).
func runApplicationReachability(
	ctx context.Context,
	progress *scanutil.ProgressWriter,
	cfg *config.Config,
	plans []*applicationReachabilityPlan,
	target string,
	report *entities.InterimReport,
	javaRuntime javaruntime.Config,
	skipMatcher skip.SkipMatcher,
	rulesManager *rules.Manager,
) (*engine.DepScanResult, error) {
	if progress != nil {
		if err := progress.Start("dependencies", "scan"); err != nil {
			return nil, progressWriteFailure(err)
		}
	}
	var primary *engine.DepScanResult
	var details map[string]any
	var err error
	for _, plan := range plans {
		var result *engine.DepScanResult
		var planDetails map[string]any
		result, planDetails, err = applicationReachability(ctx, cfg, plan, target, report, javaRuntime, skipMatcher, rulesManager)
		if err != nil {
			break
		}
		report = result.Report
		details = mergeDependencyPhaseDetails(details, planDetails)
		if primary == nil {
			primary = result
			continue
		}
		primary.Report = report
		primary.AdditionalEcosystems = append(primary.AdditionalEcosystems, result)
	}
	if progress != nil {
		var progressErr error
		if err != nil {
			progressErr = progress.Fail("dependencies", "scan", nil)
		} else {
			progressErr = progress.Complete("dependencies", "scan", details)
		}
		if progressErr != nil && err == nil {
			return nil, progressWriteFailure(progressErr)
		}
	}
	if err != nil {
		return nil, err
	}
	return primary, nil
}

// mergeDependencyPhaseDetails folds one ecosystem's dependencies phase
// details into the phase's: ecosystems and skipped lists append, counters
// add up, and the reachability answer's info code and message are the
// first ecosystem's.
func mergeDependencyPhaseDetails(into, more map[string]any) map[string]any {
	if into == nil {
		return more
	}
	for key, value := range more {
		switch v := value.(type) {
		case int:
			if have, ok := into[key].(int); ok {
				into[key] = have + v
				continue
			}
			into[key] = v
		case []string:
			have := utils.AsOr[[]string](into[key])
			into[key] = append(have, v...)
		case []engine.DependencyWithout:
			have := utils.AsOr[[]engine.DependencyWithout](into[key])
			into[key] = append(have, v...)
		case []dependencyAnsweredOffline:
			have := utils.AsOr[[]dependencyAnsweredOffline](into[key])
			into[key] = append(have, v...)
		default:
			if _, ok := into[key]; !ok {
				into[key] = v
			}
		}
	}
	return into
}

// applicationReachabilityRequest builds the one request the API and --offline
// both answer, so both read the same call sites: the project's calls into its
// dependencies, without those made from the functions the project's own
// reachability reads unreachable. It also returns how many functions that
// left out.
func applicationReachabilityRequest(closure *engine.ApplicationClosure, project *engine.DepScanResult) (*api.ApplicationReachabilityRequest, int, error) {
	empty, err := prepareScanOIDProjection(&entities.InterimReport{}, false)
	if err != nil {
		return nil, 0, failure.WrapUnknown(err, failure.CodeUnknown, failure.StageScan, "prepare call sites")
	}
	fragment := scanutil.BuildGraphFragmentExport(project, empty)
	if named := scanutil.AddReceiverProducers(closure.Project(project), &fragment); named > 0 {
		log.Debug().Int("call_sites", named).Msg("Named, on call sites of the reachability request, the dependency function that produced the receiver")
	}
	span := perf.Start("dependencies.call_site_reachability")
	unreachable := scanutil.UnreachableCallers(closure.Project(project), &fragment)
	span.End()
	for _, key := range slices.Sorted(maps.Keys(unreachable)) {
		log.Debug().Str("function", key).Msg("No project entry point reaches this function; its calls into dependencies are left out of the reachability request")
	}
	request, err := closure.Request(&fragment, unreachable, scanApplicationReachabilityMaxChains)
	if err != nil {
		return nil, 0, failure.WrapUnknown(err, failure.CodeDependencyResolutionFailed, failure.StageDependency, "build the application reachability request")
	}
	return request, len(unreachable), nil
}

func applicationReachability(
	ctx context.Context,
	cfg *config.Config,
	plan *applicationReachabilityPlan,
	target string,
	report *entities.InterimReport,
	javaRuntime javaruntime.Config,
	skipMatcher skip.SkipMatcher,
	rulesManager *rules.Manager,
) (*engine.DepScanResult, map[string]any, error) {
	closure, graphs := plan.closure, plan.graphs
	if !scanOffline {
		for _, dep := range closure.Resolved.LocalAsUnpinned(closure.Target) {
			log.Warn().Str("dependency", dep.Module).Str("dir", dep.Dir).
				Msg("Local dependency: the SCANOSS API knows only published versions, so its findings are not reported; scan with --offline to analyze it from its directory")
		}
	}
	graphSpan := perf.Start("callgraph.project")
	project, err := buildStandaloneCallGraphResultForEcosystem(graphs, target, &entities.InterimReport{}, closure.Ecosystem, javaRuntime, scanIncludeTests, scanJavaCompiledArtifact, skipMatcher, true)
	graphSpan.End()
	if err != nil {
		return nil, nil, failure.WrapUnknown(err, failure.CodeCallGraphBuildFailed, failure.StageCallGraph, "failed to build the project call graph")
	}
	if len(closure.Resolved.Dependencies) == 0 {
		log.Info().Int("unpinned", len(closure.Resolved.Unpinned)).Msg("The project has no pinned dependencies; no application reachability request")
		project.Report = report
		project.RootModule = closure.Resolved.RootModule
		outcome := engine.ApplicationReachabilityOutcome{}
		engine.AddUnpinned(&outcome, closure)
		return project, dependencyPhaseDetails(closure.Ecosystem, outcome), nil
	}
	request, unreachable, err := applicationReachabilityRequest(closure, project)
	if err != nil {
		return nil, nil, err
	}
	if rulePaths, err := rulesManager.Load(); err == nil {
		request.ConditionedRules = engine.ConditionedRules(rulePaths, closure.Ecosystem)
	} else {
		log.Warn().Err(err).Msg("Rules unavailable; the API will not specialize dependency findings by the values other dependencies pass")
	}

	start := time.Now()
	var answer *api.ApplicationReachability
	var fallback *offlineFallbackReport
	if scanOffline {
		answer, err = offlineReachability(ctx, plan, request, rulesManager, javaRuntime, nil)
		if err != nil {
			return nil, nil, offlineReachabilityFailure(err)
		}
	} else {
		var local offlineAnswerer
		if !scanNoOfflineFallback {
			local = func(ctx context.Context, purls []string) (*api.ApplicationReachability, error) {
				defer limitOfflineMemory()()
				return offlineReachability(ctx, plan, request, rulesManager, javaRuntime, purls)
			}
		}
		answer, fallback, err = onlineReachability(ctx, newOnlineClient(cfg.GetAPIURL(), cfg.GetAPIKey(), cfg.GetAllowHTTP()), request, local)
		if err != nil {
			return nil, nil, err
		}
	}
	if answer.InfoCode != "READY" && len(answer.Dependencies) == 0 {
		return nil, nil, failure.New(failure.CodeDependencyResolutionFailed, failure.StageDependency,
			fmt.Sprintf("the SCANOSS API answered %s to the application reachability request: %s", answer.InfoCode, answer.InfoMessage),
			failure.WithDetail("info_code", answer.InfoCode))
	}

	mergeSpan := perf.Start("dependencies.merge")
	project.Report = report
	result, outcome := engine.MergeApplicationReachability(report, project, closure, answer)
	engine.AddUnpinned(&outcome, closure)
	markOfflineFallbackFailures(&outcome, fallback)
	mergeSpan.End()
	for _, without := range outcome.DependenciesWithout {
		if without.Reason == engine.DependencyWithoutUnpinned {
			log.Info().Str("dependency", without.Module).Str("specifier", without.Specifier).Msg("Unpinned dependency: no version to ask for, its findings are not reported")
			continue
		}
		log.Debug().Str("dependency", without.PURL+"@"+without.Version).Str("info_code", without.InfoCode).Msg("The API holds no reachability data for this dependency")
	}
	log.Info().
		Int("dependencies", len(request.Dependencies)).
		Int("call_site_functions", len(request.CallSites.Functions)).
		Int("external_calls", len(request.CallSites.ExternalCalls)).
		Int("unreachable_callers", unreachable).
		Int("conditioned_rules", len(request.ConditionedRules)).
		Int("request_bytes", answer.RequestBytes).
		Int("response_bytes", answer.ResponseBytes).
		Dur("duration", time.Since(start)).
		Str("info_code", answer.InfoCode).
		Int("dependencies_without_data", len(outcome.DependenciesWithout)).
		Int("findings", outcome.Findings).
		Int("reachable", outcome.Reachable).
		Int("unknown", outcome.Unknown).
		Int("unreachable", outcome.Unreachable).
		Msg("Application reachability")
	details := dependencyPhaseDetails(closure.Ecosystem, outcome)
	addOfflineFallbackDetails(details, fallback)
	details["request_bytes"] = answer.RequestBytes
	details["response_bytes"] = answer.ResponseBytes
	details["request_call_site_count"] = len(request.CallSites.ExternalCalls)
	details["request_function_count"] = len(request.CallSites.Functions)
	details["reachability_info_code"] = answer.InfoCode
	details["reachability_info_message"] = answer.InfoMessage
	return result, details, nil
}

// dependencyPhaseDetails is the details object of a completed dependencies
// progress event. A dependency counts as scanned when the API answered with
// its findings, and as skipped when it holds no data for it; the dep_findings
// counters split the findings by the API's verdict.
func dependencyPhaseDetails(ecosystem string, outcome engine.ApplicationReachabilityOutcome) map[string]any {
	without := outcome.DependenciesWithout
	if without == nil {
		without = []engine.DependencyWithout{}
	}
	return map[string]any{
		"ecosystems":               []string{ecosystem},
		"deps_scanned":             outcome.Dependencies - len(outcome.DependenciesWithout),
		"deps_skipped":             len(outcome.DependenciesWithout),
		"deps_skipped_list":        without,
		"deps_failed":              0,
		"deps_with_findings":       outcome.DependenciesWithFindings,
		"total_dep_findings":       outcome.Findings,
		"dep_findings_reachable":   outcome.Reachable,
		"dep_findings_unknown":     outcome.Unknown,
		"dep_findings_unreachable": outcome.Unreachable,
	}
}

// planRubyReachability resolves a Ruby target's pinned closure from its
// Gemfile.lock (files only: nothing is downloaded). A Gemfile alone states
// ranges rather than versions, so a project without a lock is skipped:
// mining the wrong version of a gem is worse than mining none.
func planRubyReachability(ctx context.Context, graphs *graphStore, target string, skipPatterns []string) (*applicationReachabilityPlan, dependencySkip, error) {
	resolver := dependency.NewRubyResolver()
	if !resolver.CanResolve(target) && len(dependency.ResolutionRoots(target, ecosystemRuby, skipPatterns).Roots) == 0 {
		log.Warn().Str("target", target).Msg("No Gemfile.lock at or below the scan target, skipping the dependency scan")
		return nil, dependencySkip{reason: dependency.SkipReasonManifestAbsent, ecosystem: ecosystemRuby}, nil
	}
	span := perf.Start("dependencies.resolve")
	closure, err := engine.ResolveApplicationClosure(ctx, resolver, target, skipPatterns)
	span.End()
	if err != nil {
		return nil, dependencySkip{}, failure.WrapUnknown(err, failure.CodeDependencyResolutionFailed, failure.StageDependency, "dependency resolution failed")
	}
	log.Info().
		Str("source", closure.Resolved.Source).
		Int("dependencies", len(closure.Resolved.Dependencies)).
		Msg("Resolved the pinned Ruby dependency closure for application reachability")
	return &applicationReachabilityPlan{closure: closure, graphs: graphs}, dependencySkip{}, nil
}

// planCSharpReachability resolves a .NET target's pinned closure from the
// files that carry a resolved version -- the NuGet lock file, the restore's
// asset file, a packages.config (files only: nothing is restored). A project
// file states a minimum rather than a version, so a target with none of those
// is skipped: mining the wrong version of a package is worse than mining none.
func planCSharpReachability(ctx context.Context, graphs *graphStore, target string, skipPatterns []string) (*applicationReachabilityPlan, dependencySkip, error) {
	resolver := dependency.NewCSharpResolver()
	if !resolver.CanResolve(target) && len(dependency.ResolutionRoots(target, ecosystemCSharp, skipPatterns).Roots) == 0 {
		log.Warn().Str("target", target).Msg("No packages.lock.json, project.assets.json or packages.config at or below the scan target, skipping the dependency scan")
		return nil, dependencySkip{reason: dependency.SkipReasonManifestAbsent, ecosystem: ecosystemCSharp}, nil
	}
	span := perf.Start("dependencies.resolve")
	closure, err := engine.ResolveApplicationClosure(ctx, resolver, target, skipPatterns)
	span.End()
	if err != nil {
		return nil, dependencySkip{}, failure.WrapUnknown(err, failure.CodeDependencyResolutionFailed, failure.StageDependency, "dependency resolution failed")
	}
	log.Info().
		Str("source", closure.Resolved.Source).
		Int("dependencies", len(closure.Resolved.Dependencies)).
		Msg("Resolved the pinned C# dependency closure for application reachability")
	return &applicationReachabilityPlan{closure: closure, graphs: graphs}, dependencySkip{}, nil
}

// offlineReachabilityFailure classifies a failed offline dependency phase.
// --timeout bounds the whole scan, offline mining included: a scan whose
// time runs out while it mines fails as a timeout as soon as it does, and the
// dependencies mined by then stay cached for the next run.
func offlineReachabilityFailure(err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return failure.Wrap(err, failure.CodeScannerTimeout, failure.StageDependency,
			fmt.Sprintf("the scan timed out after %s while preparing the dependencies offline; the dependencies mined so far are cached, so a run with a larger --timeout continues from them", scanTimeout),
			failure.WithRetryable(true), failure.WithDetail("timeout", scanTimeout))
	case errors.Is(err, context.Canceled):
		return failure.Wrap(err, failure.CodeScannerCancelled, failure.StageDependency, "the scan was canceled while preparing the dependencies offline")
	default:
		return failure.WrapUnknown(err, failure.CodeDependencyResolutionFailed, failure.StageDependency, "offline application reachability failed")
	}
}
