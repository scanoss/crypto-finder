package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/skip"
	"github.com/scanoss/crypto-finder/internal/utils"
	"github.com/scanoss/crypto-finder/internal/version"
	"github.com/scanoss/crypto-finder/pkg/purl"
)

// maxWorkers caps the number of concurrent dependency scans to avoid
// overwhelming the system with too many opengrep processes.
const maxWorkers = 8

const npmEcosystem = "node"

// dependencyRuleTimeoutSeconds replaces OpenGrep's 5 s limit per rule and
// file, which also bounds parsing the file. Parsing a 750 KB bundle takes 2
// to 3 s on an idle host and took 7 times as long with 8 scans
// oversubscribing 32 threads, so the default dropped the whole file.
const dependencyRuleTimeoutSeconds = 30

const (
	findingSourceDependency = "dependency"
	findingSourceDirect     = "direct"
)

// DepScanOptions configures the dependency scanning behavior.
type DepScanOptions struct {
	// ScanOptions are the base scan options to reuse for each dependency scan.
	ScanOptions ScanOptions
	// Workers is the number of concurrent dependency scans (0 = default to NumCPU/2, capped at 8).
	Workers int
}

// DependencyScanner coordinates dependency resolution, scanning, call graph
// construction, and finding attribution.
type DependencyScanner struct {
	orchestrator   *Orchestrator
	resolver       dependency.Resolver
	cgBuilder      *callgraph.Builder
	findingsCache  FindingsCache
	findingsSource DependencyFindingsSource
}

// NewDependencyScanner creates a new dependency scanner.
// The optional findingsCache, if non-nil, is used to skip rescanning dependencies
// whose results are cached for the same package, rules and initialized scanner configuration.
func NewDependencyScanner(
	orchestrator *Orchestrator,
	resolver dependency.Resolver,
	cgBuilder *callgraph.Builder,
	findingsCache FindingsCache,
	opts ...DependencyScannerOption,
) *DependencyScanner {
	ds := &DependencyScanner{
		orchestrator:  orchestrator,
		resolver:      resolver,
		cgBuilder:     cgBuilder,
		findingsCache: findingsCache,
	}
	for _, opt := range opts {
		opt(ds)
	}
	return ds
}

// DepScanResult holds the aggregated result of the dependency scanning pipeline.
// It surfaces the crypto-scoped call graph so callers can export or inspect it.
type DepScanResult struct {
	Report    *entities.InterimReport
	CallGraph *callgraph.CallGraph
	// OccurrenceAnchors retains source-only declarations used to enrich finding
	// occurrence keys without changing the exported dependency call graph.
	// Keys are ecosystem-qualified FunctionID strings.
	OccurrenceAnchors map[string]*callgraph.FunctionDecl
	RootModule        string
	Ecosystem         string
	ProjectRoot       string
	Dependencies      []dependency.Dependency
	// DependencyPaths holds, per dependency module, its shortest route from
	// the application in the resolved dependency graph and whether every
	// route crosses a dependency parsed without source. Nil when the resolver
	// produced no graph.
	DependencyPaths map[string]dependency.Path
	// AdditionalEcosystems holds one call graph of the scan target's own
	// source per other supported ecosystem it contains. The fields above describe
	// the primary ecosystem, the one dependencies resolve for; a finding
	// written in another language is resolved against the entry for its own
	// ecosystem. Entries carry no dependencies and no additional ecosystems.
	AdditionalEcosystems []*DepScanResult
	summary              dependencyScanSummary
}

// ProgressDetails returns the aggregate dependency counters for structured progress.
func (r *DepScanResult) ProgressDetails() map[string]any {
	if r == nil {
		return map[string]any{
			"deps_scanned": 0, "deps_skipped": 0, "deps_failed": 0, "deps_incomplete": 0, "deps_with_findings": 0, "total_dep_findings": 0,
		}
	}
	return map[string]any{
		"deps_scanned":       r.summary.depsScanned,
		"deps_skipped":       r.summary.depsSkippedSource,
		"deps_failed":        r.summary.depsFailed,
		"deps_incomplete":    r.summary.depsIncomplete,
		"deps_with_findings": r.summary.depsWithFindings,
		"total_dep_findings": r.summary.totalDepFindings,
	}
}

type depScanStatus int

const (
	depScanStatusScanned depScanStatus = iota
	depScanStatusSkippedNoSource
	depScanStatusFailed
)

// depScanResult holds the result of handling a single dependency.
type depScanResult struct {
	index  int
	key    string
	dep    dependency.Dependency
	report *entities.InterimReport
	status depScanStatus
	// incomplete marks a scanned dependency whose scan a time or memory
	// limit cut short. Its report holds only what was found before.
	incomplete bool
	err        error
}

// ScanWithDependencies performs the full dependency scanning pipeline:
//  1. Resolve dependencies to source paths
//  2. Pre-load and filter rules by ecosystem language
//  3. Scan each dependency's source code in parallel
//  4. Build a call graph across user code + dependencies with findings
//  5. Trace each dependency crypto finding back to user code
//  6. Merge attributed findings into the user report
func (ds *DependencyScanner) ScanWithDependencies(
	ctx context.Context,
	userReport *entities.InterimReport,
	opts DepScanOptions,
) (*DepScanResult, error) {
	pipelineStart := time.Now()

	validator := &rules.ParameterConditionValidator{}
	resolved, filteredRulePaths, rulesHash, cleanupRulePaths, err := ds.prepareDependencyScan(ctx, opts, validator)
	if err != nil {
		return nil, err
	}
	defer cleanupRulePaths()
	ecosystem := ""
	if ds.resolver != nil {
		ecosystem = ds.resolver.Ecosystem()
	}
	enrichDirectFindingPURLs(userReport, opts.ScanOptions.Target, resolved, ecosystem)
	if len(resolved.Dependencies) == 0 {
		return ds.emptyDependencyScanResult(userReport, resolved, opts), nil
	}

	depResults, err := ds.scanDependenciesParallel(ctx, resolved.Dependencies, filteredRulePaths, rulesHash, opts, validator)
	if err != nil {
		return nil, err
	}
	summary := summarizeDependencyResults(depResults)
	logDependencyScanSummary(summary)
	if err := ds.reportProgress(opts, progressStatusStarted, nil); err != nil {
		return nil, err
	}

	graph, parsed, err := ds.buildDependencyCallGraph(opts.ScanOptions.Target, resolved, depResults)
	if err != nil {
		if progressErr := ds.reportProgress(opts, progressStatusFailed, err); progressErr != nil {
			return nil, progressErr
		}
		return nil, failure.WrapUnknown(
			err,
			failure.CodeCallGraphBuildFailed,
			failure.StageCallGraph,
			"failed to build call graph",
		)
	}
	if err := ds.reportProgress(opts, progressStatusComplete, nil); err != nil {
		return nil, err
	}

	tracer := callgraph.NewTracer(graph, ds.cgBuilder.PackageSeparator())
	userPackages := ds.buildUserPackages(resolved)
	ds.attributeDependencyResults(depResults, opts.ScanOptions.Target, tracer, userPackages)
	result := ds.mergeReports(userReport, depResults)

	pipelineDuration := time.Since(pipelineStart)
	log.Info().
		Str("duration", utils.HumanDuration(pipelineDuration)).
		Int64("duration_ms", pipelineDuration.Milliseconds()).
		Msg("Total dependency scan pipeline")

	return &DepScanResult{
		Report:          result,
		CallGraph:       graph,
		RootModule:      resolved.RootModule,
		Ecosystem:       ds.resolver.Ecosystem(),
		ProjectRoot:     opts.ScanOptions.Target,
		Dependencies:    canonicalDependencies(resolved.Dependencies),
		DependencyPaths: dependency.Paths(resolved, parsed),
		summary:         summary,
	}, nil
}

// resolveScanRoot resolves the scan root, reaching the module roots below it
// when the root itself holds no build manifest for this ecosystem and no
// ancestor manifest its toolchain would find on its own. A scan root that
// resolves today takes the single Resolve call it always took, with the same
// typed error.
//
// skipPatterns are the scan's exclusions. Discovery honors them because
// resolving a root runs mvn, gradle, cargo or go in that directory, which is a
// heavier consequence than reading a file the user asked to skip.
func (ds *DependencyScanner) resolveScanRoot(
	ctx context.Context,
	target string,
	skipPatterns []string,
) (*dependency.ResolveResult, error) {
	ecosystem := ds.resolver.Ecosystem()
	discovery := dependency.ResolutionRoots(target, ecosystem, skipPatterns)
	logRootDiscovery(target, ecosystem, discovery)
	if len(discovery.Roots) == 0 {
		return ds.resolver.Resolve(ctx, target)
	}

	resolutions := make([]dependency.RootResolution, 0, len(discovery.Roots))
	for i, root := range discovery.Roots {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		log.Info().Str("root", root.Rel).Int("index", i+1).Int("roots", len(discovery.Roots)).Msg("Resolving module root")
		result, err := ds.resolver.Resolve(ctx, root.Dir)
		if err != nil {
			// WrapUnknown only prefixes an already-typed failure, so the root
			// keeps its own code and details and now also names which of
			// several roots failed.
			return nil, failure.WrapUnknown(
				err,
				failure.CodeDependencyResolutionFailed,
				failure.StageDependency,
				"resolving module root "+root.Rel,
			)
		}
		resolutions = append(resolutions, dependency.RootResolution{Root: root, Result: result})
	}
	return dependency.MergeRootResolutions(resolutions), nil
}

func logRootDiscovery(target, ecosystem string, discovery dependency.RootDiscovery) {
	if !discovery.Searched {
		return
	}
	if discovery.Unreadable > 0 {
		log.Debug().Int("dirs", discovery.Unreadable).Msg("Module root discovery could not read some directories")
	}
	if discovery.Abandoned {
		log.Warn().Str("target", target).Msg("Module root discovery stopped at its entry cap; some module roots may be missing")
	}
	if len(discovery.Roots) == 0 {
		log.Info().Str("target", target).Str("ecosystem", ecosystem).Msg("No module root found below the scan root")
		return
	}
	paths := make([]string, 0, len(discovery.Roots))
	for _, root := range discovery.Roots {
		paths = append(paths, root.Rel)
	}
	log.Info().Str("ecosystem", ecosystem).Int("roots", len(paths)).Strs("paths", paths).Msg("Found module roots below the scan root")
	if discovery.Truncated {
		log.Warn().Int("found", discovery.Found).Int("resolving", len(paths)).Msg("More module roots qualified than the cap allows; the shallowest, then lexically first, were kept")
	}
}

func (ds *DependencyScanner) prepareDependencyScan(
	ctx context.Context,
	opts DepScanOptions,
	validator *rules.ParameterConditionValidator,
) (*dependency.ResolveResult, []string, string, func(), error) {
	log.Info().Str("target", opts.ScanOptions.Target).Msg("Resolving dependencies")
	resolved, err := ds.resolveScanRoot(ctx, opts.ScanOptions.Target, opts.ScanOptions.ScannerConfig.SkipPatterns)
	if err != nil {
		return nil, nil, "", func() {}, failure.WrapUnknown(
			err,
			failure.CodeDependencyResolutionFailed,
			failure.StageDependency,
			"dependency resolution failed",
		)
	}
	log.Info().Int("deps", len(resolved.Dependencies)).Msg("Resolved dependencies")
	if len(resolved.Dependencies) == 0 {
		return resolved, nil, "", func() {}, nil
	}

	filteredRulePaths, cleanupRulePaths, err := ds.loadFilteredRules(ds.resolver.Ecosystem(), validator)
	if err != nil {
		return nil, nil, "", func() {}, failure.WrapUnknown(
			err,
			failure.CodeRulesLoadFailed,
			failure.StageRules,
			"failed to load rules for dependency scanning",
		)
	}
	log.Info().
		Int("rules", len(filteredRulePaths)).
		Str("ecosystem", ds.resolver.Ecosystem()).
		Msg("Filtered rules by language")

	return resolved, filteredRulePaths, ds.computeRulesHash(filteredRulePaths), cleanupRulePaths, nil
}

func (ds *DependencyScanner) computeRulesHash(rulePaths []string) string {
	if ds.findingsCache == nil {
		return ""
	}
	rulesHash, err := ComputeRulesHash(rulePaths)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to compute rules hash, findings cache disabled for this scan")
		return ""
	}
	return rulesHash
}

func (ds *DependencyScanner) emptyDependencyScanResult(
	userReport *entities.InterimReport,
	resolved *dependency.ResolveResult,
	opts DepScanOptions,
) *DepScanResult {
	log.Info().Msg("No dependencies found, skipping dependency scan")
	return &DepScanResult{
		Report:      userReport,
		RootModule:  resolved.RootModule,
		Ecosystem:   ds.resolver.Ecosystem(),
		ProjectRoot: opts.ScanOptions.Target,
		summary:     dependencyScanSummary{},
	}
}

func (ds *DependencyScanner) reportProgress(opts DepScanOptions, status string, cause error) error {
	if opts.ScanOptions.Progress == nil {
		return nil
	}
	if err := opts.ScanOptions.Progress("callgraph", status, cause, nil); err != nil {
		return failure.WrapUnknown(err, failure.CodeOutputWriteFailed, failure.StageOutput, "failed to write scan progress")
	}
	return nil
}

type dependencyScanSummary struct {
	depsWithFindings  int
	totalDepFindings  int
	depsScanned       int
	depsSkippedSource int
	depsFailed        int
	depsIncomplete    int
}

func summarizeDependencyResults(depResults []depScanResult) dependencyScanSummary {
	summary := dependencyScanSummary{}
	for i := range depResults {
		result := &depResults[i]
		switch result.status {
		case depScanStatusScanned:
			summary.depsScanned++
		case depScanStatusSkippedNoSource:
			summary.depsSkippedSource++
		case depScanStatusFailed:
			summary.depsFailed++
		}
		if result.incomplete {
			summary.depsIncomplete++
		}
		if result.report != nil && hasFindings(result.report) {
			summary.depsWithFindings++
			for _, f := range result.report.Findings {
				summary.totalDepFindings += len(f.CryptographicAssets)
			}
		}
	}
	return summary
}

func logDependencyScanSummary(summary dependencyScanSummary) {
	event := log.Info()
	if summary.depsScanned == 0 && summary.depsSkippedSource > 0 {
		event = log.Warn()
	}
	event.
		Int("depsScanned", summary.depsScanned).
		Int("depsSkippedNoSource", summary.depsSkippedSource).
		Int("depsFailed", summary.depsFailed).
		Int("depsIncomplete", summary.depsIncomplete).
		Int("depsWithFindings", summary.depsWithFindings).
		Int("totalDepFindings", summary.totalDepFindings).
		Msg("Dependency scanning complete")
}

func (ds *DependencyScanner) buildDependencyCallGraph(
	userTarget string,
	resolved *dependency.ResolveResult,
	depResults []depScanResult,
) (*callgraph.CallGraph, map[string]bool, error) {
	sets := ds.collectPackageSets(userTarget, resolved, depResults)
	ds.cgBuilder.SetArtifactDependencies(resolved.Graph)
	graph, err := ds.cgBuilder.BuildFromDirectories(sets.graphPackages, sets.typeOnlyPackages)
	return graph, sets.parsedModules, err
}

func (ds *DependencyScanner) attributeDependencyResults(
	depResults []depScanResult,
	target string,
	tracer *callgraph.Tracer,
	userPackages map[string]bool,
) {
	for i := range depResults {
		result := &depResults[i]
		if result.status != depScanStatusScanned || result.report == nil {
			continue
		}
		ds.attributeFindings(result.report, &result.dep, target, tracer, userPackages)
	}
}

// loadFilteredRules loads all rules from the manager and filters them to only
// include rules for the ecosystem's languages. This avoids loading Java/Python/C/Rust
// rules when scanning Go dependencies, significantly reducing scanner overhead.
func (ds *DependencyScanner) loadFilteredRules(ecosystem string, validator *rules.ParameterConditionValidator) ([]string, func(), error) {
	allRules, err := ds.orchestrator.rulesManager.Load()
	if err != nil {
		return nil, func() {}, err
	}

	// Fail-fast validation against the raw loaded rules, before any
	// language filtering — a malformed parameterCondition is a hard abort
	// (resolved proposal decision), matching the same gate in Orchestrator.Scan.
	if err := validator.Validate(allRules); err != nil {
		return nil, func() {}, failure.WrapUnknown(
			err,
			failure.CodeRulesLoadFailed,
			failure.StageRules,
			"invalid parameterCondition in ruleset",
		)
	}

	languages := ecosystemToLanguages(ecosystem)
	return prepareRulePathsForScanner(allRules, languages)
}

func dependencyScanWorkers(configured int, ecosystem string) int {
	if configured > 0 {
		return configured
	}
	limit := maxWorkers
	if ecosystem == languageJava {
		limit = 2
	}
	return min(max(runtime.NumCPU()/2, 1), limit)
}

// dependencyScanJobs sizes each scanner process so concurrent dependency
// scans share the cores. A lone scan keeps the scanner's own default.
func dependencyScanJobs(workers int) int32 {
	if workers <= 1 {
		return 0
	}
	return int32(max(1, runtime.NumCPU()/workers)) //nolint:gosec // A core count fits in int32.
}

// scanDependenciesParallel scans all dependencies concurrently using a worker pool.
func (ds *DependencyScanner) scanDependenciesParallel(
	ctx context.Context,
	deps []dependency.Dependency,
	rulePaths []string,
	rulesHash string,
	opts DepScanOptions,
	validator *rules.ParameterConditionValidator,
) ([]depScanResult, error) {
	orderedDeps := canonicalDependencies(deps)

	outcomes := make([]depScanResult, len(orderedDeps))
	work := make([]depWork, 0, len(orderedDeps))
	for i, dep := range orderedDeps {
		key := dependencyKey(dep)
		if dep.Dir == "" {
			outcomes[i] = depScanResult{
				index:  i,
				key:    key,
				dep:    dep,
				status: depScanStatusSkippedNoSource,
			}
			log.Info().
				Str("module", dep.Module).
				Str("version", dep.Version).
				Msg("Skipping dependency source scan: no local source directory")
			continue
		}

		work = append(work, depWork{index: i, key: key, dep: dep})
	}

	workers := min(dependencyScanWorkers(opts.Workers, ds.resolver.Ecosystem()), len(work))
	opts.ScanOptions.ScannerConfig.Jobs = dependencyScanJobs(workers)

	log.Info().
		Int("deps", len(orderedDeps)).
		Int("scannableDeps", len(work)).
		Int("workers", workers).
		Int32("scannerJobs", opts.ScanOptions.ScannerConfig.Jobs).
		Msg("Starting parallel dependency scanning")

	if len(work) == 0 {
		return outcomes, nil
	}

	// Detach per-dep scan ctx from the parent's deadline. Without this, a long
	// setup phase (Maven dependency resolution, source download) eats the
	// caller's global scan budget; by the time per-dep opengrep starts, the
	// parent ctx is already at or past its deadline. Every per-dep
	// WithTimeout(parent, X) inside the scanner then fires instantly with a
	// misleading "timed out after X" error and a sub-millisecond duration.
	//
	// The detached context still propagates explicit cancellation (user Ctrl-C,
	// errgroup cancel) so the user can still abort the run. Each individual
	// opengrep invocation inside scanDepAlone or scanBatch gets its own per-call
	// timeout downstream, which is now unaffected by parent deadline pressure.
	depCtx, depCancel := detachDeadlineKeepCancel(ctx)
	defer depCancel()

	// Cache lookups stay per dependency; only the misses go to the scanner,
	// batched so a process loads the rules once for several dependencies.
	var mu sync.Mutex
	var misses []depWork
	batchable := false
	forEachParallel(workers, work, func(item depWork) {
		result, hit := ds.lookupDependency(depCtx, &item, rulePaths, rulesHash, opts)
		if hit {
			outcomes[item.index] = result
			return
		}
		_, canBatch := item.scanner.(scanner.BatchScanner)
		if canBatch {
			item.weight = sourceWeight(item.dep.Dir, item.scope, item.opts.LanguageHint)
		}
		mu.Lock()
		misses = append(misses, item)
		batchable = batchable || canBatch
		mu.Unlock()
	})
	sort.Slice(misses, func(i, j int) bool { return misses[i].index < misses[j].index })

	var batches []scanBatch
	if batchable {
		batches = shapeBatches(misses, workers)
	} else {
		for i := range misses {
			batches = append(batches, scanBatch{items: misses[i : i+1]})
		}
	}
	log.Info().Int("cacheMisses", len(misses)).Int("batches", len(batches)).Msg("Scanning dependencies the findings cache does not hold")
	forEachParallel(workers, batches, func(batch scanBatch) {
		results := ds.scanBatch(depCtx, batch, validator)
		for i := range results {
			outcomes[results[i].index] = results[i]
		}
	})

	for i := range outcomes {
		if outcomes[i].err != nil {
			log.Warn().Err(outcomes[i].err).Str("module", outcomes[i].dep.Module).Msg("Failed to scan dependency source")
		}
		structured, ok := failure.As(outcomes[i].err)
		if ok && structured.Code == failure.CodeScannerCancelled {
			return outcomes, outcomes[i].err
		}
	}

	return outcomes, nil
}

// forEachParallel runs fn over items on up to workers goroutines and waits.
func forEachParallel[T any](workers int, items []T, fn func(T)) {
	queue := make(chan T)
	var wg sync.WaitGroup
	for range min(workers, len(items)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range queue {
				fn(item)
			}
		}()
	}
	for _, item := range items {
		queue <- item
	}
	close(queue)
	wg.Wait()
}

// lookupDependency gives item its scan options, its initialized scanner and,
// when a findings cache is configured and rulesHash is non-empty, its cache
// key, and answers from the cache when it holds the dependency. The result
// is final when hit is true, or when the scanner could not be initialized.
func (ds *DependencyScanner) lookupDependency(
	ctx context.Context,
	item *depWork,
	rulePaths []string,
	rulesHash string,
	opts DepScanOptions,
) (result depScanResult, hit bool) {
	dep := &item.dep
	item.opts = ds.buildDepScanOptions(dep, rulePaths, opts)
	initializedScanner, err := ds.orchestrator.initializeScanner(ctx, item.opts)
	if err != nil {
		return depScanResult{index: item.index, key: item.key, dep: item.dep, status: depScanStatusFailed, err: err}, true
	}
	item.scanner = initializedScanner
	// A scanner that cannot limit detection to files scans the whole module.
	if _, scoped := initializedScanner.(scanner.ScopedScanner); scoped && dep.Files != nil {
		item.scope = sourceScope(dep)
	}
	if ds.findingsCache != nil && rulesHash != "" {
		env := os.Environ()
		sort.Strings(env)
		cwd, cwdErr := os.Getwd()
		info := initializedScanner.GetInfo()
		config := item.opts.ScannerConfig
		// The job count tunes the host, not the scan. Keying on it would split
		// the cache by core count and by how many dependencies run at once.
		config.Jobs = 0
		identity, encodeErr := json.Marshal(struct {
			Package       string
			RulesHash     string
			JavaRuntime   string
			Name          string
			Scanner       scanner.Info
			FinderVersion string
			Config        scanner.Config
			Languages     []string
			Environment   []string
			CWD           string
			// Omitted for a whole-module scan, so those keys stay as they were.
			Scope *scanner.DetectionScope `json:",omitempty"`
		}{item.key, rulesHash, item.opts.JavaRuntimeCacheToken, item.opts.ScannerName, info, version.Version, config, item.opts.LanguageHint, env, cwd, item.scope})
		// Unavailable context/identity disables caching, never scanner validation.
		if encodeErr == nil && cwdErr == nil && info.Version != "" && info.Version != "unknown" {
			item.cacheKey = fmt.Sprintf("dependency-findings-v2:%x", sha256.Sum256(identity))
		}
	}

	if item.cacheKey != "" {
		report, ok, err := ds.findingsCache.Get(ctx, item.cacheKey)
		if err != nil {
			log.Warn().Err(err).Str("module", dep.Module).Msg("Cache read error, scanning normally")
		} else if ok {
			log.Info().
				Str("module", dep.Module).
				Str("version", dep.Version).
				Msg("Cache hit for dependency scan")
			return depScanResult{index: item.index, key: item.key, dep: item.dep, report: dependencyReportWithFindings(item.ownFindings(report)), status: depScanStatusScanned}, true
		}
	}
	return ds.lookupFindingsSource(ctx, item)
}

// lookupFindingsSource answers item from the findings source, when one is
// configured and publishes the dependency's package version.
func (ds *DependencyScanner) lookupFindingsSource(ctx context.Context, item *depWork) (result depScanResult, hit bool) {
	dep := &item.dep
	if ds.findingsSource == nil || dep.Version == "" {
		return depScanResult{}, false
	}
	packageURL := purl.Dependency(ds.resolver.Ecosystem(), dep.Module, "")
	if packageURL == "" {
		return depScanResult{}, false
	}
	report, ok, err := ds.findingsSource.Findings(ctx, packageURL, dep.Version)
	if err != nil {
		log.Warn().Err(err).Str("module", dep.Module).Str("version", dep.Version).Msg("Dependency findings unavailable from the SCANOSS API, scanning locally")
		return depScanResult{}, false
	}
	if !ok {
		return depScanResult{}, false
	}
	log.Info().
		Str("module", dep.Module).
		Str("version", dep.Version).
		Str("rules_version", report.Rules.Version).
		Msg("Dependency findings from the SCANOSS API")
	return depScanResult{index: item.index, key: item.key, dep: item.dep, report: dependencyReportWithFindings(item.filesOf(report)), status: depScanStatusScanned}, true
}

// scanDepAlone scans one looked-up dependency in its own scanner process.
func (ds *DependencyScanner) scanDepAlone(ctx context.Context, item *depWork, validator *rules.ParameterConditionValidator) depScanResult {
	dep := &item.dep
	log.Info().Str("module", dep.Module).Str("version", dep.Version).Msg("Scanning dependency")

	report, err := ds.orchestrator.scan(ctx, item.opts, item.scope, item.scanner, validator)
	report = item.ownFindings(report)
	log.Info().
		Str("module", dep.Module).
		Str("version", dep.Version).
		Msg("Scanned dependency")

	incomplete := false
	if err == nil {
		incomplete = !ds.cacheIfComplete(ctx, dep, item.cacheKey, report)
	}

	return depScanResult{
		index:      item.index,
		key:        item.key,
		dep:        item.dep,
		report:     dependencyReportWithFindings(report),
		status:     scanStatusForError(err),
		incomplete: incomplete,
		err:        err,
	}
}

// scanBatch scans the batch's dependencies in one scanner process, or alone
// when the batch holds one. When the process fails, every dependency is
// scanned alone instead, so one faulty dependency fails only itself, as
// before batching; a canceled scan fails them all and rescans nothing.
func (ds *DependencyScanner) scanBatch(ctx context.Context, batch scanBatch, validator *rules.ParameterConditionValidator) []depScanResult {
	if len(batch.items) == 1 {
		return []depScanResult{ds.scanDepAlone(ctx, &batch.items[0], validator)}
	}
	members := make([]ScanOptions, 0, len(batch.items))
	roots := make([]scanner.Root, 0, len(batch.items))
	modules := make([]string, 0, len(batch.items))
	for i := range batch.items {
		members = append(members, batch.items[i].opts)
		roots = append(roots, scanner.Root{Dir: batch.items[i].dep.Dir, Scope: batch.items[i].scope})
		modules = append(modules, batch.items[i].key)
	}
	batchOpts := batchScanOptions(members)
	log.Info().Int("deps", len(roots)).Int64("sourceBytes", batch.weight).Dur("timeout", batchOpts.ScannerConfig.Timeout).Strs("modules", modules).Msg("Scanning dependency batch")
	started := time.Now()

	results := make([]depScanResult, len(batch.items))
	batchScanner, err := ds.orchestrator.initializeScanner(ctx, batchOpts)
	var reports []*entities.InterimReport
	if err == nil {
		reports, err = ds.orchestrator.scanRoots(ctx, batchOpts, roots, batchScanner, validator)
	}
	if err != nil {
		if structured, ok := failure.As(err); ok && structured.Code == failure.CodeScannerCancelled {
			for i := range batch.items {
				item := &batch.items[i]
				results[i] = depScanResult{index: item.index, key: item.key, dep: item.dep, status: depScanStatusFailed, err: err}
			}
			return results
		}
		log.Warn().Err(err).Int("deps", len(roots)).Msg("Dependency batch scan failed; scanning its dependencies one by one")
		for i := range batch.items {
			results[i] = ds.scanDepAlone(ctx, &batch.items[i], validator)
		}
		return results
	}
	for i := range batch.items {
		item := &batch.items[i]
		incomplete := !ds.cacheIfComplete(ctx, &item.dep, item.cacheKey, reports[i])
		results[i] = depScanResult{
			index:      item.index,
			key:        item.key,
			dep:        item.dep,
			report:     dependencyReportWithFindings(reports[i]),
			status:     depScanStatusScanned,
			incomplete: incomplete,
		}
	}
	log.Info().Int("deps", len(roots)).Str("duration", utils.HumanDuration(time.Since(started))).Msg("Scanned dependency batch")
	return results
}

// cacheIfComplete stores a dependency's report under cacheKey, when caching
// is on, unless a time or memory limit cut the scan short. It reports whether
// the scan was complete and warns, naming the files, when it was not.
func (ds *DependencyScanner) cacheIfComplete(ctx context.Context, dep *dependency.Dependency, cacheKey string, report *entities.InterimReport) bool {
	if len(report.IncompleteFiles) > 0 {
		log.Warn().
			Str("module", dep.Module).
			Str("version", dep.Version).
			Strs("files", report.IncompleteFiles).
			Msg("Dependency scan stopped at a time or memory limit in these files; its findings may be incomplete and are not cached")
		return false
	}
	if cacheKey != "" {
		if putErr := ds.findingsCache.Put(ctx, cacheKey, report); putErr != nil {
			log.Warn().Err(putErr).Str("module", dep.Module).Msg("Failed to cache scan result")
		}
	}
	return true
}

func dependencyReportWithFindings(report *entities.InterimReport) *entities.InterimReport {
	if !hasFindings(report) {
		return nil
	}
	return report
}

func scanStatusForError(err error) depScanStatus {
	if err != nil {
		return depScanStatusFailed
	}
	return depScanStatusScanned
}

// buildDepScanOptions creates ScanOptions for scanning a specific dependency.
func (ds *DependencyScanner) buildDepScanOptions(dep *dependency.Dependency, rulePaths []string, opts DepScanOptions) ScanOptions {
	depOpts := opts.ScanOptions
	depOpts.Target = dep.Dir
	// Use pre-loaded, language-filtered rules
	depOpts.RulePaths = rulePaths
	// Set language hint so the orchestrator skips language detection
	depOpts.LanguageHint = ecosystemToLanguages(ds.resolver.Ecosystem())
	depOpts.Progress = nil
	depOpts.ProgressDetectionStarted = false
	// Preserve only built-in test exclusions for dependency scans. Other user/project
	// skip patterns should not hide dependency source files.
	depOpts.ScannerConfig.SkipPatterns = skip.OnlyDefaultTestPatterns(depOpts.ScannerConfig.SkipPatterns)
	depOpts.ScannerConfig.IncludeGitIgnored = true
	depOpts.ScannerConfig.RuleTimeoutSeconds = dependencyRuleTimeoutSeconds
	if ds.resolver.Ecosystem() == npmEcosystem {
		// Anchor below this artifact, not every node_modules ancestor: the
		// dependency target itself usually lives inside node_modules.
		depOpts.ScannerConfig.SkipPatterns = append(depOpts.ScannerConfig.SkipPatterns, filepath.ToSlash(filepath.Join(dep.Dir, "node_modules"))+"/")
	}
	return depOpts
}

// ownFindings keeps the findings of report in the dependency's Files. A
// scanner that cannot limit detection to files scans all of Dir, which for
// a Python distribution rooted at site-packages holds every other
// distribution too.
func (item *depWork) ownFindings(report *entities.InterimReport) *entities.InterimReport {
	if item.scope != nil {
		return report
	}
	return item.filesOf(report)
}

// filesOf keeps the findings of report in the dependency's Files, whatever
// scope detection ran with. Findings published for a whole package cover
// files the import closure leaves out.
func (item *depWork) filesOf(report *entities.InterimReport) *entities.InterimReport {
	if report == nil || item.dep.Files == nil {
		return report
	}
	owned := *report
	owned.Findings = make([]entities.Finding, 0, len(report.Findings))
	for i := range report.Findings {
		path := filepath.FromSlash(report.Findings[i].FilePath)
		if !filepath.IsAbs(path) {
			path = filepath.Join(item.dep.Dir, path)
		}
		if dependency.ListsFile(item.dep.Files, filepath.Clean(path)) {
			owned.Findings = append(owned.Findings, report.Findings[i])
		}
	}
	return &owned
}

// sourceScope lists dep's Files relative to dep.Dir, sorted. A file outside
// dep.Dir adds nothing.
func sourceScope(dep *dependency.Dependency) *scanner.DetectionScope {
	scope := &scanner.DetectionScope{}
	for _, file := range dep.Files {
		rel, ok := pathRelativeToRoot(dep.Dir, file)
		if !ok {
			log.Debug().Str("module", dep.Module).Str("file", file).Msg("Dependency file lies outside its root; not scanned")
			continue
		}
		scope.Paths = append(scope.Paths, rel)
	}
	sort.Strings(scope.Paths)
	return scope
}

// packageSets separates dependencies into two groups for the two-phase callgraph build.
type packageSets struct {
	// graphPackages get full source parsing: user code + every dependency whose
	// source was resolved and scanned successfully. Non-crypto dependencies must
	// still be parsed here because they can be bridge nodes in a call chain
	// (for example A -> B(no crypto) -> C(crypto)).
	graphPackages []callgraph.PackageDir
	// typeOnlyPackages are used only for bytecode type indexing (no source parsing).
	// This preserves type resolution accuracy for dependencies whose source is
	// unavailable or whose scan failed, while avoiding duplicate source parsing for
	// dependencies already listed in graphPackages.
	typeOnlyPackages []callgraph.PackageDir
	// parsedModules names the dependencies in graphPackages: the ones whose
	// code holds call edges. Each is listed by module and by module@version,
	// for a module resolved at several versions (dependency.Paths).
	parsedModules map[string]bool
}

// collectPackageSets builds two lists of callgraph.PackageDir for the two-phase callgraph build.
// graphPackages: user code + successfully scanned deps with source, regardless of findings.
// typeOnlyPackages: Java deps not source-parsed, used for bytecode type resolution only.
func (ds *DependencyScanner) collectPackageSets(
	userTarget string,
	resolved *dependency.ResolveResult,
	depResults []depScanResult,
) packageSets {
	sets := packageSets{parsedModules: make(map[string]bool)}

	if len(resolved.WorkspaceMembers) > 0 {
		// Workspace project: each member is a separate package root
		memberDirs := make([]string, 0, len(resolved.WorkspaceMembers))
		for _, member := range resolved.WorkspaceMembers {
			memberDirs = append(memberDirs, member.Dir)
			sets.graphPackages = append(sets.graphPackages, callgraph.PackageDir{
				Dir:        member.Dir,
				ImportPath: member.Name,
			})
		}
		// The root itself carries source in some ecosystems. A Cargo workspace
		// root is a virtual manifest with nothing to parse, so this is a no-op
		// there; an npm workspace root routinely has its own index.js AND its own
		// dependencies, and taking only the members left that file in no package
		// at all — the finding was still reported, with no chain behind it.
		//
		// Members are excluded from the root's walk because they live UNDER the
		// root: without that the root re-parses each member under a second import
		// path, and one function acquires two identities.
		sets.graphPackages = append(sets.graphPackages, callgraph.PackageDir{
			Dir:         userTarget,
			ImportPath:  resolved.RootModule,
			ExcludeDirs: memberDirs,
		})
	} else {
		// Single-project: the target directory is the package root
		sets.graphPackages = append(sets.graphPackages, callgraph.PackageDir{
			Dir:        userTarget,
			ImportPath: resolved.RootModule,
		})
	}

	// Source-available deps participate in reachability when they can sit on a
	// user-code -> crypto-dependency path. Without resolver graph proof, keep the
	// old conservative behavior and parse every scanned dependency.
	graphDeps := callGraphDependencySet(resolved, depResults)
	for i := range depResults {
		result := &depResults[i]
		importPath := result.dep.ImportPath
		// A Python distribution rooted at site-packages has no import root:
		// its top-level packages and modules keep their own names.
		if importPath == "" && ds.resolver.Ecosystem() != ecosystemPython {
			importPath = result.dep.Module
		}
		pkg := callgraph.PackageDir{
			Dir:                  result.dep.Dir,
			ImportPath:           importPath,
			DistributionName:     result.dep.Module,
			Version:              result.dep.Version,
			CompiledArtifactPath: result.dep.CompiledArtifactPath,
			// Calls from an imported Go package reach only imported packages,
			// and only their types are linked, so the rest of a module holds
			// no call edge and no dispatch target. A Python namespace sibling
			// parses only its own files, so each function has one owner.
			IncludeFiles: result.dep.Files,
		}
		if result.status == depScanStatusScanned && result.dep.Dir != "" {
			if graphDeps == nil || graphDeps[result.dep.Module] {
				sets.graphPackages = append(sets.graphPackages, pkg)
				sets.parsedModules[result.dep.Module] = true
				sets.parsedModules[dependency.Ref{Module: result.dep.Module, Version: result.dep.Version}.Key()] = true
			}
			continue
		}

		if ds.resolver.Ecosystem() == "java" && result.dep.Module != "" && result.dep.Version != "" {
			sets.typeOnlyPackages = append(sets.typeOnlyPackages, pkg)
		}
	}

	return sets
}

func callGraphDependencySet(resolved *dependency.ResolveResult, depResults []depScanResult) map[string]bool {
	targets := cryptoDependencyModules(depResults)
	if len(targets) == 0 {
		return map[string]bool{}
	}
	if resolved == nil || len(resolved.Graph) == 0 {
		return nil
	}
	roots := dependencyGraphRoots(resolved)
	if len(roots) == 0 {
		return nil
	}
	reachable := reachableDependencyModules(resolved.Graph, roots)
	for target := range targets {
		if !reachable[target] {
			return nil
		}
	}
	ancestors := dependencyTargetAncestors(resolved.Graph, targets)
	keep := make(map[string]bool, len(ancestors))
	for module := range ancestors {
		if reachable[module] {
			keep[module] = true
		}
	}
	return keep
}

func cryptoDependencyModules(depResults []depScanResult) map[string]bool {
	targets := make(map[string]bool)
	for i := range depResults {
		result := &depResults[i]
		if result.status == depScanStatusScanned && hasFindings(result.report) && result.dep.Module != "" {
			targets[result.dep.Module] = true
		}
	}
	return targets
}

func dependencyGraphRoots(resolved *dependency.ResolveResult) []string {
	explicit := explicitDependencyGraphRoots(resolved)
	for i := range explicit {
		if _, ok := resolved.Graph[explicit[i]]; ok {
			return explicit
		}
	}
	if inferred := dependencyGraphSourceRoots(resolved.Graph); len(inferred) > 0 {
		return inferred
	}
	return explicit
}

func explicitDependencyGraphRoots(resolved *dependency.ResolveResult) []string {
	if len(resolved.WorkspaceMembers) > 0 {
		roots := make([]string, 0, len(resolved.WorkspaceMembers))
		for i := range resolved.WorkspaceMembers {
			if resolved.WorkspaceMembers[i].Name != "" {
				roots = append(roots, resolved.WorkspaceMembers[i].Name)
			}
		}
		return roots
	}
	if resolved.RootModule == "" {
		return nil
	}
	return []string{resolved.RootModule}
}

func dependencyGraphSourceRoots(graph map[string][]string) []string {
	children := make(map[string]bool)
	for _, values := range graph {
		for _, child := range values {
			children[child] = true
		}
	}
	roots := make([]string, 0)
	for parent := range graph {
		if !children[parent] {
			roots = append(roots, parent)
		}
	}
	sort.Strings(roots)
	return roots
}

func reachableDependencyModules(graph map[string][]string, roots []string) map[string]bool {
	seen := make(map[string]bool)
	stack := append([]string(nil), roots...)
	for len(stack) > 0 {
		last := len(stack) - 1
		module := stack[last]
		stack = stack[:last]
		if seen[module] {
			continue
		}
		seen[module] = true
		stack = append(stack, graph[module]...)
	}
	return seen
}

func dependencyTargetAncestors(graph map[string][]string, targets map[string]bool) map[string]bool {
	reverse := make(map[string][]string, len(graph))
	for parent, children := range graph {
		for _, child := range children {
			reverse[child] = append(reverse[child], parent)
		}
	}
	seen := make(map[string]bool)
	stack := make([]string, 0, len(targets))
	for target := range targets {
		stack = append(stack, target)
	}
	for len(stack) > 0 {
		last := len(stack) - 1
		module := stack[last]
		stack = stack[:last]
		if seen[module] {
			continue
		}
		seen[module] = true
		stack = append(stack, reverse[module]...)
	}
	return seen
}

// buildUserPackages returns the set of package names that constitute user code.
// For workspace projects, all workspace members are user code.
func (ds *DependencyScanner) buildUserPackages(resolved *dependency.ResolveResult) map[string]bool {
	userPackages := make(map[string]bool)
	if len(resolved.WorkspaceMembers) > 0 {
		for _, member := range resolved.WorkspaceMembers {
			userPackages[member.Name] = true
		}
	} else {
		userPackages[resolved.RootModule] = true
	}
	return userPackages
}

// attributeFindings enriches each crypto finding in a dependency report with
// dependency metadata and call chain information.
func (ds *DependencyScanner) attributeFindings(
	report *entities.InterimReport,
	dep *dependency.Dependency,
	_ string,
	_ *callgraph.Tracer,
	_ map[string]bool,
) {
	ecosystem := ""
	if ds.resolver != nil {
		ecosystem = ds.resolver.Ecosystem()
	}
	for i := range report.Findings {
		finding := &report.Findings[i]

		for j := range finding.CryptographicAssets {
			asset := &finding.CryptographicAssets[j]

			// Add dependency attribution as structured fields
			asset.Source = findingSourceDependency
			asset.PURL = ""
			asset.DependencyInfo = &entities.DependencyInfo{
				Module:  dep.Module,
				Version: dep.Version,
				PURL:    purl.Dependency(ecosystem, dep.Module, dep.Version),
			}
		}
	}
}

// mergeReports combines the user report with all dependency findings.
// Reachability filtering is handled by the callgraph export (backward_paths),
// not by the interim report.
func (ds *DependencyScanner) mergeReports(
	userReport *entities.InterimReport,
	depResults []depScanResult,
) *entities.InterimReport {
	merged := &entities.InterimReport{
		Version:  userReport.Version,
		Tool:     userReport.Tool,
		Rules:    userReport.Rules,
		Findings: make([]entities.Finding, 0, len(userReport.Findings)),
	}

	// Mark user code findings as direct
	merged.Findings = append(merged.Findings, userReport.Findings...)

	// Include all dependency findings
	for i := range depResults {
		result := &depResults[i]
		if result.status != depScanStatusScanned || result.report == nil {
			continue
		}
		merged.Findings = append(merged.Findings, result.report.Findings...)
	}

	EnsureFindingSources(merged)

	// Generate stable finding IDs for all assets
	AssignFindingIDs(merged)

	return merged
}

// EnsureFindingSources normalizes finding source attribution by defaulting any
// un-attributed finding asset to direct source.
func EnsureFindingSources(report *entities.InterimReport) {
	if report == nil {
		return
	}

	for i := range report.Findings {
		finding := &report.Findings[i]
		for j := range finding.CryptographicAssets {
			if finding.CryptographicAssets[j].Source == "" {
				finding.CryptographicAssets[j].Source = findingSourceDirect
			}
		}
	}
}

// enrichDirectFindingPURLs adds a resolved version only when the rule PURL
// matches exactly one version of a direct dependency of the owning module.
// Missing graph/version evidence deliberately leaves the versionless rule URL.
func enrichDirectFindingPURLs(report *entities.InterimReport, target string, resolved *dependency.ResolveResult, ecosystem string) {
	if report == nil || resolved == nil {
		return
	}
	for i := range report.Findings {
		finding := &report.Findings[i]
		parent := owningModule(target, finding.FilePath, resolved)
		refs := directDependencyRefs(resolved, parent)
		for j := range finding.CryptographicAssets {
			asset := &finding.CryptographicAssets[j]
			if asset.Source == findingSourceDependency || asset.PURL == "" {
				continue
			}
			asset.PURL = enrichRulePURL(asset.PURL, refs, ecosystem)
		}
	}
}

func owningModule(target, filePath string, resolved *dependency.ResolveResult) string {
	if len(resolved.WorkspaceMembers) == 0 {
		return resolved.RootModule
	}
	fullPath := filepath.Clean(filePath)
	if !filepath.IsAbs(fullPath) {
		fullPath = filepath.Join(target, fullPath)
	}
	owner := resolved.RootModule
	longest := -1
	for _, member := range resolved.WorkspaceMembers {
		if member.Name == "" || member.Dir == "" {
			continue
		}
		if rel, err := filepath.Rel(filepath.Clean(member.Dir), fullPath); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && len(member.Dir) > longest {
			owner = member.Name
			longest = len(member.Dir)
		}
	}
	return owner
}

func directDependencyRefs(resolved *dependency.ResolveResult, parent string) []dependency.Ref {
	if parent == "" {
		return nil
	}
	if refs := versionedDirectDependencyRefs(resolved, parent); len(refs) > 0 {
		return refs
	}
	if refs := graphDirectDependencyRefs(resolved, parent); len(refs) > 0 {
		return refs
	}
	return mavenRootAliasRefs(resolved, parent)
}

func versionedDirectDependencyRefs(resolved *dependency.ResolveResult, parent string) []dependency.Ref {
	var refs []dependency.Ref
	for key, children := range resolved.VersionedGraph {
		if key == parent || strings.HasPrefix(key, parent+"@") {
			refs = append(refs, children...)
		}
	}
	return refs
}

func graphDirectDependencyRefs(resolved *dependency.ResolveResult, parent string) []dependency.Ref {
	var refs []dependency.Ref
	for _, child := range resolved.Graph[parent] {
		for _, dep := range resolved.Dependencies {
			if dep.Module == child {
				refs = append(refs, dependency.Ref{Module: dep.Module, Version: dep.Version})
			}
		}
	}
	return refs
}

func mavenRootAliasRefs(resolved *dependency.ResolveResult, parent string) []dependency.Ref {
	// Maven exposes RootModule as groupId while its versioned graph keys use
	// groupId:artifactId@version. Recover that single root alias without
	// treating every same-group dependency node as a direct project edge.
	candidates := make(map[string][]dependency.Ref)
	incoming := make(map[string]bool)
	for key, children := range resolved.VersionedGraph {
		module := key
		if at := strings.LastIndexByte(module, '@'); at > 0 {
			module = module[:at]
		}
		if strings.HasPrefix(module, parent+":") {
			candidates[key] = children
		}
	}
	for _, children := range resolved.VersionedGraph {
		for _, child := range children {
			if _, ok := candidates[child.Key()]; ok {
				incoming[child.Key()] = true
			}
		}
	}
	var rootRefs []dependency.Ref
	for key, children := range candidates {
		if !incoming[key] {
			if rootRefs != nil {
				return nil
			}
			rootRefs = children
		}
	}
	return rootRefs
}

func enrichRulePURL(ruleURL string, refs []dependency.Ref, ecosystem string) string {
	want, ok := purl.Identity(ruleURL)
	if !ok {
		return ""
	}
	versions := make(map[string]struct{})
	for _, ref := range refs {
		if ref.Version == "" {
			continue
		}
		candidate := purl.Dependency(ecosystem, ref.Module, ref.Version)
		if candidate == "" {
			continue
		}
		identity, ok := purl.Identity(candidate)
		if ok && identity == want {
			versions[ref.Version] = struct{}{}
		}
	}
	if len(versions) != 1 {
		return ruleURL
	}
	for version := range versions {
		if enriched := purl.WithVersion(ruleURL, version); enriched != "" {
			return enriched
		}
	}
	return ruleURL
}

// AssignFindingIDs ensures every finding asset in the report has a stable short hash
// suitable for joining the main report to the callgraph export.
func AssignFindingIDs(report *entities.InterimReport) {
	if report == nil {
		return
	}

	MarkSyntheticVariants(report)
	for i := range report.Findings {
		finding := &report.Findings[i]
		for j := range finding.CryptographicAssets {
			asset := &finding.CryptographicAssets[j]
			asset.FindingID = generateFindingID(findingIDPath(*finding, *asset), asset.StartLine, asset.Rules, asset.ConditionedValue)
		}
	}
}

// generateFindingID produces a stable short hash for a finding.
// It hashes file_path + start_line + first_rule_id and returns the first 8 hex chars.
// A per-value asset also hashes its resolved condition, so two values of one
// rule at one call do not share an id. Every other asset passes an empty value
// and keeps the id it always had.
func generateFindingID(filePath string, startLine int, ruleInfos []entities.RuleInfo, conditionedValue string) string {
	ruleID := ""
	if len(ruleInfos) > 0 {
		ruleID = ruleInfos[0].ID
	}
	input := filePath + ":" + strconv.Itoa(startLine) + ":" + ruleID
	if conditionedValue != "" {
		input += ":" + conditionedValue
	}
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])[:8]
}

func findingIDPath(finding entities.Finding, asset entities.CryptographicAsset) string {
	if asset.DependencyInfo != nil && asset.DependencyInfo.Module != "" && asset.DependencyInfo.Version != "" {
		return asset.DependencyInfo.Module + "@" + asset.DependencyInfo.Version + "/" + finding.FilePath
	}
	return finding.FilePath
}

// ecosystemToLanguages maps an ecosystem name to language hints for the orchestrator.
func ecosystemToLanguages(ecosystem string) []string {
	switch ecosystem {
	case "go":
		return []string{"go"}
	case "python":
		return []string{"python"}
	case "java":
		return []string{"java"}
	case "rust":
		return []string{"rust"}
	case "c":
		return []string{"c"}
	case npmEcosystem:
		return []string{"javascript", "typescript"}
	default:
		return nil
	}
}

func canonicalDependencies(deps []dependency.Dependency) []dependency.Dependency {
	ordered := append([]dependency.Dependency(nil), deps...)
	sort.Slice(ordered, func(i, j int) bool {
		return dependencyLess(ordered[i], ordered[j])
	})

	unique := make(map[string]dependency.Dependency, len(ordered))
	for _, dep := range ordered {
		key := dependencyKey(dep)
		existing, ok := unique[key]
		if !ok {
			unique[key] = dep
			continue
		}
		if existing.Dir == "" && dep.Dir != "" {
			unique[key] = dep
			continue
		}
		if existing.CompiledArtifactPath == "" && dep.CompiledArtifactPath != "" {
			existing.CompiledArtifactPath = dep.CompiledArtifactPath
		}
		if existing.SourceArchivePath == "" && dep.SourceArchivePath != "" {
			existing.SourceArchivePath = dep.SourceArchivePath
		}
		existing.Files = unionPaths(existing.Files, dep.Files)
		unique[key] = existing
	}

	result := make([]dependency.Dependency, 0, len(unique))
	for _, dep := range unique {
		result = append(result, dep)
	}
	sort.Slice(result, func(i, j int) bool {
		return dependencyLess(result[i], result[j])
	})
	return result
}

// unionPaths is every path of a and b, sorted, or nil, the whole
// dependency, when either is.
func unionPaths(a, b []string) []string {
	if a == nil || b == nil {
		return nil
	}
	union := slices.Concat(a, b)
	slices.Sort(union)
	return slices.Compact(union)
}

func dependencyKey(dep dependency.Dependency) string {
	return dep.Module + "@" + dep.Version
}

func dependencyLess(a, b dependency.Dependency) bool {
	if a.Module != b.Module {
		return a.Module < b.Module
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	return a.Dir < b.Dir
}

func hasFindings(report *entities.InterimReport) bool {
	if report == nil {
		return false
	}
	for _, f := range report.Findings {
		if len(f.CryptographicAssets) > 0 {
			return true
		}
	}
	return false
}

// detachDeadlineKeepCancel returns a context whose deadline is independent of
// the parent's, but which is still canceled when the parent is *explicitly*
// canceled (parent.Err() == context.Canceled). When the parent is canceled
// because its own deadline expired (parent.Err() == context.DeadlineExceeded),
// the returned context is *not* canceled.
//
// This lets long-running children (per-dep opengrep scans) ignore an exhausted
// global scan budget while still honoring an interactive abort. Each child is
// expected to set its own appropriate timeout downstream.
//
// The caller MUST call the returned cancel func to release resources.
func detachDeadlineKeepCancel(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	// A warm cache hit can finish before the forwarding goroutine is scheduled.
	if parent.Err() == context.Canceled {
		cancel()
	}
	go func() {
		select {
		case <-parent.Done():
			if parent.Err() == context.Canceled {
				cancel()
			}
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}
