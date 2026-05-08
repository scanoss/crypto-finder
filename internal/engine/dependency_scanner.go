package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/skip"
	"github.com/scanoss/crypto-finder/internal/utils"
)

// maxWorkers caps the number of concurrent dependency scans to avoid
// overwhelming the system with too many opengrep processes.
const maxWorkers = 8

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
	orchestrator  *Orchestrator
	resolver      dependency.Resolver
	cgBuilder     *callgraph.Builder
	findingsCache FindingsCache
}

// NewDependencyScanner creates a new dependency scanner.
// The optional findingsCache, if non-nil, is used to skip rescanning dependencies
// whose results are already cached (keyed by module@version + rules hash).
func NewDependencyScanner(
	orchestrator *Orchestrator,
	resolver dependency.Resolver,
	cgBuilder *callgraph.Builder,
	findingsCache FindingsCache,
) *DependencyScanner {
	return &DependencyScanner{
		orchestrator:  orchestrator,
		resolver:      resolver,
		cgBuilder:     cgBuilder,
		findingsCache: findingsCache,
	}
}

// DepScanResult holds the aggregated result of the dependency scanning pipeline.
// It surfaces the crypto-scoped call graph so callers can export or inspect it.
type DepScanResult struct {
	Report       *entities.InterimReport
	CallGraph    *callgraph.CallGraph
	RootModule   string
	Ecosystem    string
	ProjectRoot  string
	Dependencies []dependency.Dependency
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
	err    error
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

	resolved, filteredRulePaths, rulesHash, err := ds.prepareDependencyScan(ctx, opts)
	if err != nil {
		return nil, err
	}
	if len(resolved.Dependencies) == 0 {
		return ds.emptyDependencyScanResult(userReport, resolved, opts), nil
	}

	depResults := ds.scanDependenciesParallel(ctx, resolved.Dependencies, filteredRulePaths, rulesHash, opts)
	logDependencyScanSummary(summarizeDependencyResults(depResults))

	graph, err := ds.buildDependencyCallGraph(opts.ScanOptions.Target, resolved, depResults)
	if err != nil {
		return nil, failure.WrapUnknown(
			err,
			failure.CodeCallGraphBuildFailed,
			failure.StageCallGraph,
			"failed to build call graph",
		)
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
		Report:       result,
		CallGraph:    graph,
		RootModule:   resolved.RootModule,
		Ecosystem:    ds.resolver.Ecosystem(),
		ProjectRoot:  opts.ScanOptions.Target,
		Dependencies: canonicalDependencies(resolved.Dependencies),
	}, nil
}

func (ds *DependencyScanner) prepareDependencyScan(
	ctx context.Context,
	opts DepScanOptions,
) (*dependency.ResolveResult, []string, string, error) {
	log.Info().Str("target", opts.ScanOptions.Target).Msg("Resolving dependencies")
	resolved, err := ds.resolver.Resolve(ctx, opts.ScanOptions.Target)
	if err != nil {
		return nil, nil, "", failure.WrapUnknown(
			err,
			failure.CodeDependencyResolutionFailed,
			failure.StageDependency,
			"dependency resolution failed",
		)
	}
	log.Info().Int("deps", len(resolved.Dependencies)).Msg("Resolved dependencies")
	if len(resolved.Dependencies) == 0 {
		return resolved, nil, "", nil
	}

	filteredRulePaths, err := ds.loadFilteredRules(ds.resolver.Ecosystem())
	if err != nil {
		return nil, nil, "", failure.WrapUnknown(
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

	return resolved, filteredRulePaths, ds.computeRulesHash(filteredRulePaths), nil
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
	}
}

type dependencyScanSummary struct {
	depsWithFindings  int
	totalDepFindings  int
	depsScanned       int
	depsSkippedSource int
	depsFailed        int
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
	log.Info().
		Int("depsScanned", summary.depsScanned).
		Int("depsSkippedNoSource", summary.depsSkippedSource).
		Int("depsFailed", summary.depsFailed).
		Int("depsWithFindings", summary.depsWithFindings).
		Int("totalDepFindings", summary.totalDepFindings).
		Msg("Dependency scanning complete")
}

func (ds *DependencyScanner) buildDependencyCallGraph(
	userTarget string,
	resolved *dependency.ResolveResult,
	depResults []depScanResult,
) (*callgraph.CallGraph, error) {
	sets := ds.collectPackageSets(userTarget, resolved, depResults)
	return ds.cgBuilder.BuildFromDirectories(sets.graphPackages, sets.typeOnlyPackages)
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
func (ds *DependencyScanner) loadFilteredRules(ecosystem string) ([]string, error) {
	allRules, err := ds.orchestrator.rulesManager.Load()
	if err != nil {
		return nil, err
	}

	languages := ecosystemToLanguages(ecosystem)
	if len(languages) == 0 {
		return allRules, nil
	}

	return filterRulesByLanguages(allRules, languages), nil
}

// scanDependenciesParallel scans all dependencies concurrently using a worker pool.
func (ds *DependencyScanner) scanDependenciesParallel(
	ctx context.Context,
	deps []dependency.Dependency,
	rulePaths []string,
	rulesHash string,
	opts DepScanOptions,
) []depScanResult {
	workers := opts.Workers
	if workers <= 0 {
		workers = min(max(runtime.NumCPU()/2, 1), maxWorkers)
	}

	orderedDeps := canonicalDependencies(deps)

	type depWork struct {
		index int
		key   string
		dep   dependency.Dependency
	}
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

	log.Info().
		Int("deps", len(orderedDeps)).
		Int("scannableDeps", len(work)).
		Int("workers", workers).
		Msg("Starting parallel dependency scanning")

	if len(work) == 0 {
		return outcomes
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
	// opengrep invocation inside scanSingleDep gets its own fresh per-call
	// timeout downstream, which is now unaffected by parent deadline pressure.
	depCtx, depCancel := detachDeadlineKeepCancel(ctx)
	defer depCancel()

	// Worker pool
	workCh := make(chan depWork, len(work))
	resultCh := make(chan depScanResult, len(work))

	var wg sync.WaitGroup
	for range min(workers, len(work)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range workCh {
				result := ds.scanSingleDep(depCtx, item.dep, item.key, rulePaths, rulesHash, opts)
				result.index = item.index
				resultCh <- result
			}
		}()
	}

	// Send work
	for _, w := range work {
		workCh <- w
	}
	close(workCh)

	// Wait for all workers to finish, then close results
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect results
	for result := range resultCh {
		if result.err != nil {
			log.Warn().Err(result.err).Str("module", result.dep.Module).Msg("Failed to scan dependency source")
		}
		outcomes[result.index] = result
	}

	return outcomes
}

// scanSingleDep scans a single dependency using the orchestrator.
// If a findings cache is configured and rulesHash is non-empty, it checks the cache
// before scanning and stores the result after a successful scan.
func (ds *DependencyScanner) scanSingleDep(
	ctx context.Context,
	dep dependency.Dependency,
	key string,
	rulePaths []string,
	rulesHash string,
	opts DepScanOptions,
) depScanResult {
	cacheKey := key + ":" + rulesHash
	if opts.ScanOptions.JavaRuntimeCacheToken != "" {
		cacheKey += ":" + opts.ScanOptions.JavaRuntimeCacheToken
	}

	// Check cache
	if ds.findingsCache != nil && rulesHash != "" {
		if report, ok, err := ds.findingsCache.Get(ctx, cacheKey); err == nil && ok {
			log.Info().
				Str("module", dep.Module).
				Str("version", dep.Version).
				Msg("Cache hit for dependency scan")
			return depScanResult{key: key, dep: dep, report: report, status: depScanStatusScanned}
		} else if err != nil {
			log.Warn().Err(err).Str("module", dep.Module).Msg("Cache read error, scanning normally")
		}
	}

	log.Info().Str("module", dep.Module).Str("version", dep.Version).Msg("Scanning dependency")

	depOpts := ds.buildDepScanOptions(&dep, rulePaths, opts)
	report, err := ds.orchestrator.Scan(ctx, depOpts)
	log.Info().
		Str("module", dep.Module).
		Str("version", dep.Version).
		Msg("Scanned dependency")

	// Store in cache on success
	if err == nil && ds.findingsCache != nil && rulesHash != "" {
		if putErr := ds.findingsCache.Put(ctx, cacheKey, report); putErr != nil {
			log.Warn().Err(putErr).Str("module", dep.Module).Msg("Failed to cache scan result")
		}
	}

	return depScanResult{
		key:    key,
		dep:    dep,
		report: report,
		status: scanStatusForError(err),
		err:    err,
	}
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
	// Preserve only built-in test exclusions for dependency scans. Other user/project
	// skip patterns should not hide dependency source files.
	depOpts.ScannerConfig.SkipPatterns = skip.OnlyDefaultTestPatterns(depOpts.ScannerConfig.SkipPatterns)
	return depOpts
}

// packageSets separates dependencies into two groups for the two-phase callgraph build.
type packageSets struct {
	// graphPackages get full source parsing: user code + deps with crypto findings.
	graphPackages []callgraph.PackageDir
	// typeOnlyPackages are used only for bytecode type indexing (no source parsing).
	// This preserves type resolution accuracy while avoiding expensive parsing of
	// deps that have no crypto findings.
	typeOnlyPackages []callgraph.PackageDir
}

// collectPackageSets builds two lists of PackageDirs for the two-phase callgraph build.
// graphPackages: user code + deps with findings (full source parsing).
// typeOnlyPackages: deps without findings (bytecode type index only).
func (ds *DependencyScanner) collectPackageSets(
	userTarget string,
	resolved *dependency.ResolveResult,
	depResults []depScanResult,
) packageSets {
	sets := packageSets{}

	if len(resolved.WorkspaceMembers) > 0 {
		// Workspace project: each member is a separate package root
		for _, member := range resolved.WorkspaceMembers {
			sets.graphPackages = append(sets.graphPackages, callgraph.PackageDir{
				Dir:        member.Dir,
				ImportPath: member.Name,
			})
		}
	} else {
		// Single-project: the target directory is the package root
		sets.graphPackages = append(sets.graphPackages, callgraph.PackageDir{
			Dir:        userTarget,
			ImportPath: resolved.RootModule,
		})
	}

	// Split deps: findings deps get full source parsing; others get bytecode-only type index.
	for i := range depResults {
		result := &depResults[i]
		pkg := callgraph.PackageDir{
			Dir:                  result.dep.Dir,
			ImportPath:           result.dep.Module,
			Version:              result.dep.Version,
			CompiledArtifactPath: result.dep.CompiledArtifactPath,
		}
		if result.status == depScanStatusScanned && result.report != nil && hasFindings(result.report) && result.dep.Dir != "" {
			sets.graphPackages = append(sets.graphPackages, pkg)
			continue
		}

		if ds.resolver.Ecosystem() == "java" && result.dep.Module != "" && result.dep.Version != "" {
			sets.typeOnlyPackages = append(sets.typeOnlyPackages, pkg)
		}
	}

	return sets
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
	for i := range report.Findings {
		finding := &report.Findings[i]

		for j := range finding.CryptographicAssets {
			asset := &finding.CryptographicAssets[j]

			// Add dependency attribution as structured fields
			asset.Source = findingSourceDependency
			asset.DependencyInfo = &entities.DependencyInfo{
				Module:  dep.Module,
				Version: dep.Version,
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

// AssignFindingIDs ensures every finding asset in the report has a stable short hash
// suitable for joining the main report to the callgraph export.
func AssignFindingIDs(report *entities.InterimReport) {
	if report == nil {
		return
	}

	for i := range report.Findings {
		finding := &report.Findings[i]
		for j := range finding.CryptographicAssets {
			asset := &finding.CryptographicAssets[j]
			asset.FindingID = generateFindingID(findingIDPath(*finding, *asset), asset.StartLine, asset.Rules)
		}
	}
}

// generateFindingID produces a stable short hash for a finding.
// It hashes file_path + start_line + first_rule_id and returns the first 8 hex chars.
func generateFindingID(filePath string, startLine int, rules []entities.RuleInfo) string {
	ruleID := ""
	if len(rules) > 0 {
		ruleID = rules[0].ID
	}
	input := filePath + ":" + strconv.Itoa(startLine) + ":" + ruleID
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
	for _, f := range report.Findings {
		if len(f.CryptographicAssets) > 0 {
			return true
		}
	}
	return false
}

// detachDeadlineKeepCancel returns a context whose deadline is independent of
// the parent's, but which is still cancelled when the parent is *explicitly*
// cancelled (parent.Err() == context.Canceled). When the parent is cancelled
// because its own deadline expired (parent.Err() == context.DeadlineExceeded),
// the returned context is *not* cancelled.
//
// This lets long-running children (per-dep opengrep scans) ignore an exhausted
// global scan budget while still honoring an interactive abort. Each child is
// expected to set its own appropriate timeout downstream.
//
// The caller MUST call the returned cancel func to release resources.
func detachDeadlineKeepCancel(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
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
