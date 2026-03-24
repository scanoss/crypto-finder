package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"crypto/sha256"
	"encoding/hex"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// maxWorkers caps the number of concurrent dependency scans to avoid
// overwhelming the system with too many opengrep processes.
const maxWorkers = 8

// DepScanOptions configures the dependency scanning behavior.
type DepScanOptions struct {
	// MaxDepth limits recursive dependency resolution (-1 for unlimited).
	MaxDepth int
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
	Report     *entities.InterimReport
	CallGraph  *callgraph.CallGraph
	RootModule string
	Ecosystem  string
}

// depScanResult holds the result of scanning a single dependency.
type depScanResult struct {
	key    string
	dep    *dependency.Dependency
	report *entities.InterimReport
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

	// Step 1: Resolve dependencies
	log.Info().Str("target", opts.ScanOptions.Target).Msg("Resolving dependencies")
	resolved, err := ds.resolver.Resolve(ctx, opts.ScanOptions.Target, opts.MaxDepth)
	if err != nil {
		return nil, fmt.Errorf("dependency resolution failed: %w", err)
	}
	log.Info().
		Int("deps", len(resolved.Dependencies)).
		Msg("Resolved dependencies")

	if len(resolved.Dependencies) == 0 {
		log.Info().Msg("No dependencies found, skipping dependency scan")
		return &DepScanResult{
			Report:     userReport,
			RootModule: resolved.RootModule,
			Ecosystem:  ds.resolver.Ecosystem(),
		}, nil
	}

	// Step 2: Pre-load rules once and filter by ecosystem language
	filteredRulePaths, err := ds.loadFilteredRules(ds.resolver.Ecosystem())
	if err != nil {
		return nil, fmt.Errorf("failed to load rules for dependency scanning: %w", err)
	}
	log.Info().
		Int("rules", len(filteredRulePaths)).
		Str("ecosystem", ds.resolver.Ecosystem()).
		Msg("Filtered rules by language")

	// Compute rules hash for cache keying (once per scan, not per-dep)
	var rulesHash string
	if ds.findingsCache != nil {
		rulesHash, err = ComputeRulesHash(filteredRulePaths)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to compute rules hash, findings cache disabled for this scan")
			rulesHash = ""
		}
	}

	// Step 3: Scan dependencies in parallel
	depReports, depMap := ds.scanDependenciesParallel(ctx, resolved.Dependencies, filteredRulePaths, rulesHash, opts)

	// Count findings across all deps
	depsWithFindings := 0
	totalDepFindings := 0
	for _, report := range depReports {
		if hasFindings(report) {
			depsWithFindings++
			for _, f := range report.Findings {
				totalDepFindings += len(f.CryptographicAssets)
			}
		}
	}

	log.Info().
		Int("depsScanned", len(depReports)).
		Int("depsWithFindings", depsWithFindings).
		Int("totalDepFindings", totalDepFindings).
		Msg("Dependency scanning complete")

	// Step 4: Build call graph (user code + deps with findings)
	// Always build the graph when dependency scanning is enabled — even with zero
	// dependency findings, call chain enrichment of user code findings is valuable.
	packages := ds.collectPackageDirs(opts.ScanOptions.Target, resolved, depReports, depMap)
	graph, err := ds.cgBuilder.BuildFromDirectories(packages)
	if err != nil {
		return nil, fmt.Errorf("failed to build call graph: %w", err)
	}

	// Step 5: Trace findings and add attribution metadata
	tracer := callgraph.NewTracer(graph, ds.cgBuilder.PackageSeparator())
	userPackages := ds.buildUserPackages(resolved)

	for key, report := range depReports {
		dep := depMap[key]
		ds.attributeFindings(report, dep, opts.ScanOptions.Target, tracer, userPackages)
	}

	// Step 6: Merge all findings into user report
	result := ds.mergeReports(userReport, depReports)

	log.Info().Dur("duration", time.Since(pipelineStart)).Msg("Total dependency scan pipeline")

	return &DepScanResult{
		Report:     result,
		CallGraph:  graph,
		RootModule: resolved.RootModule,
		Ecosystem:  ds.resolver.Ecosystem(),
	}, nil
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
) (map[string]*entities.InterimReport, map[string]*dependency.Dependency) {
	workers := opts.Workers
	if workers <= 0 {
		workers = min(max(runtime.NumCPU()/2, 1), maxWorkers)
	}

	// Deduplicate deps by module@version
	type depWork struct {
		key string
		dep *dependency.Dependency
	}
	seen := make(map[string]bool)
	work := make([]depWork, 0, len(deps))
	for i := range deps {
		key := deps[i].Module + "@" + deps[i].Version
		if seen[key] {
			continue
		}
		seen[key] = true
		work = append(work, depWork{key: key, dep: &deps[i]})
	}

	log.Info().Int("deps", len(work)).Int("workers", workers).Msg("Starting parallel dependency scanning")

	// Worker pool
	workCh := make(chan depWork, len(work))
	resultCh := make(chan depScanResult, len(work))

	var wg sync.WaitGroup
	for range min(workers, len(work)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range workCh {
				result := ds.scanSingleDep(ctx, item.dep, item.key, rulePaths, rulesHash, opts)
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
	depReports := make(map[string]*entities.InterimReport, len(work))
	depMap := make(map[string]*dependency.Dependency, len(work))
	for result := range resultCh {
		if result.err != nil {
			log.Warn().Err(result.err).Str("module", result.dep.Module).Msg("Failed to scan dependency, skipping")
			continue
		}
		depReports[result.key] = result.report
		depMap[result.key] = result.dep
	}

	return depReports, depMap
}

// scanSingleDep scans a single dependency using the orchestrator.
// If a findings cache is configured and rulesHash is non-empty, it checks the cache
// before scanning and stores the result after a successful scan.
func (ds *DependencyScanner) scanSingleDep(
	ctx context.Context,
	dep *dependency.Dependency,
	key string,
	rulePaths []string,
	rulesHash string,
	opts DepScanOptions,
) depScanResult {
	cacheKey := key + ":" + rulesHash

	// Check cache
	if ds.findingsCache != nil && rulesHash != "" {
		if report, ok, err := ds.findingsCache.Get(ctx, cacheKey); err == nil && ok {
			log.Info().
				Str("module", dep.Module).
				Str("version", dep.Version).
				Msg("Cache hit for dependency scan")
			return depScanResult{key: key, dep: dep, report: report}
		} else if err != nil {
			log.Warn().Err(err).Str("module", dep.Module).Msg("Cache read error, scanning normally")
		}
	}

	log.Info().Str("module", dep.Module).Str("version", dep.Version).Msg("Scanning dependency")

	depOpts := ds.buildDepScanOptions(dep, rulePaths, opts)
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
		err:    err,
	}
}

// buildDepScanOptions creates ScanOptions for scanning a specific dependency.
func (ds *DependencyScanner) buildDepScanOptions(dep *dependency.Dependency, rulePaths []string, opts DepScanOptions) ScanOptions {
	depOpts := opts.ScanOptions
	depOpts.Target = dep.Dir
	// Use pre-loaded, language-filtered rules
	depOpts.RulePaths = rulePaths
	// Set language hint so the orchestrator skips language detection
	depOpts.LanguageHint = ecosystemToLanguages(ds.resolver.Ecosystem())
	// Clear skip patterns for dependency scanning — we want to scan everything
	depOpts.ScannerConfig.SkipPatterns = nil
	return depOpts
}

// collectPackageDirs builds the list of PackageDirs for call graph construction.
// For workspace projects (e.g., Cargo workspaces), each member gets its own entry
// so that functions are assigned the correct package paths.
func (ds *DependencyScanner) collectPackageDirs(
	userTarget string,
	resolved *dependency.ResolveResult,
	depReports map[string]*entities.InterimReport,
	depMap map[string]*dependency.Dependency,
) []callgraph.PackageDir {
	baseCap := 1
	if len(resolved.WorkspaceMembers) > 0 {
		baseCap = len(resolved.WorkspaceMembers)
	}
	packages := make([]callgraph.PackageDir, 0, baseCap+len(depReports))

	if len(resolved.WorkspaceMembers) > 0 {
		// Workspace project: each member is a separate package root
		for _, member := range resolved.WorkspaceMembers {
			packages = append(packages, callgraph.PackageDir{
				Dir:        member.Dir,
				ImportPath: member.Name,
			})
		}
	} else {
		// Single-project: the target directory is the package root
		packages = append(packages, callgraph.PackageDir{
			Dir:        userTarget,
			ImportPath: resolved.RootModule,
		})
	}

	// Include ALL dependencies for complete type resolution.
	// Even deps without crypto findings contribute type declarations
	// (e.g., JwtBuilder interface) needed to resolve fluent chains.
	for key := range depMap {
		dep := depMap[key]
		packages = append(packages, callgraph.PackageDir{
			Dir:        dep.Dir,
			ImportPath: dep.Module,
		})
	}

	return packages
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
	userTarget string,
	tracer *callgraph.Tracer,
	userPackages map[string]bool,
) {
	depPrefix := dep.Module + "@" + dep.Version + "/"

	for i := range report.Findings {
		finding := &report.Findings[i]

		for j := range finding.CryptographicAssets {
			asset := &finding.CryptographicAssets[j]

			// Add dependency attribution as structured fields
			asset.Source = "dependency"
			asset.DependencyInfo = &entities.DependencyInfo{
				Module:  dep.Module,
				Version: dep.Version,
			}

			// Try to trace back to user code
			// Finding file paths are relative to the dep dir; the call graph uses absolute paths
			absFilePath := finding.FilePath
			if !filepath.IsAbs(absFilePath) {
				absFilePath = filepath.Join(dep.Dir, absFilePath)
			}
			containingFn := tracer.FindContainingFunction(absFilePath, asset.StartLine)
			if containingFn != nil {
				asset.DependencyInfo.Function = containingFn.ID.String()
			}
		}

		// Rewrite finding file path to module@version/relative format
		finding.FilePath = depPrefix + finding.FilePath
	}
}

// mergeReports combines the user report with all dependency findings.
// Reachability filtering is handled by the callgraph export (backward_paths),
// not by the interim report.
func (ds *DependencyScanner) mergeReports(
	userReport *entities.InterimReport,
	depReports map[string]*entities.InterimReport,
) *entities.InterimReport {
	merged := &entities.InterimReport{
		Version:  userReport.Version,
		Tool:     userReport.Tool,
		Findings: make([]entities.Finding, 0, len(userReport.Findings)),
	}

	// Mark user code findings as direct
	for _, finding := range userReport.Findings {
		for j := range finding.CryptographicAssets {
			if finding.CryptographicAssets[j].Source == "" {
				finding.CryptographicAssets[j].Source = "direct"
			}
		}
		merged.Findings = append(merged.Findings, finding)
	}

	// Include all dependency findings
	for _, report := range depReports {
		for _, finding := range report.Findings {
			merged.Findings = append(merged.Findings, finding)
		}
	}

	// Generate stable finding IDs for all assets
	for i := range merged.Findings {
		finding := &merged.Findings[i]
		for j := range finding.CryptographicAssets {
			asset := &finding.CryptographicAssets[j]
			asset.FindingID = generateFindingID(finding.FilePath, asset.StartLine, asset.Rules)
		}
	}

	return merged
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

func hasFindings(report *entities.InterimReport) bool {
	for _, f := range report.Findings {
		if len(f.CryptographicAssets) > 0 {
			return true
		}
	}
	return false
}
