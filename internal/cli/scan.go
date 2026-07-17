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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	api "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/cache"
	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/config"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/enricher"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/javaruntime"
	"github.com/scanoss/crypto-finder/internal/language"
	"github.com/scanoss/crypto-finder/internal/output"
	"github.com/scanoss/crypto-finder/internal/rules"
	scanutil "github.com/scanoss/crypto-finder/internal/scan"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/scanner/opengrep"
	"github.com/scanoss/crypto-finder/internal/scanner/semgrep"
	"github.com/scanoss/crypto-finder/internal/skip"
)

const (
	defaultScanner        = opengrep.ScannerName
	formatJSON            = "json"
	formatText            = "text"
	defaultFormat         = formatJSON
	defaultTimeout        = "10m"
	defaultRulesetName    = "dca"
	defaultRulesetVersion = "latest"
	ecosystemJava         = "java"
	ecosystemNode         = "node"

	findingsCacheBackendDisk     = "disk"
	findingsCacheBackendNone     = "none"
	findingsCacheBackendPostgres = "postgres"
)

// AllowedFindingsCacheBackends lists the FindingsCache backends supported by the tool.
var AllowedFindingsCacheBackends = []string{findingsCacheBackendDisk, findingsCacheBackendNone, findingsCacheBackendPostgres}

// AllowedScanners lists the scanners supported by the tool.
// TODO: We'll support more scanners in the future (e.g., cbom-toolkit).
var AllowedScanners = []string{opengrep.ScannerName, semgrep.ScannerName}

// SupportedFormats lists the output formats supported by the tool.
var SupportedFormats = []string{formatJSON, "cyclonedx"}

var (
	scanRules                []string
	scanRuleDirs             []string
	scanScanner              string
	scanFormat               string
	scanOutput               string
	scanLanguages            []string
	scanFailOnFind           bool
	scanTimeout              string
	scanNoRemoteRules        bool
	scanNoCache              bool
	scanAPIKey               string
	scanAPIURL               string
	scanStrict               bool
	scanMaxStaleAge          string
	scanNoDedup              bool
	scanInterfile            bool
	scanDependencies         bool
	scanIncludeTests         bool
	scanNoDefaultExclusions  bool     // --no-default-exclusions flag
	scanExcludePatterns      []string // --exclude flag (repeatable)
	scanDepEcosystem         string
	scanExportCallgraph      string
	scanExportCgFormat       string
	scanExportGraphFragment  string
	scanExportGfFormat       string
	scanDepWorkers           int
	scanJavaJDKMajor         string
	scanJavaJDKHomes         []string
	scanJavaCompiledArtifact string
	scanFindingsCache        string
)

var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Scan source code for cryptographic usage",
	Long: `Scan source code repositories for cryptographic algorithm usage.

	The scan command executes a scanner (default: OpenGrep) against the target
	directory or file using specified rules. By default, it outputs findings to
	stdout in JSON format. Use --output to write to a file instead.

	Examples:
	  # Scan with default JSON output to stdout
	  crypto-finder scan --rules-dir ./rules /path/to/code

	  # Save output to a file
	  crypto-finder scan --rules-dir ./rules --output results.json /path/to/code

	  # Pipe output to jq for processing
	  crypto-finder scan --rules-dir ./rules /path/to/code | jq '.findings | length'

	  # Scan with multiple rule files
	  crypto-finder scan --rules rule1.yaml --rules rule2.yaml /path/to/code

	  # Override language detection
	  crypto-finder scan --languages java,python --rules-dir ./rules/ /path/to/code

	  # Fail on findings (for CI/CD)
	  crypto-finder scan --fail-on-findings --rules-dir ./rules/ /path/to/code`,
	Args: func(_ *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("you must specify a target directory to scan")
		}
		return nil
	},
	RunE: runScan,
}

func init() {
	// Add flags
	scanCmd.Flags().StringArrayVarP(&scanRules, "rules", "r", []string{}, "Rule file path (repeatable)")
	scanCmd.Flags().StringArrayVar(&scanRuleDirs, "rules-dir", []string{}, "Rule directory path (repeatable)")
	scanCmd.Flags().StringVar(&scanScanner, "scanner", defaultScanner, fmt.Sprintf("Scanner to use (default: %s)", defaultScanner))
	scanCmd.Flags().StringVarP(&scanFormat, "format", "f", defaultFormat, "Output format: json, cyclonedx (default: json)")
	scanCmd.Flags().StringVarP(&scanOutput, "output", "o", "", "Output file path (default: stdout)")
	scanCmd.Flags().StringSliceVar(&scanLanguages, "languages", []string{}, "Override language detection (comma-separated)")
	scanCmd.Flags().BoolVar(&scanFailOnFind, "fail-on-findings", false, "Exit with error if findings detected")
	scanCmd.Flags().StringVarP(&scanTimeout, "timeout", "t", defaultTimeout, "Scan timeout (e.g., 10m, 1h, 30d, 2w)")
	scanCmd.Flags().BoolVar(&scanNoRemoteRules, "no-remote-rules", false, "Disable default remote ruleset")
	scanCmd.Flags().BoolVar(&scanNoCache, "no-cache", false, "Force fresh download of remote rules, bypass cache")
	scanCmd.Flags().StringVar(&scanAPIKey, "api-key", "", "SCANOSS API key")
	scanCmd.Flags().StringVar(&scanAPIURL, "api-url", "", "SCANOSS API base URL")
	scanCmd.Flags().BoolVar(&scanStrict, "strict", false, "Fail if cache expired and API unreachable (no stale cache fallback)")
	scanCmd.Flags().StringVar(&scanMaxStaleAge, "max-stale-age", "30d", "Maximum age for stale cache fallback (e.g., 30d, 720h, 2w, max: 90d)")
	scanCmd.Flags().BoolVar(&scanNoDedup, "no-dedup", false, "Disable per-line deduplication of findings")
	scanCmd.Flags().BoolVar(&scanInterfile, "interfile", false, "Enable cross-file analysis (Semgrep Pro only, adds --pro flag)")
	scanCmd.Flags().BoolVar(&scanDependencies, "scan-dependencies", false, "Enable recursive dependency scanning for cryptographic usage")
	scanCmd.Flags().BoolVar(&scanIncludeTests, "include-tests", false, "Include test sources in findings and dependency scans")
	scanCmd.Flags().BoolVar(&scanNoDefaultExclusions, "no-default-exclusions", false,
		"Disable the built-in default directory exclusions (e.g. docs, vendor, node_modules, dist, build, ...). "+
			"Affects the primary scan only; dependency scans still skip test patterns controlled by --include-tests. "+
			"Language detection will walk the full tree, which may significantly slow down scans on large repos. "+
			"Use --exclude to surgically re-add specific directories.")
	scanCmd.Flags().StringSliceVar(&scanExcludePatterns, "exclude", nil,
		"Glob pattern to skip during scanning (repeatable, e.g. --exclude vendor --exclude \"build/**\"). "+
			"Same gitignore-style syntax as scanoss.json settings.skip.patterns.scanning. "+
			"Patterns are added on top of the built-in defaults unless --no-default-exclusions is also set. "+
			"Duplicates are removed automatically.")
	scanCmd.Flags().StringVar(&scanDepEcosystem, "dep-ecosystem", "auto", "Dependency ecosystem: auto, go, java, python, rust")

	scanCmd.Flags().IntVar(&scanDepWorkers, "dep-workers", 0, "Number of parallel dependency scan workers (default: half of CPU cores, max 8; Java max 2)")
	scanCmd.Flags().StringVar(&scanFindingsCache, "findings-cache", "", fmt.Sprintf("FindingsCache backend: %v (default: %s; can also be set via SCANOSS_FINDINGS_CACHE_BACKEND)", AllowedFindingsCacheBackends, config.DefaultFindingsCacheBackend))
	scanCmd.Flags().StringVar(&scanExportCallgraph, "export-callgraph", "", "Export the crypto-scoped call graph to a file")
	scanCmd.Flags().StringVar(&scanExportCgFormat, "export-callgraph-format", "json", "Call graph export format (only json is supported)")
	scanCmd.Flags().StringVar(&scanExportGraphFragment, "export-graph-fragment", "", "Export a reusable structural graph fragment to a file")
	scanCmd.Flags().StringVar(&scanExportGfFormat, "export-graph-fragment-format", "json", "Graph fragment export format (only json is supported)")
	scanCmd.Flags().StringVar(&scanJavaJDKMajor, "java-jdk-major", "", "Java JDK major for Java dependency resolution/type enrichment: auto, 8, 11, 17, 21")
	scanCmd.Flags().StringArrayVar(&scanJavaJDKHomes, "java-jdk-home", []string{}, "Java JDK home mapping in the form <major>=<path> (repeatable)")
	scanCmd.Flags().StringVar(&scanJavaCompiledArtifact, "java-compiled-artifact", "", "Compiled Java artifact path used for standalone callgraph/type enrichment")
}

func callGraphTargetDir(target string) (string, error) {
	info, err := os.Stat(target)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return target, nil
	}
	return filepath.Dir(target), nil
}

func ecosystemFromHints(target string, languageHints []string) string {
	// Pick the first supported ecosystem from the hints. Auto-detected hints
	// arrive ordered by dominance (file count, see EnryDetector.Detect), so the
	// first supported entry is the repository's primary ecosystem — a lone
	// helper script (e.g. policy-check.py in a Java repo) cannot win. Hints may
	// also include unsupported languages (e.g. "xml"), so we scan past them
	// instead of trusting languageHints[0] blindly. When hints come from an
	// explicit --languages flag, the user's ordering is honored as-is.
	for _, hint := range languageHints {
		switch hint {
		case "c", "go", ecosystemJava, "python", "rust":
			return hint
		case ecosystemNode, "javascript", "typescript":
			return ecosystemNode
		}
	}

	targetDir, err := callGraphTargetDir(target)
	if err == nil {
		if ecosystem := scanutil.DetectEcosystem(targetDir); ecosystem != "" {
			return ecosystem
		}
	}

	switch filepath.Ext(target) {
	case ".c", ".h":
		return "c"
	case ".go":
		return "go"
	case ".java":
		return ecosystemJava
	case ".py":
		return "python"
	case ".rs":
		return "rust"
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts":
		return ecosystemNode
	default:
		return ""
	}
}

func resolveJavaRuntimeConfig(cfg *config.Config) (javaruntime.Config, error) {
	major := cfg.GetJavaJDKMajor()
	if scanJavaJDKMajor != "" {
		major = scanJavaJDKMajor
	}

	homes := cfg.GetJavaJDKHomes()
	if len(scanJavaJDKHomes) > 0 {
		flagHomes, err := javaruntime.ParseHomeEntries(scanJavaJDKHomes)
		if err != nil {
			return javaruntime.Config{}, err
		}
		homes = javaruntime.MergeHomes(homes, flagHomes)
	}

	return javaruntime.NewConfig(major, homes)
}

func newCallGraphBuilder(ecosystem string, javaRuntime javaruntime.Config, includeTests bool) (*callgraph.Builder, error) {
	cgParser := callgraph.NewParserForEcosystem(ecosystem, callgraph.WithIncludeTests(includeTests))
	if cgParser == nil {
		return nil, fmt.Errorf("call graph export is not supported for ecosystem %q", ecosystem)
	}

	cgBuilder := callgraph.NewBuilderForEcosystem(ecosystem, cgParser)
	if typeResolver := callgraph.NewTypeResolverForEcosystem(ecosystem, javaRuntime); typeResolver != nil {
		if javaResolver, ok := typeResolver.(*callgraph.JavaBytecodeTypeResolver); ok {
			bytecodeCache, err := callgraph.NewDiskBytecodeIndexCache()
			if err != nil {
				log.Warn().Err(err).Msg("Failed to create Java bytecode cache, bytecode indexing will not be cached")
			} else {
				javaResolver.SetBytecodeIndexCache(bytecodeCache)
			}
		}
		cgBuilder.SetTypeResolver(typeResolver)
	}

	return cgBuilder, nil
}

func applyTestSkipPatterns(patterns []string, includeTests bool) []string {
	if includeTests {
		return patterns
	}
	return skip.WithDefaultTestPatterns(patterns)
}

// buildSkipPatterns assembles skip patterns from the configured sources,
// honoring the --no-default-exclusions and --exclude CLI flags. Returns the
// merged, deduplicated pattern list plus a human-readable label for logging.
// The label and pattern list are derived from the same source slice so they
// cannot drift.
//
// On MultiSource.Load failure the function falls back to:
//   - skip.DefaultSkippedDirs when !noDefaults
//   - empty list             when  noDefaults
//
// In both cases any user --exclude patterns are merged into the fallback so
// they are not silently dropped along with the MultiSource error.
func buildSkipPatterns(targetDir string, noDefaults bool, userExcludes []string) (patterns []string, sourceLabel string) {
	sources := make([]skip.PatternSource, 0, 3)

	if !noDefaults {
		sources = append(sources, skip.NewDefaultsSource())
	} else {
		log.Warn().Msg(
			"Default directory exclusions are disabled. Language detection will walk the full tree " +
				"(including node_modules, vendor, dist, etc.), which may significantly increase scan time. " +
				"Use --exclude node_modules --exclude vendor to re-add specific directories.",
		)
	}

	sources = append(sources, skip.NewScanossConfigSourceFromDir(targetDir))

	if len(userExcludes) > 0 {
		sources = append(sources, skip.NewUserExcludeSource(userExcludes))
	}

	multi := skip.NewMultiSource(sources...)
	label := multiSourceLabel(sources, multi)

	loaded, loadErr := multi.Load()
	if loadErr != nil {
		log.Warn().Err(loadErr).Msgf("failed to load skip patterns from %s", label)

		var fallback []string
		if !noDefaults {
			fallback = append(fallback, skip.DefaultSkippedDirs...)
		}
		// Re-merge user excludes — they were in the last source which failed
		// alongside the others; preserve their explicit intent.
		// UserExcludeSource.Load never returns an error (no I/O), so it is safe to ignore.
		if len(userExcludes) > 0 {
			us, _ := skip.NewUserExcludeSource(userExcludes).Load() //nolint:errcheck // UserExcludeSource.Load never returns an error (pure trim, no I/O)
			fallback = append(fallback, us...)
		}
		return fallback, label // error swallowed to mirror pre-refactor behavior
	}

	return loaded, label
}

// multiSourceLabel produces a comma-joined name list for logging.
// MultiSource.Name() returns the opaque "MultiSource(N sources)" for N>1;
// a per-source name list is more actionable in the log line
// "Using N skip patterns from <label>".
//
// The helper is intentionally local to scan.go; it is cosmetic and must not
// modify MultiSource.Name() which has other callers.
func multiSourceLabel(sources []skip.PatternSource, multi *skip.MultiSource) string {
	if len(sources) <= 1 {
		return multi.Name()
	}
	names := make([]string, 0, len(sources))
	for _, s := range sources {
		names = append(names, s.Name())
	}
	return strings.Join(names, ", ")
}

func buildStandaloneCallGraphResult(target string, report *entities.InterimReport, languageHints []string, javaRuntime javaruntime.Config, includeTests bool, compiledArtifact string) (*engine.DepScanResult, error) {
	targetDir, err := callGraphTargetDir(target)
	if err != nil {
		return nil, fmt.Errorf("resolve call graph target: %w", err)
	}

	ecosystem := ecosystemFromHints(target, languageHints)
	if ecosystem == "" {
		return nil, fmt.Errorf("could not determine a supported ecosystem for call graph export")
	}

	cgBuilder, err := newCallGraphBuilder(ecosystem, javaRuntime, includeTests)
	if err != nil {
		return nil, err
	}

	rootModule := scanutil.DetectRootModule(targetDir, ecosystem)
	graph, err := cgBuilder.BuildFromDirectories([]callgraph.PackageDir{{
		Dir:                  targetDir,
		ImportPath:           rootModule,
		CompiledArtifactPath: compiledArtifact,
	}}, nil)
	if err != nil {
		return nil, fmt.Errorf("build call graph: %w", err)
	}

	return &engine.DepScanResult{
		Report:      report,
		CallGraph:   graph,
		RootModule:  rootModule,
		Ecosystem:   ecosystem,
		ProjectRoot: targetDir,
	}, nil
}

//nolint:gocognit,gocyclo,funlen // Main scan orchestration function handles validation, cache management, scanner execution, and output formatting - splitting would reduce clarity
func runScan(_ *cobra.Command, args []string) error {
	target := args[0]

	// Validate flags
	normalizedLanguages, err := scanutil.ValidateFlags(target, scanutil.ValidationOptions{
		RuleFiles:        scanRules,
		RuleDirs:         scanRuleDirs,
		NoRemoteRules:    scanNoRemoteRules,
		Scanner:          scanScanner,
		AllowedScanners:  AllowedScanners,
		Interfile:        scanInterfile,
		InterfileScanner: semgrep.ScannerName,
		Format:           scanFormat,
		SupportedFormats: SupportedFormats,
		Languages:        scanLanguages,
		ScanDependencies: scanDependencies,
		ExportCallgraph:  scanExportCallgraph,
	})
	if err != nil {
		return failure.WrapUnknown(err, failure.CodeInvalidArguments, failure.StageInput, err.Error())
	}
	scanLanguages = normalizedLanguages

	// Parse timeout
	timeout, err := scanutil.ParseDuration(scanTimeout)
	if err != nil {
		return failure.Wrap(
			err,
			failure.CodeInvalidTimeout,
			failure.StageInput,
			fmt.Sprintf("invalid timeout format '%s' (use format like '10m', '1h', '30d', or '2w')", scanTimeout),
			failure.WithDetail("timeout", scanTimeout),
		)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	targetDir, err := callGraphTargetDir(target)
	if err != nil {
		return failure.WrapUnknown(
			err,
			failure.CodeInvalidArguments,
			failure.StageInput,
			fmt.Sprintf("failed to resolve target directory for '%s'", target),
		)
	}

	// Load skip patterns from multiple sources, honoring --no-default-exclusions and --exclude.
	skipPatterns, skipSrcLabel := buildSkipPatterns(targetDir, scanNoDefaultExclusions, scanExcludePatterns)
	skipPatterns = applyTestSkipPatterns(skipPatterns, scanIncludeTests)

	if len(skipPatterns) > 0 {
		log.Info().Msgf("Using %d skip patterns from %s", len(skipPatterns), skipSrcLabel)
	}

	// Create skip matcher for language detection
	skipMatcher := skip.NewGitIgnoreMatcher(skipPatterns)

	// Pre-detect source languages at the CLI layer when the user did not pass
	// --languages. This makes the detected languages available to ancillary
	// features (notably --export-callgraph) that need to know the source
	// ecosystem before the scanner runs. Without this, repositories without
	// a build manifest (pom.xml, build.gradle, setup.py, go.mod, Cargo.toml)
	// fail callgraph export with "could not determine a supported ecosystem".
	// The orchestrator will reuse these hints instead of redetecting.
	if len(scanLanguages) == 0 {
		detected, detectErr := language.NewEnryDetector(skipMatcher).Detect(target)
		if detectErr != nil {
			return failure.WrapUnknown(
				detectErr,
				failure.CodeLanguageDetectionFailed,
				failure.StageScan,
				"failed to detect languages",
			)
		}
		scanLanguages = detected
	}

	cfg := config.GetInstance()
	if err := cfg.Initialize(config.InitOptions{
		APIKey:               scanAPIKey,
		APIURL:               scanAPIURL,
		FindingsCacheBackend: scanFindingsCache,
	}); err != nil {
		return failure.WrapUnknown(
			err,
			failure.CodeConfigInitializationFailed,
			failure.StageConfig,
			"failed to initialize config",
		)
	}
	var (
		javaRuntime         javaruntime.Config
		javaRuntimeResolved bool
	)
	ensureJavaRuntime := func() error {
		if javaRuntimeResolved {
			return nil
		}

		resolvedRuntime, resolveErr := resolveJavaRuntimeConfig(cfg)
		if resolveErr != nil {
			return failure.WrapUnknown(
				resolveErr,
				failure.CodeJavaRuntimeConfigInvalid,
				failure.StageConfig,
				"failed to resolve Java runtime configuration",
			)
		}

		javaRuntime = resolvedRuntime
		javaRuntimeResolved = true
		return nil
	}

	ruleSources := make([]rules.RuleSource, 0)

	if !scanNoRemoteRules {
		log.Info().
			Str("ruleset", defaultRulesetName).
			Str("version", defaultRulesetVersion).
			Bool("no-cache", scanNoCache).
			Msg("Remote rules enabled")

		apiClient := api.NewClient(cfg.GetAPIURL(), cfg.GetAPIKey())
		cacheManager, err := cache.NewManager(apiClient)
		if err != nil {
			return failure.WrapUnknown(
				err,
				failure.CodeCacheInitializationFailed,
				failure.StageConfig,
				"failed to create cache manager",
			)
		}

		cacheManager.SetNoCache(scanNoCache)
		cacheManager.SetStrictMode(scanStrict)

		// Parse and validate max stale age
		maxStaleAge, err := scanutil.ParseDuration(scanMaxStaleAge)
		if err != nil {
			return failure.Wrap(
				err,
				failure.CodeInvalidArguments,
				failure.StageInput,
				fmt.Sprintf("invalid --max-stale-age format '%s' (use format like '30d', '720h', or '2w')", scanMaxStaleAge),
				failure.WithDetail("max_stale_age", scanMaxStaleAge),
			)
		}
		if maxStaleAge > config.MaxStaleCacheAge {
			return failure.New(
				failure.CodeInvalidArguments,
				failure.StageInput,
				fmt.Sprintf("--max-stale-age cannot exceed %s (got: %s)", config.MaxStaleCacheAge, maxStaleAge),
				failure.WithDetail("max_stale_age", maxStaleAge.String()),
			)
		}
		cacheManager.SetMaxStaleCacheAge(maxStaleAge)

		remoteSource := rules.NewRemoteRuleSource(
			ctx,
			defaultRulesetName,
			defaultRulesetVersion,
			cacheManager,
		)
		ruleSources = append(ruleSources, remoteSource)
	}

	// Append local rule sources if specified
	if len(scanRules) > 0 || len(scanRuleDirs) > 0 {
		localSource := rules.NewLocalRuleSource(scanRules, scanRuleDirs)
		ruleSources = append(ruleSources, localSource)
		log.Info().Msgf("Local rules enabled: %s", localSource.Name())
	}

	// Create rules manager with all sources
	var rulesManager *rules.Manager
	switch len(ruleSources) {
	case 0:
		return failure.New(
			failure.CodeRulesLoadFailed,
			failure.StageRules,
			"no rule sources configured (use --rules, --rules-dir, or enable remote rules)",
		)
	case 1:
		rulesManager = rules.NewManager(ruleSources[0])
		log.Info().Msgf("Rules manager configured with source: %s", ruleSources[0].Name())
	default:
		multiSource := rules.NewMultiSource(ruleSources...)
		rulesManager = rules.NewManager(multiSource)
		log.Info().Msgf("Rules manager configured with %d sources", len(ruleSources))
	}

	// Setup dependencies
	langDetector := language.NewEnryDetector(skipMatcher)
	scannerRegistry := scanner.NewRegistry()

	// Register scanners
	scannerRegistry.Register(opengrep.ScannerName, opengrep.NewScanner())
	scannerRegistry.Register(semgrep.ScannerName, semgrep.NewScanner())

	orchestrator := engine.NewOrchestrator(langDetector, rulesManager, scannerRegistry)

	scanOpts := engine.ScanOptions{
		Target:                target,
		ScannerName:           scanScanner,
		LanguageHint:          scanLanguages,
		JavaRuntime:           javaRuntime,
		JavaRuntimeCacheToken: javaRuntime.CacheKeyToken(),
		ScannerConfig: scanner.Config{
			Timeout:      timeout,
			SkipPatterns: skipPatterns,
			DisableDedup: scanNoDedup,
			Interfile:    scanInterfile,
		},
	}

	log.Info().Msgf("Starting scan of %s with scanner '%s'...", target, scanScanner)

	report, err := orchestrator.Scan(ctx, scanOpts)
	if err != nil {
		return err
	}
	var callGraphResult *engine.DepScanResult

	// Dependency scanning phase.
	//nolint:nestif // This orchestration intentionally branches by ecosystem/resolver/parser/caching availability.
	if scanDependencies {
		ecosystem := scanDepEcosystem
		if ecosystem == "auto" {
			ecosystem = ecosystemFromHints(target, scanLanguages)
			if ecosystem == "" {
				ecosystem = scanutil.DetectEcosystem(target)
			}
		}

		if ecosystem != "" {
			depRegistry := dependency.NewRegistry()
			depRegistry.Register("go", dependency.NewGoResolver())
			depRegistry.Register("java", dependency.NewJavaResolver())
			depRegistry.Register("python", dependency.NewPipResolver())
			depRegistry.Register("rust", dependency.NewCargoResolver())

			resolver, resolverErr := depRegistry.Get(ecosystem)
			if resolverErr != nil {
				log.Warn().Err(resolverErr).Str("ecosystem", ecosystem).Msg("No resolver for ecosystem, skipping dependency scan")
			} else {
				if ecosystem == "java" {
					if err := ensureJavaRuntime(); err != nil {
						return err
					}
					scanOpts.JavaRuntime = javaRuntime
					scanOpts.JavaRuntimeCacheToken = javaRuntime.CacheKeyToken()
				}
				if javaResolver, ok := resolver.(dependency.JavaRuntimeConfigurer); ok {
					javaResolver.SetJavaRuntime(javaRuntime)
				}
				cgParser := callgraph.NewParserForEcosystem(ecosystem, callgraph.WithIncludeTests(scanIncludeTests))
				if cgParser == nil {
					log.Warn().Str("ecosystem", ecosystem).Msg("No call graph parser for ecosystem, skipping dependency scan")
				} else {
					cgBuilder, builderErr := newCallGraphBuilder(ecosystem, javaRuntime, scanIncludeTests)
					if builderErr != nil {
						log.Warn().Err(builderErr).Str("ecosystem", ecosystem).Msg("Failed to configure call graph builder, skipping dependency scan")
					} else {
						findingsCache, closeCache, cacheErr := newFindingsCache(ctx, cfg)
						if cacheErr != nil {
							return cacheErr
						}
						defer closeCache()

						depScanner := engine.NewDependencyScanner(orchestrator, resolver, cgBuilder, findingsCache)
						depResult, depErr := depScanner.ScanWithDependencies(ctx, report, engine.DepScanOptions{
							Workers:     scanDepWorkers,
							ScanOptions: scanOpts,
						})
						if depErr != nil {
							return failure.WrapUnknown(
								depErr,
								failure.CodeDependencyResolutionFailed,
								failure.StageDependency,
								"dependency scan failed",
							)
						}
						report = depResult.Report
						callGraphResult = depResult
					}
				}
			}
		} else {
			log.Warn().Msg("Could not detect dependency ecosystem, skipping dependency scan")
		}
	}

	engine.EnsureFindingSources(report)

	if (scanExportCallgraph != "" || scanExportGraphFragment != "") && (callGraphResult == nil || callGraphResult.CallGraph == nil) {
		if ecosystemFromHints(target, scanLanguages) == "java" {
			if err := ensureJavaRuntime(); err != nil {
				return err
			}
		}
		callGraphResult, err = buildStandaloneCallGraphResult(target, report, scanLanguages, javaRuntime, scanIncludeTests, scanJavaCompiledArtifact)
		if err != nil {
			return failure.WrapUnknown(
				err,
				failure.CodeCallGraphBuildFailed,
				failure.StageCallGraph,
				"failed to build call graph for export",
			)
		}
	}

	// Type 2 libraries (fluent/builder/DSL, e.g. Password4J) carry their crypto
	// semantic on the public API boundary, not in a detectable primitive call
	// inside their own source. When such a library is itself being scanned,
	// surface those API methods as crypto entry points using the ruleset's
	// metadata.crypto (the single source of truth) joined on api↔definition.
	// Gated structurally (method definition present, no in-body finding), so it
	// is a no-op when scanning a consumer of the library or a Type 1 library.
	if callGraphResult != nil && callGraphResult.CallGraph != nil {
		if rulePaths, rerr := rulesManager.Load(); rerr == nil {
			engine.SynthesizeRuleCryptoEntryPoints(report, callGraphResult.CallGraph, rulePaths, callGraphResult.Ecosystem)
		} else {
			log.Debug().
				Err(rerr).
				Str("call_graph", fmt.Sprintf("%p", callGraphResult.CallGraph)).
				Str("report", fmt.Sprintf("%p", report)).
				Int("function_count", len(callGraphResult.CallGraph.Functions)).
				Int("finding_count", len(report.Findings)).
				Strs("rule_paths", rulePaths).
				Msg("failed to load rules for synthesis")
		}
	}

	if scanExportCallgraph != "" || scanExportGraphFragment != "" {
		engine.AssignFindingIDs(report)
		if callGraphResult != nil {
			callGraphResult.Report = report
		}
	}

	if scanExportCallgraph != "" {
		exportStart := time.Now()
		log.Info().
			Str("file", scanExportCallgraph).
			Str("format", scanExportCgFormat).
			Msg("Starting call graph export")
		if exportErr := scanutil.ExportCallGraph(scanExportCallgraph, scanExportCgFormat, callGraphResult); exportErr != nil {
			return failure.WrapUnknown(
				exportErr,
				failure.CodeCallGraphExportFailed,
				failure.StageExport,
				"failed to export call graph",
			)
		}
		log.Info().
			Str("file", scanExportCallgraph).
			Dur("duration", time.Since(exportStart)).
			Msg("Call graph export complete")
	}

	if scanExportGraphFragment != "" {
		exportStart := time.Now()
		log.Info().
			Str("file", scanExportGraphFragment).
			Str("format", scanExportGfFormat).
			Msg("Starting graph fragment export")
		if exportErr := scanutil.ExportGraphFragment(scanExportGraphFragment, scanExportGfFormat, callGraphResult); exportErr != nil {
			return failure.WrapUnknown(
				exportErr,
				failure.CodeCallGraphExportFailed,
				failure.StageExport,
				"failed to export graph fragment",
			)
		}
		log.Info().
			Str("file", scanExportGraphFragment).
			Dur("duration", time.Since(exportStart)).
			Msg("Graph fragment export complete")
	}

	report.Version = entities.InterimFormatVersion

	oidEnricher := enricher.NewOIDEnricher()
	oidStart := time.Now()
	log.Info().Msg("Starting OID enrichment")
	oidEnricher.EnrichReport(report)
	log.Info().
		Dur("duration", time.Since(oidStart)).
		Msg("OID enrichment finished")

	factory := output.NewWriterFactory()
	writer, err := factory.GetWriter(scanFormat)
	if err != nil {
		return failure.WrapUnknown(
			err,
			failure.CodeOutputWriterUnavailable,
			failure.StageOutput,
			"failed to get output writer",
		)
	}

	// Write output (to stdout or file)
	writeStart := time.Now()
	log.Info().
		Str("destination", scanOutput).
		Str("format", scanFormat).
		Msg("Writing scan output")
	if err := writer.Write(report, scanOutput); err != nil {
		return failure.WrapUnknown(
			err,
			failure.CodeOutputWriteFailed,
			failure.StageOutput,
			"failed to write output",
		)
	}
	log.Info().
		Str("destination", scanOutput).
		Dur("duration", time.Since(writeStart)).
		Msg("Scan output write complete")

	findingsCount := scanutil.CountFindings(report)
	filesCount := len(report.Findings)

	if normalizedErrorOutputFormat() != formatJSON {
		err = scanutil.PrintSummary(scanOutput, filesCount, findingsCount)
		if err != nil {
			log.Error().Err(err).Msg("Failed to render scan summary")
		}
	}

	// Handle --fail-on-findings
	if scanFailOnFind && findingsCount > 0 {
		return failure.New(
			failure.CodeFindingsDetected,
			failure.StagePolicy,
			fmt.Sprintf("scan detected %d findings (--fail-on-findings enabled)", findingsCount),
			failure.WithDetail("findings_count", fmt.Sprintf("%d", findingsCount)),
		)
	}

	return nil
}

// newFindingsCache builds the FindingsCache backend selected by configuration.
//
// Failure semantics differ by backend:
//   - For the disk backend, construction errors are non-fatal: a warning is
//     logged and (nil, noop, nil) is returned so the dependency scan still
//     runs without caching (preserves the historical behavior).
//   - For the postgres backend, any failure (missing DSN, pool init, schema
//     bootstrap) is fatal: the scan is aborted with a structured error so
//     misconfiguration cannot silently fall back to an unshared cache.
func newFindingsCache(ctx context.Context, cfg *config.Config) (engine.FindingsCache, func(), error) {
	noop := func() {}
	backend := cfg.GetFindingsCacheBackend()

	switch backend {
	case "", findingsCacheBackendDisk:
		fc, err := engine.NewDiskFindingsCache()
		if err != nil {
			log.Warn().Err(err).Msg("Failed to create findings cache, dependency scans will not be cached")
			return nil, noop, nil
		}
		return fc, noop, nil

	case findingsCacheBackendNone:
		return nil, noop, nil

	case findingsCacheBackendPostgres:
		dsn := cfg.GetFindingsCacheDSN()
		if dsn == "" {
			return nil, noop, failure.New(
				failure.CodeCacheInitializationFailed,
				failure.StageConfig,
				"findings cache: SCANOSS_FINDINGS_CACHE_DSN must be set when --findings-cache=postgres",
			)
		}
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			return nil, noop, failure.WrapUnknown(err,
				failure.CodeCacheInitializationFailed,
				failure.StageConfig,
				"findings cache: failed to create Postgres pool",
			)
		}
		table := cfg.GetFindingsCacheTable()
		if err := engine.EnsureSchema(ctx, pool, table); err != nil {
			pool.Close()
			return nil, noop, failure.WrapUnknown(err,
				failure.CodeCacheInitializationFailed,
				failure.StageConfig,
				"findings cache: failed to ensure schema",
			)
		}
		return engine.NewPostgresFindingsCache(pool, engine.WithTableName(table)), pool.Close, nil

	default:
		return nil, noop, failure.New(
			failure.CodeInvalidArguments,
			failure.StageInput,
			fmt.Sprintf("unknown findings-cache backend %q (allowed: %v)", backend, AllowedFindingsCacheBackends),
		)
	}
}
