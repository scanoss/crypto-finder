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
	"path/filepath"

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
	defaultFormat         = "json"
	defaultTimeout        = "10m"
	defaultRulesetName    = "dca"
	defaultRulesetVersion = "latest"
)

// AllowedScanners lists the scanners supported by the tool.
// TODO: We'll support more scanners in the future (e.g., cbom-toolkit).
var AllowedScanners = []string{opengrep.ScannerName, semgrep.ScannerName}

// SupportedFormats lists the output formats supported by the tool.
var SupportedFormats = []string{"json", "cyclonedx"} // Future: csv, html, sarif

var (
	scanRules           []string
	scanRuleDirs        []string
	scanScanner         string
	scanFormat          string
	scanOutput          string
	scanLanguages       []string
	scanFailOnFind      bool
	scanTimeout         string
	scanNoRemoteRules   bool
	scanNoCache         bool
	scanAPIKey          string
	scanAPIURL          string
	scanStrict          bool
	scanMaxStaleAge     string
	scanNoDedup         bool
	scanInterfile       bool
	scanDependencies    bool
	scanDepMaxDepth     int
	scanDepEcosystem    string
	scanDepUnreachable  bool
	scanExportCallgraph string
	scanExportCgFormat  string
	scanDepWorkers      int
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
	scanCmd.Flags().IntVar(&scanDepMaxDepth, "dep-max-depth", 3, "Maximum depth for recursive dependency resolution")
	scanCmd.Flags().StringVar(&scanDepEcosystem, "dep-ecosystem", "auto", "Dependency ecosystem: auto, go, java, python, rust")
	scanCmd.Flags().BoolVar(&scanDepUnreachable, "dep-include-unreachable", false, "Include crypto findings in dependencies not reachable from user code call graph")
	scanCmd.Flags().IntVar(&scanDepWorkers, "dep-workers", 0, "Number of parallel dependency scan workers (default: half of CPU cores, max 8)")
	scanCmd.Flags().StringVar(&scanExportCallgraph, "export-callgraph", "", "Export the crypto-scoped call graph to a file (requires --scan-dependencies)")
	scanCmd.Flags().StringVar(&scanExportCgFormat, "export-callgraph-format", "json", "Call graph export format: json, dot, text")
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
		return err
	}
	scanLanguages = normalizedLanguages

	// Parse timeout
	timeout, err := scanutil.ParseDuration(scanTimeout)
	if err != nil {
		return fmt.Errorf("invalid timeout format '%s': %w (use format like '10m', '1h', '30d', or '2w')", scanTimeout, err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	targetDir := filepath.Dir(target)

	// Load skip patterns from multiple sources
	// We will use our default list and scanoss.json as, but also a custom source could be easily added implementing PatternSource interface
	skipPatternsSources := []skip.PatternSource{
		skip.NewDefaultsSource(),
		skip.NewScanossConfigSourceFromDir(targetDir),
	}
	multiSourceSkipPatterns := skip.NewMultiSource(skipPatternsSources...)
	skipPatterns, err := multiSourceSkipPatterns.Load()
	if err != nil {
		log.Warn().Err(err).Msgf("failed to load skip patterns from %s", multiSourceSkipPatterns.Name())
		// Fallback to just use default skipped directories
		skipPatterns = skip.DefaultSkippedDirs
	}

	if len(skipPatterns) > 0 {
		log.Info().Msgf("Using %d skip patterns from %s", len(skipPatterns), multiSourceSkipPatterns.Name())
	}

	// Create skip matcher for language detection
	skipMatcher := skip.NewGitIgnoreMatcher(skipPatterns)

	cfg := config.GetInstance()
	if err := cfg.Initialize(scanAPIKey, scanAPIURL); err != nil {
		return fmt.Errorf("failed to initialize config: %w", err)
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
			return fmt.Errorf("failed to create cache manager: %w", err)
		}

		cacheManager.SetNoCache(scanNoCache)
		cacheManager.SetStrictMode(scanStrict)

		// Parse and validate max stale age
		maxStaleAge, err := scanutil.ParseDuration(scanMaxStaleAge)
		if err != nil {
			return fmt.Errorf("invalid --max-stale-age format '%s': %w (use format like '30d', '720h', or '2w')", scanMaxStaleAge, err)
		}
		if maxStaleAge > config.MaxStaleCacheAge {
			return fmt.Errorf("--max-stale-age cannot exceed %s (got: %s)", config.MaxStaleCacheAge, maxStaleAge)
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
		return fmt.Errorf("no rule sources configured (use --rules, --rules-dir, or enable remote rules)")
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
		Target:       target,
		ScannerName:  scanScanner,
		LanguageHint: scanLanguages,
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

	// Dependency scanning phase.
	//nolint:nestif // This orchestration intentionally branches by ecosystem/resolver/parser/caching availability.
	if scanDependencies {
		ecosystem := scanDepEcosystem
		if ecosystem == "auto" {
			ecosystem = scanutil.DetectEcosystem(target)
		}

		if ecosystem != "" {
			depRegistry := dependency.NewRegistry()
			depRegistry.Register("go", dependency.NewGoResolver())
			depRegistry.Register("java", dependency.NewMavenResolver())
			depRegistry.Register("python", dependency.NewPipResolver())
			depRegistry.Register("rust", dependency.NewCargoResolver())

			resolver, resolverErr := depRegistry.Get(ecosystem)
			if resolverErr != nil {
				log.Warn().Err(resolverErr).Str("ecosystem", ecosystem).Msg("No resolver for ecosystem, skipping dependency scan")
			} else {
				cgParser := callgraph.NewParserForEcosystem(ecosystem)
				if cgParser == nil {
					log.Warn().Str("ecosystem", ecosystem).Msg("No call graph parser for ecosystem, skipping dependency scan")
				} else {
					cgBuilder := callgraph.NewBuilder(cgParser)

					var findingsCache engine.FindingsCache
					fc, cacheErr := engine.NewDiskFindingsCache()
					if cacheErr != nil {
						log.Warn().Err(cacheErr).Msg("Failed to create findings cache, dependency scans will not be cached")
					} else {
						findingsCache = fc
					}

					depScanner := engine.NewDependencyScanner(orchestrator, resolver, cgBuilder, findingsCache)
					depResult, depErr := depScanner.ScanWithDependencies(ctx, report, engine.DepScanOptions{
						MaxDepth:           scanDepMaxDepth,
						IncludeUnreachable: scanDepUnreachable,
						Workers:            scanDepWorkers,
						ScanOptions:        scanOpts,
					})
					if depErr != nil {
						return fmt.Errorf("dependency scan failed: %w", depErr)
					}
					report = depResult.Report

					// Export call graph if requested
					if scanExportCallgraph != "" && depResult.CallGraph != nil {
						if exportErr := scanutil.ExportCallGraph(scanExportCallgraph, scanExportCgFormat, depResult); exportErr != nil {
							return fmt.Errorf("failed to export call graph: %w", exportErr)
						}
					}
				}
			}
		} else {
			log.Warn().Msg("Could not detect dependency ecosystem, skipping dependency scan")
		}
	}

	report.Version = entities.InterimFormatVersion

	oidEnricher := enricher.NewOIDEnricher()
	oidEnricher.EnrichReport(report)

	factory := output.NewWriterFactory()
	writer, err := factory.GetWriter(scanFormat)
	if err != nil {
		return fmt.Errorf("failed to get output writer: %w", err)
	}

	// Write output (to stdout or file)
	if err := writer.Write(report, scanOutput); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	findingsCount := scanutil.CountFindings(report)
	filesCount := len(report.Findings)

	err = scanutil.PrintSummary(scanOutput, filesCount, findingsCount)
	if err != nil {
		log.Error().Err(err).Msg("Failed to render scan summary")
	}

	// Handle --fail-on-findings
	if scanFailOnFind && findingsCount > 0 {
		return fmt.Errorf("scan detected %d findings (--fail-on-findings enabled)", findingsCount)
	}

	return nil
}
