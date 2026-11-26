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
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scanoss/reach/graphfrag"
	"github.com/scanoss/reach/language"
	"github.com/scanoss/reach/skip"
	"github.com/spf13/cobra"

	api "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/cache"
	"github.com/scanoss/crypto-finder/internal/config"
	"github.com/scanoss/crypto-finder/internal/deadcode"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/oid"
	"github.com/scanoss/crypto-finder/internal/output"
	"github.com/scanoss/crypto-finder/internal/pqc"
	"github.com/scanoss/crypto-finder/internal/rules"
	scanutil "github.com/scanoss/crypto-finder/internal/scan"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/scanner/cards"
	"github.com/scanoss/crypto-finder/internal/utils"
)

var (
	annotateImportFragment   string
	annotateSource           string
	annotateOutput           string
	annotateRules            []string
	annotateRuleDirs         []string
	annotateTimeout          string
	annotateNoRemoteRules    bool
	annotateNoCache          bool
	annotateRulesetVersion   string
	annotateRuleset          string
	annotateAPIKey           string
	annotateAPIURL           string
	annotateAllowHTTP        bool
	annotateLanguages        []string
	annotateIncludeTests     bool
	annotateNoDefaultExclude bool
	annotateExcludePatterns  []string
	annotateFindingsOutput   string
)

var annotateCmd = &cobra.Command{
	Use:   "annotate",
	Short: "Re-annotate a cached structural graph fragment with fresh crypto findings",
	Long: `Re-run ONLY crypto detection over a previously-exported structural graph
fragment, WITHOUT rebuilding the call graph.

The call graph build (parse + inference) is the expensive ~95% of a scan and is
rules-independent. When only the crypto ruleset changes, annotate imports the
cached structural fragment, matches the ruleset's cards against its call sites,
maps each finding to its containing function, and emits crypto_annotations that
are byte-identical to a full 'scan --export-graph-fragment' for the same source
and rules.

Examples:
  # Re-detect a stored graph with the default remote ruleset, no source tree
  crypto-finder annotate --import-fragment frag.json --output annotation.json

  # Re-detect with a local ruleset and also write the findings report, as
  # scan --output writes it
  crypto-finder annotate --import-fragment frag.json --rules-dir ./ruleset --no-remote-rules \
    --output annotation.json --findings-output findings.json

Without --source, detection reads only the fragment (graph-fragment-1.16 or
later, which carries the call sites' source lines).`,
	RunE: runAnnotate,
}

func init() {
	annotateCmd.Flags().StringVar(&annotateImportFragment, "import-fragment", "", "Path to the cached structural graph fragment JSON to re-annotate (required)")
	annotateCmd.Flags().StringVar(&annotateSource, "source", "", "Source tree the fragment was exported from, to read the source lines a fragment older than graph-fragment-1.16 does not carry")
	annotateCmd.Flags().StringVar(&annotateFindingsOutput, "findings-output", "", "Also write the findings report, as scan --output writes it, to this file")
	annotateCmd.Flags().StringVarP(&annotateOutput, "output", "o", "", "Output file path for the annotation JSON (default: stdout)")
	annotateCmd.Flags().StringArrayVarP(&annotateRules, "rules", "r", []string{}, "Rule file path (repeatable)")
	annotateCmd.Flags().StringArrayVar(&annotateRuleDirs, "rules-dir", []string{}, "Rule directory path (repeatable)")
	annotateCmd.Flags().StringVarP(&annotateTimeout, "timeout", "t", defaultTimeout, "Detection timeout (e.g., 10m, 1h)")
	annotateCmd.Flags().BoolVar(&annotateNoRemoteRules, "no-remote-rules", false, "Disable the default remote ruleset")
	annotateCmd.Flags().BoolVar(&annotateNoCache, "no-cache", false, "Force fresh download of remote rules, bypass cache")
	annotateCmd.Flags().StringVar(&annotateRuleset, rulesetFlag, defaultRulesetName, rulesetUsage)
	annotateCmd.Flags().StringVar(&annotateRulesetVersion, rulesetVersionFlag, defaultRulesetVersion,
		"Remote ruleset version to fetch, as for scan: latest or a release version such as v1.39.0")
	annotateCmd.Flags().StringVar(&annotateAPIKey, "api-key", "", "SCANOSS API key")
	annotateCmd.Flags().StringVar(&annotateAPIURL, "api-url", "", "SCANOSS API base URL")
	annotateCmd.Flags().BoolVar(&annotateAllowHTTP, allowHTTPFlag, false, allowHTTPUsage)
	annotateCmd.Flags().StringSliceVar(&annotateLanguages, "languages", []string{}, "Override language detection (comma-separated)")
	annotateCmd.Flags().BoolVar(&annotateIncludeTests, "include-tests", false, "Include test sources in detection")
	annotateCmd.Flags().BoolVar(&annotateNoDefaultExclude, "no-default-exclusions", false, "Disable the built-in default exclusions")
	annotateCmd.Flags().StringSliceVar(&annotateExcludePatterns, "exclude", nil, "Glob pattern to skip during detection (repeatable)")
}

func runAnnotate(cmd *cobra.Command, _ []string) error {
	if annotateImportFragment == "" {
		return failure.New(failure.CodeInvalidArguments, failure.StageInput, "--import-fragment is required")
	}

	// Load the cached structural fragment first: if it is unreadable there is no
	// point running detection.
	document, err := loadImportedFragment(annotateImportFragment)
	if err != nil {
		return err
	}
	if annotateSource == "" && !hasSourceLines(document) {
		return failure.New(failure.CodeInvalidArguments, failure.StageInput,
			fmt.Sprintf("--import-fragment %q has no source lines (%s; graph-fragment-1.16 or later is needed without --source)",
				annotateImportFragment, document.SchemaVersion))
	}

	timeout, err := scanutil.ParseDuration(annotateTimeout)
	if err != nil {
		return failure.Wrap(err, failure.CodeInvalidTimeout, failure.StageInput,
			fmt.Sprintf("invalid timeout format '%s' (use format like '10m', '1h')", annotateTimeout))
	}
	rulesetName, rulesetVersion, err := resolveRemoteRuleset(cmd.Flags(), annotateRuleset, annotateRulesetVersion, annotateNoRemoteRules)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	report, graph, err := runAnnotateDetection(ctx, timeout, rulesetName, rulesetVersion, document)
	if err != nil {
		return err
	}
	resolved, err := prepareAnnotateProjection(report)
	if err != nil {
		return failure.WrapUnknown(err, failure.CodeUnknown, failure.StageScan, "prepare exact OID report")
	}

	// With the cards scanner the call graph is rebuilt from the fragment, and
	// the annotation is what a scan's graph-fragment export writes from it.
	payload := scanutil.BuildGraphAnnotateExport(graph, resolved, document)
	if annotateFindingsOutput != "" {
		if err := writeAnnotateFindings(resolved); err != nil {
			return err
		}
	}

	if annotateOutput == "" {
		data, err := scanutil.MarshalAnnotateExport(&payload)
		if err != nil {
			return failure.WrapUnknown(err, failure.CodeOutputWriteFailed, failure.StageOutput, "failed to render annotation")
		}
		if _, err := os.Stdout.Write(data); err != nil {
			return failure.WrapUnknown(err, failure.CodeOutputWriteFailed, failure.StageOutput, "failed to write annotation to stdout")
		}
		return nil
	}
	if err := scanutil.WriteAnnotateExport(annotateOutput, &payload); err != nil {
		return failure.WrapUnknown(err, failure.CodeOutputWriteFailed, failure.StageOutput, "failed to write annotation")
	}
	log.Info().
		Str("output", annotateOutput).
		Int("crypto_annotations", len(payload.CryptoAnnotations)).
		Msg("Annotation written")
	return nil
}

// prepareAnnotateProjection finalizes finding identity before exact OID resolution.
// The returned report is the single object used by the annotation projection.
func prepareAnnotateProjection(report *entities.InterimReport) (*oid.ResolvedReport, error) {
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)
	report.Version = entities.InterimFormatVersion
	prepared, err := oid.NewDefaultResolver().PrepareReport(report)
	if err != nil {
		return nil, err
	}
	return prepared.ReportClone(), nil
}

// writeAnnotateFindings writes the findings report as scan --output writes
// it, with the PQC classification. It runs after the annotation is built, so
// the classification never enters it, as in a scan.
func writeAnnotateFindings(findings *oid.ResolvedReport) error {
	pqc.Annotate(findings)
	writer, err := output.NewWriterFactory().GetWriter(formatJSON)
	if err != nil {
		return failure.WrapUnknown(err, failure.CodeOutputWriterUnavailable, failure.StageOutput, "failed to get output writer")
	}
	if err := writer.WriteResolved(findings, annotateFindingsOutput); err != nil {
		return failure.WrapUnknown(err, failure.CodeOutputWriteFailed, failure.StageOutput, "failed to write findings")
	}
	return nil
}

// hasSourceLines reports a fragment schema that carries the call sites'
// source lines (graph-fragment-1.16 and later).
func hasSourceLines(document *graphfrag.GraphFragmentExport) bool {
	minor, ok := strings.CutPrefix(document.SchemaVersion, "graph-fragment-1.")
	if !ok {
		return false
	}
	n, err := strconv.Atoi(minor)
	return err == nil && n >= 16
}

// loadImportedFragment reads the cached fragment. The annotation reads it
// through the graphfrag model; the cards scanner also gets the whole
// document, whose source lines, constant references, declarations and casts
// the model does not keep, as a scan builds it in memory.
func loadImportedFragment(path string) (*graphfrag.GraphFragmentExport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, failure.WrapUnknown(err, failure.CodeInvalidArguments, failure.StageInput,
			fmt.Sprintf("failed to read --import-fragment %q", path))
	}
	// The document is decoded once: a stored fragment runs to hundreds of
	// megabytes.
	var document graphfrag.GraphFragmentExport
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, failure.WrapUnknown(err, failure.CodeInvalidArguments, failure.StageInput,
			fmt.Sprintf("failed to decode --import-fragment %q", path))
	}
	// What a 1.22 producer wrote once is restored before any section is read.
	document.RestoreElided()
	document.ExpandInternalEdges()
	return &document, nil
}

// runAnnotateDetection runs ONLY the crypto detection pass (no callgraph build)
// over --source and returns the interim report and, with document, the call
// graph rebuilt from it with the report attached. It mirrors the detection setup
// of the scan command but stops at orchestrator.Scan — deliberately skipping the
// callgraph/inference work that annotate exists to avoid.
//
// With the cards scanner and no --source, detection matches document alone
// and runs over an empty directory, so no source file is read.
func runAnnotateDetection(ctx context.Context, timeout time.Duration, rulesetName, rulesetVersion string, document *graphfrag.GraphFragmentExport) (*entities.InterimReport, *engine.DepScanResult, error) {
	target := annotateSource
	if target == "" {
		empty, err := os.MkdirTemp("", "crypto-finder-annotate-")
		if err != nil {
			return nil, nil, failure.WrapUnknown(err, failure.CodeUnknown, failure.StageInput, "failed to create the detection directory")
		}
		defer func() { utils.Discard(os.RemoveAll(empty)) }()
		target = empty
	}

	normalizedLanguages, err := scanutil.ValidateFlags(target, scanutil.ValidationOptions{
		RuleFiles:        annotateRules,
		RuleDirs:         annotateRuleDirs,
		NoRemoteRules:    annotateNoRemoteRules,
		Format:           formatJSON,
		SupportedFormats: SupportedFormats,
		Languages:        annotateLanguages,
	})
	if err != nil {
		return nil, nil, failure.WrapUnknown(err, failure.CodeInvalidArguments, failure.StageInput, "failed to validate annotate flags")
	}
	languages := normalizedLanguages

	targetDir, err := callGraphTargetDir(target)
	if err != nil {
		return nil, nil, failure.WrapUnknown(err, failure.CodeInvalidArguments, failure.StageInput,
			fmt.Sprintf("failed to resolve source directory for '%s'", target))
	}

	skipPatterns, _ := buildSkipPatterns(targetDir, annotateNoDefaultExclude, annotateExcludePatterns)
	skipPatterns = applyTestSkipPatterns(skipPatterns, annotateIncludeTests)
	skipPatterns = applyCTestSkipPatterns(skipPatterns, targetDir, annotateIncludeTests)
	skipMatcher := skip.NewMatcher(skipPatterns, !annotateNoDefaultExclude)

	// The stored graph names its ecosystem and is matched with that
	// language's cards, whatever --languages says.
	cardsLanguage, err := annotateCardsLanguage(document)
	if err != nil {
		return nil, nil, err
	}
	if len(languages) == 0 {
		languages = []string{cardsLanguage}
	}

	cfg := config.GetInstance()
	if err := cfg.Initialize(config.InitOptions{APIKey: annotateAPIKey, APIURL: annotateAPIURL, AllowHTTP: annotateAllowHTTP}); err != nil {
		return nil, nil, failure.WrapUnknown(err, failure.CodeConfigInitializationFailed, failure.StageConfig, "failed to initialize config")
	}

	rulesManager, remoteSource, err := buildAnnotateRulesManager(ctx, cfg, rulesetName, rulesetVersion)
	if err != nil {
		return nil, nil, err
	}
	if remoteSource != nil {
		defer remoteSource.Close()
	}

	langDetector := language.NewEnryDetector(skipMatcher)
	scannerRegistry := scanner.NewRegistry()
	scannerRegistry.RegisterFactory(cards.ScannerName, cards.NewScannerFactory(cards.Options{
		Language: cardsLanguage,
		Ruleset:  cardsRuleset(annotateRuleDirs, rulesManager),
		// The cards match the stored call sites, whatever directory
		// detection runs over.
		Fragment: func(string) (graphfrag.GraphFragmentExport, error) { return *document, nil },
	}))

	orchestrator := engine.NewOrchestrator(langDetector, rulesManager, scannerRegistry)

	log.Info().Msgf("Running crypto detection over %s (annotate-only, no callgraph)...", target)
	report, err := orchestrator.Scan(ctx, engine.ScanOptions{
		Target:       target,
		ScannerName:  cards.ScannerName,
		LanguageHint: languages,
		ScannerConfig: scanner.Config{
			Timeout:      timeout,
			SkipPatterns: skipPatterns,
		},
	})
	if err != nil {
		return nil, nil, err
	}
	// A scan drops the findings inside a C file's #if 0 blocks, which it
	// reads in the file; the fragment's source lines hold the blocks'
	// conditionals for a detection that has no file to read.
	report = deadcode.FilterReportLines(report, document.SourceLines)
	graph, err := runFragmentGraphPasses(report, document, targetDir, rulesManager)
	if err != nil {
		return nil, nil, err
	}
	return report, graph, nil
}

// annotateCardsLanguage is the cards language (cards.Options.Language) of
// the stored graph: the one of its ecosystem. A graph written before scan
// metadata named an ecosystem (the empty one) is Java's; any other ecosystem
// without a scanned cards language fails.
func annotateCardsLanguage(document *graphfrag.GraphFragmentExport) (string, error) {
	ecosystem := ecosystemJava
	if document != nil && document.GraphEcosystem() != "" {
		ecosystem = document.GraphEcosystem()
	}
	return cardsLanguageOf(ecosystem)
}

// runFragmentGraphPasses runs over the fragment's call graph the passes a
// scan runs over the graph it built after detection, in the scan's order:
// rule entry points, conditioned findings and related material, finding ids,
// then occurrence keys. It returns the rebuilt graph.
func runFragmentGraphPasses(report *entities.InterimReport, document *graphfrag.GraphFragmentExport, projectRoot string, rulesManager *rules.Manager) (*engine.DepScanResult, error) {
	engine.EnsureFindingSources(report)
	result := scanutil.FragmentScanResult(document, projectRoot, report)
	if err := runRuleGraphPasses(nil, "", rulesManager, report, []*engine.DepScanResult{result}); err != nil {
		return nil, err
	}
	engine.AssignFindingIDs(report)
	if scanutil.CountFindings(report) > 0 {
		scanutil.FilterForeignReceiverAssets(report, result)
		scanutil.AssignOccurrenceKeys(result)
	}
	return result, nil
}

// buildAnnotateRulesManager returns the rules manager and, when remote rules
// are enabled, the remote source, which the caller must Close.
func buildAnnotateRulesManager(ctx context.Context, cfg *config.Config, rulesetName, rulesetVersion string) (*rules.Manager, *rules.RemoteRuleSource, error) {
	ruleSources := make([]rules.RuleSource, 0)
	var remoteSource *rules.RemoteRuleSource

	if !annotateNoRemoteRules {
		if err := checkAPIURL(cfg.GetAPIURL(), cfg.GetAllowHTTP()); err != nil {
			return nil, nil, err
		}
		apiClient := api.NewClient(cfg.GetAPIURL(), cfg.GetAPIKey(), api.WithAllowHTTP(cfg.GetAllowHTTP()))
		cacheManager, err := cache.NewManager(apiClient)
		if err != nil {
			return nil, nil, failure.WrapUnknown(err, failure.CodeCacheInitializationFailed, failure.StageConfig, "failed to create cache manager")
		}
		cacheManager.SetNoCache(annotateNoCache)
		remoteSource = rules.NewRemoteRuleSource(ctx, rulesetName, rulesetVersion, cacheManager)
		ruleSources = append(ruleSources, remoteSource)
	}

	if len(annotateRules) > 0 || len(annotateRuleDirs) > 0 {
		ruleSources = append(ruleSources, rules.NewLocalRuleSource(annotateRules, annotateRuleDirs))
	}

	switch len(ruleSources) {
	case 0:
		return nil, nil, failure.New(failure.CodeRulesLoadFailed, failure.StageRules,
			"no rule sources configured (use --rules, --rules-dir, or enable remote rules)")
	case 1:
		return rules.NewManager(ruleSources[0]), remoteSource, nil
	default:
		return rules.NewManager(rules.NewMultiSource(ruleSources...)), remoteSource, nil
	}
}
