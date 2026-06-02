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
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	api "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/cache"
	"github.com/scanoss/crypto-finder/internal/config"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/language"
	"github.com/scanoss/crypto-finder/internal/rules"
	scanutil "github.com/scanoss/crypto-finder/internal/scan"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/scanner/opengrep"
	"github.com/scanoss/crypto-finder/internal/scanner/semgrep"
	"github.com/scanoss/crypto-finder/internal/skip"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

var (
	annotateImportFragment   string
	annotateSource           string
	annotateOutput           string
	annotateRules            []string
	annotateRuleDirs         []string
	annotateScanner          string
	annotateTimeout          string
	annotateNoRemoteRules    bool
	annotateNoCache          bool
	annotateAPIKey           string
	annotateAPIURL           string
	annotateLanguages        []string
	annotateIncludeTests     bool
	annotateNoDefaultExclude bool
	annotateExcludePatterns  []string
)

var annotateCmd = &cobra.Command{
	Use:   "annotate",
	Short: "Re-annotate a cached structural graph fragment with fresh crypto findings",
	Long: `Re-run ONLY crypto detection over a source tree and map the findings onto a
previously-exported structural graph fragment, WITHOUT rebuilding the call graph.

The call graph build (parse + inference) is the expensive ~95% of a scan and is
rules-independent. When only the crypto ruleset changes, annotate imports the
cached structural fragment, runs detection, maps each finding to its containing
function via the fragment's function line ranges, and emits crypto_annotations
that are byte-identical to a full 'scan --export-graph-fragment' for the same
source + rules.

Examples:
  # Re-annotate using a cached fragment and the default remote ruleset
  crypto-finder annotate --import-fragment graph-fragment.json --source ./src --output annotation.json

  # Re-annotate with local rules only
  crypto-finder annotate --import-fragment frag.json --source ./src --rules-dir ./rules --no-remote-rules`,
	RunE: runAnnotate,
}

func init() {
	annotateCmd.Flags().StringVar(&annotateImportFragment, "import-fragment", "", "Path to the cached structural graph fragment JSON to re-annotate (required)")
	annotateCmd.Flags().StringVar(&annotateSource, "source", "", "Source directory to run crypto detection over (required)")
	annotateCmd.Flags().StringVarP(&annotateOutput, "output", "o", "", "Output file path for the annotation JSON (default: stdout)")
	annotateCmd.Flags().StringArrayVarP(&annotateRules, "rules", "r", []string{}, "Rule file path (repeatable)")
	annotateCmd.Flags().StringArrayVar(&annotateRuleDirs, "rules-dir", []string{}, "Rule directory path (repeatable)")
	annotateCmd.Flags().StringVar(&annotateScanner, "scanner", defaultScanner, fmt.Sprintf("Scanner to use (default: %s)", defaultScanner))
	annotateCmd.Flags().StringVarP(&annotateTimeout, "timeout", "t", defaultTimeout, "Detection timeout (e.g., 10m, 1h)")
	annotateCmd.Flags().BoolVar(&annotateNoRemoteRules, "no-remote-rules", false, "Disable the default remote ruleset")
	annotateCmd.Flags().BoolVar(&annotateNoCache, "no-cache", false, "Force fresh download of remote rules, bypass cache")
	annotateCmd.Flags().StringVar(&annotateAPIKey, "api-key", "", "SCANOSS API key")
	annotateCmd.Flags().StringVar(&annotateAPIURL, "api-url", "", "SCANOSS API base URL")
	annotateCmd.Flags().StringSliceVar(&annotateLanguages, "languages", []string{}, "Override language detection (comma-separated)")
	annotateCmd.Flags().BoolVar(&annotateIncludeTests, "include-tests", false, "Include test sources in detection")
	annotateCmd.Flags().BoolVar(&annotateNoDefaultExclude, "no-default-exclusions", false, "Disable the built-in default directory exclusions")
	annotateCmd.Flags().StringSliceVar(&annotateExcludePatterns, "exclude", nil, "Glob pattern to skip during detection (repeatable)")
}

func runAnnotate(_ *cobra.Command, _ []string) error {
	if annotateImportFragment == "" {
		return failure.New(failure.CodeInvalidArguments, failure.StageInput, "--import-fragment is required")
	}
	if annotateSource == "" {
		return failure.New(failure.CodeInvalidArguments, failure.StageInput, "--source is required")
	}

	// Load the cached structural fragment first: if it is unreadable there is no
	// point running detection.
	fragment, err := loadImportedFragment(annotateImportFragment)
	if err != nil {
		return err
	}

	timeout, err := scanutil.ParseDuration(annotateTimeout)
	if err != nil {
		return failure.Wrap(err, failure.CodeInvalidTimeout, failure.StageInput,
			fmt.Sprintf("invalid timeout format '%s' (use format like '10m', '1h')", annotateTimeout))
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	report, err := runAnnotateDetection(ctx, timeout)
	if err != nil {
		return err
	}

	// Stamp the same finding source + finding IDs the full scan stamps before
	// export, so finding_id is byte-identical across both paths.
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)

	payload := scanutil.BuildAnnotateExport(report, fragment)

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

func loadImportedFragment(path string) (graphfrag.Fragment, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return graphfrag.Fragment{}, failure.WrapUnknown(err, failure.CodeInvalidArguments, failure.StageInput,
			fmt.Sprintf("failed to read --import-fragment %q", path))
	}
	// ComponentKey identity is not needed for annotation (function_key join is
	// by signature/line range, not purl), so an empty key is sufficient.
	fragment, err := graphfrag.DecodeFragment(graphfrag.ComponentKey{}, data)
	if err != nil {
		return graphfrag.Fragment{}, failure.WrapUnknown(err, failure.CodeInvalidArguments, failure.StageInput,
			fmt.Sprintf("failed to decode --import-fragment %q", path))
	}
	return fragment, nil
}

// runAnnotateDetection runs ONLY the crypto detection pass (no callgraph build)
// over --source and returns the interim report. It mirrors the detection setup
// of the scan command but stops at orchestrator.Scan — deliberately skipping the
// callgraph/inference work that annotate exists to avoid.
func runAnnotateDetection(ctx context.Context, timeout time.Duration) (*entities.InterimReport, error) {
	target := annotateSource

	normalizedLanguages, err := scanutil.ValidateFlags(target, scanutil.ValidationOptions{
		RuleFiles:        annotateRules,
		RuleDirs:         annotateRuleDirs,
		NoRemoteRules:    annotateNoRemoteRules,
		Scanner:          annotateScanner,
		AllowedScanners:  AllowedScanners,
		Format:           formatJSON,
		SupportedFormats: SupportedFormats,
		Languages:        annotateLanguages,
	})
	if err != nil {
		return nil, failure.WrapUnknown(err, failure.CodeInvalidArguments, failure.StageInput, err.Error())
	}
	languages := normalizedLanguages

	targetDir, err := callGraphTargetDir(target)
	if err != nil {
		return nil, failure.WrapUnknown(err, failure.CodeInvalidArguments, failure.StageInput,
			fmt.Sprintf("failed to resolve source directory for '%s'", target))
	}

	skipPatterns, _ := buildSkipPatterns(targetDir, annotateNoDefaultExclude, annotateExcludePatterns)
	skipPatterns = applyTestSkipPatterns(skipPatterns, annotateIncludeTests)
	skipMatcher := skip.NewGitIgnoreMatcher(skipPatterns)

	if len(languages) == 0 {
		detected, detectErr := language.NewEnryDetector(skipMatcher).Detect(target)
		if detectErr != nil {
			return nil, failure.WrapUnknown(detectErr, failure.CodeLanguageDetectionFailed, failure.StageScan, "failed to detect languages")
		}
		languages = detected
	}

	cfg := config.GetInstance()
	if err := cfg.Initialize(config.InitOptions{APIKey: annotateAPIKey, APIURL: annotateAPIURL}); err != nil {
		return nil, failure.WrapUnknown(err, failure.CodeConfigInitializationFailed, failure.StageConfig, "failed to initialize config")
	}

	rulesManager, err := buildAnnotateRulesManager(ctx, cfg)
	if err != nil {
		return nil, err
	}

	langDetector := language.NewEnryDetector(skipMatcher)
	scannerRegistry := scanner.NewRegistry()
	scannerRegistry.Register(opengrep.ScannerName, opengrep.NewScanner())
	scannerRegistry.Register(semgrep.ScannerName, semgrep.NewScanner())

	orchestrator := engine.NewOrchestrator(langDetector, rulesManager, scannerRegistry)

	log.Info().Msgf("Running crypto detection over %s (annotate-only, no callgraph)...", target)
	report, err := orchestrator.Scan(ctx, engine.ScanOptions{
		Target:       target,
		ScannerName:  annotateScanner,
		LanguageHint: languages,
		ScannerConfig: scanner.Config{
			Timeout:      timeout,
			SkipPatterns: skipPatterns,
		},
	})
	if err != nil {
		return nil, err
	}
	return report, nil
}

func buildAnnotateRulesManager(ctx context.Context, cfg *config.Config) (*rules.Manager, error) {
	ruleSources := make([]rules.RuleSource, 0)

	if !annotateNoRemoteRules {
		apiClient := api.NewClient(cfg.GetAPIURL(), cfg.GetAPIKey())
		cacheManager, err := cache.NewManager(apiClient)
		if err != nil {
			return nil, failure.WrapUnknown(err, failure.CodeCacheInitializationFailed, failure.StageConfig, "failed to create cache manager")
		}
		cacheManager.SetNoCache(annotateNoCache)
		remoteSource := rules.NewRemoteRuleSource(ctx, defaultRulesetName, defaultRulesetVersion, cacheManager)
		ruleSources = append(ruleSources, remoteSource)
	}

	if len(annotateRules) > 0 || len(annotateRuleDirs) > 0 {
		ruleSources = append(ruleSources, rules.NewLocalRuleSource(annotateRules, annotateRuleDirs))
	}

	switch len(ruleSources) {
	case 0:
		return nil, failure.New(failure.CodeRulesLoadFailed, failure.StageRules,
			"no rule sources configured (use --rules, --rules-dir, or enable remote rules)")
	case 1:
		return rules.NewManager(ruleSources[0]), nil
	default:
		return rules.NewManager(rules.NewMultiSource(ruleSources...)), nil
	}
}
