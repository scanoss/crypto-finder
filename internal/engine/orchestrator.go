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

// Package engine coordinates the scanning workflow by managing language detection,
// rule loading, scanner execution, and result processing.
package engine

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/javaruntime"
	"github.com/scanoss/crypto-finder/internal/language"
	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/version"
)

// Orchestrator coordinates the entire scanning workflow.
// It manages language detection, rule loading, scanner execution, and result processing.
type Orchestrator struct {
	langDetector language.Detector
	rulesManager *rules.Manager
	scannerReg   *scanner.Registry
	processor    *Processor
}

// NewOrchestrator creates a new orchestrator with the required dependencies.
func NewOrchestrator(
	langDetector language.Detector,
	rulesManager *rules.Manager,
	scannerReg *scanner.Registry,
) *Orchestrator {
	return &Orchestrator{
		langDetector: langDetector,
		rulesManager: rulesManager,
		scannerReg:   scannerReg,
		processor:    NewProcessor(),
	}
}

// ScanOptions contains all configuration options for a scan operation.
type ScanOptions struct {
	// Target is the directory or file to scan
	Target string

	// ScannerName is the name of the scanner to use (e.g., "semgrep")
	ScannerName string

	// LanguageHint allows manual override of language detection (from --languages flag)
	LanguageHint []string

	// ScannerConfig contains scanner-specific configuration
	ScannerConfig scanner.Config

	// RulePaths, when non-nil, bypasses the rules manager and uses these paths directly.
	// This is used by the dependency scanner to pass pre-loaded, language-filtered rules.
	RulePaths []string

	// JavaRuntime controls Java-specific dependency resolution and bytecode type enrichment.
	JavaRuntime javaruntime.Config

	// JavaRuntimeCacheToken partitions dependency scan caches by Java runtime selection.
	JavaRuntimeCacheToken string

	// Progress reports the top-level rules and detection lifecycle. Dependency scans
	// clear it so their workers never emit nested primary scan events.
	Progress ProgressReporter

	// ProgressDetectionStarted reports that the caller already opened detection
	// before invoking Scan, for example while it pre-detects languages for export.
	ProgressDetectionStarted bool
}

// ProgressReporter receives a lifecycle transition for a scan phase.
type ProgressReporter func(phase, status string, cause error) error

const (
	progressPhaseRules     = "rules"
	progressPhaseDetection = "detection"
	progressStatusStarted  = "started"
	progressStatusComplete = "completed"
	progressStatusFailed   = "failed"
)

// Scan orchestrates the complete scanning workflow.
//
// Workflow:
//  1. Detect languages (or use hint if provided)
//  2. Load rules from manager
//  3. Get scanner from registry
//  4. Initialize scanner
//  5. Execute scan with loaded rule paths
//  6. Process and enrich results
//
// Returns the final interim report or an error if any step fails.
//
//nolint:gocognit // Scan lifecycle and failure mapping must share the named return observed by deferred progress reporting.
func (o *Orchestrator) Scan(ctx context.Context, opts ScanOptions) (result *entities.InterimReport, err error) {
	if opts.Progress != nil && !opts.ProgressDetectionStarted {
		if progressErr := o.reportProgress(opts, progressPhaseDetection, progressStatusStarted, nil); progressErr != nil {
			return nil, progressErr
		}
	}
	if opts.Progress != nil {
		defer func() {
			status := progressStatusComplete
			if err != nil {
				status = progressStatusFailed
			}
			if progressErr := o.reportProgress(opts, progressPhaseDetection, status, err); progressErr != nil {
				result = nil
				err = progressErr
			}
		}()
	}

	// Step 1: Detect languages
	var languages []string

	if len(opts.LanguageHint) > 0 {
		// Use provided language hint
		languages = opts.LanguageHint
		log.Info().Strs("languages", opts.LanguageHint).Msg("Using provided language hints")
	} else {
		// Auto-detect languages so we can use only the needed rules. This significantly optimizes scanner performance.
		detectedLanguages, detectErr := o.langDetector.Detect(opts.Target)
		if detectErr != nil {
			return nil, failure.WrapUnknown(
				detectErr,
				failure.CodeLanguageDetectionFailed,
				failure.StageScan,
				"failed to detect languages",
			)
		}
		languages = detectedLanguages
	}

	// Step 2: Load rules (use pre-loaded paths if provided, otherwise load from manager)
	var rulePaths []string
	var rawRulePaths []string
	var cleanupRulePaths func()
	defer func() {
		if cleanupRulePaths != nil {
			cleanupRulePaths()
		}
	}()
	if loadErr := o.loadRules(opts, languages, &rulePaths, &rawRulePaths, &cleanupRulePaths); loadErr != nil {
		return nil, loadErr
	}

	// Step 3: Get scanner from registry
	scannerInstance, getErr := o.scannerReg.Get(opts.ScannerName)
	if getErr != nil {
		return nil, failure.WrapUnknown(
			getErr,
			failure.CodeScannerUnavailable,
			failure.StageScan,
			"failed to get scanner",
			failure.WithDetail("scanner", opts.ScannerName),
		)
	}

	// Step 4: Initialize scanner
	if err := scannerInstance.Initialize(ctx, opts.ScannerConfig); err != nil {
		if ctxErr := scanner.InitializationContextError(ctx, opts.ScannerName); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, failure.WrapUnknown(
			err,
			failure.CodeScannerInitializationFailed,
			failure.StageScan,
			fmt.Sprintf("failed to initialize scanner '%s'", opts.ScannerName),
			failure.WithDetail("scanner", opts.ScannerName),
		)
	}
	if ctxErr := scanner.InitializationContextError(ctx, opts.ScannerName); ctxErr != nil {
		return nil, ctxErr
	}

	// Step 5: Execute scan
	// Create tool info from crypto-finder's name and version
	toolInfo := entities.ToolInfo{
		Name:    version.ToolName,
		Version: version.Version,
	}
	report, scanErr := scannerInstance.Scan(ctx, opts.Target, rulePaths, toolInfo)
	if scanErr != nil {
		return nil, failure.WrapUnknown(
			scanErr,
			failure.CodeScannerExecutionFailed,
			failure.StageScan,
			"scan failed",
			failure.WithDetail("scanner", opts.ScannerName),
		)
	}

	// Step 5b: Stamp the ruleset that produced these findings. Best-effort:
	// remote sources lift it from .cache-meta.json, local sources compute a
	// content fingerprint, MultiSource picks the first non-empty. An empty
	// RulesInfo is acceptable (ad-hoc local files with no metadata).
	report.Rules = o.rulesManager.Info()

	// Step 6: Process and enrich results
	enrichedReport, processErr := o.processor.Process(report, languages, opts.Target)
	if processErr != nil {
		return nil, failure.WrapUnknown(
			processErr,
			failure.CodeScannerExecutionFailed,
			failure.StageScan,
			"failed to process results",
		)
	}

	return enrichedReport, nil
}

func (o *Orchestrator) loadRules(opts ScanOptions, languages []string, rulePaths, rawRulePaths *[]string, cleanupRulePaths *func()) (err error) {
	if progressErr := o.reportProgress(opts, progressPhaseRules, progressStatusStarted, nil); progressErr != nil {
		return progressErr
	}
	defer func() {
		status := progressStatusComplete
		if err != nil {
			status = progressStatusFailed
		}
		if progressErr := o.reportProgress(opts, progressPhaseRules, status, err); progressErr != nil {
			err = progressErr
		}
	}()

	if len(opts.RulePaths) > 0 {
		*rawRulePaths = opts.RulePaths
		preparedRulePaths, cleanup, loadErr := optimizeRulePathsForScanner(opts.RulePaths)
		if loadErr != nil {
			return failure.WrapUnknown(loadErr, failure.CodeRulesLoadFailed, failure.StageRules, "failed to prepare pre-loaded rules for scanner")
		}
		*rulePaths, *cleanupRulePaths = preparedRulePaths, cleanup
		log.Debug().Int("count", len(*rulePaths)).Msg("Using pre-loaded rule paths")
	} else {
		loadedRulePaths, loadErr := o.rulesManager.Load()
		if loadErr != nil {
			return failure.WrapUnknown(loadErr, failure.CodeRulesLoadFailed, failure.StageRules, "failed to load rules")
		}
		*rulePaths = loadedRulePaths
		log.Info().Int("count", len(*rulePaths)).Msg("Loaded rules")
		*rawRulePaths = *rulePaths
		preparedRulePaths, cleanup, prepareErr := prepareRulePathsForScanner(*rulePaths, languages)
		if prepareErr != nil {
			return failure.WrapUnknown(prepareErr, failure.CodeRulesLoadFailed, failure.StageRules, "failed to prepare filtered rules for scanner")
		}
		*rulePaths, *cleanupRulePaths = preparedRulePaths, cleanup
	}

	if validationErr := rules.ValidateParameterConditions(*rawRulePaths); validationErr != nil {
		return failure.WrapUnknown(validationErr, failure.CodeRulesLoadFailed, failure.StageRules, "invalid parameterCondition in ruleset")
	}
	return nil
}

func (o *Orchestrator) reportProgress(opts ScanOptions, phase, status string, cause error) error {
	if opts.Progress == nil {
		return nil
	}
	if err := opts.Progress(phase, status, cause); err != nil {
		return failure.WrapUnknown(err, failure.CodeOutputWriteFailed, failure.StageOutput, "failed to write scan progress")
	}
	return nil
}
