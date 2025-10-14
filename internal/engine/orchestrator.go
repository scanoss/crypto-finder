// Package engine coordinates the scanning workflow by managing language detection,
// rule loading, scanner execution, and result processing.
package engine

import (
	"context"
	"fmt"

	"github.com/scanoss/crypto-finder/internal/language"
	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/pkg/schema"
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

	// RulePaths are individual rule file paths (from --rules flags)
	RulePaths []string

	// RuleDirs are rule directory paths (from --rules-dir flags)
	RuleDirs []string

	// LanguageHint allows manual override of language detection (from --languages flag)
	LanguageHint []string

	// ScannerConfig contains scanner-specific configuration
	ScannerConfig scanner.Config
}

// Scan orchestrates the complete scanning workflow.
//
// Workflow:
//  1. Detect languages (or use hint if provided)
//  2. Load and validate rules
//  3. Get scanner from registry
//  4. Initialize scanner
//  5. Execute scan
//  6. Process and enrich results
//
// Returns the final interim report or an error if any step fails.
func (o *Orchestrator) Scan(ctx context.Context, opts ScanOptions) (*schema.InterimReport, error) {
	// Step 1: Detect languages
	var languages []string
	var err error

	if len(opts.LanguageHint) > 0 {
		// Use provided language hint
		languages = opts.LanguageHint
	} else {
		// Auto-detect languages
		languages, err = o.langDetector.Detect(opts.Target)
		if err != nil {
			return nil, fmt.Errorf("failed to detect languages: %w", err)
		}
	}

	// Step 2: Load and validate rules
	rulePaths, err := o.rulesManager.LoadLocal(opts.RulePaths, opts.RuleDirs)
	if err != nil {
		return nil, fmt.Errorf("failed to load rules: %w", err)
	}

	// Step 3: Get scanner from registry
	scannerInstance, err := o.scannerReg.Get(opts.ScannerName)
	if err != nil {
		return nil, fmt.Errorf("failed to get scanner: %w", err)
	}

	// Step 4: Initialize scanner
	if err := scannerInstance.Initialize(opts.ScannerConfig); err != nil {
		return nil, fmt.Errorf("failed to initialize scanner '%s': %w", opts.ScannerName, err)
	}

	// Step 5: Execute scan
	report, err := scannerInstance.Scan(ctx, opts.Target, rulePaths)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	// Step 6: Process and enrich results
	enrichedReport, err := o.processor.Process(report, languages)
	if err != nil {
		return nil, fmt.Errorf("failed to process results: %w", err)
	}

	return enrichedReport, nil
}
