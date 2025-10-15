package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/language"
	"github.com/scanoss/crypto-finder/internal/output"
	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/scanner/semgrep"
	"github.com/scanoss/crypto-finder/internal/skip"
)

const DEFAULT_SCANNER = "semgrep"
const DEFAULT_FORMAT = "json"
const DEFAULT_TIMEOUT = "10m"

// TODO: We'll support more scanners in the future.
var ALLOWED_SCANNERS []string = []string{"semgrep"}

// Supported output formats
var SUPPORTED_FORMATS []string = []string{"json"} // Future: csv, html, sarif

var (
	scanRules      []string
	scanRuleDirs   []string
	scanScanner    string
	scanFormat     string
	scanOutput     string
	scanLanguages  []string
	scanFailOnFind bool
	scanTimeout    string
)

var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Scan source code for cryptographic usage",
	Long: `Scan source code repositories for cryptographic algorithm usage.

	The scan command executes a scanner (default: Semgrep) against the target
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
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("you must specify a target directory to scan")
		}
		return nil
	},
	RunE: runScan,
}

func init() {
	// Add flags
	scanCmd.Flags().StringArrayVar(&scanRules, "rules", []string{}, "Rule file path (repeatable)")
	scanCmd.Flags().StringArrayVar(&scanRuleDirs, "rules-dir", []string{}, "Rule directory path (repeatable)")
	scanCmd.Flags().StringVar(&scanScanner, "scanner", DEFAULT_SCANNER, "Scanner to use")
	scanCmd.Flags().StringVar(&scanFormat, "format", DEFAULT_FORMAT, "Output format: json (csv, html, sarif coming soon)")
	scanCmd.Flags().StringVar(&scanOutput, "output", "", "Output file path (default: stdout)")
	scanCmd.Flags().StringSliceVar(&scanLanguages, "languages", []string{}, "Override language detection (comma-separated)")
	scanCmd.Flags().BoolVar(&scanFailOnFind, "fail-on-findings", false, "Exit with error if findings detected")
	scanCmd.Flags().StringVar(&scanTimeout, "timeout", DEFAULT_TIMEOUT, "Scan timeout (e.g., 10m, 1h)")
}

func runScan(cmd *cobra.Command, args []string) error {
	target := args[0]

	// Validate flags
	if err := validateScanFlags(target); err != nil {
		return err
	}

	// Parse timeout
	timeout, err := time.ParseDuration(scanTimeout)
	if err != nil {
		return fmt.Errorf("invalid timeout format '%s': %w (use format like '10m' or '1h')", scanTimeout, err)
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

	// Setup rule sources and inject into manager
	// For MVP, we only use local rules, but remote sources can be easily added
	localRuleSource := rules.NewLocalRuleSource(scanRules, scanRuleDirs)
	rulesManager := rules.NewManager(localRuleSource)

	log.Info().Msgf("Rules manager configured with source: %s", localRuleSource.Name())

	// Setup dependencies
	langDetector := language.NewEnryDetector(skipMatcher)
	scannerRegistry := scanner.NewRegistry()

	// Register scanners
	// TODO: Register opengrep, cbom-toolkit
	scannerRegistry.Register("semgrep", semgrep.NewSemgrepScanner())

	// Create orchestrator
	orchestrator := engine.NewOrchestrator(langDetector, rulesManager, scannerRegistry)

	// Build scan options
	scanOpts := engine.ScanOptions{
		Target:       target,
		ScannerName:  scanScanner,
		LanguageHint: scanLanguages,
		ScannerConfig: scanner.Config{
			Timeout:      timeout,
			SkipPatterns: skipPatterns,
		},
	}

	// Execute scan
	log.Info().Msgf("Starting scan of %s with scanner '%s'...", target, scanScanner)

	report, err := orchestrator.Scan(ctx, scanOpts)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Get the appropriate writer for the format
	factory := output.NewWriterFactory()
	writer, err := factory.GetWriter(scanFormat)
	if err != nil {
		return fmt.Errorf("failed to get output writer: %w", err)
	}

	// Write output (to stdout or file)
	if err := writer.Write(report, scanOutput); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	// Print summary to stderr
	findingsCount := countFindings(report)
	filesCount := len(report.Findings)

	fmt.Fprintf(os.Stderr, "\nScan complete:\n")
	fmt.Fprintf(os.Stderr, "  Files with findings: %d\n", filesCount)
	fmt.Fprintf(os.Stderr, "  Total crypto assets: %d\n", findingsCount)

	// Show output location conditionally
	if scanOutput != "" && scanOutput != "-" {
		fmt.Fprintf(os.Stderr, "  Output: %s\n", scanOutput)
	} else {
		fmt.Fprintf(os.Stderr, "  Output: <stdout>\n")
	}

	// Handle --fail-on-findings
	if scanFailOnFind && findingsCount > 0 {
		return fmt.Errorf("scan detected %d findings (--fail-on-findings enabled)", findingsCount)
	}

	return nil
}

func validateScanFlags(target string) error {
	// Validate target exists
	if _, err := os.Stat(target); os.IsNotExist(err) {
		return fmt.Errorf("target path does not exist: %s", target)
	}

	// Validate that at least one rule source is specified
	if len(scanRules) == 0 && len(scanRuleDirs) == 0 {
		return fmt.Errorf("no rules specified: use --rules <file> or --rules-dir <directory>")
	}

	// Validate scanner
	if !slices.Contains(ALLOWED_SCANNERS, scanScanner) {
		return fmt.Errorf("invalid scanner name: %s", scanScanner)
	}

	// Validate output format
	if !slices.Contains(SUPPORTED_FORMATS, scanFormat) {
		return fmt.Errorf("unsupported output format '%s' (supported: %v)", scanFormat, SUPPORTED_FORMATS)
	}

	// Normalize language hints to lowercase
	for i, lang := range scanLanguages {
		scanLanguages[i] = strings.ToLower(strings.TrimSpace(lang))
	}

	return nil
}

func countFindings(report *entities.InterimReport) int {
	if report == nil {
		return 0
	}

	count := 0
	for _, finding := range report.Findings {
		count += len(finding.CryptographicAssets)
	}
	return count
}
