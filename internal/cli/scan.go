package cli

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/language"
	"github.com/scanoss/crypto-finder/internal/output"
	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/scanner/semgrep"
	"github.com/scanoss/crypto-finder/pkg/schema"
)

const DEFAULT_SCANNER = "semgrep"
const DEFAULT_OUTPUT_FILE = "crypto-results.json"
const DEFAULT_TIMEOUT = "10m"

// TODO: We'll support more scanners in the future.
var ALLOWED_SCANNERS []string = []string{"semgrep"}

var (
	scanRules      []string
	scanRuleDirs   []string
	scanScanner    string
	scanOutputFile string
	scanLanguages  []string
	scanFailOnFind bool
	scanTimeout    string
)

var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Scan source code for cryptographic usage",
	Long: `Scan source code repositories for cryptographic algorithm usage.

	The scan command executes a scanner (default: Semgrep) against the target
	directory or file using specified rules. It outputs findings in a standardized
	interim JSON format.

	Examples:
	  # Scan with a single rule file
	  crypto-finder scan --rules ./rules/aes.yaml /path/to/code

	  # Scan with multiple rule files
	  crypto-finder scan --rules rule1.yaml --rules rule2.yaml /path/to/code

	  # Scan with a rule directory
	  crypto-finder scan --rules-dir ./rules/java/ /path/to/code.java

	  # Specify scanner and output file
	  crypto-finder scan --scanner semgrep --output-file results.json /path/to/code

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
	scanCmd.Flags().StringVar(&scanOutputFile, "output-file", DEFAULT_OUTPUT_FILE, "Output file path")
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

	// Setup dependencies
	langDetector := language.NewEnryDetector()
	rulesManager := rules.NewManager()
	scannerRegistry := scanner.NewRegistry()

	// Register scanners
	scannerRegistry.Register("semgrep", semgrep.NewAdapter())
	// TODO: Register opengrep, cbom-toolkit

	// Create orchestrator
	orchestrator := engine.NewOrchestrator(langDetector, rulesManager, scannerRegistry)

	// Build scan options
	scanOpts := engine.ScanOptions{
		Target:       target,
		ScannerName:  scanScanner,
		RulePaths:    scanRules,
		RuleDirs:     scanRuleDirs,
		LanguageHint: scanLanguages,
		ScannerConfig: scanner.Config{
			Timeout: timeout,
		},
	}

	// Execute scan
	if verbose {
		fmt.Fprintf(os.Stderr, "Starting scan of %s with scanner '%s'...\n", target, scanScanner)
	}

	report, err := orchestrator.Scan(ctx, scanOpts)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Write output
	writer := output.NewJSONWriter()
	if err := writer.Write(report, scanOutputFile); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	// Print summary to stderr
	findingsCount := countFindings(report)
	filesCount := len(report.Findings)

	fmt.Fprintf(os.Stderr, "\nScan complete:\n")
	fmt.Fprintf(os.Stderr, "  Files with findings: %d\n", filesCount)
	fmt.Fprintf(os.Stderr, "  Total crypto assets: %d\n", findingsCount)
	fmt.Fprintf(os.Stderr, "  Output: %s\n", scanOutputFile)

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

	// Normalize language hints to lowercase
	for i, lang := range scanLanguages {
		scanLanguages[i] = strings.ToLower(strings.TrimSpace(lang))
	}

	return nil
}

func countFindings(report *schema.InterimReport) int {
	if report == nil {
		return 0
	}

	count := 0
	for _, finding := range report.Findings {
		count += len(finding.CryptographicAssets)
	}
	return count
}
