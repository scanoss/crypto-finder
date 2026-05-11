package scan

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/scanoss/crypto-finder/internal/utils"
)

// ValidationOptions contains scan flag values required for validation.
type ValidationOptions struct {
	RuleFiles        []string
	RuleDirs         []string
	NoRemoteRules    bool
	Scanner          string
	AllowedScanners  []string
	Interfile        bool
	InterfileScanner string
	Format           string
	SupportedFormats []string
	Languages        []string
	ScanDependencies bool
	ExportCallgraph  string
}

// ValidateFlags validates scan inputs and returns normalized language hints.
func ValidateFlags(target string, opts ValidationOptions) ([]string, error) {
	// Validate target exists.
	if _, err := os.Stat(target); os.IsNotExist(err) {
		return nil, fmt.Errorf("target path does not exist: %s", target)
	}

	// Validate that at least one rule source is specified.
	// Either local rules OR remote rules (unless --no-remote-rules is set).
	if len(opts.RuleFiles) == 0 && len(opts.RuleDirs) == 0 && opts.NoRemoteRules {
		return nil, fmt.Errorf("no rules specified: use --rules <file>, --rules-dir <directory>, or enable remote rules")
	}

	for _, ruleDir := range opts.RuleDirs {
		if err := utils.ValidateRuleDirNotEmpty(ruleDir); err != nil {
			return nil, err
		}
	}

	// Validate scanner.
	if !slices.Contains(opts.AllowedScanners, opts.Scanner) {
		return nil, fmt.Errorf("invalid scanner name: %s", opts.Scanner)
	}

	// Validate interfile flag is only used with the configured interfile scanner.
	if opts.Interfile && opts.Scanner != opts.InterfileScanner {
		return nil, fmt.Errorf("--interfile flag is only supported with --scanner %s", opts.InterfileScanner)
	}

	// Validate output format.
	if !slices.Contains(opts.SupportedFormats, opts.Format) {
		return nil, fmt.Errorf("unsupported output format '%s' (supported: %v)", opts.Format, opts.SupportedFormats)
	}

	// Normalize language hints to lowercase.
	normalizedLanguages := make([]string, len(opts.Languages))
	for i, lang := range opts.Languages {
		normalizedLanguages[i] = strings.ToLower(strings.TrimSpace(lang))
	}

	return normalizedLanguages, nil
}
