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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/javaruntime"
	"github.com/scanoss/reach/language"
	"github.com/scanoss/reach/parsememo"
	"github.com/scanoss/reach/perf"
	"github.com/scanoss/reach/skip"
	"github.com/spf13/cobra"

	api "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/cache"
	"github.com/scanoss/crypto-finder/internal/config"

	// The callgraph engine embeds no knowledge; importing cryptokb installs
	// the crypto KB as its contracts source.
	_ "github.com/scanoss/crypto-finder/internal/cryptokb"
	"github.com/scanoss/crypto-finder/internal/dependency"
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
)

const (
	formatJSON            = "json"
	formatText            = "text"
	defaultFormat         = formatJSON
	defaultTimeout        = "10m"
	defaultRulesetVersion = "latest"
	// progressStepScan is the scan command's top-level progress step, and the
	// parent of the detection, dependencies and export steps.
	progressStepScan  = "scan"
	ecosystemJava     = "java"
	ecosystemNode     = "node"
	ecosystemCPP      = "cpp"
	languageCPlusPlus = "c++" // the detector's and users' spelling of C++
	ecosystemRust     = "rust"
	ecosystemPython   = "python"
	ecosystemGo       = "go"
	ecosystemRuby     = "ruby"
	ecosystemCSharp   = "csharp"
)

// SupportedFormats lists the output formats supported by the tool.
var SupportedFormats = []string{formatJSON, "cyclonedx"}

var (
	scanRules                    []string
	scanRuleDirs                 []string
	scanCardsIndex               string
	scanCardsDir                 string
	scanFormat                   string
	scanOutput                   string
	scanLanguages                []string
	scanFailOnFind               bool
	scanTimeout                  string
	scanNoRemoteRules            bool
	scanNoCache                  bool
	scanAPIKey                   string
	scanAPIURL                   string
	scanAllowHTTP                bool
	scanStrict                   bool
	scanMaxStaleAge              string
	scanRulesetVersion           string
	scanRuleset                  string
	scanNoDedup                  bool
	scanDependencies             bool
	scanIncludeTests             bool
	scanNoDefaultExclusions      bool     // --no-default-exclusions flag
	scanExcludePatterns          []string // --exclude flag (repeatable)
	scanExportCallgraph          string
	scanExportCgFormat           string
	scanExportCallgraphMaxChains int
	scanExportEntryPoints        bool
	scanExportInternedFrames     bool
	scanExportProjectReach       bool
	scanExportGraphFragment      string
	scanExportGfFormat           string
	scanJavaJDKMajor             string
	scanJavaJDKHomes             []string
	scanJavaCompiledArtifact     string
	scanTypeJARs                 string
	scanTypePackages             string
	scanProgress                 bool
	scanCPUProfile               string
	scanMemProfile               string
	scanTraceProfile             string
)

var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Scan source code for cryptographic usage",
	Long: `Scan source code repositories for cryptographic algorithm usage.

	The scan command builds the target's typed call graph and matches the
	ruleset's cards against its call sites. This version detects cryptography
	in Java, Python, Go, JavaScript, TypeScript, Rust, Ruby, C, C++ and C#; a
	target in another language is reported as not supported. By
	default, it outputs findings to stdout in JSON format. Use --output to
	write to a file instead.

	Examples:
	  # Scan with default JSON output to stdout
	  crypto-finder scan --rules-dir ./rules /path/to/code

	  # Save output to a file
	  crypto-finder scan --rules-dir ./rules --output results.json /path/to/code

	  # Pipe output to jq for processing
	  crypto-finder scan --rules-dir ./rules /path/to/code | jq '.findings | length'

	  # Scan with multiple rule files
	  crypto-finder scan --rules rule1.yaml --rules rule2.yaml /path/to/code

	  # Report the dependencies' cryptography and whether the project reaches it
	  crypto-finder scan --scan-dependencies --export-callgraph callgraph.json /path/to/code

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
	scanCmd.Flags().StringVar(&scanCardsIndex, "cards-index", "", "Compiled card index to detect with, instead of compiling it from the ruleset's Java rules")
	scanCmd.Flags().StringVar(&scanCardsDir, "cards-dir", "", "Cards directory to detect with, instead of the ruleset's cards/")
	scanCmd.Flags().StringVarP(&scanFormat, "format", "f", defaultFormat, "Output format: json, cyclonedx (default: json)")
	scanCmd.Flags().StringVarP(&scanOutput, "output", "o", "", "Output file path (default: stdout)")
	scanCmd.Flags().StringSliceVar(&scanLanguages, "languages", []string{}, "Override language detection (comma-separated)")
	scanCmd.Flags().BoolVar(&scanFailOnFind, "fail-on-findings", false, "Exit with error if findings detected")
	scanCmd.Flags().StringVarP(&scanTimeout, "timeout", "t", defaultTimeout, "Scan timeout (e.g., 10m, 1h, 30d, 2w)")
	scanCmd.Flags().BoolVar(&scanNoRemoteRules, "no-remote-rules", false, "Disable default remote ruleset")
	scanCmd.Flags().BoolVar(&scanNoCache, "no-cache", false, "Force fresh download of remote rules, bypass cache")
	scanCmd.Flags().StringVar(&scanAPIKey, "api-key", "", "SCANOSS API key")
	scanCmd.Flags().StringVar(&scanAPIURL, "api-url", "", "SCANOSS API base URL")
	scanCmd.Flags().BoolVar(&scanAllowHTTP, allowHTTPFlag, false, allowHTTPUsage)
	scanCmd.Flags().BoolVar(&scanStrict, "strict", false, "Fail if cache expired and API unreachable (no stale cache fallback)")
	scanCmd.Flags().StringVar(&scanMaxStaleAge, "max-stale-age", "30d", "Maximum age for stale cache fallback (e.g., 30d, 720h, 2w, max: 90d)")
	scanCmd.Flags().StringVar(&scanRuleset, rulesetFlag, defaultRulesetName, rulesetUsage)
	scanCmd.Flags().StringVar(&scanRulesetVersion, rulesetVersionFlag, defaultRulesetVersion,
		"Remote ruleset version to fetch: latest or a release version such as v1.39.0 (pin it to reproduce a scan with identical rules)")
	scanCmd.Flags().BoolVar(&scanNoDedup, "no-dedup", false, "Disable per-line deduplication of findings")
	scanCmd.Flags().BoolVar(&scanDependencies, "scan-dependencies", false,
		"Report the cryptography of the project's dependencies (Java, Python, Go, JavaScript/TypeScript, Rust, Ruby, C#) and whether "+
			"the project reaches it: resolve the pinned dependency closure and ask the SCANOSS API in one request "+
			"(/v3/cryptography/reachability/application) for every dependency finding and its verdict. Dependencies the API has no data "+
			"for are mined locally (see --no-offline-fallback); --offline mines every dependency locally")
	scanCmd.Flags().BoolVar(&scanIncludeTests, "include-tests", false, "Include test sources in findings")
	scanCmd.Flags().BoolVar(&scanNoDefaultExclusions, "no-default-exclusions", false,
		"Disable the built-in default exclusions (docs, vendor, node_modules, shaded, generated protobuf stubs, ...). "+
			"Test sources stay excluded unless --include-tests is set. "+
			"Language detection will walk the full tree, which may significantly slow down scans on large repos. "+
			"Use --exclude to surgically re-add specific paths.")
	scanCmd.Flags().StringSliceVar(&scanExcludePatterns, "exclude", nil,
		"Glob pattern to skip during scanning (repeatable, e.g. --exclude vendor --exclude \"build/**\"). "+
			"Same gitignore-style syntax as scanoss.json settings.skip.patterns.scanning. "+
			"Patterns are added on top of the built-in defaults unless --no-default-exclusions is also set. "+
			"Duplicates are removed automatically.")
	scanCmd.Flags().StringVar(&scanExportCallgraph, "export-callgraph", "", "Export the crypto-scoped call graph to a file")
	scanCmd.Flags().StringVar(&scanExportCgFormat, "export-callgraph-format", "json", "Call graph export format (only json is supported)")
	scanCmd.Flags().IntVar(&scanExportCallgraphMaxChains, "export-callgraph-max-chains", 8,
		"Per-finding sampled call-chain budget (default 8, not a complete graph; opt in to 128 for more routes). Depth cap remains 32.")
	scanCmd.Flags().BoolVar(&scanExportEntryPoints, "export-callgraph-entry-points", false,
		"Include the optional full crypto_entry_points reverse-reachability index (default false)")
	scanCmd.Flags().BoolVar(&scanExportInternedFrames, "export-callgraph-interned-frames", true,
		"Emit schema 6.18: hydrate frame identity from functions[] via call_chain_indexes (default true). Set false for legacy schema 6.14 inlined frames.")
	scanCmd.Flags().BoolVar(&scanExportProjectReach, "export-callgraph-project-reachability", false,
		"When no dependency set was resolved, classify reachability against the scan target's own source packages, as a --scan-dependencies run does for first-party findings (default false). Leave it off when scanning a library on its own.")
	scanCmd.Flags().StringVar(&scanExportGraphFragment, "export-graph-fragment", "", "Export a reusable structural graph fragment to a file")
	scanCmd.Flags().StringVar(&scanExportGfFormat, "export-graph-fragment-format", "json", "Graph fragment export format (only json is supported)")
	scanCmd.Flags().StringVar(&scanJavaJDKMajor, "java-jdk-major", "", "Java JDK major for Java dependency resolution/type enrichment: auto, 8, 11, 17, 21")
	scanCmd.Flags().StringArrayVar(&scanJavaJDKHomes, "java-jdk-home", []string{}, "Java JDK home mapping in the form <major>=<path> (repeatable)")
	scanCmd.Flags().StringVar(&scanJavaCompiledArtifact, "java-compiled-artifact", "", "Compiled Java artifact path used for standalone callgraph/type enrichment")
	scanCmd.Flags().StringVar(&scanTypePackages, "type-packages", "", "Installed Python dependency packages (OS path-list separated: site-packages or virtual environment directories, unpacked wheels or sdists) indexed for Python type resolution only: neither parsed nor scanned, nothing run")
	scanCmd.Flags().StringVar(&scanTypeJARs, "type-jars", "", "Compiled dependency JARs (OS path-list separated) indexed for Java type resolution only: neither parsed nor scanned")
	scanCmd.Flags().BoolVar(&scanProgress, "progress", false, "Write structured scan progress JSONL to stderr")
	scanCmd.Flags().StringVar(&scanCPUProfile, "cpuprofile", "", "Write a pprof CPU profile of the whole scan to this file")
	scanCmd.Flags().StringVar(&scanMemProfile, "memprofile", "", "Write a pprof heap profile, taken after a GC at the end of the scan, to this file")
	scanCmd.Flags().StringVar(&scanTraceProfile, "trace", "", "Write a Go execution trace of the whole scan to this file")
	for _, name := range []string{"cpuprofile", "memprofile", "trace"} {
		if err := scanCmd.Flags().MarkHidden(name); err != nil {
			panic(err)
		}
	}
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
		if ecosystem := ecosystemFromHint(target, hint); ecosystem != "" {
			return ecosystem
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
	case ".cc", ".cp", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx", ".h++":
		return ecosystemCPP
	case ".go":
		return "go"
	case ".java":
		return ecosystemJava
	case ".py":
		return ecosystemPython
	case ".rs":
		return ecosystemRust
	case ".rb":
		return ecosystemRuby
	case ".cs":
		return ecosystemCSharp
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts":
		return ecosystemNode
	default:
		return ""
	}
}

func ecosystemFromHint(target, hint string) string {
	switch hint {
	case "c":
		if cppOnlyTarget(target) {
			return ecosystemCPP
		}
		return hint
	case "go", ecosystemJava, ecosystemPython, ecosystemRust, ecosystemRuby, ecosystemCSharp:
		return hint
	case "c#":
		return ecosystemCSharp
	case ecosystemCPP, languageCPlusPlus:
		return ecosystemCPP
	case ecosystemNode, "javascript", "typescript":
		return ecosystemNode
	default:
		return ""
	}
}

var (
	errCPPHeaderDetected = errors.New("c++ header detected")
	errCSourceDetected   = errors.New("c source detected")
)

// cppOnlyTarget reports a C target that reads as C++: it holds a C++ header
// (isCPPHeader) and no C source file. A target with a .c file is C whatever
// its headers say: the C graph is built from its .c units and their
// headers, the graph the C cards match, and C++ is a language of its own.
// A C++ header beside them (a C++ wrapper, a test or tool written in C++)
// does not make it C++. A header-only C++ library, or a C++ header scanned
// alone, has no C unit and reads as C++.
func cppOnlyTarget(target string) bool {
	return !hasCSource(target) && cppHeaderTarget(target)
}

// hasCSource reports a .c file at or under target.
func hasCSource(target string) bool {
	return walkTargetFiles(target, func(path string) error {
		if strings.EqualFold(filepath.Ext(path), ".c") {
			return errCSourceDetected
		}
		return nil
	}, errCSourceDetected)
}

func cppHeaderTarget(target string) bool {
	return walkTargetFiles(target, func(path string) error {
		if isCPPHeader(path) {
			return errCPPHeaderDetected
		}
		return nil
	}, errCPPHeaderDetected)
}

// walkTargetFiles calls visit on target, a file, or on every file under it,
// outside .git, build and vendor directories, and reports whether visit
// stopped the walk with found.
func walkTargetFiles(target string, visit func(path string) error, found error) bool {
	info, err := os.Stat(target)
	if err != nil {
		return false
	}
	if !info.IsDir() {
		return errors.Is(visit(target), found)
	}
	err = filepath.WalkDir(target, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "build", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		return visit(path)
	})
	return errors.Is(err, found)
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

func newCallGraphBuilder(ecosystem string, javaRuntime javaruntime.Config, includeTests bool, skipMatcher skip.SkipMatcher) (*callgraph.Builder, error) {
	cgParser := callgraph.NewParserForEcosystem(ecosystem, callgraph.WithIncludeTests(includeTests))
	if cgParser == nil {
		return nil, fmt.Errorf("call graph export is not supported for ecosystem %q", ecosystem)
	}

	cgBuilder := callgraph.NewBuilderForEcosystem(ecosystem, cgParser)
	cgBuilder.SetSkipMatcher(skipMatcher)
	if typeResolver := callgraph.NewTypeResolverForEcosystem(ecosystem, javaRuntime); typeResolver != nil {
		configureTypeResolverCaches(typeResolver)
		cgBuilder.SetTypeResolver(typeResolver)
	}

	return cgBuilder, nil
}

// warnJavaPlatformSignaturesUnavailable warns, once per scan, that the JDK the
// Java type resolver used gave no platform method signatures (a JRE or a
// jlink'd image has no jmods/). Calls dispatched on JDK types then resolve by
// name only and their chains can end unknown. The verdicts are not changed.
func warnJavaPlatformSignaturesUnavailable(graphs *graphStore, ecosystem string, meta *callgraph.JavaPlatformSignatureMetadata, runtime javaruntime.Config) {
	if ecosystem != ecosystemJava || meta == nil || meta.SignaturesUsed || !graphs.firstJavaPlatformWarning() {
		return
	}
	javaHome, source := javaHomeTried(runtime)
	if javaHome == "" {
		javaHome = "(not set)"
	}
	log.Warn().
		Str("java_home", javaHome).
		Str("java_home_source", source).
		Str("reason", meta.UnavailableReason).
		Msgf("Java platform signatures are unavailable from the JDK at %s; calls dispatched on JDK types resolve by name only and may end unknown. Full Java dispatch needs a JDK 21 with jmods/ (set JAVA_HOME or --java-jdk-home)", javaHome)
}

// javaHomeTried is the JDK home the Java type resolver reads platform
// signatures from, and where it came from: the configured home of an explicit
// major (--java-jdk-major with --java-jdk-home), else JAVA_HOME.
func javaHomeTried(runtime javaruntime.Config) (home, source string) {
	if major := runtime.RequestedMajorOrAuto(); major != javaruntime.AutoMajor {
		return strings.TrimSpace(runtime.Homes[major]), "java-jdk-home"
	}
	return strings.TrimSpace(os.Getenv("JAVA_HOME")), "JAVA_HOME"
}

// javaTypeIndex, when set, is shared by the Java type resolver of every call
// graph this process builds, so building many graphs indexes the Java
// platform and each type JAR once. A mode that builds many graphs in one
// process sets it; a single scan leaves it nil.
var javaTypeIndex *callgraph.SharedJavaTypeIndex

// configureTypeResolverCaches injects an on-disk cache into a type
// resolver that supports one, when that ecosystem-specific cache type
// assertion matches. Extracted from newCallGraphBuilder to keep that
// function's nesting flat as ecosystem-specific cache wiring grows
// (row 14, python-parser-parity-2, mirrors the pre-existing Java
// bytecode-cache wiring).
func configureTypeResolverCaches(typeResolver callgraph.TypeResolver) {
	javaResolver, isJava := typeResolver.(*callgraph.JavaBytecodeTypeResolver)
	pythonResolver, isPython := typeResolver.(*callgraph.PythonTypeResolverChain)
	if !isJava && !isPython {
		return
	}
	cacheRoot, cacheRootErr := config.GetCacheDir()
	if isJava {
		bytecodeCache, err := diskCache(cacheRoot, cacheRootErr, callgraph.NewDiskBytecodeIndexCache)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to create Java bytecode cache, bytecode indexing will not be cached")
		} else {
			javaResolver.SetBytecodeIndexCache(bytecodeCache)
		}
		javaResolver.SetSharedIndex(javaTypeIndex)
	}
	if isPython {
		signatureCache, err := diskCache(cacheRoot, cacheRootErr, callgraph.NewDiskPythonSignatureIndexCache)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to create Python signature cache, dependency signature indexing will not be cached")
		} else {
			pythonResolver.SetSignatureIndexCache(signatureCache)
		}
	}
}

// diskCache opens a callgraph disk cache under the crypto-finder cache root,
// reporting a failed cache-root lookup as the cache's error.
func diskCache[C any](cacheRoot string, cacheRootErr error, open func(string) (C, error)) (C, error) {
	if cacheRootErr != nil {
		var zero C
		return zero, fmt.Errorf("failed to get cache dir: %w", cacheRootErr)
	}
	return open(cacheRoot)
}

func applyTestSkipPatterns(patterns []string, includeTests bool) []string {
	if includeTests {
		return patterns
	}
	return skip.WithDefaultTestPatterns(patterns)
}

// applyCTestSkipPatterns adds the bundled C/C++ test-source patterns when the
// target holds other C/C++ product sources they leave in the scan.
func applyCTestSkipPatterns(patterns []string, targetDir string, includeTests bool) []string {
	if includeTests {
		return patterns
	}
	return append(patterns, skip.CTestPatternsFor(targetDir)...)
}

// buildSkipPatterns assembles skip patterns from the configured sources,
// honoring the --no-default-exclusions and --exclude CLI flags. Returns the
// merged, deduplicated pattern list plus a human-readable label for logging.
// The label and pattern list are derived from the same source slice so they
// cannot drift.
//
// On MultiSource.Load failure the function falls back to:
//   - skip.DefaultPatterns() when !noDefaults
//   - empty list             when  noDefaults
//
// In both cases any user --exclude patterns are merged into the fallback so
// they are not silently dropped along with the MultiSource error.
func buildSkipPatterns(targetDir string, noDefaults bool, userExcludes []string) (patterns []string, sourceLabel string) {
	sources := make([]skip.PatternSource, 0, 3)

	var defaults *skip.DefaultsSource
	if !noDefaults {
		defaults = skip.NewDefaultsSourceForTarget(targetDir)
		sources = append(sources, defaults)
		if rescued := defaults.Rescued(); len(rescued) > 0 {
			// Warn, not Info: a default run must show that a built-in
			// exclusion was dropped, in the run that dropped it.
			log.Warn().Msgf(
				"%s holds the only source in this tree, so it is scanned instead of excluded. "+
					"A published package is not a checkout: excluding its compiled output would "+
					"leave nothing to read and report no cryptography. Use --exclude %s to override.",
				strings.Join(rescued, ", "), strings.Join(rescued, " --exclude "),
			)
		}
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
			// DefaultsSource.Load never returns an error (no I/O), and reusing
			// it keeps the fallback on the same rescue decision as the happy
			// path instead of re-excluding a directory that is the artifact.
			ds, _ := defaults.Load() //nolint:errcheck // DefaultsSource.Load never returns an error
			fallback = append(fallback, ds...)
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

func buildStandaloneCallGraphResult(graphs *graphStore, target string, report *entities.InterimReport, languageHints []string, javaRuntime javaruntime.Config, includeTests bool, compiledArtifact string, skipMatcher skip.SkipMatcher) (*engine.DepScanResult, error) {
	ecosystem := ecosystemFromHints(target, languageHints)
	if ecosystem == "" {
		return nil, fmt.Errorf("could not determine a supported ecosystem for call graph export")
	}
	return buildStandaloneCallGraphResultForEcosystem(graphs, target, report, ecosystem, javaRuntime, includeTests, compiledArtifact, skipMatcher, true)
}

func buildStandaloneCallGraphResultForEcosystem(graphs *graphStore, target string, report *entities.InterimReport, ecosystem string, javaRuntime javaruntime.Config, includeTests bool, compiledArtifact string, skipMatcher skip.SkipMatcher, withTypeResolution bool) (*engine.DepScanResult, error) {
	if withTypeResolution {
		if stored, ok := graphs.load(target, ecosystem, report); ok {
			return stored, nil
		}
	}
	targetDir, err := callGraphTargetDir(target)
	if err != nil {
		return nil, fmt.Errorf("resolve call graph target: %w", err)
	}

	var cgBuilder *callgraph.Builder
	if withTypeResolution {
		var err error
		cgBuilder, err = newCallGraphBuilder(ecosystem, javaRuntime, includeTests, skipMatcher)
		if err != nil {
			return nil, err
		}
		if ecosystem == "go" {
			cgBuilder.SetTypeResolver(callgraph.NewGoSourceTypeResolver(goSourceRoots(targetDir)))
		}
	} else {
		cgParser := callgraph.NewParserForEcosystem(ecosystem, callgraph.WithIncludeTests(includeTests))
		if cgParser == nil {
			return nil, fmt.Errorf("call graph export is not supported for ecosystem %q", ecosystem)
		}
		cgBuilder = callgraph.NewBuilderForEcosystem(ecosystem, cgParser)
		cgBuilder.SetSkipMatcher(skipMatcher)
	}

	rootModule := scanutil.DetectRootModule(targetDir, ecosystem)
	var typeOnly []callgraph.PackageDir
	if withTypeResolution && ecosystem == "java" {
		typeOnly = typeOnlyJARPackages(graphs.typeJARList())
	}
	if withTypeResolution && ecosystem == ecosystemPython {
		typeOnly = typeOnlyPythonPackages(graphs.typePackageList())
	}
	graph, err := cgBuilder.BuildFromDirectories([]callgraph.PackageDir{{
		Dir:                  targetDir,
		ImportPath:           rootModule,
		CompiledArtifactPath: compiledArtifact,
	}}, typeOnly)
	if err != nil {
		return nil, fmt.Errorf("build call graph: %w", err)
	}

	result := &engine.DepScanResult{
		Report:      report,
		CallGraph:   graph,
		RootModule:  rootModule,
		Ecosystem:   ecosystem,
		ProjectRoot: targetDir,
	}
	if withTypeResolution {
		graphs.keep(target, ecosystem, result)
		warnJavaPlatformSignaturesUnavailable(graphs, ecosystem, graph.JavaPlatformSignatures, javaRuntime)
	}
	return result, nil
}

// attachAdditionalEcosystemGraphs builds a call graph for every other
// supported ecosystem the report has first-party findings in, so each of those
// findings resolves against the graph of its own language instead of the
// primary one. An ecosystem the dependency phase already resolved keeps the
// dependency-aware graph it built and gets no second, source-only one. A
// graph that fails to build is left out with a warning: its findings are then
// exported as not analyzed, and the scan still completes.
func attachAdditionalEcosystemGraphs(graphs *graphStore, target string, report *entities.InterimReport, result *engine.DepScanResult, javaRuntime javaruntime.Config, includeTests bool, skipMatcher skip.SkipMatcher) {
	if result == nil || result.CallGraph == nil {
		return
	}
	for _, ecosystem := range scanutil.MissingAdditionalCallGraphEcosystems(report, result) {
		extra, err := buildStandaloneCallGraphResultForEcosystem(graphs, target, report, ecosystem, javaRuntime, includeTests, "", skipMatcher, true)
		if err != nil {
			log.Warn().Err(err).Str("ecosystem", ecosystem).Msg("Failed to build call graph for additional ecosystem; its findings are exported as not analyzed")
			continue
		}
		log.Info().
			Str("ecosystem", ecosystem).
			Int("functions", len(extra.CallGraph.Functions)).
			Msg("Built call graph for additional ecosystem")
		result.AdditionalEcosystems = append(result.AdditionalEcosystems, extra)
	}
}

// prepareScanOIDProjection returns the only report used by OID projections.
// All mutable finding identity and output-version state is finalized first.
func prepareScanOIDProjection(report *entities.InterimReport, assignFindingIDs bool) (*oid.ResolvedReport, error) {
	engine.EnsureFindingSources(report)
	if assignFindingIDs {
		engine.AssignFindingIDs(report)
	}
	report.Version = entities.InterimFormatVersion
	prepared, err := oid.NewDefaultResolver().PrepareReport(report)
	if err != nil {
		return nil, err
	}
	return prepared.ReportClone(), nil
}

// prepareReportOccurrenceKeys reuses source-only callgraphs for normal findings
// output, without starting dependency scanning. Source anchors are optional, so
// parser failures leave the existing report unchanged.
func prepareReportOccurrenceKeys(graphs *graphStore, target string, report *entities.InterimReport, languageHints []string, javaRuntime javaruntime.Config, includeTests bool, compiledArtifact string, skipMatcher skip.SkipMatcher, result *engine.DepScanResult) *engine.DepScanResult {
	if scanutil.CountFindings(report) == 0 {
		return result
	}
	for _, ecosystem := range reportOccurrenceKeyEcosystems(target, report, languageHints) {
		result = addReportOccurrenceKeyAnchors(graphs, target, report, ecosystem, javaRuntime, includeTests, compiledArtifact, skipMatcher, result)
		// A Rust rule anchors its crate with a file-level import guard, which
		// cannot constrain the receiver of a method call; drop the matches whose
		// receiver type the scanned source declares itself. This is the only
		// hook that runs on EVERY scan: the export-path call graph at the top of
		// runScan is built only under --export-callgraph/--export-graph-fragment,
		// while this loop builds one per ecosystem whenever there are findings.
		// It also runs after rule-entrypoint synthesis and conditioned-finding
		// materialization, so it sees the assets those two passes add.
		//
		// A mixed-language target loops over several ecosystems and keeps the
		// first graph in result, so the filter runs only on the iteration of
		// the ecosystem that graph was built for.
		if result != nil && result.Ecosystem == ecosystem {
			scanutil.FilterForeignReceiverAssets(report, result)
		}
	}
	if result != nil {
		result.Report = report
		scanutil.AssignOccurrenceKeys(result)
	}
	return result
}

func addReportOccurrenceKeyAnchors(graphs *graphStore, target string, report *entities.InterimReport, ecosystem string, javaRuntime javaruntime.Config, includeTests bool, compiledArtifact string, skipMatcher skip.SkipMatcher, result *engine.DepScanResult) *engine.DepScanResult {
	if result != nil && result.CallGraph != nil && result.Ecosystem == ecosystem {
		return result
	}
	anchors, ok := graphs.load(target, ecosystem, report)
	var err error
	if !ok {
		anchors, err = buildStandaloneCallGraphResultForEcosystem(graphs, target, report, ecosystem, javaRuntime, includeTests, compiledArtifact, skipMatcher, false)
	}
	if err != nil {
		log.Warn().Err(err).Str("ecosystem", ecosystem).Msg("Failed to build optional source anchors for occurrence keys")
		return result
	}
	result = mergeOccurrenceKeyAnchors(result, anchors)
	if result.OccurrenceAnchors == nil {
		result.OccurrenceAnchors = make(map[string]*callgraph.FunctionDecl)
	}
	for id, function := range anchors.CallGraph.Functions {
		result.OccurrenceAnchors[occurrenceAnchorKey(ecosystem, id)] = function
	}
	return result
}

func mergeOccurrenceKeyAnchors(result, anchors *engine.DepScanResult) *engine.DepScanResult {
	if result == nil {
		return anchors
	}
	if result.CallGraph != nil {
		return result
	}
	result.CallGraph = anchors.CallGraph
	if result.RootModule == "" {
		result.RootModule = anchors.RootModule
	}
	if result.Ecosystem == "" {
		result.Ecosystem = anchors.Ecosystem
	}
	if result.ProjectRoot == "" {
		result.ProjectRoot = anchors.ProjectRoot
	}
	return result
}

func reportOccurrenceKeyEcosystems(target string, report *entities.InterimReport, languageHints []string) []string {
	seen := make(map[string]bool)
	ecosystems := make([]string, 0, len(languageHints))
	addEcosystem := func(ecosystem string) {
		if ecosystem != "" && !seen[ecosystem] {
			seen[ecosystem] = true
			ecosystems = append(ecosystems, ecosystem)
		}
	}
	add := func(hint string) { addEcosystem(ecosystemFromHint(target, hint)) }
	cppScan := cppLanguageScan(target, languageHints)
	for _, finding := range report.Findings {
		if isCFamilyLanguage(finding.Language) && cppScan {
			// A C++ scan keys a C-family finding (a C rule matches C++
			// sources too) on the C++ graph alone, the graph its fragment
			// stores, as a C target keys on the C graph alone (below):
			// anchors of a C parse of a header would give the finding the
			// key of a function annotate does not know, and annotate keys
			// it by its file.
			addEcosystem(ecosystemCPP)
			continue
		}
		if isCFamilyLanguage(finding.Language) {
			// A C-language detector can report both C and C++ sources. Build both
			// source-only parsers so a C++ header never hides .c anchors.
			//
			// This tests the C FAMILY, not the literal "c". Once the detector
			// reads file content it can tell a C++ header from a C one and
			// reports "c++" for the former, which used to fall through to the
			// generic branch below and add only cpp -- dropping the c ecosystem
			// this branch exists to guarantee.
			//
			// A C target (cppOnlyTarget is false) keys its findings on the C
			// graph alone, the graph its fragment stores: annotate keys them
			// on that graph, so anchors of a C++ parse of its headers would
			// give a finding in a header another key.
			addEcosystem("c")
			if isCPPSource(finding.FilePath) || cppOnlyTarget(target) {
				addEcosystem(ecosystemCPP)
			}
			continue
		}
		add(finding.Language)
	}
	for _, hint := range languageHints {
		add(hint)
	}
	if len(ecosystems) == 0 {
		add(ecosystemFromHints(target, languageHints))
	}
	return ecosystems
}

// cppLanguageScan reports a scan in C++: its first supported language hint
// is cpp (`--languages cpp`, or a target the detector reads as C++ first).
// A `--languages c` target that reads as C++ (cppOnlyTarget) is not one.
func cppLanguageScan(target string, languageHints []string) bool {
	for _, hint := range languageHints {
		if ecosystemFromHint(target, hint) != "" {
			return hint == ecosystemCPP || hint == languageCPlusPlus
		}
	}
	return false
}

// isCFamilyLanguage reports whether a detected language is C or C++, which
// share headers and translation units and so share the anchor treatment above.
func isCFamilyLanguage(lang string) bool {
	switch lang {
	case "c", languageCPlusPlus, ecosystemCPP:
		return true
	default:
		return false
	}
}

func occurrenceAnchorKey(ecosystem, functionID string) string {
	return ecosystem + "\x00" + functionID
}

func isCPPSource(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".cc", ".cp", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx", ".h++":
		return true
	default:
		return false
	}
}

//nolint:gocognit,gocyclo,funlen // Main scan orchestration function handles validation, cache management, scanner execution, and output formatting - splitting would reduce clarity
func runScan(cmd *cobra.Command, args []string) (runErr error) {
	target := args[0]
	graphs := newGraphStore(target, scanTypeJARs)
	graphs.typePackages = scanTypePackages
	if scanOffline && scanDependencies {
		defer limitOfflineMemory()()
	}

	// Validate flags
	normalizedLanguages, err := scanutil.ValidateFlags(target, scanutil.ValidationOptions{
		RuleFiles:        scanRules,
		RuleDirs:         scanRuleDirs,
		NoRemoteRules:    scanNoRemoteRules,
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
	if scanOffline && !scanDependencies {
		log.Warn().Msg("--offline applies to --scan-dependencies only; this scan resolves no dependencies")
	}
	rulesetName, rulesetVersion, err := resolveRemoteRuleset(cmd.Flags(), scanRuleset, scanRulesetVersion, scanNoRemoteRules)
	if err != nil {
		return err
	}
	if scanExportCallgraphMaxChains < 1 {
		return failure.WrapUnknown(
			fmt.Errorf("export-callgraph-max-chains must be at least 1"),
			failure.CodeInvalidArguments,
			failure.StageInput,
			"--export-callgraph-max-chains must be at least 1",
		)
	}

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

	stopProfiles, err := startScanProfiles(scanProfilePaths{
		CPU:   scanCPUProfile,
		Mem:   scanMemProfile,
		Trace: scanTraceProfile,
	}.withEnvDefaults(os.LookupEnv))
	if err != nil {
		return err
	}
	finishProfiles := func() {
		if profileErr := stopProfiles(); profileErr != nil {
			if runErr == nil {
				runErr = profileErr
				return
			}
			log.Warn().Err(profileErr).Msg("Failed to write scan profile")
		}
	}
	defer finishProfiles()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
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
	skipPatterns = applyCTestSkipPatterns(skipPatterns, targetDir, scanIncludeTests)

	if len(skipPatterns) > 0 {
		log.Info().Msgf("Using %d skip patterns from %s", len(skipPatterns), skipSrcLabel)
	}

	// Create skip matcher for language detection
	skipMatcher := skip.NewMatcher(skipPatterns, !scanNoDefaultExclusions)

	cfg := config.GetInstance()
	if err := cfg.Initialize(config.InitOptions{
		APIKey:    scanAPIKey,
		APIURL:    scanAPIURL,
		AllowHTTP: scanAllowHTTP,
	}); err != nil {
		return failure.WrapUnknown(
			err,
			failure.CodeConfigInitializationFailed,
			failure.StageConfig,
			"failed to initialize config",
		)
	}
	// The API serves the remote ruleset and, unless --offline, the
	// dependency findings.
	if !scanNoRemoteRules || (scanDependencies && !scanOffline) {
		if err := checkAPIURL(cfg.GetAPIURL(), cfg.GetAllowHTTP()); err != nil {
			return err
		}
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
	var remoteSource *rules.RemoteRuleSource

	if !scanNoRemoteRules {
		log.Info().
			Str("ruleset", rulesetName).
			Str("version", rulesetVersion).
			Bool("no-cache", scanNoCache).
			Msg("Remote rules enabled")

		apiClient := api.NewClient(cfg.GetAPIURL(), cfg.GetAPIKey(), api.WithAllowHTTP(cfg.GetAllowHTTP()))
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

		remoteSource = rules.NewRemoteRuleSource(
			ctx,
			rulesetName,
			rulesetVersion,
			cacheManager,
		)
		// A leased ruleset is decrypted into a per-run directory; remove it
		// when the scan ends, however it ends.
		defer remoteSource.Close()
		ruleSources = append(ruleSources, remoteSource)
	}

	// Append local rule sources if specified
	if len(scanRules) > 0 || len(scanRuleDirs) > 0 {
		localSource := rules.NewLocalRuleSource(scanRules, scanRuleDirs)
		ruleSources = append(ruleSources, localSource)
		log.Info().Msgf("Local rules enabled: %s", localSource.Name())
	}

	// Parsed card files are kept for the next scan only when every rule is a
	// local file; a leased ruleset must not outlive its run in clear.
	if remoteSource == nil {
		if cacheDir, err := config.GetCacheDir(); err == nil {
			parsememo.Enable(cacheDir)
		}
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

	var progress *scanutil.ProgressWriter
	scanStarted := false
	if scanProgress {
		progress = scanutil.NewProgressWriter(os.Stderr)
		if err := progress.Start(progressStepScan, ""); err != nil {
			return progressWriteFailure(err)
		}
		scanStarted = true
		defer func() {
			if progress == nil || !scanStarted {
				return
			}
			var progressErr error
			switch {
			case isScanCanceled(runErr):
				progressErr = progress.Cancel(progressStepScan, "", nil)
			case runErr != nil:
				progressErr = progress.Fail(progressStepScan, "", nil)
			default:
				progressErr = progress.Complete(progressStepScan, "", nil)
			}
			if progressErr != nil {
				runErr = progressWriteFailure(progressErr)
			}
		}()
	}
	// Deferred again so the profiles are written before the scan's terminal
	// progress event, which must report a profile write failure as failed.
	defer finishProfiles()

	// Pre-detect source languages at the CLI layer when the user did not pass
	// --languages. This makes the detected languages available to ancillary
	// features (notably --export-callgraph) that need to know the source
	// ecosystem before the scanner runs. Without this, repositories without
	// a build manifest (pom.xml, build.gradle, setup.py, go.mod, Cargo.toml)
	// fail callgraph export with "could not determine a supported ecosystem".
	// The orchestrator will reuse these hints instead of redetecting.
	detectionStarted := false
	//nolint:nestif // Pre-detection reports its lifecycle alongside the detection error.
	if len(scanLanguages) == 0 {
		if progress != nil {
			if err := progress.Start("detection", progressStepScan); err != nil {
				return progressWriteFailure(err)
			}
			detectionStarted = true
		}
		detected, detectErr := language.NewEnryDetector(skipMatcher).Detect(target)
		if detectErr != nil {
			if detectionStarted {
				if progressErr := progress.Fail("detection", progressStepScan, nil); progressErr != nil {
					return progressWriteFailure(progressErr)
				}
			}
			return failure.WrapUnknown(
				detectErr,
				failure.CodeLanguageDetectionFailed,
				failure.StageScan,
				"failed to detect languages",
			)
		}
		scanLanguages = detected
	}

	// This version detects cryptography in the scanned languages of the cards
	// table: a target is scanned for each one it holds, the first in detection order
	// (the most files) being the primary ecosystem. A target with source in
	// no other crypto language than unsupported ones fails; a mixed one
	// names the others in a warning and on the detection progress event.
	ecosystems, unsupported := scannedEcosystems(scanLanguages)
	if len(ecosystems) == 0 && len(unsupported) > 0 {
		if detectionStarted {
			if progressErr := progress.Fail("detection", progressStepScan, nil); progressErr != nil {
				return progressWriteFailure(progressErr)
			}
		}
		return languageNotSupported(unsupported)
	}
	if len(unsupported) > 0 {
		log.Warn().Strs("languages", unsupported).Msg("This version detects cryptography in Java, Python, Go, JavaScript, TypeScript, Rust, Ruby, C, C++ and C#; the target's sources in these languages are not scanned")
	}
	if len(ecosystems) == 0 {
		ecosystems = []string{ecosystemJava}
	}
	// The rule filter and every later step take the scanned languages by
	// their canonical names, with Java among them or not: the detector's
	// names (typescript, tsx) are not the card directory's (javascript).
	scanLanguages = scannedLanguageHints(ecosystems)

	// A dependency scan resolves each ecosystem's dependency closure before
	// detection: the Java closure's JARs type the one Java graph the scan
	// builds.
	var applicationPlans []*applicationReachabilityPlan
	depSkip := dependencySkip{reason: depSkipNotRequested}
	if scanDependencies {
		applicationPlans, depSkip, err = planApplicationReachabilities(ctx, graphs, target, ecosystems, func() (javaruntime.Config, error) {
			runtimeErr := ensureJavaRuntime()
			return javaRuntime, runtimeErr
		}, skipPatterns)
		if err != nil {
			return err
		}
	}

	// Setup dependencies
	langDetector := language.NewEnryDetector(skipMatcher)
	scannerRegistry := scanner.NewRegistry()

	// The cards detector is the only one: it matches the ruleset's cards
	// against the call sites of the target's typed call graph, one graph per
	// scanned ecosystem.
	javaRuntimeFn := func() (javaruntime.Config, error) {
		err := ensureJavaRuntime()
		return javaRuntime, err
	}
	cardsOptions := cards.Options{
		IndexPath: scanCardsIndex,
		CardsDir:  scanCardsDir,
		Ruleset:   cardsRuleset(scanRuleDirs, rulesManager),
	}
	for i, ecosystem := range ecosystems {
		fragment := cardsFragmentBuilder(graphs, target, ecosystem, javaRuntimeFn, scanIncludeTests, scanJavaCompiledArtifact, skipMatcher)
		cardsLanguage, languageErr := cardsLanguageOf(ecosystem)
		if languageErr != nil {
			return languageErr
		}
		if i == 0 {
			cardsOptions.Fragment, cardsOptions.Language = fragment, cardsLanguage
			continue
		}
		cardsOptions.Also = append(cardsOptions.Also, cards.AlsoLanguage{Language: cardsLanguage, Fragment: fragment})
	}
	scannerRegistry.RegisterFactory(cards.ScannerName, cards.NewScannerFactory(cardsOptions))

	orchestrator := engine.NewOrchestrator(langDetector, rulesManager, scannerRegistry)

	scanOpts := engine.ScanOptions{
		Target:       target,
		ScannerName:  cards.ScannerName,
		LanguageHint: scanLanguages,
		ScannerConfig: scanner.Config{
			Timeout:      timeout,
			SkipPatterns: skipPatterns,
			DisableDedup: scanNoDedup,
		},
	}
	if progress != nil {
		scanOpts.Progress = newProgressReporter(progress, "")
		scanOpts.ProgressDetectionStarted = detectionStarted
		scanOpts.UnsupportedLanguages = unsupported
	}

	log.Info().Msgf("Starting scan of %s...", target)

	detectSpan := perf.Start("scan")
	report, err := orchestrator.Scan(ctx, scanOpts)
	detectSpan.End()
	if err != nil {
		return err
	}
	var callGraphResult *engine.DepScanResult

	// Dependency phase: each closure's findings and verdicts from the API.
	if len(applicationPlans) > 0 {
		callGraphResult, err = runApplicationReachability(ctx, progress, cfg, applicationPlans, target, report, javaRuntime, skipMatcher, rulesManager)
		if err != nil {
			return err
		}
		report = callGraphResult.Report
	} else if progress != nil {
		if err := progress.SkipWithDetails("dependencies", progressStepScan, depSkip.reason, dependencySkipDetails(depSkip.reason, depSkip.ecosystem)); err != nil {
			return progressWriteFailure(err)
		}
	}

	engine.EnsureFindingSources(report)

	exportStarted := false
	exportCompleted := false
	defer func() {
		if progress == nil || !exportStarted || exportCompleted {
			return
		}
		var progressErr error
		if isScanCanceled(runErr) {
			progressErr = progress.Cancel("export", progressStepScan, nil)
		} else {
			progressErr = progress.Fail("export", progressStepScan, nil)
		}
		if progressErr != nil {
			runErr = progressWriteFailure(progressErr)
		}
	}()

	startExport := func() error {
		if progress == nil || exportStarted {
			return nil
		}
		if err := progress.Start("export", progressStepScan); err != nil {
			return progressWriteFailure(err)
		}
		exportStarted = true
		return nil
	}

	//nolint:nestif // Standalone export keeps progress and Java runtime lifecycle with callgraph construction.
	if (scanExportCallgraph != "" || scanExportGraphFragment != "") && (callGraphResult == nil || callGraphResult.CallGraph == nil) {
		if err := startExport(); err != nil {
			return err
		}
		// A primary ecosystem that resolved no dependencies has no graph,
		// while another ecosystem the dependency phase resolved may carry
		// one. The export then builds the primary's own source graph, for
		// that same ecosystem, and keeps the others beside it; with no
		// other ecosystem it builds the dominant language's graph as before.
		var resolvedBeside []*engine.DepScanResult
		standaloneEcosystem := ecosystemFromHints(target, scanLanguages)
		if callGraphResult != nil && len(callGraphResult.AdditionalEcosystems) > 0 {
			resolvedBeside = callGraphResult.AdditionalEcosystems
			standaloneEcosystem = callGraphResult.Ecosystem
		}
		if standaloneEcosystem == ecosystemJava {
			if err := ensureJavaRuntime(); err != nil {
				return err
			}
		}
		if progress != nil {
			if err := progress.Start("callgraph", "export"); err != nil {
				return progressWriteFailure(err)
			}
		}
		standaloneSpan := perf.Start("callgraph.standalone")
		if resolvedBeside != nil {
			callGraphResult, err = buildStandaloneCallGraphResultForEcosystem(graphs, target, report, standaloneEcosystem, javaRuntime, scanIncludeTests, scanJavaCompiledArtifact, skipMatcher, true)
			if err == nil {
				callGraphResult.AdditionalEcosystems = resolvedBeside
			}
		} else {
			callGraphResult, err = buildStandaloneCallGraphResult(graphs, target, report, scanLanguages, javaRuntime, scanIncludeTests, scanJavaCompiledArtifact, skipMatcher)
		}
		standaloneSpan.End()
		if err != nil {
			if progress != nil {
				var progressErr error
				if isScanCanceled(err) {
					progressErr = progress.Cancel("callgraph", "export", nil)
				} else {
					progressErr = progress.Fail("callgraph", "export", nil)
				}
				if progressErr != nil {
					return progressWriteFailure(progressErr)
				}
			}
			return failure.WrapUnknown(
				err,
				failure.CodeCallGraphBuildFailed,
				failure.StageCallGraph,
				"failed to build call graph for export",
			)
		}
		if progress != nil {
			if err := progress.Complete("callgraph", "export", nil); err != nil {
				return progressWriteFailure(err)
			}
		}
	}

	// An export that built its own graph is still open here, so the passes below
	// run inside it and report as its children rather than as the scan's.
	passParent := progressStepScan
	if exportStarted {
		passParent = "export"
	}

	passResults := ruleGraphPassResults(callGraphResult)
	graphPasses := len(passResults) > 0
	if graphPasses {
		if err := runRuleGraphPasses(progress, passParent, rulesManager, report, passResults); err != nil {
			return err
		}
	}

	// Finalize all non-OID report metadata before preparation. The resolved
	// object below is the sole report passed to OID-consuming projections.
	// The graph passes add assets after a dependency scan assigned its ids.
	needsFindingIDs := scanExportCallgraph != "" || scanExportGraphFragment != "" || graphPasses
	if needsFindingIDs {
		if err := runScanPhase(progress, "finding_ids", passParent, func() error {
			engine.AssignFindingIDs(report)
			return nil
		}); err != nil {
			return err
		}
	}
	if err := runScanPhase(progress, "occurrence_keys", passParent, func() error {
		callGraphResult = prepareReportOccurrenceKeys(graphs, target, report, scanLanguages, javaRuntime, scanIncludeTests, scanJavaCompiledArtifact, skipMatcher, callGraphResult)
		return nil
	}); err != nil {
		return err
	}
	var resolved *oid.ResolvedReport
	if err := runScanPhase(progress, "oid_projection", passParent, func() error {
		var prepareErr error
		resolved, prepareErr = prepareScanOIDProjection(report, false)
		if prepareErr != nil {
			return failure.WrapUnknown(prepareErr, failure.CodeUnknown, failure.StageScan, "prepare exact OID report")
		}
		return nil
	}); err != nil {
		return err
	}

	if scanExportCallgraph != "" || scanExportGraphFragment != "" {
		if err := startExport(); err != nil {
			return err
		}
	}

	if scanExportCallgraph != "" {
		if slices.Contains(scanutil.MissingAdditionalCallGraphEcosystems(report, callGraphResult), ecosystemJava) {
			if err := ensureJavaRuntime(); err != nil {
				return err
			}
		}
		perf.Time("callgraph.additional_ecosystems", func() {
			attachAdditionalEcosystemGraphs(graphs, target, report, callGraphResult, javaRuntime, scanIncludeTests, skipMatcher)
		})
		exportSpan := perf.Start("export.callgraph")
		exportStart := time.Now()
		log.Info().
			Str("file", scanExportCallgraph).
			Str("format", scanExportCgFormat).
			Msg("Starting call graph export")
		if exportErr := scanutil.ExportResolvedCallGraph(scanExportCallgraph, scanExportCgFormat, callGraphResult, resolved, scanutil.CallGraphExportOptions{
			MaxChains:             scanExportCallgraphMaxChains,
			OmitCryptoEntryPoints: !scanExportEntryPoints,
			InternedFrames:        scanExportInternedFrames,
			ProjectReachability:   scanExportProjectReach,
		}); exportErr != nil {
			return failure.WrapUnknown(
				exportErr,
				failure.CodeCallGraphExportFailed,
				failure.StageExport,
				"failed to export call graph",
			)
		}
		exportSpan.End()
		log.Info().
			Str("file", scanExportCallgraph).
			Dur("duration", time.Since(exportStart)).
			Msg("Call graph export complete")
	}

	if scanExportGraphFragment != "" {
		exportSpan := perf.Start("export.graph_fragment")
		exportStart := time.Now()
		log.Info().
			Str("file", scanExportGraphFragment).
			Str("format", scanExportGfFormat).
			Msg("Starting graph fragment export")
		if exportErr := scanutil.ExportResolvedGraphFragment(scanExportGraphFragment, scanExportGfFormat, callGraphResult, resolved); exportErr != nil {
			return failure.WrapUnknown(
				exportErr,
				failure.CodeCallGraphExportFailed,
				failure.StageExport,
				"failed to export graph fragment",
			)
		}
		exportSpan.End()
		log.Info().
			Str("file", scanExportGraphFragment).
			Dur("duration", time.Since(exportStart)).
			Msg("Graph fragment export complete")
	}
	switch {
	case scanExportCallgraph != "" || scanExportGraphFragment != "":
		if progress != nil {
			if err := progress.Complete("export", progressStepScan, nil); err != nil {
				return progressWriteFailure(err)
			}
		}
		exportCompleted = true
	case progress != nil:
		if err := progress.Skip("export", progressStepScan, "not_requested"); err != nil {
			return progressWriteFailure(err)
		}
	}

	if err := runScanPhase(progress, "output", "scan", func() error {
		return writeScanOutput(resolved)
	}); err != nil {
		return err
	}

	findingsCount := 0
	for _, finding := range resolved.Findings {
		findingsCount += len(finding.CryptographicAssets)
	}
	filesCount := len(resolved.Findings)

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

// runRuleGraphPasses runs the two passes that join the ruleset onto the call
// graph. Type 2 libraries (fluent/builder/DSL, e.g. Password4J) carry their
// crypto semantic on the public API boundary, not in a detectable primitive
// call inside their own source. When such a library is itself being scanned,
// surface those API methods as crypto entry points using the ruleset's
// metadata.crypto (the single source of truth) joined on api↔definition.
// Gated structurally (method definition present, no in-body finding), so it is
// a no-op when scanning a consumer of the library or a Type 1 library.
// ruleGraphPassResults lists the call graphs the rule graph passes run on:
// the primary one, and every additional ecosystem auto mode resolved
// dependencies for. A secondary ecosystem's dependency findings then get the
// same synthesized entry points, conditioned findings and related material as
// when that ecosystem is primary, and still get them when the primary
// resolved no dependencies and so built no graph. The source-only graphs an
// export attaches later never took these passes and still do not.
func ruleGraphPassResults(primary *engine.DepScanResult) []*engine.DepScanResult {
	if primary == nil {
		return nil
	}
	var out []*engine.DepScanResult
	if primary.CallGraph != nil {
		out = append(out, primary)
	}
	for _, extra := range primary.AdditionalEcosystems {
		if extra != nil && extra.CallGraph != nil {
			out = append(out, extra)
		}
	}
	return out
}

// runRuleGraphPasses runs each pass over every graph in results, reporting
// each pass once. A pass resolves a finding through the function containing
// its file in the graph, so a graph only adds to the findings of its own
// ecosystem, and conditioned findings already present are not added twice.
func runRuleGraphPasses(progress *scanutil.ProgressWriter, parent string, rulesManager *rules.Manager, report *entities.InterimReport, results []*engine.DepScanResult) error {
	rulePaths, loadErr := rulesManager.Load()
	if loadErr != nil {
		log.Debug().
			Err(loadErr).
			Int("call_graphs", len(results)).
			Str("report", fmt.Sprintf("%p", report)).
			Int("finding_count", len(report.Findings)).
			Strs("rule_paths", rulePaths).
			Msg("failed to load rules for synthesis")
		return nil
	}
	if err := runScanPhase(progress, "entry_points", parent, func() error {
		for _, result := range results {
			engine.SynthesizeRuleCryptoEntryPointsForResult(result, rulePaths)
		}
		return nil
	}); err != nil {
		return err
	}
	// Both passes add assets the call graph derives from rule findings, so they
	// report as one progress phase.
	return runScanPhase(progress, "conditioned_findings", parent, func() error {
		for _, result := range results {
			scanutil.MaterializeConditionedFindings(report, result, rulePaths)
			scanutil.MaterializeRelatedMaterial(report, result)
		}
		return nil
	})
}

func writeScanOutput(resolved *oid.ResolvedReport) error {
	// After the exports, so the classification never enters a mined fragment.
	pqc.Annotate(resolved)
	writer, err := output.NewWriterFactory().GetWriter(scanFormat)
	if err != nil {
		return failure.WrapUnknown(
			err,
			failure.CodeOutputWriterUnavailable,
			failure.StageOutput,
			"failed to get output writer",
		)
	}

	writeStart := time.Now()
	log.Info().
		Str("destination", scanOutput).
		Str("format", scanFormat).
		Msg("Writing scan output")
	if err := writer.WriteResolved(resolved, scanOutput); err != nil {
		return failure.WrapUnknown(err, failure.CodeOutputWriteFailed, failure.StageOutput, "failed to write output")
	}
	log.Info().
		Str("destination", scanOutput).
		Dur("duration", time.Since(writeStart)).
		Msg("Scan output write complete")
	return nil
}

// runScanPhase reports run as one progress phase under parent. A failure of run
// closes the phase as failed or canceled and is returned unchanged.
func runScanPhase(progress *scanutil.ProgressWriter, phase, parent string, run func() error) error {
	span := perf.Start(phase)
	defer span.End()
	if progress == nil {
		return run()
	}
	if err := progress.Start(phase, parent); err != nil {
		return progressWriteFailure(err)
	}
	runErr := run()
	var progressErr error
	switch {
	case runErr == nil:
		progressErr = progress.Complete(phase, parent, nil)
	case isScanCanceled(runErr):
		progressErr = progress.Cancel(phase, parent, nil)
	default:
		progressErr = progress.Fail(phase, parent, nil)
	}
	if progressErr != nil {
		return progressWriteFailure(progressErr)
	}
	return runErr
}

func newProgressReporter(progress *scanutil.ProgressWriter, callgraphParent string) engine.ProgressReporter {
	return func(phase, status string, cause error, details map[string]any) error {
		parent := "scan"
		if phase == "callgraph" {
			parent = callgraphParent
		}
		switch status {
		case "started":
			return progress.Start(phase, parent)
		case progressStatusCompleted:
			return progress.Complete(phase, parent, details)
		case "failed":
			if isScanCanceled(cause) {
				return progress.Cancel(phase, parent, nil)
			}
			return progress.Fail(phase, parent, nil)
		default:
			return fmt.Errorf("unknown scan progress status %q", status)
		}
	}
}

func isScanCanceled(err error) bool {
	if errors.Is(err, context.Canceled) {
		return true
	}
	structured, ok := failure.As(err)
	return ok && structured.Code == failure.CodeScannerCancelled
}

func progressWriteFailure(err error) error {
	return failure.WrapUnknown(err, failure.CodeOutputWriteFailed, failure.StageOutput, "failed to write scan progress")
}

// typeOnlyPythonPackages turns --type-packages (directories separated by the
// OS path-list separator) into Python type-only packages: their stubs and
// annotations type the scanned component's calls into its dependencies
// (return types, class hierarchies; PythonDependencyTypeResolver) without
// parsing or scanning them. A directory holding *.dist-info metadata (a
// site-packages directory, a virtual environment, an unpacked wheel) gives
// one package per distribution, limited to the files its RECORD installed;
// any other directory (an unpacked sdist, a source tree whose top level is
// the import package) is one package named after it. Each is read as data:
// nothing is imported or run.
func typeOnlyPythonPackages(list string) []callgraph.PackageDir {
	var out []callgraph.PackageDir
	for _, dir := range filepath.SplitList(list) {
		if dir = strings.TrimSpace(dir); dir == "" {
			continue
		}
		dir = cleanAbs(dir)
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			continue
		}
		dists := dependency.InstalledPythonDistributions(dir)
		if len(dists) == 0 {
			out = append(out, callgraph.PackageDir{Dir: dir, DistributionName: filepath.Base(dir), Version: "type-only"})
			continue
		}
		for _, d := range dists {
			if len(d.Files) == 0 {
				continue
			}
			out = append(out, callgraph.PackageDir{Dir: d.Dir, DistributionName: d.Name, Version: d.Version, IncludeFiles: d.Files})
		}
	}
	return out
}

// typeOnlyJARPackages turns --type-jars (compiled JARs separated by the OS
// path-list separator) into type-only packages: their bytecode types the scanned component's calls
// into its dependencies without parsing or scanning them. The miner, which
// already holds each component version's pinned dependencies, passes them so
// that no build tool runs.
func typeOnlyJARPackages(list string) []callgraph.PackageDir {
	var out []callgraph.PackageDir
	for _, jar := range filepath.SplitList(list) {
		if jar = strings.TrimSpace(jar); jar == "" {
			continue
		}
		if _, err := os.Stat(jar); err != nil {
			continue
		}
		out = append(out, callgraph.PackageDir{
			Dir:                  filepath.Dir(jar),
			ImportPath:           strings.TrimSuffix(filepath.Base(jar), ".jar"),
			CompiledArtifactPath: jar,
		})
	}
	return out
}
