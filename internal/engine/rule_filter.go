package engine

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"go.yaml.in/yaml/v3"

	"github.com/scanoss/crypto-finder/internal/config"
)

// ruleFile is a minimal representation of a semgrep rule file, used only to
// extract the languages field for filtering.
type ruleFile struct {
	Rules []struct {
		Languages []string `yaml:"languages"`
	} `yaml:"rules"`
}

// ruleLanguages parses a rule YAML file and returns the set of languages it targets.
func ruleLanguages(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("Failed to read rule file for language extraction")
		return nil
	}

	var rf ruleFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		log.Debug().Err(err).Str("path", path).Msg("Failed to parse rule file for language extraction")
		return nil
	}

	seen := make(map[string]bool)
	var langs []string
	for _, r := range rf.Rules {
		for _, l := range r.Languages {
			lower := strings.ToLower(l)
			if !seen[lower] {
				seen[lower] = true
				langs = append(langs, lower)
			}
		}
	}
	return langs
}

// filterRulesByLanguages filters rule paths to only include rules whose YAML
// `languages:` field matches at least one of the detected languages.
// If filtering would result in zero rules, returns all rules unchanged.
func filterRulesByLanguages(allRules, languages []string) []string {
	candidateRules := expandRulePaths(allRules)

	if len(languages) == 0 {
		return candidateRules
	}

	// Build lookup set from detected languages (normalized to lowercase)
	wanted := make(map[string]bool, len(languages))
	for _, lang := range languages {
		wanted[strings.ToLower(lang)] = true
	}

	filtered := make([]string, 0, len(candidateRules))
	for _, rulePath := range candidateRules {
		ruleLangs := ruleLanguages(rulePath)
		if len(ruleLangs) == 0 {
			// Can't determine language — include to be safe
			filtered = append(filtered, rulePath)
			continue
		}
		for _, rl := range ruleLangs {
			if wanted[rl] {
				filtered = append(filtered, rulePath)
				break
			}
		}
	}

	if len(filtered) == 0 {
		log.Warn().
			Strs("languages", languages).
			Msg("No rules matched language filter, falling back to all rules")
		return candidateRules
	}

	log.Info().
		Int("total", len(candidateRules)).
		Int("filtered", len(filtered)).
		Strs("languages", languages).
		Msg("Filtered rules by detected languages")

	return filtered
}

func prepareRulePathsForScanner(allRules, languages []string) ([]string, func(), error) {
	candidateRules := allRules
	if len(languages) > 0 {
		candidateRules = filterRulesByLanguages(allRules, languages)
	}

	return optimizeRulePathsForScanner(candidateRules)
}

func optimizeRulePathsForScanner(rulePaths []string) ([]string, func(), error) {
	if len(rulePaths) <= 1 {
		return rulePaths, func() {}, nil
	}

	allDirs := true
	for _, path := range rulePaths {
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			allDirs = false
			break
		}
	}
	if allDirs {
		return rulePaths, func() {}, nil
	}

	expanded := expandRulePaths(rulePaths)
	if len(expanded) <= 1 {
		return expanded, func() {}, nil
	}
	for _, path := range expanded {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			log.Debug().
				Err(err).
				Str("path", path).
				Msg("Skipping rule materialization because a filtered rule path is unavailable")
			return rulePaths, func() {}, nil
		}
	}

	return materializeRuleFiles(expanded)
}

func materializeRuleFiles(ruleFiles []string) ([]string, func(), error) {
	baseDir := commonRuleBaseDir(ruleFiles)
	tempParent := ""
	if rulesetRoot := rulesetVersionRoot(baseDir); rulesetRoot != "" {
		tempParent = filepath.Join(rulesetRoot, config.FilteredRulesDirName)
		if err := os.MkdirAll(tempParent, 0o750); err != nil {
			return nil, nil, fmt.Errorf("create filtered rules temp parent: %w", err)
		}
		// Reap orphaned run-* dirs from prior jobs. The deferred cleanup
		// below removes this run's dir on exit, but the mining worker
		// SIGKILLs the whole process group on timeout, so killed jobs never
		// run it and leak their run-* dir into the shared HOME cache. Prune
		// only dirs older than the longest possible job so an in-flight
		// concurrent run is never touched.
		pruneStaleFilteredRuns(tempParent)
	}

	tempRoot, err := os.MkdirTemp(tempParent, "run-*")
	if err != nil {
		return nil, nil, fmt.Errorf("create filtered rules temp dir: %w", err)
	}

	targetRoot := tempRoot
	if baseName := filepath.Base(baseDir); baseName != "" && baseName != "." && baseName != string(os.PathSeparator) {
		targetRoot = filepath.Join(tempRoot, baseName)
	}

	for _, ruleFile := range ruleFiles {
		relPath, err := filepath.Rel(baseDir, ruleFile)
		if err != nil {
			removeMaterializedRules(tempRoot)
			return nil, nil, fmt.Errorf("resolve relative rule path for %s: %w", ruleFile, err)
		}

		destPath := filepath.Join(targetRoot, relPath)
		if err := copyRuleFile(ruleFile, destPath); err != nil {
			removeMaterializedRules(tempRoot)
			return nil, nil, err
		}
	}

	log.Info().
		Int("sourceFiles", len(ruleFiles)).
		Str("path", targetRoot).
		Msg("Materialized filtered rules for scanner")

	return []string{targetRoot}, func() {
		removeMaterializedRules(tempRoot)
	}, nil
}

// filteredRunTTL is how old a run-* dir under .crypto-finder-filtered must be
// before pruneStaleFilteredRuns reclaims it. It must comfortably exceed the
// longest scan a concurrent process could still be running against its own
// run-* dir, so we never delete a live one. Scans are bounded by the caller's
// --timeout (the mining worker uses 30m); 2h leaves a wide safety margin while
// still reclaiming disk from SIGKILLed jobs within the same day.
const filteredRunTTL = 2 * time.Hour

// pruneStaleFilteredRuns removes orphaned run-* directories left under
// tempParent by jobs that never ran their cleanup (e.g. SIGKILLed on timeout
// by the mining worker's process-group kill). Best-effort: only dirs whose
// mtime is older than filteredRunTTL are removed, so an in-flight concurrent
// run is never touched. All errors are swallowed — this is opportunistic
// housekeeping, not part of the scan's correctness.
func pruneStaleFilteredRuns(tempParent string) {
	entries, err := os.ReadDir(tempParent)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-filteredRunTTL)
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "run-") {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		stale := filepath.Join(tempParent, entry.Name())
		if rmErr := os.RemoveAll(stale); rmErr != nil {
			log.Debug().Err(rmErr).Str("path", stale).Msg("Failed to prune stale filtered rules dir")
		}
	}
}

// removeMaterializedRules deletes a materialized rules directory, logging a
// warning if cleanup fails rather than propagating the error.
func removeMaterializedRules(tempRoot string) {
	if err := os.RemoveAll(tempRoot); err != nil {
		log.Warn().Err(err).Str("path", tempRoot).Msg("Failed to clean up materialized filtered rules")
	}
}

func copyRuleFile(srcPath, destPath string) (err error) {
	if mkErr := os.MkdirAll(filepath.Dir(destPath), 0o750); mkErr != nil {
		return fmt.Errorf("create filtered rule directory for %s: %w", destPath, mkErr)
	}

	srcFile, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open source rule file %s: %w", srcPath, err)
	}
	defer func() {
		if closeErr := srcFile.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close source rule file %s: %w", srcPath, closeErr)
		}
	}()

	destFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("create filtered rule file %s: %w", destPath, err)
	}
	defer func() {
		if closeErr := destFile.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close filtered rule file %s: %w", destPath, closeErr)
		}
	}()

	if _, copyErr := io.Copy(destFile, srcFile); copyErr != nil {
		return fmt.Errorf("copy filtered rule file %s: %w", srcPath, copyErr)
	}

	return nil
}

func commonRuleBaseDir(paths []string) string {
	if len(paths) == 0 {
		return ""
	}

	baseDir := filepath.Dir(paths[0])
	for _, path := range paths[1:] {
		baseDir = commonPathPrefix(baseDir, filepath.Dir(path))
	}
	if baseDir == "" {
		return string(os.PathSeparator)
	}
	return baseDir
}

func commonPathPrefix(left, right string) string {
	left = filepath.Clean(left)
	right = filepath.Clean(right)

	if left == right {
		return left
	}

	leftParts := strings.Split(filepath.Clean(left), string(os.PathSeparator))
	rightParts := strings.Split(filepath.Clean(right), string(os.PathSeparator))

	size := min(len(leftParts), len(rightParts))
	common := make([]string, 0, size)
	for i := 0; i < size; i++ {
		if leftParts[i] != rightParts[i] {
			break
		}
		common = append(common, leftParts[i])
	}

	if len(common) == 0 {
		if filepath.VolumeName(left) != "" {
			return filepath.VolumeName(left) + string(os.PathSeparator)
		}
		return string(os.PathSeparator)
	}

	if common[0] == "" {
		return string(os.PathSeparator) + filepath.Join(common[1:]...)
	}

	return filepath.Join(common...)
}

func rulesetVersionRoot(path string) string {
	rulesetsDir, err := config.GetRulesetsDir()
	if err != nil {
		return ""
	}

	absPath := path
	if resolved, err := filepath.Abs(path); err == nil {
		absPath = resolved
	}

	rel, err := filepath.Rel(rulesetsDir, absPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return ""
	}

	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) < 2 {
		return ""
	}

	return filepath.Join(rulesetsDir, parts[0], parts[1])
}

func expandRulePaths(paths []string) []string {
	expanded := make([]string, 0, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			expanded = append(expanded, path)
			continue
		}
		if !info.IsDir() {
			expanded = append(expanded, path)
			continue
		}

		dirRules := collectRuleFiles(path)
		if len(dirRules) == 0 {
			expanded = append(expanded, path)
			continue
		}
		expanded = append(expanded, dirRules...)
	}
	return expanded
}

func collectRuleFiles(root string) []string {
	var files []string
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Never descend into the materialized-rules dir: it lives inside
			// the ruleset tree we're walking, so ingesting it would re-copy
			// prior runs' output and the cache would grow geometrically.
			if d.Name() == config.FilteredRulesDirName {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		log.Debug().Err(err).Str("root", root).Msg("Failed to walk rule directory")
	}
	sort.Strings(files)
	return files
}
