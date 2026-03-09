package engine

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"
	"go.yaml.in/yaml/v3"
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
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)
	return files
}
