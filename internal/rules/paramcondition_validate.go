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

package rules

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/scanoss/reach/paramcondition"

	"github.com/scanoss/crypto-finder/internal/utils"
)

const (
	yamlFileExt = ".yaml"
	ymlFileExt  = ".yml"
)

// paramConditionRuleFile is a narrow representation of a semgrep rule file,
// used only to extract each rule's id and parameterCondition predicate.
type paramConditionRuleFile struct {
	Rules []struct {
		ID       string `yaml:"id"`
		Metadata struct {
			Crypto struct {
				ParameterCondition string `yaml:"parameterCondition"`
			} `yaml:"crypto"`
		} `yaml:"metadata"`
	} `yaml:"rules"`
}

// ValidateParameterConditions parses every parameterCondition predicate
// across the given rule paths (files or directories) and returns an
// aggregated error naming the offending rule id and raw predicate string
// for each malformed one. Returns nil when every predicate is well-formed
// or absent.
//
// This is a hard, non-configurable fail-fast gate: callers MUST abort the
// scan on a non-nil error rather than continue with a partially-invalid
// ruleset (resolved proposal decision — warn-and-continue was rejected).
func ValidateParameterConditions(rulePaths []string) error {
	return ValidateParameterConditionDocuments(nil, rulePaths)
}

// ParameterConditionView is the view the validator decodes, for a Documents
// shared with other passes over the same rule files.
func ParameterConditionView() any {
	return new(paramConditionRuleFile)
}

// ValidateParameterConditionDocuments is ValidateParameterConditions decoding
// each file through docs, so a pass that registered ParameterConditionView
// shares its YAML parse.
func ValidateParameterConditionDocuments(docs *Documents, rulePaths []string) error {
	var errs []error
	for _, path := range expandParamConditionRulePaths(rulePaths) {
		if IsCardsFile(path) {
			found, readErr, parseErr := cardsRulesAt(path)
			if readErr != nil {
				errs = append(errs, fmt.Errorf("read rule file %s: %w", path, readErr))
			} else if err := validateCardsRules(path, found, parseErr); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("read rule file %s: %w", path, err))
			continue
		}
		if err := validateParameterConditionBytes(docs, path, data); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func validateParameterConditionBytes(docs *Documents, path string, data []byte) error {
	if IsCardsFile(path) {
		return validateCardsParameterConditions(path, data)
	}
	var parsed paramConditionRuleFile
	if err := docs.Decode(path, data, &parsed); err != nil {
		return fmt.Errorf("parse rule file %s: %w", path, err)
	}
	var errs []error
	for _, r := range parsed.Rules {
		raw := strings.TrimSpace(r.Metadata.Crypto.ParameterCondition)
		if raw == "" {
			continue
		}
		if _, err := paramcondition.ParseAll(raw); err != nil {
			errs = append(errs, fmt.Errorf("rule %q (%s): %w", r.ID, path, err))
		}
	}
	return errors.Join(errs...)
}

// expandParamConditionRulePaths resolves rulePaths (a mix of individual rule
// files and directories) to the flat list of .yaml/.yml files they contain.
func expandParamConditionRulePaths(rulePaths []string) []string {
	var files []string
	for _, path := range rulePaths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			files = append(files, path)
			continue
		}

		start := len(files)
		if err := filepath.WalkDir(path, func(p string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(p))
			if ext == yamlFileExt || ext == ymlFileExt {
				files = append(files, p)
			}
			return nil
		}); err != nil {
			continue
		}
		if len(files) == start {
			// A ruleset of v3 card files only: its card files are its rules.
			files = append(files, CardFilesUnder(path)...)
		}
	}
	return files
}

// validateCardsParameterConditions is validateParameterConditionBytes for a
// v3 card file: the parameterCondition of each rule of its rules: block. An
// earlier card file carries no rules (they are in a rule YAML beside it), so
// there is nothing to validate, as the cards scanner skips it.
func validateCardsParameterConditions(path string, data []byte) error {
	found, err := ReadCardsRules(data)
	return validateCardsRules(path, found, err)
}

// validateCardsRules is validateCardsParameterConditions of a card file's
// rules and parse error.
func validateCardsRules(path string, found []CardsRule, err error) error {
	if errors.Is(err, ErrNotV3Cards) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("parse card file %s: %w", path, err)
	}
	var errs []error
	for _, r := range found {
		raw := utils.AsOr[string](r.Crypto["parameterCondition"])
		if raw = strings.TrimSpace(raw); raw == "" {
			continue
		}
		if _, err := paramcondition.ParseAll(raw); err != nil {
			errs = append(errs, fmt.Errorf("rule %q (%s): %w", r.ID, path, err))
		}
	}
	return errors.Join(errs...)
}
