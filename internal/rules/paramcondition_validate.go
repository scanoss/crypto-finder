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

	"go.yaml.in/yaml/v3"

	"github.com/scanoss/crypto-finder/pkg/paramcondition"
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
	var errs []error

	for _, ruleFile := range expandParamConditionRulePaths(rulePaths) {
		if err := validateParameterConditionsInFile(ruleFile); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// validateParameterConditionsInFile parses one rule YAML file and validates
// every non-empty parameterCondition predicate it declares.
func validateParameterConditionsInFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read rule file %s: %w", path, err)
	}

	var parsed paramConditionRuleFile
	if err := yaml.Unmarshal(data, &parsed); err != nil {
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

		_ = filepath.WalkDir(path, func(p string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(p))
			if ext == ".yaml" || ext == ".yml" {
				files = append(files, p)
			}
			return nil
		})
	}
	return files
}
