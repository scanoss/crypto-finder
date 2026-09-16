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
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"

	"github.com/scanoss/crypto-finder/pkg/paramcondition"
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
	return (*ParameterConditionValidator)(nil).Validate(rulePaths)
}

// ParameterConditionValidator reuses successful validation of exact file bytes.
// Create one per dependency invocation, never retain it across scans. Each gate
// still discovers and reads files; this is not an atomic execution snapshot.
// The zero value is ready for use. A nil validator disables proof reuse.
type ParameterConditionValidator struct {
	mu         sync.Mutex
	successful map[string][sha256.Size]byte
}

// Validate preserves the standalone gate's aggregated errors and path handling.
func (v *ParameterConditionValidator) Validate(rulePaths []string) error {
	var errs []error
	for _, path := range expandParamConditionRulePaths(rulePaths) {
		if err := v.validateFile(path); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (v *ParameterConditionValidator) validateFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read rule file %s: %w", path, err)
	}
	if v == nil {
		return validateParameterConditionBytes(path, data)
	}
	digest := sha256.Sum256(data)
	v.mu.Lock()
	defer v.mu.Unlock()
	if previous, ok := v.successful[path]; ok && previous == digest {
		return nil
	}
	if err := validateParameterConditionBytes(path, data); err != nil {
		return err
	}
	if v.successful == nil {
		v.successful = make(map[string][sha256.Size]byte)
	}
	v.successful[path] = digest
	return nil
}

func validateParameterConditionBytes(path string, data []byte) error {
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
	}
	return files
}
