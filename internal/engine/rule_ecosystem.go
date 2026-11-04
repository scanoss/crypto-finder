// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package engine

import "strings"

// ecosystemRuleLanguages lists the semgrep languages whose rules apply to a
// call graph of each ecosystem. A C graph also holds C++ sources when headers
// are shared.
var ecosystemRuleLanguages = map[string][]string{
	"java":          {"java", "kotlin"},
	ecosystemPython: {"python"},
	ecosystemNode:   {"javascript", "typescript", "js", "ts"},
	"go":            {"go", "golang"},
	ecosystemRust:   {"rust"},
	"c":             {"c", "cpp", "c++"},
	"cpp":           {"cpp", "c++", "c"},
}

// RuleTargetsEcosystem reports whether a rule for ruleLanguages applies to
// ecosystem, since languages share api symbols; unknown cases are kept.
func RuleTargetsEcosystem(ruleLanguages []string, ecosystem string) bool {
	allowed, known := ecosystemRuleLanguages[ecosystem]
	if !known || len(ruleLanguages) == 0 {
		return true
	}
	for _, language := range ruleLanguages {
		language = strings.ToLower(strings.TrimSpace(language))
		for _, candidate := range allowed {
			if language == candidate {
				return true
			}
		}
	}
	return false
}
