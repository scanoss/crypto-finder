package engine

// The conditioned-rule fields of each rule, as the migration export to v3
// card files writes them (cards-export). Deleted with the rule compiler.

import (
	"os"
	"strings"
)

// RuleConditioned is what the conditioned-rule catalog reads from a rule's
// patterns. A v3 card file carries it in its rules: entry.
type RuleConditioned struct {
	Symbols        []string `json:"symbols"`
	CaptureNames   []string `json:"capture_names"`
	CaptureBinders []string `json:"capture_binders"`
}

// RuleConditionedFields returns, for every rule of the YAML rule files at
// rulePaths with a parameterCondition, the symbols, capture names and capture
// binders the catalog reads from its patterns (cards-export).
func RuleConditionedFields(rulePaths []string) map[string]RuleConditioned {
	out := make(map[string]RuleConditioned)
	for _, path := range rulePaths {
		for _, file := range expandRuleFiles(path) {
			var rf ruleFileCryptoYAML
			data, err := os.ReadFile(file) // #nosec G304 -- a rule file of the rules directory the user named.
			if err != nil || ruleCryptoDocuments.Decode(file, data, &rf) != nil {
				continue
			}
			for i := range rf.Rules {
				rule := &rf.Rules[i]
				if strings.TrimSpace(stringifyCryptoBlock(rule.Metadata.Crypto)["parameterCondition"]) == "" {
					continue
				}
				binders := ruleCaptureBinders(rule.PatternSources)
				fields := RuleConditioned{
					Symbols:        nonNil(ruleCryptoEntrypoints(rule)),
					CaptureNames:   nonNil(ruleCaptureNames(rule.PatternSources)),
					CaptureBinders: make([]string, len(binders)),
				}
				for j, re := range binders {
					fields.CaptureBinders[j] = re.String()
				}
				out[rule.ID] = fields
			}
		}
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
