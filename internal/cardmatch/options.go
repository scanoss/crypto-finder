package cardmatch

import (
	"path/filepath"
	"strings"
)

// DefaultMetadataKey is the rule metadata block a finding carries when
// Options.MetadataKey is empty: metadata.crypto of a rule YAML, crypto of a
// v3 rules entry.
const DefaultMetadataKey = "crypto"

// Options configure a matcher. The zero value is the defaults.
type Options struct {
	// MetadataKey names the rule metadata block a finding carries
	// (metadata.<key> of a rule YAML, <key> of a v3 rules entry). Empty is
	// DefaultMetadataKey.
	MetadataKey string
	// ExtraRuleKeys are further keys a v3 rules entry may hold, besides the
	// metadata key and severity, message, purl, conditioned and pending.
	ExtraRuleKeys []string
	// LanguageOf is the language of a card file from its path, "" for none.
	// A card file holds cards of its language's rules only, a v3 rule is a
	// Rust rule when its file is a Rust one, and parsed card files are
	// memoised per language. Nil is CardsDirLanguage.
	LanguageOf func(path string) string
	// ConstantComparisons overrides how a constant a comparison, an equals
	// call or a case label reads is reported: ComparisonsAll reports every
	// one, as OpenGrep does, ComparisonsOff none. Empty reports one only when
	// the value compared with it can be that constant.
	ConstantComparisons ComparisonPolicy
	// PyMembership is how a Python constant in an `in` test is reported.
	// Empty reports it as a comparison (only when the compared value can be
	// the constant); ComparisonsAll reports every one, for debugging.
	// Dict, list, tuple and set entries are table entries, always reported.
	PyMembership ComparisonPolicy
}

// CardsDirLanguage is the language of a card file as rulesets lay them out:
// the directory below the nearest cards/ directory of its path
// (cards/<language>/...), or "" when the path holds none.
func CardsDirLanguage(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i := len(parts) - 2; i > 0; i-- {
		if parts[i-1] == "cards" {
			return parts[i]
		}
	}
	return ""
}

// settings are Options resolved.
type settings struct {
	metaKey     string
	ruleKeys    map[string]bool
	languageOf  func(string) string
	comparisons ComparisonPolicy
	membership  ComparisonPolicy
}

func (o Options) settings() *settings {
	s := &settings{
		metaKey: o.MetadataKey, languageOf: o.LanguageOf,
		comparisons: o.ConstantComparisons, membership: o.PyMembership,
	}
	if s.metaKey == "" {
		s.metaKey = DefaultMetadataKey
	}
	if s.languageOf == nil {
		s.languageOf = CardsDirLanguage
	}
	s.ruleKeys = setOf(append([]string{"severity", "message", "purl", s.metaKey, "conditioned", "pending"}, o.ExtraRuleKeys...)...)
	return s
}

// defaults are the zero Options resolved.
var defaults = Options{}.settings()

// applyPolicies sets the comparison policies the options override on fr.
// Assets built without Load (tests) have none.
func (s *settings) applyPolicies(fr *Frag) {
	if s == nil {
		return
	}
	if s.comparisons != "" {
		fr.Comparisons = s.comparisons
	}
	if s.membership != "" {
		fr.Membership = s.membership
	}
}
