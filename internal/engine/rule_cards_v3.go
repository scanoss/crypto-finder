package engine

// Rule data read from v3 card files (rules.CardsFormat): the conditioned-rule
// catalog and the entry-point synthesis take a rule's metadata from its card
// file's rules: block exactly as they take it from a rule YAML file, and its
// catalog symbols, capture names and binders from the block's conditioned
// entry instead of the rule's patterns.

import (
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/scanoss/reach/paramcondition"
	"github.com/scanoss/reach/purl"

	"github.com/scanoss/crypto-finder/internal/config"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/rules"
)

// cardsRuleCrypto is a v3 card file's rules as the rule YAML readers decode
// them, with the file's language for the ecosystem gates.
func cardsRuleCrypto(file string) ([]ruleCryptoYAML, []*rules.CardsConditioned) {
	found, err := rules.ReadCardsRulesFile(file)
	if err != nil {
		log.Debug().Err(err).Str("path", file).Msg("failed to read card file rules")
		return nil, nil
	}
	language := config.CardsLanguage(file)
	out := make([]ruleCryptoYAML, len(found))
	conditioned := make([]*rules.CardsConditioned, len(found))
	for i := range found {
		r := &found[i]
		out[i] = ruleCryptoYAML{ID: r.ID, Message: r.Message, Severity: r.Severity}
		if language != "" {
			out[i].Languages = []string{language}
		}
		out[i].Metadata.PURL = r.PURL
		out[i].Metadata.Crypto = r.Crypto
		conditioned[i] = r.Conditioned
	}
	return out, conditioned
}

// appendCardsRuleCryptoMetadata is appendRuleCryptoMetadata for a rule of a
// v3 card file: its symbols, capture names and binders come from its
// conditioned entry.
func appendCardsRuleCryptoMetadata(out map[string][]RuleCryptoMetadata, rule *ruleCryptoYAML, fields *rules.CardsConditioned) {
	if fields == nil || len(fields.Symbols) == 0 {
		return
	}
	metadata := stringifyCryptoBlock(rule.Metadata.Crypto)
	metadata[RulePURLMetadataKey] = purl.Rule(rule.Metadata.PURL)
	conditions, err := paramcondition.ParseAll(metadata["parameterCondition"])
	if err != nil || len(conditions) == 0 {
		return
	}
	var binders []*regexp.Regexp
	for _, b := range fields.CaptureBinders {
		re, err := regexp.Compile(b)
		if err != nil {
			continue
		}
		binders = append(binders, re)
	}
	candidate := RuleCryptoMetadata{
		Rule:     entities.RuleInfo{ID: rule.ID, Message: rule.Message, Severity: strings.ToUpper(rule.Severity)},
		Metadata: metadata, ParameterConditions: conditions, CaptureNames: emptyAsNil(fields.CaptureNames),
		CaptureBinders: binders,
		Languages:      rule.Languages,
	}
	addRuleCryptoCandidate(out, fields.Symbols, candidate)
}

// emptyAsNil gives an empty list as nil, as a rule YAML with no capture
// names gives it.
func emptyAsNil(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}
