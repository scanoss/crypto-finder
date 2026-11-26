package engine

// The identity checks of the v3 migration (cards verify) for the rule data
// the engine reads: v3 card files against the rule YAML they replace.
// Deleted with the rule YAML readers.

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	"github.com/scanoss/reach/purl"

	"github.com/scanoss/crypto-finder/internal/rules"
)

// V3RulesReport is what VerifyV3Rules compared and the differences found.
type V3RulesReport struct {
	// ConditionedRules is the number of rules in the conditioned catalog (A2).
	ConditionedRules int
	// APIs is the number of api symbols of the synthesis map (A3).
	APIs int
	// CryptoRules is the number of rules whose metadata was compared (A4).
	CryptoRules int
	Diffs       []string
}

// VerifyV3Rules compares, for ecosystem, the rule data the engine reads from
// the rule YAML under yamlDir with what it reads from the v3 card files under
// cardsDir (a cards/<language> directory):
//
//   - A2: the conditioned-rule catalog (ConditionedRules);
//   - A3: the entry-point synthesis map (buildRuleCryptoByAPI);
//   - A4, the engine's view: each rule's metadata.crypto and purl.
func VerifyV3Rules(yamlDir, cardsDir, ecosystem string) (*V3RulesReport, error) { //nolint:gocognit,gocyclo // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
	rep := &V3RulesReport{}
	diff := func(format string, a ...any) { rep.Diffs = append(rep.Diffs, fmt.Sprintf(format, a...)) }

	fromYAML, fromCards := ConditionedRules([]string{yamlDir}, ecosystem), ConditionedRules([]string{cardsDir}, ecosystem)
	rep.ConditionedRules = len(fromYAML)
	if a, b := jsonOf(fromYAML), jsonOf(fromCards); a != b {
		diff("A2: conditioned catalog differs (%d rules from YAML, %d from cards)", len(fromYAML), len(fromCards))
	}

	apiYAML, apiCards := buildRuleCryptoByAPI([]string{yamlDir}, ecosystem), buildRuleCryptoByAPI([]string{cardsDir}, ecosystem)
	rep.APIs = len(apiYAML)
	for _, api := range slices.Sorted(maps.Keys(apiYAML)) {
		if a, b := jsonOf(apiYAML[api]), jsonOf(apiCards[api]); a != b {
			diff("A3: synthesis blocks of %s differ", api)
		}
	}
	for api := range apiCards {
		if _, ok := apiYAML[api]; !ok {
			diff("A3: %s only from cards", api)
		}
	}

	yamlCrypto := map[string]string{}
	for _, file := range expandRuleFiles(yamlDir) {
		var rf ruleFileCryptoYAML
		data, err := readRuleFile(file)
		if err != nil || ruleCryptoDocuments.Decode(file, data, &rf) != nil {
			return nil, fmt.Errorf("read %s", file)
		}
		for i := range rf.Rules {
			yamlCrypto[rf.Rules[i].ID] = cryptoKey(rf.Rules[i].Metadata.Crypto, rf.Rules[i].Metadata.PURL)
		}
	}
	cardsCrypto := map[string]string{}
	for _, file := range rules.CardFilesUnder(cardsDir) {
		found, err := rules.ReadCardsRulesFile(file)
		if err != nil {
			return nil, err
		}
		for _, r := range found {
			cardsCrypto[r.ID] = cryptoKey(r.Crypto, r.PURL)
		}
	}
	rep.CryptoRules = len(yamlCrypto)
	for _, id := range slices.Sorted(maps.Keys(yamlCrypto)) {
		got, ok := cardsCrypto[id]
		switch {
		case !ok:
			diff("A4: %s has no rules entry", id)
		case got != yamlCrypto[id]:
			diff("A4: %s: crypto or purl differs: yaml %s, cards %s", id, yamlCrypto[id], got)
		}
	}
	if len(cardsCrypto) != len(yamlCrypto) {
		diff("A4: %d rules entries for %d rules", len(cardsCrypto), len(yamlCrypto))
	}
	return rep, nil
}

func cryptoKey(crypto map[string]any, rulePURL string) string {
	meta := stringifyCryptoBlock(crypto)
	meta[RulePURLMetadataKey] = purl.Rule(rulePURL)
	return jsonOf(meta)
}

func jsonOf(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return "error: " + err.Error()
	}
	return string(data)
}
