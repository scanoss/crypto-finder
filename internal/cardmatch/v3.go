package cardmatch

// Card files v3 (format: scanoss-cards/3): a card file that carries its rules.
// Its rules: block maps each rule id to the rule's severity, message, purl,
// metadata.crypto (crypto) and, when no card can detect it yet, pending. Its
// cards: list holds the v2 card kinds plus site cards: a compiled index entry
// (Entry, without rule_id and metadata, which its rules entry gives) that the
// index matcher runs. A directory of v3 card files is a whole ruleset for the
// matcher: no rule YAML is read.

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/scanoss/crypto-finder/internal/config"
)

// CardsFormatV3 is the format key of a v3 card file.
const CardsFormatV3 = "scanoss-cards/3"

var (
	v3FileKeys = setOf("format", "rules", "cards")
	v3RuleKeys = setOf("severity", "message", "purl", "crypto", "conditioned", "pending")
	siteKeys   = setOf("rule", "site", "lossy", "note")
)

// cardFile is one parsed card file.
type cardFile struct {
	path, rel string
	doc       *OMap
}

// readCardFiles parses the card files under cardsDir and reports whether
// they are v3. A directory mixing v3 and earlier card files is an error.
func readCardFiles(cardsDir string) ([]cardFile, bool, error) {
	paths, err := pyGlob(cardsDir, func(n string) bool {
		return strings.HasSuffix(n, ".cards") || strings.HasSuffix(n, ".yaml")
	})
	if err != nil {
		return nil, false, err
	}
	var files []cardFile
	v3, older := 0, 0
	for _, path := range paths {
		doc, err := loadYAML(path)
		if err != nil {
			return nil, false, err
		}
		if !pyTruthy(doc) {
			continue
		}
		m := mustMap(doc, path)
		rel := lenient(filepath.Rel(cardsDir, path))
		files = append(files, cardFile{path: path, rel: rel, doc: m})
		if f, has := m.Get("format"); has {
			if f != any(CardsFormatV3) {
				return nil, false, fmt.Errorf("%s: card format %v, want %s", path, f, CardsFormatV3)
			}
			v3++
		} else {
			older++
		}
	}
	if v3 > 0 && older > 0 {
		return nil, false, fmt.Errorf("%s: %d v3 and %d earlier card files; a cards directory holds one format", cardsDir, v3, older)
	}
	return files, v3 > 0, nil
}

// loadV3 builds the index (from site cards) and the hand cards of v3 card
// files. Rules keep the order of their files, and site entries the order of
// their cards, which is the compiler's order of the rules they replace.
func loadV3(files []cardFile) (*Index, *CardSet, error) { //nolint:gocognit,gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	table := map[string]ruleInfo{}
	pending := map[string]bool{}
	for _, f := range files {
		for _, k := range f.doc.Keys {
			if ks, ok := k.(string); !ok || (!v3FileKeys[ks] && !strings.HasPrefix(ks, "x-")) {
				return nil, nil, fmt.Errorf("%s: unknown key %v", f.path, k)
			}
		}
		rulesAny := f.doc.GetOr("rules")
		if rulesAny == nil {
			continue
		}
		rules := mustMap(rulesAny, f.path+": rules")
		for i, k := range rules.Keys {
			id, ok := k.(string)
			if !ok {
				return nil, nil, fmt.Errorf("%s: rule id %v is not a string", f.path, k)
			}
			if _, dup := table[id]; dup {
				return nil, nil, fmt.Errorf("%s: rule %s is defined twice", f.path, id)
			}
			r := mustMap(rules.Vals[i], f.path+": rule "+id)
			if unk := unknownKeys(r, v3RuleKeys); len(unk) > 0 {
				return nil, nil, fmt.Errorf("%s: rule %s: unknown keys %v", f.path, id, unk)
			}
			meta := &OMap{}
			if cr := r.GetOr("crypto"); pyTruthy(cr) {
				meta = mustMap(cr, f.path)
			}
			// A v3 rules entry names no language; the card file's place
			// does, as rulesets ship them (cards/<language>/...): a rule
			// is Rust when its file is under cards/rust/.
			lang := config.CardsLanguage(f.path)
			table[id] = ruleInfo{Meta: meta, Rust: lang == ecosystemRust, Lang: lang}
			if pyTruthy(r.GetOr("pending")) {
				pending[id] = true
			}
		}
	}
	set := &CardSet{RuleIDs: map[string]bool{}}
	var entries []*OMap
	for _, f := range files {
		for _, cAny := range listOf(f.doc.GetOr("cards")) {
			c := mustMap(cAny, f.path)
			rule := asOr[string](c.GetOr("rule"))
			if pending[rule] {
				return nil, nil, fmt.Errorf("%s: rule %s is pending and has a card", f.path, rule)
			}
			site, isSite := c.Get("site")
			if !isSite {
				if err := set.add(c, f.path, f.rel, table); err != nil {
					return nil, nil, err
				}
				continue
			}
			info, known := table[rule]
			if unk := unknownKeys(c, siteKeys); len(unk) > 0 || !known {
				return nil, nil, fmt.Errorf("%s: bad site card %s %v", f.path, rule, unk)
			}
			if err := info.sameLanguage(f.path, rule); err != nil {
				return nil, nil, err
			}
			entries = append(entries, siteIndexEntry(mustMap(site, f.path), rule, info.Meta, listOf(c.GetOr("lossy"))))
		}
	}
	index, err := (&compiledRules{Entries: entries}).index()
	if err != nil {
		return nil, nil, err
	}
	return index, set, nil
}

// siteIndexEntry is the index entry of a site card: the site with the rule
// id, the rule's metadata.crypto and the card's lossy clauses.
func siteIndexEntry(site *OMap, rule string, meta *OMap, lossy []any) *OMap {
	e := &OMap{}
	for i, k := range site.Keys {
		e.Set(k, site.Vals[i])
	}
	if !e.Has(strTaint) {
		e.Set(strTaint, false)
	}
	if lossy == nil {
		lossy = []any{}
	}
	e.Set("dropped_clauses", lossy)
	e.Set("rule_id", rule)
	e.Set("metadata", meta)
	return e
}
