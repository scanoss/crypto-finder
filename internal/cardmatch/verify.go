package cardmatch

// The identity checks of the v3 migration (cards verify): v3 card files
// against the rule YAML and the compiler they replace. Deleted with the
// compiler.

import (
	"encoding/json"
	"fmt"
	"sort"
)

// V3Report is what VerifyV3 compared and the differences it found.
type V3Report struct {
	Rules, HandRules, SiteRules, Sites, Pending int
	// Entries is the number of index entries compared after loading.
	Entries int
	Diffs   []string
}

// VerifyV3 compares the v3 card files under cardsDir with the rules under
// rulesDir and the cards those files replace:
//
//   - A1: every rule without a hand card has the compiler's entries as its
//     site cards (SiteEntry, as sorted canonical JSON), and the index loaded from the site cards equals
//     the compiled index minus the hand-carded rules;
//   - every rule is in one rules entry, with the metadata.crypto the matcher
//     reads from the YAML (the matcher's view of A4);
//   - a rule is pending exactly when the compiler skips it and it has no
//     hand card.
func VerifyV3(rulesDir, cardsDir string) (*V3Report, error) { //nolint:funlen,gocognit,gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	compiled, err := compileRulesDir(rulesDir)
	if err != nil {
		return nil, err
	}
	table, err := ruleTable(rulesDir)
	if err != nil {
		return nil, err
	}
	files, v3, err := readCardFiles(cardsDir)
	if err != nil {
		return nil, err
	}
	if !v3 {
		return nil, fmt.Errorf("%s holds no v3 card files", cardsDir)
	}
	index, cards, err := loadV3(files)
	if err != nil {
		return nil, err
	}
	// Loading rewrites keyword indices in place: the site cards as written
	// come from a second read.
	if files, _, err = readCardFiles(cardsDir); err != nil {
		return nil, err
	}
	rep := &V3Report{}
	diff := func(format string, a ...any) { rep.Diffs = append(rep.Diffs, fmt.Sprintf(format, a...)) }

	// The rules entries, and each rule's site cards as written.
	v3Meta := map[string]*OMap{}
	pending := map[string]bool{}
	sites := map[string][]string{}
	for _, f := range files {
		if rules, ok := f.doc.Get("rules"); ok && rules != nil {
			rm := as[*OMap](rules)
			for i, k := range rm.Keys {
				id := pyStr(k)
				r := as[*OMap](rm.Vals[i])
				meta := &OMap{}
				if cr := r.GetOr("crypto"); pyTruthy(cr) {
					meta = as[*OMap](cr)
				}
				v3Meta[id] = meta
				if pyTruthy(r.GetOr("pending")) {
					pending[id] = true
				}
			}
		}
		for _, cAny := range listOf(f.doc.GetOr("cards")) {
			c := as[*OMap](cAny)
			if site, ok := c.Get("site"); ok {
				s := &OMap{}
				for i, k := range as[*OMap](site).Keys {
					s.Set(k, as[*OMap](site).Vals[i])
				}
				if l := listOf(c.GetOr("lossy")); len(l) > 0 {
					s.Set("lossy", l)
				}
				id := pyStr(c.GetOr("rule"))
				sites[id] = append(sites[id], canonicalJSON(jsonValue(s)))
			}
		}
	}

	expected := map[string][]string{}
	for _, e := range compiled.Entries {
		id := pyStr(e.GetOr("rule_id"))
		expected[id] = append(expected[id], canonicalJSON(jsonValue(SiteEntry(e))))
	}
	for _, r := range compiled.Rules {
		id := pyStr(r.GetOr("rule_id"))
		rep.Rules++
		meta, inV3 := v3Meta[id]
		if !inV3 {
			diff("%s: no rules entry", id)
			continue
		}
		if a, b := jsonValue(table[id].Meta), jsonValue(meta); a != b {
			diff("%s: crypto differs: yaml %s, v3 %s", id, a, b)
		}
		hand := cards.RuleIDs[id]
		skipped := r.GetOr("status") == any("skipped")
		switch {
		case hand:
			rep.HandRules++
			if len(sites[id]) > 0 {
				diff("%s: has a hand card and site cards", id)
			}
		case skipped:
			rep.Pending++
			if !pending[id] {
				diff("%s: skipped by the compiler, has no hand card, is not pending", id)
			}
		default:
			rep.SiteRules++
			rep.Sites += len(sites[id])
			if !equalStrings(expected[id], sites[id]) {
				diff("%s: site cards differ from the compiled entries (%d compiled, %d sites)", id, len(expected[id]), len(sites[id]))
			}
		}
		if pending[id] && (hand || !skipped) {
			diff("%s: pending but %s", id, map[bool]string{true: "hand-carded", false: "compiled"}[hand])
		}
	}
	if len(v3Meta) != rep.Rules {
		diff("%d rules entries for %d rules", len(v3Meta), rep.Rules)
	}

	// The loaded index against the compiled one minus the hand-carded rules.
	full, err := compiled.index()
	if err != nil {
		return nil, err
	}
	var want []string
	for _, e := range full.Entries {
		if !cards.RuleIDs[e.RuleID] {
			want = append(want, entryKey(e))
		}
	}
	got := make([]string, len(index.Entries))
	for i, e := range index.Entries {
		got[i] = entryKey(e)
	}
	rep.Entries = len(got)
	if len(want) != len(got) {
		diff("index: %d entries loaded, %d compiled", len(got), len(want))
	} else {
		for i := range want {
			if want[i] != got[i] {
				diff("index entry %d differs: compiled %s, loaded %s", i, want[i], got[i])
			}
		}
	}
	return rep, nil
}

// canonicalJSON is a JSON text with its objects' keys sorted.
func canonicalJSON(text string) string {
	var v any
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		return text
	}
	out := lenient(json.Marshal(sortedJSON(v)))
	return string(out)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// entryKey is a loaded entry as canonical JSON, without what a site card
// does not carry (the pattern text, whose receiver metavariable it keeps;
// dropped clauses, which it keeps as lossy; constraint clauses), at every
// level.
func entryKey(e *Entry) string {
	data, err := json.Marshal(e)
	if err != nil {
		panic(err)
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		panic(err)
	}
	strip(v)
	m := as[map[string]any](v)
	m["receiver_metavar"] = e.receiverMetavar()
	m["dropped_clauses_top"] = e.DroppedClauses
	out := lenient(json.Marshal(sortedJSON(v)))
	return string(out)
}

func strip(v any) {
	switch x := v.(type) {
	case map[string]any:
		for _, k := range []string{"pattern", "receiver_var", "dropped_clauses", "clause"} {
			delete(x, k)
		}
		for _, y := range x {
			strip(y)
		}
	case []any:
		for _, y := range x {
			strip(y)
		}
	}
}

// sortedJSON gives maps as sorted key/value lists, so the encoding does not
// depend on the encoder's key order.
func sortedJSON(v any) any {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make([]any, 0, 2*len(keys))
		for _, k := range keys {
			out = append(out, k, sortedJSON(x[k]))
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, y := range x {
			out[i] = sortedJSON(y)
		}
		return out
	}
	return v
}
