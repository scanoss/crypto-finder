package cardmatch

// The migration export: what the compiler makes of each rule, for the card
// generator of the ruleset repository (cards-export). It is deleted with the
// compiler once every rule is a card.

import (
	"encoding/json"
)

// ExportedRule is one rule as the compiler reads it.
type ExportedRule struct {
	ID string `json:"id"`
	// File is the rule file, relative to the rules directory.
	File string `json:"file"`
	// Status is "compiled" or "skipped"; Reason says why a rule was skipped.
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	Taint  bool   `json:"taint"`
	// DroppedClauses are the clauses the compiled entries leave out.
	DroppedClauses []string `json:"dropped_clauses"`
	// Sites are the rule's index entries as site cards hold them (SiteEntry).
	Sites []json.RawMessage `json:"sites"`
}

// ExportRules compiles the rules under rulesDir and returns each rule's
// record with its index entries in site form, in compile order.
func ExportRules(rulesDir string, opts Options) ([]ExportedRule, error) {
	c, err := opts.settings().compileRulesDir(rulesDir)
	if err != nil {
		return nil, err
	}
	sites := make(map[string][]json.RawMessage)
	for _, e := range c.Entries {
		id := pyStr(e.GetOr("rule_id"))
		sites[id] = append(sites[id], json.RawMessage(jsonValue(SiteEntry(e))))
	}
	out := make([]ExportedRule, 0, len(c.Rules))
	for _, r := range c.Rules {
		id := pyStr(r.GetOr("rule_id"))
		rule := ExportedRule{
			ID: id, File: pyStr(r.GetOr("file")), Status: pyStr(r.GetOr("status")),
			Taint: r.GetOr(strTaint) == any(true), DroppedClauses: []string{}, Sites: sites[id],
		}
		if reason, ok := r.Get("reason"); ok {
			rule.Reason = pyStr(reason)
		}
		for _, d := range listOf(r.GetOr("dropped_clauses")) {
			rule.DroppedClauses = append(rule.DroppedClauses, pyStr(d))
		}
		if rule.Sites == nil {
			rule.Sites = []json.RawMessage{}
		}
		out = append(out, rule)
	}
	return out, nil
}

// SiteEntry is a compiled index entry as a site card holds it: without what the
// card file's rules entry carries (rule_id, metadata), without the rule's
// pattern text (its receiver metavariable, the only thing read from it,
// becomes receiver_var), and with dropped_clauses moved to the card's lossy.
// Constraint clauses, read only to describe an approximation, are left out.
func SiteEntry(entry *OMap) *OMap {
	out := siteEntry(entry)
	out.del("rule_id")
	out.del("metadata")
	out.del("dropped_clauses")
	if dropped := listOf(entry.GetOr("dropped_clauses")); len(dropped) > 0 {
		out.Set("lossy", dropped)
	}
	return out
}

// siteEntry rewrites one entry and the entries nested in it (call arguments,
// not_calls, not_inside).
func siteEntry(entry *OMap) *OMap { //nolint:gocognit,gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	out := &OMap{}
	for i, k := range entry.Keys {
		v := entry.Vals[i]
		switch k {
		case "pattern":
			if mv := receiverMetavar(entry); mv != "" {
				out.Set("receiver_var", mv)
			}
			continue
		case "dropped_clauses":
			if len(listOf(v)) == 0 {
				continue
			}
		case "constraints":
			items := listOf(v)
			cs := make([]any, 0, len(items))
			for _, c := range items {
				cm := as[*OMap](c)
				cc := &OMap{}
				for j, ck := range cm.Keys {
					if ck != "clause" {
						cc.Set(ck, cm.Vals[j])
					}
				}
				cs = append(cs, cc)
			}
			v = cs
		case "args":
			items := listOf(v)
			args := make([]any, 0, len(items))
			for _, a := range items {
				am := as[*OMap](a)
				if call, ok := am.Get("call"); ok && call != nil {
					cp := &OMap{}
					for j, ak := range am.Keys {
						cp.Set(ak, am.Vals[j])
					}
					cp.Set("call", siteEntry(as[*OMap](call)))
					a = cp
				}
				args = append(args, a)
			}
			v = args
		case "not_calls", "not_inside":
			items := listOf(v)
			nested := make([]any, 0, len(items))
			for _, n := range items {
				nested = append(nested, siteEntry(as[*OMap](n)))
			}
			v = nested
		}
		out.Set(k, v)
	}
	return out
}

// del removes key k.
func (m *OMap) del(k string) {
	i := m.index(k)
	if i < 0 {
		return
	}
	m.Keys = append(m.Keys[:i], m.Keys[i+1:]...)
	m.Vals = append(m.Vals[:i], m.Vals[i+1:]...)
}
