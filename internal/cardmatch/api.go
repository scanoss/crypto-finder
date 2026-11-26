// Package cardmatch is the PoC card matcher (symbol-index PoC, gomatch/) copied as a library:
// a compiled index plus hand-written cards matched against the call sites of a graph fragment.
// The matching code (cards.go, frag.go, index.go, pyre.go, pyyaml.go, text.go) is the PoC's,
// unchanged apart from the package name, the yaml import path, the call site carried on a Finding,
// the string form of non-string metadata values, and the OpenGrep precision rules of frag.go
// (receiverClass, receiverless, delegation), findingKey's column, constant references at any
// position, and declaration cards, casts and assigned_type read from the fragment's declarations
// and casts (graph-fragment-1.18). A Python fragment is read in a Python mode (python.go,
// the PoC's pymatch.py). This file is the only API.
package cardmatch

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
)

// Assets is what the matcher loads once: the compiled index and the hand cards.
type Assets struct {
	index *Index
	cards *CardSet
	node  *nodeIndex // the node entries indexed, built by the first node match
	opts  *settings
}

// matching serializes the matcher: it memoises regex results and per-pattern
// method tests in package-level maps, so one load or match runs at a time in
// the process, whatever Assets it uses (an offline scan mines several
// dependencies at once, each with its own).
var matching sync.Mutex

// Load reads the compiled index (compile_rules.py) and the hand cards. rulesDir is the rules
// directory the cards take their metadata.crypto templates from. An empty indexPath compiles the
// index from the rules in rulesDir (CompileIndex) instead of reading one.
//
// When cardsDir holds v3 card files (CardsFormatV3), they are the whole ruleset: their site
// cards are the index and their rules entries the metadata; rulesDir is not read.
func Load(indexPath, cardsDir, rulesDir string, opts Options) (*Assets, error) {
	matching.Lock()
	defer matching.Unlock()
	s := opts.settings()
	if cardsDir != "" { //nolint:nestif // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
		files, v3, err := s.readCardFiles(cardsDir)
		if err != nil {
			return nil, err
		}
		if v3 {
			if indexPath != "" {
				return nil, fmt.Errorf("a compiled index does not apply to v3 card files (%s)", cardsDir)
			}
			index, cards, err := s.loadV3(files)
			if err != nil {
				return nil, err
			}
			return &Assets{index: index, cards: cards, opts: s}, nil
		}
	}
	var index *Index
	var err error
	if indexPath == "" {
		index, err = s.compileIndex(rulesDir)
	} else {
		index, err = loadIndex(indexPath)
	}
	if err != nil {
		return nil, err
	}
	cards, err := s.loadCards(cardsDir, rulesDir)
	if err != nil {
		return nil, err
	}
	return &Assets{index: index, cards: cards, opts: s}, nil
}

// Match is gomatch's run: the findings of the compiled index (minus the rules that have a hand
// card) plus the cards', with metadata filled the way crypto-finder fills it. It also returns
// the number of call sites looked at. A card or rule the matcher cannot evaluate is an error
// naming it, never a panic.
func (a *Assets) Match(frag *FragmentJSON) (findings []*Finding, sites int, err error) {
	matching.Lock()
	defer matching.Unlock()
	defer func() {
		if r := recover(); r != nil {
			findings, sites, err = nil, 0, matchError(r)
		}
	}()
	found, n := a.match(frag)
	return found, n, nil
}

// cardPanic is a panic raised while a hand card was evaluated, with the card.
type cardPanic struct {
	card  *Card
	cause any
}

// matchError is the error of a panic recovered from a match.
func matchError(r any) error {
	if p, ok := r.(cardPanic); ok {
		return fmt.Errorf("cards: card %s (%s) cannot be evaluated: %v", p.card.Rule, p.card.File, p.cause)
	}
	return fmt.Errorf("cards: a card or rule cannot be evaluated: %v", r)
}

func (a *Assets) match(frag *FragmentJSON) ([]*Finding, int) {
	fr := newFrag(frag)
	if fr.Node {
		return a.matchNode(fr), len(fr.Sites)
	}
	fr.ResolveParams = true
	a.opts.applyPolicies(fr)
	if frag.c() {
		return matchC(a, fr), len(fr.Sites)
	}
	if frag.rust() {
		return matchRust(a, fr), len(fr.Sites)
	}
	var compiled []*Entry
	for _, e := range a.index.Entries {
		if !a.cards.RuleIDs[e.RuleID] && e.Callee == nil && e.Rust == nil && e.C == nil {
			compiled = append(compiled, e)
		}
	}
	found := matchIndex(compiled, fr, true, "cf")
	found = append(found, matchCards(a.cards.Cards, fr)...)
	if fr.Python {
		found = dropRepeats(found)
	}
	return found, len(fr.Sites)
}

// matchNode is Match for a node fragment: the compiled node entries (minus
// the rules that have a hand card). The hand-card DSL does not run on node
// fragments.
func (a *Assets) matchNode(fr *Frag) []*Finding {
	if a.node == nil {
		var compiled []*Entry
		for _, e := range a.index.Entries {
			if !a.cards.RuleIDs[e.RuleID] {
				compiled = append(compiled, e)
			}
		}
		a.node = buildNodeIndex(compiled)
	}
	return matchNodeIndex(a.node, fr)
}

// dropRepeats keeps one of the findings that report the same rule at the
// same position with the same value and metadata: the variants of one
// Python call (pyValueVariants) find the same asset again whenever the
// rule does not read the argument they differ in.
func dropRepeats(found []*Finding) []*Finding {
	seen := make(map[string]bool, len(found))
	out := found[:0]
	for _, f := range found {
		var b strings.Builder
		fmt.Fprintf(&b, "%s\x00%s\x00%d:%v\x00%d:%v\x00", f.RuleID, f.File, f.Line, f.LineOK, f.Col, f.ColOK)
		if f.Value != nil {
			b.WriteString("v" + *f.Value)
		}
		b.WriteString("\x00" + jsonValue(f.Metadata))
		if key := b.String(); !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}

// MetadataFields returns a finding's filled rule metadata (Options.MetadataKey) as a map.
func (f *Finding) MetadataFields() map[string]any {
	out := make(map[string]any, len(f.Metadata.Keys))
	for i, k := range f.Metadata.Keys {
		name, ok := k.(string)
		if !ok {
			name = pyStr(k)
		}
		out[name] = f.Metadata.Vals[i]
	}
	return out
}

// metadataStr is the string a filled metadata value takes when it is not a string: booleans
// in lower case, numbers as written.
func metadataStr(v any) string {
	if b, ok := v.(bool); ok {
		return strconv.FormatBool(b)
	}
	return pyStr(v)
}

func jstr(s string) string {
	b := lenient(json.Marshal(s))
	return string(b)
}

// jsonValue writes a loaded value as JSON, keeping map order (the compiled index, the tests).
func jsonValue(v any) string {
	switch x := v.(type) {
	case string:
		return jstr(x)
	case jsonNumber:
		return string(x)
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case *big.Int:
		return x.String()
	case float64:
		return pyFloatRepr(x)
	case *OMap:
		parts := make([]string, len(x.Keys))
		for i := range x.Keys {
			k, ok := x.Keys[i].(string)
			if !ok {
				k = pyStr(x.Keys[i])
			}
			parts[i] = jstr(k) + ": " + jsonValue(x.Vals[i])
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = jsonValue(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	return jstr(pyStr(v))
}
