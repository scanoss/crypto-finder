package cardmatch

import (
	"reflect"
	"sort"
	"testing"
)

// precisionFrag: internal edges whose matches OpenGrep does not make (a
// dispatch-expanded edge, a call written without a receiver, a constructor
// delegation) next to the ones it does, and two calls of one rule on one line.
func precisionFrag(withSource bool) *Frag {
	strs := []string{"", "exact", "interface_dispatch", "name_only", "crypto.BlockCipher", "init", "sha256", "<init>", "cipher", "aes"}
	edge := func(caller, callee, line, res, decl, method, arity, recv, col, endCol int) CompactEdge {
		return CompactEdge{N: [13]int{caller, callee, line, res, decl, method, arity, recv, 0, 0, col, endCol}}
	}
	frag := &FragmentJSON{
		Functions: []FunctionJSON{
			{Key: "app.(Mode).init#0", Package: "app", FilePath: "app/Mode.java"},              // 0
			{Key: "crypto.(BlockCipher).init#2", Package: "crypto", FilePath: "crypto/B.java"}, // 1
			{Key: "crypto.engines.(AESEngine).init#2", Package: "crypto.engines", FilePath: "crypto/engines/AESEngine.java"},
			{Key: "crypto.engines.(RSAEngine).init#2", Package: "crypto.engines", FilePath: "crypto/engines/RSAEngine.java"},
			{Key: "crypto.(DigestUtils).sha256#1", Package: "crypto", FilePath: "crypto/DigestUtils.java"}, // 4
			{Key: "crypto.(DigestUtils).sha256Hex#1", Package: "crypto", FilePath: "crypto/DigestUtils.java"},
			{Key: "crypto.(SHA3Digest).<init>#1", Package: "crypto", FilePath: "crypto/SHA3Digest.java"}, // 6
			{Key: "crypto.(SHA3Digest).<init>#0", Package: "crypto", FilePath: "crypto/SHA3Digest.java"},
			{Key: "app.(Use).run#0", Package: "app", FilePath: "app/Use.java"}, // 8
		},
		InternalEdgeStrings: strs,
		InternalEdges: []CompactEdge{
			// cipher.init(true, params) on a BlockCipher: one exact edge to
			// BlockCipher.init, dispatch-expanded edges to the implementations.
			edge(0, 1, 10, 1, 0, 5, 2, 8, 9, 34),
			edge(0, 2, 10, 2, 4, 5, 2, 8, 9, 34),
			edge(0, 3, 10, 3, 4, 5, 2, 8, 9, 34),
			// aes.init(true, params) on an AESEngine.
			edge(0, 2, 12, 1, 0, 5, 2, 9, 9, 31),
			// sha256(data) inside DigestUtils, then DigestUtils.sha256(data).
			edge(5, 4, 20, 1, 0, 6, 1, 0, 16, 28),
			edge(5, 4, 21, 1, 0, 6, 1, 0, 16, 40),
			// A column at the method name, after the receiver's dot.
			edge(5, 4, 22, 1, 0, 6, 1, 0, 28, 40),
			// this(256) in SHA3Digest(), then new SHA3Digest(512) in a client.
			edge(7, 6, 30, 1, 0, 7, 1, 0, 9, 18),
			edge(8, 6, 40, 1, 0, 7, 1, 0, 20, 39),
			// a(new SHA3Digest(512), new SHA3Digest(256)): two calls, one line.
			edge(8, 6, 50, 1, 0, 7, 1, 0, 11, 30),
			edge(8, 6, 50, 1, 0, 7, 1, 0, 32, 51),
		},
		ExternalCalls: []ExternalJSON{{
			CallerKey: "crypto.(SHA3Digest).<init>#0", TargetKey: "java.lang.(Object).<init>#1", Raw: "super",
			Line: intp(31), Resolution: "exact", MethodName: "<init>", Arity: 1, StartCol: intp(9),
			EntryCall: &CallSiteJSON{Parameters: []Param{{ParameterIndex: 0, ArgumentExpression: `"SHA3"`}}},
		}},
	}
	if withSource {
		frag.SourceLines = map[string]map[int]string{
			"app/Mode.java": {10: "        cipher.init(true, params);", 12: "        aes.init(true, params);"},
			"crypto/DigestUtils.java": {
				20: "        return sha256(data);", 21: "        return DigestUtils.sha256(data);",
				22: "        return DigestUtils.sha256(data);",
			},
			"crypto/SHA3Digest.java": {30: "        this(256);", 31: `        super("SHA3");`},
			"app/Use.java": {
				40: "        Digest d = new SHA3Digest(512);",
				50: "        a(new SHA3Digest(512), new SHA3Digest(256));",
			},
		}
	}
	return newFrag(frag)
}

func intp(n int) *int { return &n }

func findingLines(fs []*Finding) map[string][]int {
	out := map[string][]int{}
	for _, f := range fs {
		out[f.RuleID] = append(out[f.RuleID], f.Line*100+f.Col)
	}
	for _, v := range out {
		sort.Ints(v)
	}
	return out
}

// want: findings by rule as line*100+column.
var precisionWant = map[string][]int{
	"aes":    {1209},             // not the dispatch-expanded cipher.init at 10
	"sha256": {2116, 2228},       // not the receiver-less sha256(data) at 20
	"sha3":   {4020, 5011, 5032}, // not this(256) at 30; both calls at 50
	"super":  {3109},             // super(...) cards keep matching
}

func TestCompiledEntriesMatchAsOpenGrep(t *testing.T) {
	fr := precisionFrag(true)
	entries := []*Entry{
		{Receiver: "typed_metavar", Type: strp("AESEngine"), Method: strp("init"), MinArity: 2, RuleID: "aes", Metadata: JSONMeta{M: &OMap{}}},
		{Receiver: "type", Type: strp("DigestUtils"), Method: strp("sha256"), MinArity: 1, RuleID: "sha256", Metadata: JSONMeta{M: &OMap{}}},
		{Receiver: "type", Type: strp("SHA3Digest"), Method: strp("<init>"), MinArity: 0, RuleID: "sha3", Metadata: JSONMeta{M: &OMap{}}},
	}
	got := findingLines(matchIndex(entries, fr, false, "cf"))
	want := map[string][]int{"aes": precisionWant["aes"], "sha256": precisionWant["sha256"], "sha3": precisionWant["sha3"]}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("compiled entries\n got %v\nwant %v", got, want)
	}
}

func TestCardsMatchAsOpenGrep(t *testing.T) {
	fr := precisionFrag(true)
	cards := cardsFrom(t, `
- rule: aes
  match: {call: AESEngine.init, arity: 2}
- rule: sha256
  match: {call: DigestUtils.sha256}
- rule: sha3
  match: {new: SHA3Digest}
- rule: super
  match: {super: true, arity: 1, args: {0: {literal: '"SHA3"'}}}
`)
	if got := findingLines(matchCards(cards, fr)); !reflect.DeepEqual(got, precisionWant) {
		t.Errorf("cards\n got %v\nwant %v", got, precisionWant)
	}
}

// Without source lines (a fragment before graph-fragment-1.16) a receiver or a
// delegation cannot be read, so those sites still match; the declared type of
// a dispatch-expanded edge is in every fragment.
func TestWithoutSourceLines(t *testing.T) {
	fr := precisionFrag(false)
	cards := cardsFrom(t, `
- rule: aes
  match: {call: AESEngine.init, arity: 2}
- rule: sha256
  match: {call: DigestUtils.sha256}
- rule: sha3
  match: {new: SHA3Digest}
`)
	want := map[string][]int{"aes": {1209}, "sha256": {2016, 2116, 2228}, "sha3": {3009, 4020, 5011, 5032}}
	if got := findingLines(matchCards(cards, fr)); !reflect.DeepEqual(got, want) {
		t.Errorf("cards without source lines\n got %v\nwant %v", got, want)
	}
}
