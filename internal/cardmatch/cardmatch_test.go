package cardmatch

import (
	"reflect"
	"testing"
)

func strp(s string) *string { return &s }

// Regex translation: Python re semantics on regexp2.
func TestPythonRegex(t *testing.T) {
	cases := []struct {
		name, rx, text string
		search         bool
		want           Groups // nil = no match
	}{
		{"python named group", `^"(?P<size>\d+)"$`, `"256"`, false, Groups{"size": "256", "1": "256"}},
		{"pcre named group", `^"(?<size>\d+)"$`, `"256"`, false, Groups{"size": "256", "1": "256"}},
		{"match anchors at start", `AES`, `"AES"`, false, nil},
		{"match does not anchor at end", `AES`, `AES/GCM`, false, Groups{}},
		{"search finds inside", `G(?<m>CM)`, `AES/GCM`, true, Groups{"m": "CM", "1": "CM"}},
		{"dollar before final newline", `^abc$`, "abc\n", false, Groups{}},
		{"negative lookahead", `^(?!\d+$)`, `128`, false, nil},
		{"negative lookahead passes", `^(?!\d+$)`, `size`, false, Groups{}},
		{"inline ignore case", `(?i)^"blake2b-(?P<size>\d+)"$`, `"BLAKE2B-512"`, false, Groups{"size": "512", "1": "512"}},
		{"group that did not take part is dropped", `^(?:(?P<a>x)|(?P<b>y))$`, `y`, false, Groups{"b": "y", "2": "y"}},
		// OpenGrep binds every group by its number too, left to right over
		// named and unnamed groups alike (.NET would number the named last).
		{"numbered groups in python order", `^"(?P<alg>\w+)-(\w+)"$`, `"aes-cbc"`, false, Groups{"alg": "aes", "1": "aes", "2": "cbc"}},
		{"lookbehind and classes are not groups", `(?<=x)[(](a)\((b)`, `x(a(b`, true, Groups{"1": "a", "2": "b"}},
		{"alternation anchored as a whole", `a|b`, `xb`, false, nil},
	}
	for _, c := range cases {
		var got Groups
		if c.search {
			got = reSearch(c.rx, c.text)
		} else {
			got = reMatch(c.rx, c.text)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %q on %q = %v, want %v", c.name, c.rx, c.text, got, c.want)
		}
	}
}

func TestParseKeyAndCall(t *testing.T) {
	cls, m, ok := parseKey("javax.crypto.(Cipher).getInstance#2")
	if !ok || cls != "javax.crypto.Cipher" || m != "getInstance" {
		t.Errorf("parseKey = %q %q %v", cls, m, ok)
	}
	if _, _, ok := parseKey("no.key"); ok {
		t.Error("parseKey accepted a key without #n")
	}
	// A key with no package, both ways in: the ASCII fast path and the
	// regex one a non-ASCII identifier takes must read it the same.
	for _, key := range []string{"(Type).method#1", "(Clé).chiffrer#1"} {
		wantClass := "Type"
		if !isASCII(key) {
			wantClass = "Clé"
		}
		cls, m, ok := parseKey(key)
		if !ok || cls != wantClass || m == "" {
			t.Errorf("parseKey(%q) = %q %q %v, want %q", key, cls, m, ok, wantClass)
		}
	}
	pc := parseCall(`(Foo) new javax.crypto.spec.SecretKeySpec(k, "AES")`)
	if pc == nil || pc.Type != "javax.crypto.spec.SecretKeySpec" || pc.Method != "<init>" || !reflect.DeepEqual(pc.Args, []string{"k", `"AES"`}) {
		t.Errorf("parseCall new = %+v", pc)
	}
	pc = parseCall(`Jwts.SIG.ES256.keyPair().build()`)
	if pc == nil || pc.Receiver != "Jwts.SIG.ES256.keyPair()" || pc.Method != "build" || len(pc.Args) != 0 {
		t.Errorf("parseCall chain = %+v", pc)
	}
	if cast, rest := stripCast(`(X509Certificate) cf.generateCertificate(in)`); cast != "X509Certificate" || rest != "cf.generateCertificate(in)" {
		t.Errorf("stripCast = %q %q", cast, rest)
	}
}

// PyYAML (YAML 1.1) scalar resolution and merge-key order.
func TestYAML11(t *testing.T) {
	v, err := parseYAML([]byte("a: yes\nb: 0777\nc: '1'\nd: 1.5\ne: ~\nbase: &b {x: 1, y: 2}\nm:\n  <<: *b\n  y: 3\n  z: 4\n"))
	if err != nil {
		t.Fatal(err)
	}
	m := v.(*OMap)
	if m.GetOr("a") != true || m.GetOr("b") != int64(511) || m.GetOr("c") != "1" || m.GetOr("d") != 1.5 || m.GetOr("e") != nil {
		t.Errorf("scalars: %v", m.Vals)
	}
	mm := m.GetOr("m").(*OMap)
	if !reflect.DeepEqual(mm.Keys, []any{"x", "y", "z"}) || !reflect.DeepEqual(mm.Vals, []any{int64(1), int64(3), int64(4)}) {
		t.Errorf("merge: %v %v", mm.Keys, mm.Vals)
	}
}

// A tiny fragment: one function with a KeyPairGenerator flow, a chained call, a cast and a constant.
func tinyFrag() *Frag { return newFrag(tinyFragJSON()) }

func tinyFragJSON() *FragmentJSON {
	ln := func(n int) *int { return &n }
	call := func(target, raw, method string, line, arity int, assigned, recv string, params ...Param) ExternalJSON {
		return ExternalJSON{
			CallerKey: "app.(Demo).run#0", TargetKey: target, Raw: raw, Line: ln(line), Resolution: "exact",
			MethodName: method, Arity: arity, AssignedVar: assigned, ReceiverVar: recv, StartCol: ln(5),
			EntryCall: &CallSiteJSON{Parameters: params},
		}
	}
	frag := &FragmentJSON{
		Functions: []FunctionJSON{{Key: "app.(Demo).run#0", Package: "app", FilePath: "src/Demo.java"}},
		ExternalCalls: []ExternalJSON{
			call("java.security.(KeyPairGenerator).getInstance#1", "KeyPairGenerator.getInstance", "getInstance", 3, 1, "kpg", "",
				Param{ParameterIndex: 0, ArgumentExpression: `"RSA"`, ResolvedValue: `"RSA"`}),
			call("java.security.(KeyPairGenerator).generateKeyPair#0", "kpg.generateKeyPair", "generateKeyPair", 4, 0, "", "kpg"),
			call("io.jsonwebtoken.(Jwts).builder#0", "Jwts.builder", "builder", 6, 0, "", ""),
			call("io.jsonwebtoken.(JwtBuilder).signWith#1", "Jwts.builder().signWith", "signWith", 6, 1, "", "",
				Param{ParameterIndex: 0, ArgumentExpression: "SignatureAlgorithm.HS256"}),
			call("java.lang.(System).exit#1", "System.exit", "exit", 8, 1, "", "",
				Param{ParameterIndex: 0, ArgumentExpression: "AlgorithmIdentifiers.RSA_USING_SHA256"}),
		},
	}
	frag.ExternalCalls[3].EndLine = 7 // signWith(...) closes on the next line
	return frag
}

func cardsFrom(t *testing.T, src string) []*Card {
	v, err := parseYAML([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	items := v.([]any)
	out := make([]*Card, 0, len(items))
	for _, c := range items {
		m := c.(*OMap)
		card := &Card{
			Raw: m, Rule: m.GetOr("rule").(string), Metadata: &OMap{Keys: []any{"algorithmName"}, Vals: []any{"$name"}},
			With: expandList(listOf(m.GetOr("with"))), Without: expandList(listOf(m.GetOr("without"))), File: "t.yaml",
		}
		if x, ok := m.Get("match"); ok {
			card.Match = expandObjects(x).(*OMap)
		} else if x, ok := m.Get("declaration"); ok {
			card.Declaration = x.(*OMap)
		} else if x, ok := m.Get("store"); ok {
			card.Store = x.(*OMap)
		} else {
			card.Constant = m.GetOr("constant").(*OMap)
		}
		out = append(out, card)
	}
	return out
}

func TestCardShapes(t *testing.T) {
	fr := tinyFrag()
	cards := cardsFrom(t, `
- rule: call
  match: {call: KeyPairGenerator.getInstance, args: {0: {regex: '^"(?<name>RSA|EC)"$'}}}
- rule: flow-with
  match: {method: generateKeyPair, arity: 0, receiver: $K}
  with:
  - {call: java.security.KeyPairGenerator.getInstance, assigned: $K, when: before, args: {0: {regex: '^"(?<name>RSA)"$'}}}
- rule: flow-without
  match: {method: generateKeyPair, arity: 0, receiver: $K}
  without:
  - {call: KeyPairGenerator.getInstance, assigned: $K, args: {0: {literal: '"RSA"'}}}
- rule: chain-from
  match: {method: signWith, receiver: {via: chain, from: {call: Jwts.builder, arity: 0}}, args: {0: {const: io.jsonwebtoken.SignatureAlgorithm, member: '^(?<name>HS\d+)$'}}}
- rule: constant
  constant: {const: AlgorithmIdentifiers, member: '^RSA_USING_SHA(?<name>256|384|512)$'}
`)
	got := map[string]string{}
	for _, f := range matchCards(cards, fr) {
		got[f.RuleID+"@"+itoa(f.Line)] = jsonValue(f.Metadata)
		if want := map[string]int{"chain-from": 7}[f.RuleID]; f.EndLine != want {
			t.Errorf("%s: end line %d, want %d", f.RuleID, f.EndLine, want)
		}
	}
	want := map[string]string{
		"call@3":       `{"algorithmName": "RSA"}`,
		"flow-with@4":  `{"algorithmName": "RSA"}`,
		"chain-from@6": `{"algorithmName": "HS256"}`,
		"constant@8":   `{"algorithmName": "256"}`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings\n got %v\nwant %v", got, want)
	}
}

func itoa(n int) string { return jsonValue(int64(n)) }

// Compiled entries: the two fills, and a qualified constant in the rule matching the short name in
// the source (call_matches_const, with package evidence from the io.jsonwebtoken classes the file uses).
func TestIndexFill(t *testing.T) {
	fr := tinyFrag()
	e := &Entry{
		Receiver: "type", Type: strp("JwtBuilder"), Method: strp("signWith"), MinArity: 1, MaxArity: nil,
		Args:     []IndexArg{{Kind: "text", Value: strp("io.jsonwebtoken.SignatureAlgorithm.HS256"), Index: new(int)}},
		RuleID:   "hs256",
		Metadata: JSONMeta{M: &OMap{Keys: []any{"algorithmName", "size", "missing"}, Vals: []any{"HMAC", jsonNumber("256"), "$X"}}},
	}
	raw := matchIndex([]*Entry{e}, fr, false, "raw")
	cf := matchIndex([]*Entry{e}, fr, false, "cf")
	if len(raw) != 1 || len(cf) != 1 {
		t.Fatalf("findings raw=%d cf=%d", len(raw), len(cf))
	}
	if raw[0].EndLine != 7 {
		t.Errorf("end line %d, want the call's 7", raw[0].EndLine)
	}
	if g := jsonValue(raw[0].Metadata); g != `{"algorithmName": "HMAC", "size": 256, "missing": "$X"}` {
		t.Errorf("raw fill %s", g)
	}
	if g := jsonValue(cf[0].Metadata); g != `{"algorithmName": "HMAC", "size": "256"}` {
		t.Errorf("cf fill %s", g)
	}
}

// A taint card reads, as OpenGrep's taint does, the literals a PARAMETER
// argument receives from the component's internal callers (with
// ResolveParams) and the literals a variable written more than once may hold.
func TestTaintFollowsParametersAndMayValues(t *testing.T) {
	ln := func(n int) *int { return &n }
	zero := 0
	sig := func(caller string, line int, node SourceNode) ExternalJSON {
		return ExternalJSON{
			CallerKey: caller, TargetKey: "java.security.(Signature).getInstance#1", Raw: "Signature.getInstance",
			Line: ln(line), Resolution: "exact", MethodName: "getInstance", Arity: 1, StartCol: ln(5),
			EntryCall: &CallSiteJSON{Parameters: []Param{{ParameterIndex: 0, ArgumentExpression: "alg", SourceNodes: []SourceNode{node}}}},
		}
	}
	frag := &FragmentJSON{
		Functions: []FunctionJSON{
			{Key: "app.(X).get#1", Package: "app", FilePath: "app/X.java"},
			{Key: "app.(X).use#0", Package: "app", FilePath: "app/X.java"},
			{Key: "app.(X).branches#1", Package: "app", FilePath: "app/X.java"},
			{Key: "app.(Other).call#0", Package: "app", FilePath: "app/Other.java"},
		},
		InternalEdgeStrings: []string{"", "exact", "get"},
		InternalEdges: []CompactEdge{
			// A caller in another file: OpenGrep's taint does not follow it.
			{N: [13]int{3, 0, 4, 1, 0, 2, 1}, Entry: &CallSiteJSON{Parameters: []Param{
				{ParameterIndex: 0, ArgumentExpression: `"SHA384withECDSA"`, ResolvedValue: `"SHA384withECDSA"`},
			}}},
			{N: [13]int{1, 0, 8, 1, 0, 2, 1}, Entry: &CallSiteJSON{Parameters: []Param{
				{ParameterIndex: 0, ArgumentExpression: `"SHA256withECDSA"`, ResolvedValue: `"SHA256withECDSA"`},
			}}},
		},
		ExternalCalls: []ExternalJSON{
			sig("app.(X).get#1", 5, SourceNode{Type: "PARAMETER", Name: "alg", ParameterIndex: &zero}),
			sig("app.(X).branches#1", 12, SourceNode{Type: "VARIABLE", Name: "alg", MayValues: []string{`"SHA384withECDSA"`}, MayValuesExhaustive: true}),
		},
	}
	cards := cardsFrom(t, `
- rule: ecdsa
  match: {call: Signature.getInstance, args: {0: {taint: '"SHA(?<name>256|384)withECDSA"'}}}
`)
	run := func(resolve bool) map[int]string {
		fr := newFrag(frag)
		fr.ResolveParams = resolve
		got := map[int]string{}
		for _, f := range matchCards(cards, fr) {
			got[f.Line] = jsonValue(f.Metadata)
		}
		return got
	}
	if got, want := run(true), map[int]string{5: `{"algorithmName": "256"}`, 12: `{"algorithmName": "384"}`}; !reflect.DeepEqual(got, want) {
		t.Errorf("resolved: %v, want %v", got, want)
	}
	if got, want := run(false), map[int]string{12: `{"algorithmName": "384"}`}; !reflect.DeepEqual(got, want) {
		t.Errorf("parameters not followed: %v, want %v", got, want)
	}
	// A variable only ever assigned literals holds a string constant, so the
	// dynamic rule does not apply; one that may hold something else keeps it.
	nodes := frag.ExternalCalls[1].EntryCall.Parameters[0].SourceNodes
	if !startsWithQuoteValueChild(nodes) {
		t.Error("a variable only assigned literals reads as a string constant")
	}
	nodes[0].MayValuesExhaustive = false
	if startsWithQuoteValueChild(nodes) {
		t.Error("a variable also assigned a non-literal reads as a string constant")
	}
}

// A taint source regex binds its groups by number too, a group that did not
// take part as nil (Claude review on #21).
func TestReMatchFullNumberedGroups(t *testing.T) {
	got, ok := reMatchFull(`^"(?P<alg>\w+)-(\w+)(-(x))?"$`, `"aes-cbc"`)
	if !ok {
		t.Fatal("no match")
	}
	want := map[string]string{"alg": "aes", "1": "aes", "2": "cbc"}
	for k, v := range want {
		if got[k] == nil || *got[k] != v {
			t.Errorf("group %s = %v, want %q", k, got[k], v)
		}
	}
	for _, k := range []string{"3", "4"} {
		if v, present := got[k]; !present || v != nil {
			t.Errorf("group %s = %v (present %v), want nil", k, v, present)
		}
	}
}
