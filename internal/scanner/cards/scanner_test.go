package cards

import (
	"reflect"
	"testing"

	"github.com/scanoss/reach/graphfrag"
)

func TestArgumentSpan(t *testing.T) {
	line := `        Mac mac = Mac.getInstance("HmacSHA256", provider(a, b));`
	call := `Mac.getInstance("HmacSHA256", provider(a, b))`
	start := 19
	end := start + len(call)
	cases := []struct {
		index      int
		want       string
		start, end int
		found      bool
	}{
		{0, `"HmacSHA256"`, 35, 47, true},
		{1, `provider(a, b)`, 49, 63, true},
		{1, `other`, 0, 0, false},
		{2, ``, 0, 0, false},
	}
	for _, c := range cases {
		gotStart, gotEnd, found := argumentSpan(line, start, end, c.index, c.want)
		if gotStart != c.start || gotEnd != c.end || found != c.found {
			t.Errorf("argument %d: got %d..%d %v, want %d..%d %v", c.index, gotStart, gotEnd, found, c.start, c.end, c.found)
		}
	}
	// A call that continues on the next line has no closing parenthesis here.
	if _, _, found := argumentSpan(`x = Mac.getInstance(`, 5, 21, 0, "a"); found {
		t.Error("multi-line call: want not found")
	}
}

// A finding's matched text comes from the fragment's source lines when it has
// them, so a stored fragment is re-detected without the source tree; a call
// over several lines reports all of them.
func TestLineReaderReadsTheFragment(t *testing.T) {
	fragment := map[string]map[int]string{"app/Caller.java": {
		5: `        Cipher c = Cipher.getInstance(`,
		6: `            "AES/GCM/NoPadding");`,
	}}
	lines := newLineReader(t.TempDir(), fragment)
	if got := lines.span("app/Caller.java", 5, 6); got != "        Cipher c = Cipher.getInstance(\n            \"AES/GCM/NoPadding\");" {
		t.Errorf("span = %q", got)
	}
	if got := lines.line("app/Caller.java", 5); got != fragment["app/Caller.java"][5] {
		t.Errorf("line = %q", got)
	}
}

// The matcher reads a call's receiver and a constructor delegation from the
// fragment's source lines, so the in-memory fragment hands them over.
func TestMatcherFragmentKeepsSourceLines(t *testing.T) {
	lines := map[string]map[int]string{"app/Digest.java": {30: "        this(256);"}}
	got := toMatcherFragment(&graphfrag.GraphFragmentExport{SourceLines: lines}).SourceLines
	if !reflect.DeepEqual(got, lines) {
		t.Errorf("source lines = %v, want %v", got, lines)
	}
}

// Constant cards match the fragment's constant references, so the
// in-memory fragment hands them over.
func TestMatcherFragmentKeepsConstantRefs(t *testing.T) {
	refs := []graphfrag.GraphFragmentConstantRef{{Line: 5, StartCol: 16, EndCol: 29, Text: "Alg.HS256", Context: "return"}}
	got := toMatcherFragment(&graphfrag.GraphFragmentExport{ConstantRefs: refs}).ConstantRefs
	if !reflect.DeepEqual(got, refs) {
		t.Errorf("constant refs = %v, want %v", got, refs)
	}
}

// Declaration and cast cards read the fragment's declarations and casts,
// and its schema version tells the matcher that it records them, so the
// in-memory fragment hands all three over.
func TestMatcherFragmentKeepsDeclarationsAndCasts(t *testing.T) {
	declarations := []graphfrag.GraphFragmentDeclaration{{Line: 5, StartCol: 9, EndCol: 37, Type: "X509Certificate", Name: "c", Init: "null"}}
	casts := []graphfrag.GraphFragmentCast{{Line: 7, StartCol: 16, EndCol: 61, Type: "X509Certificate", InnerLine: 7, InnerCol: 34}}
	got := toMatcherFragment(&graphfrag.GraphFragmentExport{SchemaVersion: "graph-fragment-1.18", Declarations: declarations, Casts: casts})
	if got.SchemaVersion != "graph-fragment-1.18" || !reflect.DeepEqual(got.Declarations, declarations) || !reflect.DeepEqual(got.Casts, casts) {
		t.Errorf("fragment = %q %v %v, want the schema version, declarations and casts", got.SchemaVersion, got.Declarations, got.Casts)
	}
}

// Rust use and item contexts read the items a file declares: their spans
// tell the block a use holds in. The in-memory fragment hands them over.
func TestMatcherFragmentKeepsItems(t *testing.T) {
	items := map[string][]graphfrag.GraphFragmentItem{"src/main.rs": {{Line: 3, StartCol: 1, EndCol: 2, EndLine: 9, Kind: "fn", Name: "main"}}}
	got := toMatcherFragment(&graphfrag.GraphFragmentExport{Items: items}).Items
	if !reflect.DeepEqual(got, items) {
		t.Errorf("items = %v, want %v", got, items)
	}
}

// A rule that reports an argument of a call written over several lines gets
// the argument's own span, on whichever line it is, as OpenGrep reports it.
func TestCallArgumentSpanAcrossLines(t *testing.T) {
	first := `        CertStore certStore = CertStore.getInstance("Collection",`
	second := `                new CollectionCertStoreParameters(crls), "BC");`
	lines := newLineReader(t.TempDir(), map[string]map[int]string{"A.java": {10: first, 11: second}})
	start := 31        // CertStore.getInstance(
	end := len(second) // one past the closing parenthesis, before ';'
	cases := []struct {
		index int
		want  string
		span  lineSpan
	}{
		{0, `"Collection"`, lineSpan{10, 53, 10, 65}},
		{1, `new CollectionCertStoreParameters(crls)`, lineSpan{11, 17, 11, 56}},
		{2, `"BC"`, lineSpan{11, 58, 11, 62}},
	}
	for _, c := range cases {
		got, found := callArgumentSpan(lines, "A.java", 10, 11, start, end, c.index, c.want)
		if !found || got != c.span {
			t.Errorf("argument %d: got %+v %v, want %+v", c.index, got, found, c.span)
		}
	}
}
