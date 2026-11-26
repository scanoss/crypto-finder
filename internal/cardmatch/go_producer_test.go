// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var goProducerDir = filepath.Join("testdata", "go_producer")

// goProducerOpenGrepOnly are the places OpenGrep reports and the matcher
// does not, from OpenGrep's looser package naming:
// `other.X` through `other "example.com/other/srv"` (or
// `.../other/mode`) in a file that also imports example.com/acme/srv (or
// `.../acme/mode`), both read by the last path element. The matcher
// compares the import path.
var goProducerOpenGrepOnly = map[rustPinKey]bool{
	{"src/srvlike.go", 10, 2, 14}: true,
	{"src/sinkpkg.go", 12, 2, 22}: true,
}

// TestGoProducerMatchesAsOpenGrep pins Go rules that say where a sink's
// argument or receiver comes from with a pattern-inside assignment
// (`$BLOCK, $ERR := $PKG.NewCipher($KEY) ... cipher.NewCBCEncrypter($BLOCK, ...)`,
// go-port audit T8) to what OpenGrep 1.33.1 reports for invented rules on
// invented files: through the import idiom that binds $PKG whether the file
// aliases the package or not, inside a nested block (even one that shadows
// the name), and after a later reassignment of the local (pattern-inside
// does not end there); not in a sibling
// block (the other branch of an if, another case of a switch, whether the
// sibling declares the name with := or assigns it with =, sibling.go), not
// past the if or switch whose header assigns it (initstmt.go: its body, else
// and cases only, blank lines and comments between cases included), not through a parameter, from
// another call, nor from a package of the same name at another path. An
// import clause naming the sink's own package qualifies the sink
// (sinkpkg.go); one naming neither still requires the file to import it
// (gcm.go, not gcmother.go). `$V = call` and an either of producers read the same. A
// producer in a branch whose import clause is outside it (`nested`) keeps
// the rule: the producer says what the untyped receiver is, and the outer
// import qualifies the producer (a package of the same name at another path
// does not match, srvother.go).
func TestGoProducerMatchesAsOpenGrep(t *testing.T) {
	assets, frag, want := rustFixtureAt(t, goProducerDir)
	found, _ := assets.mustMatch(t, frag)
	got := map[string]map[rustPinKey]bool{}
	for _, f := range found {
		if got[f.RuleID] == nil {
			got[f.RuleID] = map[rustPinKey]bool{}
		}
		got[f.RuleID][rustPinKey{f.File, f.Line, f.Col, f.EndCol}] = true
	}
	for _, id := range []string{"mode", "verify", "single", "nested", "sinkpkg", "gcm"} {
		exp := map[rustPinKey]bool{}
		for _, h := range want[id] {
			if k := (rustPinKey{h.File, h.Line, h.Col, h.EndCol}); !goProducerOpenGrepOnly[k] {
				exp[k] = true
			}
		}
		if g, w := rustPinKeys(got[id]), rustPinKeys(exp); !slices.Equal(g, w) {
			t.Errorf("%s\n got %v\nwant %v", id, g, w)
		}
	}
}

// A producer compiles into an origin on the sink's argument, its package
// qualified through the import idiom; a producer of a metavariable the sink
// does not bind skips the rule.
func TestCompileGoProducer(t *testing.T) {
	sinks, err := compileGoRule(t, `rules:
  - id: r
    message: m
    severity: INFO
    languages: [go]
    patterns:
      - pattern-inside: |
          $B, $E := $PKG.NewCipher($K)
          ...
      - pattern: cipher.NewCBCEncrypter($B, ...)
      - pattern-either:
          - pattern-inside: |
              import $PKG "example.com/acme/blk"
              ...
          - patterns:
              - pattern-inside: |
                  import "example.com/acme/blk"
                  ...
              - pattern-not-inside: |
                  import $ALIAS "example.com/acme/blk"
                  ...
              - metavariable-pattern:
                  metavariable: $PKG
                  patterns:
                    - pattern-regex: ^blk$
`)
	if err != nil || len(sinks) != 1 {
		t.Fatalf("sinks %v, err %v", sinks, err)
	}
	insides := pyRepr(sinks[0].GetOr("insides"))
	if !strings.Contains(insides, "'$B'") || !strings.Contains(insides, "example.com/acme/blk.NewCipher") {
		t.Errorf("insides = %s, want an origin on $B from example.com/acme/blk.NewCipher", insides)
	}
	if typ := getString(sinks[0], strType); typ != "cipher" {
		t.Errorf("sink type %q, want cipher (the import qualifies the producer, not the sink)", typ)
	}
	_, err = compileGoRule(t, `rules:
  - id: r
    message: m
    severity: INFO
    languages: [go]
    patterns:
      - pattern-inside: |
          $X := acme.New()
          ...
      - pattern: lib.Use($Y)
`)
	if s, ok := asSkip(err); !ok || s.reason != "producer metavariable the sink does not bind" {
		t.Errorf("unbound producer: err %v, want the producer skip", err)
	}
}

// A fragment from before graph-fragment-1.36 lists no blocks and no
// assignments: the producer scope falls back to the source lines' indentation
// (a call reassignment at the producer's depth ends it, so two OpenGrep
// places are missed), and the object flow follows no local copy, field or
// composite return.
func TestGoFlowWithoutBlockFacts(t *testing.T) {
	old := func(dir string) (*Assets, *FragmentJSON) {
		assets, frag, _ := rustFixtureAt(t, dir)
		frag.SchemaVersion, frag.GoBlocks = "graph-fragment-1.34", nil
		for file, values := range frag.GoValues {
			kept := values[:0]
			for _, v := range values {
				if v.Kind != goFactAssign {
					kept = append(kept, v)
				}
			}
			frag.GoValues[file] = kept
		}
		return assets, frag
	}
	lines := func(found []*Finding, id string) []int {
		var out []int
		for _, f := range found {
			if f.RuleID == id && f.File != "src/reach.go" && f.File != "src/sibling.go" {
				out = append(out, f.Line)
			}
		}
		slices.Sort(out)
		return out
	}
	assets, frag := old(goProducerDir)
	found, _ := assets.mustMatch(t, frag)
	if got := lines(found, "single"); !slices.Equal(got, []int{28}) {
		t.Errorf("single: %v, want [28] (31 is a call reassignment)", got)
	}
	for _, f := range found {
		if f.RuleID == "mode" && f.File == "src/sibling.go" && slices.Contains([]int{16, 27, 48, 60, 68}, f.Line) {
			t.Errorf("mode: sibling.go:%d reported without blocks", f.Line)
		}
	}
	assets, frag = old(goObjectDir)
	found, _ = assets.mustMatch(t, frag)
	if got := lines(found, "object"); !slices.Equal(got, []int{7, 12, 16, 20, 41}) {
		t.Errorf("object: %v, want [7 12 16 20 41] (no copy or field)", got)
	}
}
