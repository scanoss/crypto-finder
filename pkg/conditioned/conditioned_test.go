// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package conditioned

import (
	"maps"
	"regexp"
	"testing"

	"github.com/scanoss/reach/graphfrag"
	"github.com/scanoss/reach/paramcondition"
)

func mustConditions(t *testing.T, raw string) []paramcondition.Condition {
	t.Helper()
	conditions, err := paramcondition.ParseAll(raw)
	if err != nil {
		t.Fatalf("ParseAll(%q): %v", raw, err)
	}
	return conditions
}

func TestMatchConditions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		conditions string
		args       []Argument
		ok         bool
		value      string
	}{
		{"exact on a quoted literal", "param[0]==SHA256withECDSA", []Argument{{Value: `"SHA256withECDSA"`}}, true, "param[0]==SHA256withECDSA"},
		{"exact refutes another value", "param[0]==SHA256withECDSA", []Argument{{Value: `"SHA384withECDSA"`}}, false, ""},
		{"regex resolves to the value", "param[0]~=^PBKDF2", []Argument{{Value: `"PBKDF2with8BIT"`}}, true, "param[0]==PBKDF2with8BIT"},
		{"unresolved argument does not hold", "param[0]~=^PBKDF2", []Argument{{Value: ""}}, false, ""},
		{"missing argument does not hold", "param[1]==X", []Argument{{Value: "X"}}, false, ""},
		{"type condition reads the type", "param[0]:type~=Engine$", []Argument{{Type: "AESEngine"}}, true, "param[0]:type==AESEngine"},
		{"keyword selector reads the name", "param[alg]==sha256", []Argument{{Value: "'x'", Name: "other"}, {Value: "'sha256'", Name: "alg"}}, true, "param[alg]==sha256"},
		{"every condition must hold", "param[0]==A,param[1]==B", []Argument{{Value: `"A"`}, {Value: `"C"`}}, false, ""},
	}
	for _, tc := range tests {
		match, ok := MatchConditions(mustConditions(t, tc.conditions), tc.args, nil)
		if ok != tc.ok {
			t.Fatalf("%s: ok = %v, want %v", tc.name, ok, tc.ok)
		}
		if got := match.ConditionedValue(); got != tc.value {
			t.Errorf("%s: conditioned value = %q, want %q", tc.name, got, tc.value)
		}
	}
}

func TestMatchMetadata(t *testing.T) {
	t.Parallel()

	template := map[string]string{
		"algorithmName":   "ECDSA-$hash",
		"algorithmFamily": "ECDSA",
		"curve":           "$curve",
		"operation":       "sign",
	}
	before := maps.Clone(template)
	match, ok := MatchConditions(mustConditions(t, "param[0]~=^(SHA\\d+)withECDSA$"), []Argument{{Value: `"SHA384withECDSA"`}}, []string{"hash"})
	if !ok {
		t.Fatal("condition did not hold")
	}
	got := match.Metadata(template, nil)
	want := map[string]string{
		"algorithmName":      "ECDSA-SHA384",
		"algorithmFamily":    "ECDSA",
		"operation":          "sign",
		"cryptoFunction":     "sign",
		"parameterCondition": "param[0]==SHA384withECDSA",
	}
	if !maps.Equal(got, want) {
		t.Errorf("metadata = %v, want %v", got, want)
	}
	if !maps.Equal(template, before) {
		t.Errorf("template modified: %v", template)
	}
}

func TestMatchMetadataBindsRuleGroupsBeforePositions(t *testing.T) {
	t.Parallel()

	binder := regexp.MustCompile(`^(?:"?(?P<family>[A-Z]+)-(?P<bits>\d+))`)
	match, ok := MatchConditions(mustConditions(t, "param[0]~=^([A-Z]+)-(\\d+)$"), []Argument{{Value: `"SHA-256"`}}, []string{"bits", "family"})
	if !ok {
		t.Fatal("condition did not hold")
	}
	got := match.Metadata(map[string]string{"algorithmName": "$family$bits"}, []*regexp.Regexp{binder})
	if got["algorithmName"] != "SHA256" {
		t.Errorf("algorithmName = %q, want SHA256 (the rule's named groups win over position)", got["algorithmName"])
	}
}

func TestPlaceholderFiller(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		captures map[string]string
		in, want string
	}{
		{"mode never eats model", map[string]string{"mode": "CBC", "model": "M1"}, "$mode-$model", "CBC-M1"},
		{"only the shorter name is bound", map[string]string{"mode": "CBC"}, "$mode/$model", "CBC/CBCl"},
		{"an inserted value is not substituted again", map[string]string{"a": "$b", "b": "X"}, "$a $b", "$b X"},
		{"no captures", nil, "$a", "$a"},
	}
	for _, tc := range tests {
		if got := placeholderFiller(tc.captures)(tc.in); got != tc.want {
			t.Errorf("%s: fill(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

func TestNormalizeValue(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]string{
		`"SHA-1"`:      "SHA-1",
		`'sha1'`:       "sha1",
		"`sha1`":       "sha1",
		"`sha${bits}`": "`sha${bits}`",
		`'mixed"`:      `'mixed"`,
		`sha1`:         "sha1",
	} {
		if got := NormalizeValue(in); got != want {
			t.Errorf("NormalizeValue(%q) = %q, want %q", in, got, want)
		}
	}
}

// A selector's index reads the positional argument at that place, and
// `param[i|name]` falls back to the Python keyword argument passed as name; a
// keyword argument is never read by its place in the call. Arguments without
// keywords (Java, Go, ...) select as before: by index, else by the variable
// name.
func TestArgumentIndexKeywords(t *testing.T) {
	t.Parallel()
	positional := []Argument{{Value: "a"}, {Value: "b", Name: "alg"}}
	keywords := []Argument{{Value: "data"}, {Value: "x", Keyword: "dklen", Name: "alg"}, {Value: "s", Keyword: "alg"}}
	tests := []struct {
		name     string
		selector string
		args     []Argument
		want     int
	}{
		{"index reads a positional argument", "param[1]==b", positional, 1},
		{"index out of range", "param[2]==b", positional, 2},
		{"index with a name and no keyword arguments", "param[1|alg]==b", positional, 1},
		{"index out of range with a name and no keywords", "param[3|alg]==b", positional, 3},
		{"name reads the variable without keywords", "param[alg]==b", positional, 1},
		{"index never reads a keyword argument", "param[1]==x", keywords, -1},
		{"index falls back to the keyword", "param[1|alg]==s", keywords, 2},
		{"index past the call falls back to the keyword", "param[5|alg]==s", keywords, 2},
		{"keyword wins over a variable name", "param[alg]==s", keywords, 2},
		{"index on a keyword slot whose name is absent", "param[1|nope]==x", keywords, -1},
		{"name with no such argument", "param[nope]==x", keywords, -1},
	}
	for _, tc := range tests {
		got := ArgumentIndex(mustConditions(t, tc.selector)[0], tc.args)
		if got != tc.want {
			t.Errorf("%s: ArgumentIndex(%s) = %d, want %d", tc.name, tc.selector, got, tc.want)
		}
	}
}

// The arguments the expansion reads carry the keyword of each parameter.
func TestArgumentsCarryKeywords(t *testing.T) {
	t.Parallel()
	args := arguments([]graphfrag.Parameter{{ResolvedValue: `"a"`, VariableName: "v"}, {ResolvedValue: `"s"`, Keyword: "alg"}})
	if args[0].Keyword != "" || args[0].Name != "v" || args[1].Keyword != "alg" || args[1].Value != `"s"` {
		t.Fatalf("arguments = %+v", args)
	}
}
