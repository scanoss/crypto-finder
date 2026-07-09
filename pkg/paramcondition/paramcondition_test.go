// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package paramcondition

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func intPtr(i int) *int       { return &i }
func strPtr(s string) *string { return &s }

func TestParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want Condition
	}{
		{
			name: "positional exact value match",
			raw:  "param[0]==true",
			want: Condition{
				Raw:      "param[0]==true",
				Selector: Selector{Index: intPtr(0)},
				Operator: OpExact,
				Match:    MatchValue,
				Value:    "true",
			},
		},
		{
			name: "keyword exact value match",
			raw:  "param[name]==md5",
			want: Condition{
				Raw:      "param[name]==md5",
				Selector: Selector{Name: strPtr("name")},
				Operator: OpExact,
				Match:    MatchValue,
				Value:    "md5",
			},
		},
		{
			name: "dual-binding regex value match",
			raw:  "param[0|forEncryption]~=^enc",
			want: Condition{
				Raw:      "param[0|forEncryption]~=^enc",
				Selector: Selector{Index: intPtr(0), Name: strPtr("forEncryption")},
				Operator: OpRegex,
				Match:    MatchValue,
				Value:    "^enc",
			},
		},
		{
			name: "positional dotted type exact match",
			raw:  "param[1]:type==javax.crypto.SecretKey",
			want: Condition{
				Raw:      "param[1]:type==javax.crypto.SecretKey",
				Selector: Selector{Index: intPtr(1)},
				Operator: OpExact,
				Match:    MatchType,
				Value:    "javax.crypto.SecretKey",
			},
		},
		{
			name: "positional type regex match",
			raw:  `param[0]:type~=^java\.security\..*Key$`,
			want: Condition{
				Raw:      `param[0]:type~=^java\.security\..*Key$`,
				Selector: Selector{Index: intPtr(0)},
				Operator: OpRegex,
				Match:    MatchType,
				Value:    `^java\.security\..*Key$`,
			},
		},
		{
			name: "value containing ] is preserved verbatim",
			raw:  "param[0]~=a]b",
			want: Condition{
				Raw:      "param[0]~=a]b",
				Selector: Selector{Index: intPtr(0)},
				Operator: OpRegex,
				Match:    MatchValue,
				Value:    "a]b",
			},
		},
		{
			name: "value containing == is preserved verbatim",
			raw:  "param[0]==a==b",
			want: Condition{
				Raw:      "param[0]==a==b",
				Selector: Selector{Index: intPtr(0)},
				Operator: OpExact,
				Match:    MatchValue,
				Value:    "a==b",
			},
		},
		{
			name: "dotted FQN value parses unaffected by internal dots",
			raw:  "param[1]:type==org.bouncycastle.crypto.params.KeyParameter",
			want: Condition{
				Raw:      "param[1]:type==org.bouncycastle.crypto.params.KeyParameter",
				Selector: Selector{Index: intPtr(1)},
				Operator: OpExact,
				Match:    MatchType,
				Value:    "org.bouncycastle.crypto.params.KeyParameter",
			},
		},
		{
			name: "enum value parses unaffected by internal dot",
			raw:  "param[1]==CryptoServicePurpose.AGREEMENT",
			want: Condition{
				Raw:      "param[1]==CryptoServicePurpose.AGREEMENT",
				Selector: Selector{Index: intPtr(1)},
				Operator: OpExact,
				Match:    MatchValue,
				Value:    "CryptoServicePurpose.AGREEMENT",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Parse(tt.raw)
			if err != nil {
				t.Fatalf("Parse(%q) returned unexpected error: %v", tt.raw, err)
			}
			if diff := diffCondition(got, tt.want); diff != "" {
				t.Errorf("Parse(%q) mismatch: %s", tt.raw, diff)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
	}{
		{name: "missing param[ prefix", raw: "foo==true"},
		{name: "missing closing bracket", raw: "param[0==true"},
		{name: "empty value", raw: "param[0]=="},
		{name: "unknown operator", raw: "param[0]!=true"},
		{name: "empty selector", raw: "param[]==true"},
		{name: "negative index in dual-binding selector", raw: "param[-1|forEncryption]==true"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := Parse(tt.raw)
			if err == nil {
				t.Fatalf("Parse(%q) = nil error, want error", tt.raw)
			}
			var parseErr *ParseError
			ok := false
			if pe, isPE := err.(*ParseError); isPE {
				parseErr = pe
				ok = true
			}
			if !ok {
				t.Fatalf("Parse(%q) error = %T, want *ParseError", tt.raw, err)
			}
			if !strings.Contains(parseErr.Error(), tt.raw) {
				t.Errorf("Parse(%q) error %q does not contain the raw input", tt.raw, parseErr.Error())
			}
		})
	}
}

func TestParseAll(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want []Condition
	}{
		{
			name: "two comma-joined predicates",
			raw:  "param[0]==true,param[1]==256",
			want: []Condition{
				{Raw: "param[0]==true", Selector: Selector{Index: intPtr(0)}, Operator: OpExact, Match: MatchValue, Value: "true"},
				{Raw: "param[1]==256", Selector: Selector{Index: intPtr(1)}, Operator: OpExact, Match: MatchValue, Value: "256"},
			},
		},
		{
			name: "regex value containing a comma is not split",
			raw:  "param[0]~=^(a,b)$",
			want: []Condition{
				{Raw: "param[0]~=^(a,b)$", Selector: Selector{Index: intPtr(0)}, Operator: OpRegex, Match: MatchValue, Value: "^(a,b)$"},
			},
		},
		{
			name: "regex value containing ] is not truncated",
			raw:  `param[0]~=^\[foo\]bar$`,
			want: []Condition{
				{Raw: `param[0]~=^\[foo\]bar$`, Selector: Selector{Index: intPtr(0)}, Operator: OpRegex, Match: MatchValue, Value: `^\[foo\]bar$`},
			},
		},
		{
			name: "whitespace around comma-separated predicates is trimmed",
			raw:  " param[0]==true , param[1]==256 ",
			want: []Condition{
				{Raw: "param[0]==true", Selector: Selector{Index: intPtr(0)}, Operator: OpExact, Match: MatchValue, Value: "true"},
				{Raw: "param[1]==256", Selector: Selector{Index: intPtr(1)}, Operator: OpExact, Match: MatchValue, Value: "256"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseAll(tt.raw)
			if err != nil {
				t.Fatalf("ParseAll(%q) returned unexpected error: %v", tt.raw, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ParseAll(%q) returned %d conditions, want %d: %+v", tt.raw, len(got), len(tt.want), got)
			}
			for i := range got {
				if diff := diffCondition(got[i], tt.want[i]); diff != "" {
					t.Errorf("ParseAll(%q)[%d] mismatch: %s", tt.raw, i, diff)
				}
			}
		})
	}
}

func TestSelectorJSONNullRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("positional selector renders name as null", func(t *testing.T) {
		t.Parallel()

		cond, err := Parse("param[0]==true")
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		b, err := json.Marshal(cond.Selector)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		want := `{"index":0,"name":null}`
		if string(b) != want {
			t.Errorf("Marshal(Selector) = %s, want %s", b, want)
		}
	})

	t.Run("keyword selector renders index as null", func(t *testing.T) {
		t.Parallel()

		cond, err := Parse("param[name]==md5")
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		b, err := json.Marshal(cond.Selector)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		want := `{"index":null,"name":"name"}`
		if string(b) != want {
			t.Errorf("Marshal(Selector) = %s, want %s", b, want)
		}
	})
}

// diffCondition returns a human-readable diff string, or "" when equal.
func diffCondition(got, want Condition) string {
	var mismatches []string
	if got.Raw != want.Raw {
		mismatches = append(mismatches, fmt.Sprintf("Raw = %q, want %q", got.Raw, want.Raw))
	}
	if got.Operator != want.Operator {
		mismatches = append(mismatches, fmt.Sprintf("Operator = %q, want %q", got.Operator, want.Operator))
	}
	if got.Match != want.Match {
		mismatches = append(mismatches, fmt.Sprintf("Match = %q, want %q", got.Match, want.Match))
	}
	if got.Value != want.Value {
		mismatches = append(mismatches, fmt.Sprintf("Value = %q, want %q", got.Value, want.Value))
	}
	if diff := diffIntPtr(got.Selector.Index, want.Selector.Index); diff != "" {
		mismatches = append(mismatches, "Selector.Index "+diff)
	}
	if diff := diffStrPtr(got.Selector.Name, want.Selector.Name); diff != "" {
		mismatches = append(mismatches, "Selector.Name "+diff)
	}
	return strings.Join(mismatches, "; ")
}

func diffIntPtr(got, want *int) string {
	switch {
	case got == nil && want == nil:
		return ""
	case got == nil:
		return fmt.Sprintf("= nil, want %d", *want)
	case want == nil:
		return fmt.Sprintf("= %d, want nil", *got)
	case *got != *want:
		return fmt.Sprintf("= %d, want %d", *got, *want)
	default:
		return ""
	}
}

func diffStrPtr(got, want *string) string {
	switch {
	case got == nil && want == nil:
		return ""
	case got == nil:
		return fmt.Sprintf("= nil, want %q", *want)
	case want == nil:
		return fmt.Sprintf("= %q, want nil", *got)
	case *got != *want:
		return fmt.Sprintf("= %q, want %q", *got, *want)
	default:
		return ""
	}
}
