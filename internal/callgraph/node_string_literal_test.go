// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

func TestCanonicalNodeStringLiteral(t *testing.T) {
	t.Parallel()
	tests := []struct {
		source string
		want   string
		ok     bool
	}{
		{`"NN"`, `"NN"`, true},
		{`'NN'`, `"NN"`, true},
		{"`NN`", `"NN"`, true},
		{`''`, `""`, true},
		{`'it\'s'`, `"it's"`, true},
		{`'say "hi"'`, `"say \"hi\""`, true},
		{"`a \\` b`", "\"a ` b\"", true},
		{"`cost \\${x}`", `"cost ${x}"`, true},
		{"`cost $x`", `"cost $x"`, true},
		{`'N\u004E'`, `"NN"`, true},
		{`'\u{4E}N'`, `"NN"`, true},
		{`'\x4E\x4E'`, `"NN"`, true},
		{`'\uD83D\uDE00'`, `"` + "\U0001F600" + `"`, true},
		{`'a\tb\n'`, `"a\tb\n"`, true},
		{`'\0'`, `"\x00"`, true},
		{`'\d'`, `"d"`, true},
		{"'line\\\ncontinued'", `"linecontinued"`, true},
		{"`N${suffix}`", "", false},
		{`'NN' + 'KK'`, "", false},
		{`"NN'`, "", false},
		{`NN`, "", false},
		{`'`, "", false},
		{`'\1'`, "", false},
		{`'\x4'`, "", false},
		{`'\uD83D'`, "", false},
		{`'\u{110000}'`, "", false},
		{`'trailing\'`, "", false},
	}
	for _, tt := range tests {
		got, ok := canonicalNodeStringLiteral(tt.source)
		if got != tt.want || ok != tt.ok {
			t.Errorf("canonicalNodeStringLiteral(%s) = %q, %v; want %q, %v", tt.source, got, ok, tt.want, tt.ok)
		}
	}
}
