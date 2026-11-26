// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/engine"
)

const pythonKeywordSource = `import hashlib


def digest(data, alg: str, *, rounds: int = 1):
    return hashlib.new(alg, data)


def run(password, salt, opts):
    hashlib.pbkdf2_hmac("sha256", password, salt, iterations=100000, dklen = 32)
    hashlib.new(password == salt, opts)
    hashlib.new("md5", **opts)
    hashlib.scrypt(password, salt=(
        salt
    ), n=2)
    return digest(alg="sha1", data=salt, rounds=hashlib.SHA256)
`

// A Python keyword argument is exported with its keyword and the value alone,
// at its place in the call: its value resolves as a positional one does, and
// its type is the type of the callee parameter it names, never the type of
// the parameter at its place. Comparisons and splats are positional text.
func TestExportGraphFragment_PythonKeywordArguments(t *testing.T) {
	t.Parallel()
	export := exportPythonSource(t, pythonKeywordSource)
	type arg struct {
		keyword, expr, resolved, typ string
	}
	wants := map[string][]arg{
		"hashlib.pbkdf2_hmac": {
			{"", `"sha256"`, `"sha256"`, ""},
			{"", "password", "", ""},
			{"", "salt", "", ""},
			{"iterations", "100000", "100000", ""},
			{"dklen", "32", "32", ""},
		},
		"app.mod.digest": {
			{"alg", `"sha1"`, `"sha1"`, "str"}, {"data", "salt", "", ""}, {"rounds", "hashlib.SHA256", "hashlib.SHA256", "int"},
		},
	}
	byLine := map[int][]arg{
		10: {{"", "password == salt", "", ""}, {"", "opts", "", ""}},
		11: {{"", `"md5"`, `"md5"`, ""}, {"", "**opts", "", ""}},
	}
	wants["hashlib.scrypt"] = []arg{{"", "password", "", ""}, {"salt", "(\n        salt\n    )", "", ""}, {"n", "2", "2", ""}}
	check := func(name string, cs *graphfrag.GraphFragmentCallSite, want []arg) {
		t.Helper()
		if cs == nil {
			t.Errorf("%s: no call site", name)
			return
		}
		var got []arg
		for i, p := range cs.Parameters {
			if p.ParameterIndex != i {
				t.Errorf("%s: parameter %d has index %d", name, i, p.ParameterIndex)
			}
			if p.ArgumentExpression == "" {
				continue // a declared parameter the call does not pass
			}
			got = append(got, arg{p.Keyword, p.ArgumentExpression, p.ResolvedValue, p.Type})
		}
		if len(got) != len(want) {
			t.Errorf("%s: arguments %+v, want %+v", name, got, want)
			return
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s argument %d = %+v, want %+v", name, i, got[i], want[i])
			}
		}
	}
	seen := 0
	for _, e := range export.ExternalCalls {
		if want, ok := wants[e.TargetKey]; ok {
			check(e.TargetKey, e.EntryCall, want)
			seen++
		}
		if want, ok := byLine[e.Line]; ok && e.TargetKey == "hashlib.new" {
			check(e.Raw, e.EntryCall, want)
			seen++
		}
	}
	for _, e := range export.InternalEdges {
		if want, ok := wants[e.CalleeKey]; ok && e.CallerKey == "app.mod.run" {
			check(e.CalleeKey, e.EntryCall, want)
			seen++
		}
	}
	if seen != 5 {
		t.Errorf("checked %d calls, want 5", seen)
	}
}

// A keyword argument read back from a fragment has the text the parser gave
// it, so re-detection over a stored fragment sees the call the scan saw.
func TestFragmentCallArguments_PythonKeywordText(t *testing.T) {
	t.Parallel()
	entry := &graphfrag.GraphFragmentCallSite{Parameters: []graphfrag.GraphFragmentParameter{
		{ParameterIndex: 0, ArgumentExpression: "data"},
		{ParameterIndex: 1, Keyword: "alg", ArgumentExpression: `"md5"`},
	}}
	args, _ := fragmentCallArguments("", entry, make([]string, 2))
	if len(args) != 2 || args[0] != "data" || args[1] != `alg="md5"` {
		t.Fatalf("arguments %q, want [data alg=\"md5\"]", args)
	}
}

// Code that finds a keyword argument by name in exported parameters reads
// the call's text, keyword included.
func TestParameterArgumentSlot_KeywordParameter(t *testing.T) {
	t.Parallel()
	params := []callGraphParameter{
		{ParameterIndex: 0, ArgumentExpression: "data"},
		{ParameterIndex: 1, Keyword: "alg", ArgumentExpression: `"md5"`},
	}
	if slot, ok := parameterArgumentSlot(params, 1, "alg"); !ok || slot != 1 {
		t.Errorf("slot of alg = %d, %v; want 1, true", slot, ok)
	}
	if _, ok := parameterArgumentSlot(params, 1, ""); ok {
		t.Error("a keyword argument was read as the positional argument at its place")
	}
	if got := params[1].argumentText(); got != `alg="md5"` {
		t.Errorf("argumentText = %q", got)
	}
	if got := params[0].argumentText(); got != "data" {
		t.Errorf("argumentText = %q", got)
	}
}

// The keyword's parameter type comes from the callee's declaration by name.
func TestPythonKeywordParameterType(t *testing.T) {
	t.Parallel()
	callee := &callgraph.FunctionDecl{Parameters: []callgraph.FunctionParameter{{Name: "data", Type: "bytes"}, {Name: "alg", Type: " str "}}}
	if got := pythonKeywordParameterType(callee, "alg"); got != "str" {
		t.Errorf("type of alg = %q, want str", got)
	}
	if got := pythonKeywordParameterType(callee, "nope"); got != "" {
		t.Errorf("type of an undeclared keyword = %q", got)
	}
	if got := pythonKeywordParameterType(nil, "alg"); got != "" {
		t.Errorf("type without a callee = %q", got)
	}
}

// Key-length resolution reads a keyword argument by its keyword as the
// export now writes it (keyword apart from the value): `dklen=32` is the
// derived key's length, and `count=1000` at the length's position is not.
func TestResolvedKeyLength_PythonKeywordParameters(t *testing.T) {
	t.Parallel()
	ctx := newExportBuildContext(&engine.DepScanResult{CallGraph: &callgraph.CallGraph{}, Ecosystem: "python"})

	call, parameters := pythonKDFCall("dklen=32", "32")
	parameters[4] = callGraphParameter{ParameterIndex: 4, Keyword: "dklen", ArgumentExpression: "32", ResolvedValue: "32"}
	got := resolvedKeyLengthFromContract(ctx, contractMatchesForCall(ctx, call, len(call.Arguments)), call, parameters, nil)
	if got == nil || got.Bits == nil || *got.Bits != 256 {
		t.Fatalf("dklen keyword: resolved key length = %#v, want 256 bits", got)
	}

	pbkdf2 := &callgraph.FunctionCall{
		Callee:    callgraph.FunctionID{Package: "Crypto.Protocol.KDF", Type: "PBKDF2", Name: constructorMethodName},
		FilePath:  "derive.py",
		Line:      9,
		Arguments: []string{"password", "salt", "count=1000"},
	}
	counted := []callGraphParameter{
		{ParameterIndex: 0, ArgumentExpression: "password"},
		{ParameterIndex: 1, ArgumentExpression: "salt"},
		{ParameterIndex: 2, Keyword: "count", ArgumentExpression: "1000", ResolvedValue: "1000"},
	}
	if got := resolvedKeyLengthFromContract(ctx, contractMatchesForCall(ctx, pbkdf2, len(pbkdf2.Arguments)), pbkdf2, counted, nil); got != nil {
		t.Fatalf("count keyword at the length's position: resolved key length = %#v, want nil", got)
	}
}

// The arguments a call's own conditions read carry each keyword, so
// `param[2|digestmod]` finds `digestmod="sha256"` wherever it is written.
func TestConditionArguments_Keywords(t *testing.T) {
	t.Parallel()
	args := conditionArguments([]callGraphParameter{
		{ParameterIndex: 0, ArgumentExpression: "key", VariableName: "key"},
		{ParameterIndex: 1, Keyword: "digestmod", ArgumentExpression: `"sha256"`, ResolvedValue: `"sha256"`},
	})
	if args[0].Keyword != "" || args[0].Name != "key" || args[1].Keyword != "digestmod" || args[1].Value != `"sha256"` {
		t.Fatalf("condition arguments = %+v", args)
	}
}
