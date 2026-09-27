// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func parseNodeSource(t *testing.T, src string) *FileAnalysis {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lib.js"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewNodeParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	return analyses[0]
}

func nodeCallNames(fn *FunctionDecl) []string {
	names := make([]string, 0, len(fn.Calls))
	for i := range fn.Calls {
		names = append(names, fn.Calls[i].Callee.Name)
	}
	sort.Strings(names)
	return names
}

// A CommonJS module declares its functions by assignment, and the calls in an
// anonymous callback belong to the function that runs it.
func TestNodeParser_AssignedFunctionsAndCallbacks(t *testing.T) {
	t.Parallel()

	analysis := parseNodeSource(t, `var crypto = require('crypto');

var hash = exports.hash = function (data) {
  return crypto.createHash('sha256').update(data).digest('hex');
};

module.exports.sign = function (data, key) {
  return new Promise(function (resolve) {
    var signer = crypto.createSign('SHA256');
    signer.update(data);
    resolve(signer.sign(key));
  });
};

Hasher.prototype.run = (data) => [data].map((d) => crypto.randomBytes(d));

function Hasher() {}
`)
	byID := map[string]*FunctionDecl{}
	for i := range analysis.Functions {
		byID[analysis.Functions[i].ID.String()] = &analysis.Functions[i]
	}
	for id, want := range map[string][]string{
		"app/lib.hash":         {"createHash", "digest", "update"},
		"app/lib.sign":         {"createSign", "resolve", "sign", "update"},
		"app/lib.(Hasher).run": {"map", "randomBytes"},
	} {
		fn := byID[id]
		if fn == nil {
			t.Errorf("no declaration %s; got %v", id, nodeDeclIDs(byID))
			continue
		}
		if got := nodeCallNames(fn); !equalStrings(got, want) {
			t.Errorf("%s calls = %v, want %v", id, got, want)
		}
	}
	sign := byID["app/lib.sign"]
	if sign != nil {
		for i := range sign.Calls {
			if call := &sign.Calls[i]; call.Callee.Name == "update" && call.ReceiverVar != "signer" {
				t.Errorf("signer.update ReceiverVar = %q, want signer", call.ReceiverVar)
			}
		}
	}
	// Nothing runs at module scope but the require, so there is no <module>.
	if fn := byID["app/lib."+moduleInitMethodName]; fn != nil {
		t.Errorf("unexpected %s with calls %v", moduleInitMethodName, nodeCallNames(fn))
	}
}

// Module-scope calls belong to a synthetic <module> declaration, and a call on
// a variable the module declares records that variable as its receiver.
func TestNodeParser_ModuleScope(t *testing.T) {
	t.Parallel()

	analysis := parseNodeSource(t, `const EC = require('elliptic').ec;
const ec = new EC('secp256k1');

function sign(msg) {
  return ec.sign(msg);
}
`)
	var module, sign *FunctionDecl
	for i := range analysis.Functions {
		switch analysis.Functions[i].ID.Name {
		case moduleInitMethodName:
			module = &analysis.Functions[i]
		case "sign":
			sign = &analysis.Functions[i]
		}
	}
	if module == nil || len(module.Calls) != 1 || module.Calls[0].Callee.String() != "elliptic.(ec).<init>" || module.Calls[0].AssignedVar != "ec" {
		t.Fatalf("module declaration = %+v, want one elliptic.ec constructor call bound to ec", module)
	}
	if module.FunctionType != functionTypeModuleInit || module.StartLine != 1 {
		t.Errorf("module declaration type %q from line %d", module.FunctionType, module.StartLine)
	}
	if sign == nil || len(sign.Calls) != 1 || sign.Calls[0].ReceiverVar != "ec" {
		t.Fatalf("sign = %+v, want one call on the module's ec", sign)
	}
}

func nodeDeclIDs(m map[string]*FunctionDecl) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
