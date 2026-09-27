// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

func buildNodeGraph(t *testing.T, src string) *CallGraph {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := NewBuilderForEcosystem("node", NewNodeParser()).BuildFromDirectories([]PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

func nodeCalleesByLine(t *testing.T, graph *CallGraph, fnName string) map[int][]string {
	t.Helper()
	for _, fn := range graph.Functions {
		if fn.ID.Name != fnName {
			continue
		}
		out := map[int][]string{}
		for i := range fn.Calls {
			out[fn.Calls[i].Line] = append(out[fn.Calls[i].Line], fn.Calls[i].Callee.String())
		}
		return out
	}
	t.Fatalf("function %s not found", fnName)
	return nil
}

// A variable bound to a contracted result types the calls made on it, and a
// rebinding to something of unknown type ends that.
func TestNodeAssignedVarTypesReceiverCalls(t *testing.T) {
	t.Parallel()

	graph := buildNodeGraph(t, `const EC = require('elliptic').ec;
const hash = require('hash.js');

function run(msg, helper) {
  const ec = new EC('secp256k1');
  let key = ec.genKeyPair();
  key.sign(msg);
  key = helper();
  key.sign(msg);
  const h = hash.sha256();
  return h.update(msg).digest('hex');
}
`)
	got := nodeCalleesByLine(t, graph, "run")
	want := map[int][]string{
		5:  {"elliptic.(ec).<init>"},
		6:  {"elliptic.(ec).genKeyPair"},
		7:  {"elliptic.(KeyPair).sign"},
		8:  {"app.helper"},
		9:  {"app.sign"},
		10: {"hash.js.sha256"},
		// The chain is rooted at h, so it resolves only once h has a type.
		11: {"hash.js.(SHA256).digest", "hash.js.(SHA256).update"},
	}
	for line, callees := range want {
		if len(got[line]) != len(callees) {
			t.Errorf("line %d: callees %v, want %v", line, got[line], callees)
			continue
		}
		for i := range callees {
			if got[line][i] != callees[i] {
				t.Errorf("line %d: callees %v, want %v", line, got[line], callees)
				break
			}
		}
	}
}

// A chain rooted at a contracted factory resolves link by link through the
// contract return types, which is how hash.js is written.
func TestNodeFluentChainResolvesThroughContracts(t *testing.T) {
	t.Parallel()

	graph := buildNodeGraph(t, `const hash = require('hash.js');
function run(m) {
  return hash.sha256().update(m).digest('hex');
}
`)
	got := nodeCalleesByLine(t, graph, "run")[3]
	want := []string{"hash.js.(SHA256).digest", "hash.js.(SHA256).update", "hash.js.sha256"}
	if len(got) != len(want) {
		t.Fatalf("callees %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("callees %v, want %v", got, want)
		}
	}
}

// A variable the module binds types the calls every function makes on it,
// unless the function binds that name itself.
func TestNodeModuleVariableTypesFunctionReceivers(t *testing.T) {
	t.Parallel()

	graph := buildNodeGraph(t, `const EC = require('elliptic').ec;
const ec = new EC('secp256k1');

function run(msg) {
  const key = ec.genKeyPair();
  return key.sign(msg);
}

function shadow(ec) {
  return ec.genKeyPair();
}
`)
	for fn, want := range map[string]map[int][]string{
		"run":    {5: {"elliptic.(ec).genKeyPair"}, 6: {"elliptic.(KeyPair).sign"}},
		"shadow": {10: {"app.genKeyPair"}},
	} {
		got := nodeCalleesByLine(t, graph, fn)
		for line, callees := range want {
			if len(got[line]) != 1 || got[line][0] != callees[0] {
				t.Errorf("%s line %d: callees %v, want %v", fn, line, got[line], callees)
			}
		}
	}
}
