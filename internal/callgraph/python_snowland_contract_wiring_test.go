// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

func pythonCalleeKey(id FunctionID) string {
	if id.Type != "" {
		return id.Package + "." + id.Type + "." + id.Name
	}
	return id.Package + "." + id.Name
}

// Sm4 and SM4BlockCyphers own set_key; crypt_* is inherited from BlockCyphers,
// whose contracts the Python export cannot reach from a concrete receiver. The
// second half pins that gap: when an inherited fallback lands, flip it.
func TestSnowlandInheritedCryptIsAnExportGap(t *testing.T) {
	kb := pythonEmbeddedKB(t)
	g := pythonPropagationGraph(t, `from pysmx.SM4 import Sm4, SM4BlockCyphers
from pysmx.block_cyphers import ENCRYPT

def own(key, iv, data):
    s = Sm4()
    s.set_key(key, ENCRYPT)
    return s.crypt_cbc(iv, data)

def adapter(key, iv, data):
    b = SM4BlockCyphers(key, iv, ENCRYPT)
    b.sm4_set_key(key, ENCRYPT)
    return b.crypt_cbc(iv, data)
`, kb)

	for _, tc := range []struct{ fn, method, key string }{
		{"own", "set_key", "pysmx.SM4._SM4.Sm4.set_key"},
		{"adapter", "sm4_set_key", "pysmx.SM4._SM4.SM4BlockCyphers.sm4_set_key"},
	} {
		call := findPythonCallByMethod(g.Functions[FunctionID{Package: "mypkg.src", Name: tc.fn}.String()], tc.method)
		if call == nil || pythonCalleeKey(call.Callee) != tc.key || len(kb.ContractsFor(tc.key, 2)) != 1 {
			t.Errorf("%s: %s did not resolve to contract %q (call %+v)", tc.fn, tc.method, tc.key, call)
		}
	}

	if len(kb.ContractsFor("pysmx.block_cyphers._block_cyphers.BlockCyphers.crypt_cbc", 2)) != 1 {
		t.Fatal("BlockCyphers.crypt_cbc contract missing")
	}
	for _, tc := range []struct{ fn, key string }{
		{"own", "pysmx.SM4._SM4.Sm4.crypt_cbc"},
		{"adapter", "pysmx.SM4._SM4.SM4BlockCyphers.crypt_cbc"},
	} {
		call := findPythonCallByMethod(g.Functions[FunctionID{Package: "mypkg.src", Name: tc.fn}.String()], "crypt_cbc")
		if call == nil || pythonCalleeKey(call.Callee) != tc.key {
			t.Fatalf("%s: crypt_cbc callee = %+v, want %q", tc.fn, call, tc.key)
		}
		if got := kb.ContractsForTolerant(tc.key, 2); len(got) != 0 {
			t.Errorf("%s now has a contract; the inherited gap is closed, update this test and snowland-smx.yaml", tc.key)
		}
	}
}
