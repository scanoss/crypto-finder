// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"maps"
	"os"
	"path/filepath"
	"testing"
)

func writeShapeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// An export built by a factory in another module has the members that factory
// returns, through spreads, Object.freeze and local bindings.
func TestNodeShapesFollowFactoriesAcrossModules(t *testing.T) {
	t.Parallel()
	root := writeShapeFiles(t, map[string]string{
		"bls12.js": "import { bls } from './abstract/bls.js';\nexport const bls12 = bls(1);\n",
		"abstract/bls.js": "function hashers(f) {\n  const base = { fields: f };\n  return Object.freeze({ ...base, G1: 1, G2: 2 });\n}\n" +
			"export function bls(f) {\n  const base = hashers(f);\n  const longSignatures = { sign() {}, verify() {} };\n" +
			"  return Object.freeze({ ...base, longSignatures, shortSignatures: {} });\n}\n",
	})
	s := NewNodeShapes()
	defer s.Close()

	keys, ok := s.ExportMembers(filepath.Join(root, "bls12.js"), "bls12")
	want := map[string]bool{"fields": true, "G1": true, "G2": true, "longSignatures": true, "shortSignatures": true}
	if !ok || !maps.Equal(keys, want) {
		t.Errorf("members = %v (known %v), want %v", keys, ok, want)
	}
}

// A CommonJS export of a factory result and an object literal are both known.
func TestNodeShapesReadCommonJSExports(t *testing.T) {
	t.Parallel()
	root := writeShapeFiles(t, map[string]string{
		"index.js": "exports.ec = make();\nfunction make() { return { sign() {} }; }\nmodule.exports.other = { verify: v };\n",
	})
	s := NewNodeShapes()
	defer s.Close()

	if keys, ok := s.ExportMembers(filepath.Join(root, "index.js"), "ec"); !ok || !maps.Equal(keys, map[string]bool{"sign": true}) {
		t.Errorf("ec = %v (known %v), want {sign}", keys, ok)
	}
	if keys, ok := s.ExportMembers(filepath.Join(root, "index.js"), "other"); !ok || !maps.Equal(keys, map[string]bool{"verify": true}) {
		t.Errorf("other = %v (known %v), want {verify}", keys, ok)
	}
}

// What only exists at run time is unknown, not empty: a subclass, a value from
// another package, an object spread from a parameter.
func TestNodeShapesLeaveRunTimeValuesUnknown(t *testing.T) {
	t.Parallel()
	root := writeShapeFiles(t, map[string]string{
		"index.js": "import { make, Base } from 'other-package';\nexport class Key extends Base {}\nexport const ext = make();\n" +
			"export const spread = build({});\nfunction build(o) { return { ...o, a: 1 }; }\n" +
			"export function eddsa() {}\nfunction legacy(eddsa) { return Object.assign({}, eddsa, { x: 1 }); }\nexport const shadowed = legacy({});\n",
	})
	s := NewNodeShapes()
	defer s.Close()

	for _, name := range []string{"Key", "ext", "spread", "shadowed"} {
		if keys, ok := s.ExportMembers(filepath.Join(root, "index.js"), name); ok {
			t.Errorf("%s = %v, want unknown", name, keys)
		}
	}
}

// Comments and strings are not code names.
func TestNodeCodeNamesSkipCommentsAndStrings(t *testing.T) {
	t.Parallel()
	root := writeShapeFiles(t, map[string]string{"index.js": "// pairing-friendly curve\nconst s = 'verify';\nexports.bn = curve.sign();\n"})
	names, err := NodeCodeNames(filepath.Join(root, "index.js"))
	if err != nil {
		t.Fatal(err)
	}
	if names["pairing"] || names["verify"] || !names["sign"] || !names["bn"] {
		t.Errorf("names = %v", names)
	}
}

// A class or constructor function offers its methods, statics and prototype
// assignments; a constant is not a constructor.
func TestNodeShapesReadClassesAndConstructors(t *testing.T) {
	t.Parallel()
	root := writeShapeFiles(t, map[string]string{
		"index.js": "export class Key { static from() {} sign() {} }\nfunction EC() {}\nEC.prototype.genKeyPair = function() {};\n" +
			"EC.curves = {};\nexport { EC };\nexport const VERSION = '1.0';\n",
	})
	s := NewNodeShapes()
	defer s.Close()
	file := filepath.Join(root, "index.js")

	if keys, ok := s.ExportMembers(file, "Key"); !ok || !maps.Equal(keys, map[string]bool{"from": true, "sign": true}) {
		t.Errorf("Key = %v (known %v)", keys, ok)
	}
	if keys, ok := s.ExportMembers(file, "EC"); !ok || !maps.Equal(keys, map[string]bool{"genKeyPair": true, "curves": true}) {
		t.Errorf("EC = %v (known %v)", keys, ok)
	}
	for name, want := range map[string]bool{"Key": true, "EC": true, "VERSION": false} {
		if callable, known := s.ExportIsCallable(file, name); !known || callable != want {
			t.Errorf("%s callable = %v (known %v), want %v", name, callable, known, want)
		}
	}
}

// An object filled in after its literal (`var hotp = {}; hotp.gen = ..`) has
// those members, and each is defined where it is assigned.
func TestNodeShapesReadObjectsFilledByAssignment(t *testing.T) {
	t.Parallel()
	root := writeShapeFiles(t, map[string]string{
		"index.js": "var hotp = {};\nhotp.gen = function(key) {};\nhotp.verify = function(token, key) {};\nmodule.exports.hotp = hotp;\n",
	})
	s := NewNodeShapes()
	defer s.Close()
	file := filepath.Join(root, "index.js")

	if keys, ok := s.ExportMembers(file, "hotp"); !ok || !maps.Equal(keys, map[string]bool{"gen": true, "verify": true}) {
		t.Errorf("hotp = %v (known %v), want {gen, verify}", keys, ok)
	}
	if _, line, ok := s.Definition(file, "hotp", []string{"verify"}); !ok || line != 3 {
		t.Errorf("hotp.verify defined at line %d (found %v), want 3", line, ok)
	}
}

// tsc forward-declares exports in a chain ending in `void 0`; the definition is
// the later assignment, followed through an alias of another export.
func TestNodeShapesSkipChainedForwardDeclarations(t *testing.T) {
	t.Parallel()
	root := writeShapeFiles(t, map[string]string{
		"account.js": "exports.publicToAddress = exports.pubToAddress = exports.Account = void 0;\n" +
			"const pubToAddress = function (pubKey) {};\nexports.pubToAddress = pubToAddress;\n" +
			"exports.publicToAddress = exports.pubToAddress;\n",
	})
	s := NewNodeShapes()
	defer s.Close()
	if _, line, ok := s.Definition(filepath.Join(root, "account.js"), "publicToAddress", nil); !ok || line != 2 {
		t.Errorf("publicToAddress defined at line %d (found %v), want 2", line, ok)
	}
	exports, err := NodeModuleExports(filepath.Join(root, "account.js"))
	if err != nil {
		t.Fatal(err)
	}
	if exports.Lines["publicToAddress"] != 4 || exports.Lines["pubToAddress"] != 3 {
		t.Errorf("export lines = %v, want the assignments, not the forward declaration", exports.Lines)
	}
}
