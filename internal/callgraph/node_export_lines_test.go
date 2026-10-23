// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestNodeExportLines(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, file, src string
		want            map[string]int
	}{
		{
			name: "ES exports of any kind",
			file: "ec.js",
			src: `import { make } from './utils.js';
export const ec = make('secp256k1'), other = 1;
export function sign() {}
export class Point {}
const hidden = 2;
export { hidden as visible };
`,
			want: map[string]int{"ec": 2, "other": 2, "sign": 3, "Point": 4, "visible": 6},
		},
		{
			name: "CommonJS as tsc emits it",
			file: "ec.cjs",
			src: `"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ec = exports.sign = void 0;
exports.ec = (0, utils_1.make)('secp256k1');
function sign() {}
exports.sign = sign;
Object.defineProperty(exports, "Point", { enumerable: true, get: function () { return p.Point; } });
`,
			want: map[string]int{"__esModule": 2, "ec": 4, "sign": 6, "Point": 7},
		},
		{
			name: "module.exports object",
			file: "index.js",
			src: `function sign() {}
module.exports = {
  sign,
  verify: sign,
  hash (plain, options) {},
};
`,
			want: map[string]int{"sign": 3, "verify": 4, "hash": 5},
		},
		{
			name: "TypeScript",
			file: "ec.ts",
			src: `export const ec: Curve = make('secp256k1');
export abstract class Base {}
`,
			want: map[string]int{"ec": 1, "Base": 2},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), tc.file)
			if err := os.WriteFile(path, []byte(tc.src), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := NodeExportLines(path)
			if err != nil {
				t.Fatal(err)
			}
			if !maps.Equal(got, tc.want) {
				t.Errorf("exports = %v, want %v", got, tc.want)
			}
		})
	}
}

// A CommonJS module re-exports a required module, exports a factory's result,
// or exports a factory whose returned object is the API.
func TestNodeModuleExportsReadsModuleExportsValues(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "index.js")
	src := "try { module.exports = require('./bindings') } catch (e) {}\n" +
		"module.exports = require('./lib')(addon)\n" +
		"module.exports = function (impl) {\n  return { sign () {}, verify: v }\n}\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := NodeModuleExports(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.StarFrom, []string{"./bindings"}) || !slices.Equal(got.FactoryFrom, []string{"./lib"}) ||
		!maps.Equal(got.Returned, map[string]int{"sign": 4, "verify": 4}) {
		t.Errorf("stars %v factories %v returned %v", got.StarFrom, got.FactoryFrom, got.Returned)
	}
}

// An exported factory named by its declaration returns a frozen API object.
func TestNodeModuleExportsReadsNamedFrozenFactory(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "handshake.js")
	src := "function createHandshake (deps) {\n  function keygen () {}\n  return Object.freeze({\n    keygen,\n    SKLEN: 32\n  })\n}\nmodule.exports = createHandshake\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := NodeModuleExports(path)
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(got.Returned, map[string]int{"keygen": 4, "SKLEN": 5}) {
		t.Errorf("returned = %v", got.Returned)
	}
}

func TestNodeModuleExportsFollowsAliasesAndStars(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, src  string
		lines      map[string]int
		stars      []string
		namespaces map[string]string
	}{
		{
			name: "alias of exports",
			src: `var elliptic = exports;
elliptic.version = '6.6.1';
elliptic.ec = require('./elliptic/ec');
`,
			lines: map[string]int{"version": 2, "ec": 3},
		},
		{
			name: "module.exports bound to a name",
			src: `const bls = {};
bls.SecretKey = class {};
module.exports = bls;
`,
			lines: map[string]int{"SecretKey": 2},
		},
		{
			name: "IIFE handed module.exports (tweetnacl)",
			src: `(function(nacl) {
nacl.box = function() {};
nacl.box.before = function() {};
})(typeof module !== 'undefined' && module.exports ? module.exports : {});
`,
			lines: map[string]int{"box": 2},
		},
		{
			name: "module.exports = lib inside a UMD guard (scrypt-js)",
			src: `(function(root) {
  const lib = {
    scrypt: function() {},
    syncScrypt,
  };
  if (typeof(exports) !== 'undefined') {
    module.exports = lib;
  }
})(this);
`,
			lines: map[string]int{"scrypt": 3, "syncScrypt": 4},
		},
		{
			name: "star re-exports, ES and tsc",
			src: `export * from './signature.js';
export * as ns from './ns.js';
export { a } from './a.js';
tslib_1.__exportStar(require("./account"), exports);
(0, tslib_1.__exportStar)(require("./bytes"), exports);
__exportStar(require("other-package"), exports);
`,
			lines:      map[string]int{"ns": 2, "a": 3},
			stars:      []string{"./signature.js", "./account", "./bytes", "other-package"},
			namespaces: map[string]string{"ns": "./ns.js"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "index.js")
			if err := os.WriteFile(path, []byte(tc.src), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := NodeModuleExports(path)
			if err != nil {
				t.Fatal(err)
			}
			if !maps.Equal(got.Lines, tc.lines) || !slices.Equal(got.StarFrom, tc.stars) {
				t.Errorf("exports = %v stars %v, want %v stars %v", got.Lines, got.StarFrom, tc.lines, tc.stars)
			}
			if len(tc.namespaces) > 0 && !maps.Equal(got.NamespaceOf, tc.namespaces) {
				t.Errorf("namespaces = %v, want %v", got.NamespaceOf, tc.namespaces)
			}
		})
	}
}

func TestNodeExportLinesRejectsUnsupportedFiles(t *testing.T) {
	t.Parallel()
	if _, err := NodeExportLines(filepath.Join(t.TempDir(), "x.py")); err == nil {
		t.Error("a .py file must be rejected")
	}
}
