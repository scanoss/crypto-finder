// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"maps"
	"os"
	"path/filepath"
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

func TestNodeExportLinesRejectsUnsupportedFiles(t *testing.T) {
	t.Parallel()
	if _, err := NodeExportLines(filepath.Join(t.TempDir(), "x.py")); err == nil {
		t.Error("a .py file must be rejected")
	}
}
