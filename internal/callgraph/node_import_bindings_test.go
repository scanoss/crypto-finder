// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

// Each call below reaches a library export through a different import form.
// The callee must name the export, whatever the consumer called it locally.
func TestNodeParser_CalleesNameTheImportedExport(t *testing.T) {
	t.Parallel()

	src := `"use strict";
const tslib_1 = require("tslib");
const jsonwebtoken_1 = tslib_1.__importDefault(require("jsonwebtoken"));
const jose = _interopRequireWildcard(require("jose"));
const { sign: jwtSign } = require("jsonwebtoken");
const EC = require("elliptic").ec;
const { SHA256 } = require("crypto-js").algo;
import { verify as jwtVerify } from "jsonwebtoken";
import CryptoJS, { default as C2 } from "crypto-js";

class Local {}

function run(payload, secret) {
  jsonwebtoken_1.default.sign(payload, secret);
  (0, jsonwebtoken_1.default.verify)(payload, secret);
  jose.importJWK(payload);
  jwtSign(payload, secret);
  jwtVerify(payload, secret);
  SHA256.create();
  C2.MD5(payload);
  CryptoJS.SHA1(payload);
  const ec = new EC("secp256k1");
  const local = new Local();
  const err = new Error("x");
  return [ec, local, err];
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "run.js"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewNodeParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	run := nodeFunction(t, analyses[0], "run")

	got := map[int]string{}
	for i := range run.Calls {
		got[run.Calls[i].Line] = run.Calls[i].Callee.String()
	}
	want := map[int]string{
		14: "jsonwebtoken.sign",
		15: "jsonwebtoken.verify",
		16: "jose.importJWK",
		17: "jsonwebtoken.sign",
		18: "jsonwebtoken.verify",
		19: "crypto-js.algo.SHA256.create",
		20: "crypto-js.MD5",
		21: "crypto-js.SHA1",
		22: "elliptic.(ec).<init>",
	}
	for line, callee := range want {
		if got[line] != callee {
			t.Errorf("line %d: callee %q, want %q", line, got[line], callee)
		}
	}
	// new Local() and new Error() reach no import, so they are not calls.
	if len(got) != len(want) {
		t.Errorf("calls by line = %v, want %v", got, want)
	}
	for _, alias := range []string{"jsonwebtoken_1", "jose", "jwtSign", "EC", "SHA256"} {
		if analyses[0].Imports[alias] == "" {
			t.Errorf("Imports[%q] is empty", alias)
		}
	}
}
