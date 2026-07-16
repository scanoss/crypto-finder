// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNodeParser_ImportsCallsAndLifecycleFields(t *testing.T) {
	t.Parallel()

	src := `import crypto from "node:crypto";
import { createHash, createCipheriv as cipher } from "node:crypto";
import * as forge from "node-forge";
const CryptoJS = require("crypto-js");
const { HmacSHA256: hmac } = require("crypto-js");

export function digest(data) {
  const hash = crypto.createHash("sha256");
  hash.update(data);
  return createHash("sha256").digest("hex");
}

export const forgeDigest = (data) => {
  const result = forge.md.sha256.create().update(data).digest();
  CryptoJS.AES.encrypt(data, "secret");
  return hmac(data, "secret");
};
`
	dir := t.TempDir()
	filePath := filepath.Join(dir, "crypto.js")
	if err := os.WriteFile(filePath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	analyses, err := NewNodeParser().ParseDirectory(dir, "example-app")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("analyses = %d, want 1", len(analyses))
	}
	analysis := analyses[0]
	wantImports := map[string]string{
		"crypto":     "node:crypto",
		"createHash": "node:crypto",
		"cipher":     "node:crypto",
		"forge":      "node-forge",
		"CryptoJS":   "crypto-js",
		"hmac":       "crypto-js",
	}
	for alias, want := range wantImports {
		if got := analysis.Imports[alias]; got != want {
			t.Errorf("Imports[%q] = %q, want %q", alias, got, want)
		}
	}

	digest := nodeFunction(t, analysis, "digest")
	create := nodeCall(t, digest, "node:crypto", "createHash", "crypto.createHash")
	if create.AssignedVar != "hash" {
		t.Errorf("createHash AssignedVar = %q, want hash", create.AssignedVar)
	}
	if got := nodeCallSpan(t, src, create); got != `crypto.createHash("sha256")` {
		t.Errorf("createHash span = %q", got)
	}
	update := nodeCall(t, digest, "example-app", "update", "hash.update")
	if update.ReceiverVar != "hash" {
		t.Errorf("hash.update ReceiverVar = %q, want hash", update.ReceiverVar)
	}
	_ = nodeCall(t, digest, "node:crypto", "createHash", "createHash")

	forgeDigest := nodeFunction(t, analysis, "forgeDigest")
	createLink := nodeCall(t, forgeDigest, "node-forge.md.sha256", "create", "forge.md.sha256.create")
	updateLink := nodeCall(t, forgeDigest, "example-app", "update", "forge.md.sha256.create().update")
	digestLink := nodeCall(t, forgeDigest, "example-app", "digest", "forge.md.sha256.create().update(data).digest")
	if createLink.ChainID == "" || createLink.ChainID != updateLink.ChainID || createLink.ChainID != digestLink.ChainID {
		t.Fatalf("fluent ChainIDs = %q, %q, %q", createLink.ChainID, updateLink.ChainID, digestLink.ChainID)
	}
	if digestLink.AssignedVar != "result" || createLink.AssignedVar != "" || updateLink.AssignedVar != "" {
		t.Errorf("fluent AssignedVars = create:%q update:%q digest:%q", createLink.AssignedVar, updateLink.AssignedVar, digestLink.AssignedVar)
	}
	_ = nodeCall(t, forgeDigest, "crypto-js.AES", "encrypt", "CryptoJS.AES.encrypt")
	_ = nodeCall(t, forgeDigest, "crypto-js", "hmac", "hmac")
}

func TestNodeParser_TypeScriptAndRegistryAliases(t *testing.T) {
	t.Parallel()

	for _, ecosystem := range []string{"node", "javascript", "typescript"} {
		if _, ok := NewParserForEcosystem(ecosystem).(*NodeParser); !ok {
			t.Fatalf("NewParserForEcosystem(%q) did not return *NodeParser", ecosystem)
		}
	}

	dir := t.TempDir()
	src := `import { createCipheriv } from "node:crypto";
export function encrypt(data: Buffer): Buffer {
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  return cipher.update(data);
}
`
	if err := os.WriteFile(filepath.Join(dir, "crypto.ts"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	analyses, err := NewNodeParser().ParseDirectory(dir, "example-app")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("analyses = %d, want 1", len(analyses))
	}
	encrypt := nodeFunction(t, analyses[0], "encrypt")
	call := nodeCall(t, encrypt, "node:crypto", "createCipheriv", "createCipheriv")
	if call.AssignedVar != "cipher" {
		t.Errorf("createCipheriv AssignedVar = %q, want cipher", call.AssignedVar)
	}
	update := nodeCall(t, encrypt, "example-app", "update", "cipher.update")
	if update.ReceiverVar != "cipher" {
		t.Errorf("cipher.update ReceiverVar = %q, want cipher", update.ReceiverVar)
	}
}

func nodeFunction(t *testing.T, analysis *FileAnalysis, name string) *FunctionDecl {
	t.Helper()
	for i := range analysis.Functions {
		if analysis.Functions[i].ID.Name == name {
			return &analysis.Functions[i]
		}
	}
	t.Fatalf("function %q not found", name)
	return nil
}

func nodeCall(t *testing.T, fn *FunctionDecl, pkg, name, raw string) *FunctionCall {
	t.Helper()
	for i := range fn.Calls {
		call := &fn.Calls[i]
		if call.Callee.Package == pkg && call.Callee.Type == "" && call.Callee.Name == name && call.Raw == raw {
			return call
		}
	}
	t.Fatalf("call %s.%s (%q) not found in %#v", pkg, name, raw, fn.Calls)
	return nil
}

func nodeCallSpan(t *testing.T, src string, call *FunctionCall) string {
	t.Helper()
	lines := strings.Split(src, "\n")
	if call.Line < 1 || call.Line > len(lines) || call.StartCol < 1 || call.EndCol <= call.StartCol {
		t.Fatalf("invalid call position: %+v", call)
	}
	line := lines[call.Line-1]
	return line[call.StartCol-1 : call.EndCol-1]
}
