// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"sort"
	"strings"
	"testing"
)

// Every spelling of the WebCrypto API lands on its WebIDL interface: the
// global crypto object in a browser or in Node, Node's crypto.webcrypto, and
// the subtle object held in a variable or destructured. The Node module's own
// functions keep their module name, and a project object named crypto, or a
// method of the same name on another receiver, is never WebCrypto.
func TestNodeParser_WebCryptoCallsResolveToTheirInterface(t *testing.T) {
	t.Parallel()

	analysis := parseNodeSource(t, `import nodeCrypto from 'node:crypto';
import { webcrypto, subtle as nodeSubtle } from 'crypto';
const { subtle: destructuredSubtle } = require('node:crypto').webcrypto;

const moduleSubtle = crypto.subtle;
const { subtle: cryptoSubtle } = globalThis.crypto;

export async function browser(data) {
  await crypto.subtle.digest('SHA-256', data);
  await window.crypto.subtle.encrypt({ name: 'AES-GCM' }, data);
  await globalThis.crypto.subtle.sign('HMAC', data);
  await self.crypto.subtle.verify('HMAC', data);
  crypto.getRandomValues(new Uint8Array(12));
  crypto.randomUUID();
  await moduleSubtle.deriveBits({ name: 'PBKDF2' }, data, 256);
  await cryptoSubtle.exportKey('raw', data);
}

export async function node(data) {
  await nodeCrypto.webcrypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  await webcrypto.subtle.importKey('raw', data, 'PBKDF2', false, ['deriveBits']);
  await nodeSubtle.deriveKey({ name: 'HKDF' }, data, { name: 'AES-GCM' }, false, ['encrypt']);
  await destructuredSubtle.wrapKey('raw', data, data, 'AES-KW');
  await require('crypto').webcrypto.subtle.unwrapKey('raw', data, data, 'AES-KW', 'AES-GCM', false, ['encrypt']);
  await require('node:crypto').subtle.decrypt({ name: 'AES-GCM' }, data, data);
  nodeCrypto.getRandomValues(new Uint8Array(12));
  webcrypto.getRandomValues(new Uint8Array(12));
  const { subtle } = nodeCrypto.webcrypto;
  await subtle.digest('SHA-1', data);
  nodeCrypto.randomUUID();
  nodeCrypto.createHash('sha256');
}

export async function lookalikes(crypto, store) {
  await crypto.subtle.digest('SHA-256', store);
  const subtle = store.subtle;
  await subtle.digest('SHA-256', store);
  await store.crypto.subtle.digest('SHA-256', store);
  globalThis.crypto = store;
  return store.getRandomValues(store);
}
`)
	calls := func(name string) []string {
		t.Helper()
		for i := range analysis.Functions {
			fn := &analysis.Functions[i]
			if fn.ID.Name != name {
				continue
			}
			var out []string
			for _, call := range fn.Calls {
				if call.Callee.Name == "Uint8Array" {
					continue
				}
				out = append(out, call.Callee.String())
			}
			sort.Strings(out)
			return out
		}
		t.Fatalf("function %s not parsed", name)
		return nil
	}

	want := map[string][]string{
		"browser": {
			"(Crypto).getRandomValues",
			"(Crypto).randomUUID",
			"(SubtleCrypto).deriveBits",
			"(SubtleCrypto).digest",
			"(SubtleCrypto).encrypt",
			"(SubtleCrypto).exportKey",
			"(SubtleCrypto).sign",
			"(SubtleCrypto).verify",
		},
		"node": {
			"(Crypto).getRandomValues",
			"(Crypto).getRandomValues",
			"(SubtleCrypto).decrypt",
			"(SubtleCrypto).deriveKey",
			"(SubtleCrypto).digest",
			"(SubtleCrypto).generateKey",
			"(SubtleCrypto).importKey",
			"(SubtleCrypto).unwrapKey",
			"(SubtleCrypto).wrapKey",
			"node:crypto.createHash",
			"node:crypto.randomUUID",
		},
	}
	for name, expected := range want {
		if got := calls(name); strings.Join(got, "\n") != strings.Join(expected, "\n") {
			t.Errorf("%s calls:\n got %q\nwant %q", name, got, expected)
		}
	}
	for _, call := range calls("lookalikes") {
		if strings.Contains(call, "Crypto") {
			t.Errorf("lookalikes: %s resolved to WebCrypto", call)
		}
	}
}
