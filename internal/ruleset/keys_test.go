// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package ruleset

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestTrustedKeysFromEnv(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(pub)

	t.Setenv(PubKeysEnv, "")
	v, err := NewVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Keys) != len(embeddedKeys) {
		t.Fatalf("keys = %v, want the embedded ones", v.Keys)
	}

	t.Setenv(PubKeysEnv, " dev-1:"+b64+" , uat-1:"+b64)
	v, err = NewVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Keys) != len(embeddedKeys)+2 || !v.Keys["dev-1"].Equal(pub) || !v.Keys["uat-1"].Equal(pub) {
		t.Fatalf("keys = %v", v.Keys)
	}

	// A key of the same id replaces the embedded one.
	t.Setenv(PubKeysEnv, "srv-2026-11:"+b64)
	v, err = NewVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if !v.Keys["srv-2026-11"].Equal(pub) {
		t.Fatal("PubKeysEnv did not replace the embedded key")
	}
}

func TestEmbeddedProductionKey(t *testing.T) {
	t.Setenv(PubKeysEnv, "")
	keys, err := TrustedKeys()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := base64.StdEncoding.DecodeString("e99SEjRkkkwjCFRcUk8efbwy3304CLpnZcMv8eQ2tXQ=")
	if !keys["srv-2026-11"].Equal(ed25519.PublicKey(want)) {
		t.Fatalf("srv-2026-11 = %x", keys["srv-2026-11"])
	}
}

func TestParsePublicKeysRejectsMalformed(t *testing.T) {
	for _, spec := range []string{"nocolon", ":AAAA", "id:not-base64!", "id:" + base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := ParsePublicKeys(spec); err == nil {
			t.Errorf("ParsePublicKeys(%q) succeeded", spec)
		}
	}
}
