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
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func newPair(t *testing.T, id string) (Signer, Verifier) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return Signer{KeyID: id, Key: priv}, Verifier{Keys: map[string]ed25519.PublicKey{id: pub}}
}

func sampleLease(bundle []byte) Lease {
	now := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	return Lease{
		Format: LeaseFormat, Name: "dca", Domain: "crypto", Version: "v1.40.0",
		PayloadSHA: SHA256Hex([]byte("payload")), BundleSHA: SHA256Hex(bundle),
		KeyRef: "k_3f2a9c1b7d4e", Tenant: "acme",
		IssuedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour),
	}
}

func TestSignParseCheck(t *testing.T) {
	s, v := newPair(t, "srv-2026-11")
	bundle := []byte("tar bytes")
	data, err := s.Sign(sampleLease(bundle))
	if err != nil {
		t.Fatal(err)
	}
	l, err := v.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if l.SigningKeyID != "srv-2026-11" || l.KeyRef != "k_3f2a9c1b7d4e" {
		t.Fatalf("unexpected lease %+v", l)
	}
	v.Now = func() time.Time { return l.IssuedAt.Add(time.Hour) }
	if err := v.Check(l, bundle); err != nil {
		t.Fatal(err)
	}
}

func TestRejects(t *testing.T) {
	s, v := newPair(t, "a")
	bundle := []byte("tar bytes")
	data, _ := s.Sign(sampleLease(bundle))

	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	env.Lease = []byte(strings.Replace(string(env.Lease), `"tenant":"acme"`, `"tenant":"evil"`, 1))
	tampered, _ := json.Marshal(env)
	if _, err := v.Parse(tampered); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered lease: got %v", err)
	}
	_, other := newPair(t, "b")
	if _, err := other.Parse(data); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key: got %v", err)
	}
	l, _ := v.Parse(data)
	v.Now = func() time.Time { return l.ExpiresAt }
	if err := v.Check(l, bundle); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: got %v", err)
	}
	v.Now = func() time.Time { return l.IssuedAt }
	if err := v.Check(l, []byte("other bytes")); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("hash: got %v", err)
	}
	// Unknown fields added by a newer server must not break verification.
	var env2 Envelope
	_ = json.Unmarshal(data, &env2)
	if _, err := v.Parse(data); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(Lease{Format: "nope"}); !errors.Is(err, ErrBadFormat) {
		t.Fatalf("format: got %v", err)
	}
}

func TestSealOpen(t *testing.T) {
	bundle := []byte("rules")
	sealed, err := Seal("key-abc", "dca", bundle)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open("key-abc", "dca", sealed)
	if err != nil || string(got) != "rules" {
		t.Fatalf("open: %v %q", err, got)
	}
	if _, err := Open("key-xyz", "dca", sealed); err == nil {
		t.Fatal("wrong api key must fail")
	}
	if _, err := Open("key-abc", "open", sealed); err == nil {
		t.Fatal("wrong name must fail")
	}
	if _, err := Seal("", "dca", bundle); err == nil {
		t.Fatal("empty api key must fail")
	}
}

func TestParseIgnoresUnknownLeaseFields(t *testing.T) {
	s, v := newPair(t, "a")
	l := sampleLease([]byte("x"))
	l.SigningKeyID = "a"
	payload, _ := json.Marshal(l)
	payload = []byte(strings.TrimSuffix(string(payload), "}") + `,"future_field":1}`)
	env, _ := json.Marshal(Envelope{Format: LeaseFormat, Lease: payload, Signature: ed25519.Sign(s.Key, payload)})
	if got, err := v.Parse(env); err != nil || got.Tenant != "acme" {
		t.Fatalf("future field: %v %+v", err, got)
	}
}
