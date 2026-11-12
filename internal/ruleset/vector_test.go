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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

// testdata/lease-vector.json was produced by the SCANOSS API's own
// pkg/ruleset Signer.Sign, so this test checks that the client verifies
// exactly what the server signs, from the wire form (the base64
// SCANOSS-Ruleset-Lease header) down.
type leaseVector struct {
	SeedText     string `json:"seed_text"`
	SigningKeyID string `json:"signing_key_id"`
	PublicKey    string `json:"public_key"`
	Bundle       string `json:"bundle"`
	Envelope     string `json:"envelope"`
	Header       string `json:"header"`
}

func loadLeaseVector(t *testing.T) leaseVector {
	t.Helper()
	data, err := os.ReadFile("testdata/lease-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v leaseVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestServerLeaseVector(t *testing.T) {
	vec := loadLeaseVector(t)
	pub, err := decodePublicKey(vec.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := base64.StdEncoding.DecodeString(vec.Header)
	if err != nil || string(envelope) != vec.Envelope {
		t.Fatalf("header does not decode to the envelope: %v", err)
	}

	v := Verifier{Keys: map[string]ed25519.PublicKey{vec.SigningKeyID: pub}}
	l, err := v.Parse(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if l.Name != "dca" || l.Version != "v1.40.0" || l.Tenant != "acme" || l.KeyRef != "k_3f2a9c1b7d4e" || l.SigningKeyID != vec.SigningKeyID {
		t.Fatalf("lease = %+v", l)
	}
	if l.PayloadSHA != SHA256Hex([]byte("scanoss ruleset payload test vector")) {
		t.Fatalf("payload_sha256 = %s", l.PayloadSHA)
	}
	v.Now = func() time.Time { return l.IssuedAt }
	if err := v.Check(l, []byte(vec.Bundle)); err != nil {
		t.Fatal(err)
	}
	v.Now = func() time.Time { return l.ExpiresAt }
	if err := v.Check(l, []byte(vec.Bundle)); !errors.Is(err, ErrExpired) {
		t.Fatalf("at expires_at: got %v", err)
	}

	// Ed25519 is deterministic: signing the same lease with the same seed
	// gives the server's envelope byte for byte.
	seed := sha256.Sum256([]byte(vec.SeedText))
	l.SigningKeyID = ""
	resigned, err := Signer{KeyID: vec.SigningKeyID, Key: ed25519.NewKeyFromSeed(seed[:])}.Sign(l)
	if err != nil {
		t.Fatal(err)
	}
	if string(resigned) != vec.Envelope {
		t.Fatalf("client Sign differs from the server's envelope:\n%s\n%s", resigned, vec.Envelope)
	}
}
