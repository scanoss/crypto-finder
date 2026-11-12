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
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// PubKeysEnv names the environment variable that adds or overrides trusted
// signing keys: "id:base64pub[,id:base64pub...]".
const PubKeysEnv = "SCANOSS_RULESET_PUBKEYS"

// embeddedKeys are the ruleset signing public keys built into the client, by
// key id, as base64 of the raw Ed25519 public key: the keys the SCANOSS API
// signs leases with (rulesets.signing_key_id and the public key printed by
// `scanoss-services ruleset keygen`).
var embeddedKeys = map[string]string{
	"srv-2026-11": "e99SEjRkkkwjCFRcUk8efbwy3304CLpnZcMv8eQ2tXQ=",
}

// TrustedKeys returns the embedded keys plus the ones named in PubKeysEnv,
// which replace an embedded key of the same id.
func TrustedKeys() (map[string]ed25519.PublicKey, error) {
	keys := make(map[string]ed25519.PublicKey, len(embeddedKeys))
	for id, b64 := range embeddedKeys {
		pub, err := decodePublicKey(b64)
		if err != nil {
			return nil, fmt.Errorf("ruleset: embedded key %q: %w", id, err)
		}
		keys[id] = pub
	}
	extra, err := ParsePublicKeys(os.Getenv(PubKeysEnv))
	if err != nil {
		return nil, fmt.Errorf("ruleset: %s: %w", PubKeysEnv, err)
	}
	for id, pub := range extra {
		keys[id] = pub
	}
	return keys, nil
}

// NewVerifier returns a Verifier over TrustedKeys.
func NewVerifier() (Verifier, error) {
	keys, err := TrustedKeys()
	if err != nil {
		return Verifier{}, err
	}
	return Verifier{Keys: keys}, nil
}

// ParsePublicKeys parses "id:base64pub[,id:base64pub...]". An empty string
// yields no keys.
func ParsePublicKeys(spec string) (map[string]ed25519.PublicKey, error) {
	keys := make(map[string]ed25519.PublicKey)
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, b64, ok := strings.Cut(entry, ":")
		id = strings.TrimSpace(id)
		if !ok || id == "" {
			return nil, fmt.Errorf("entry %q is not id:base64pub", entry)
		}
		pub, err := decodePublicKey(strings.TrimSpace(b64))
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", id, err)
		}
		keys[id] = pub
	}
	return keys, nil
}

func decodePublicKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("want a %d-byte Ed25519 public key, got %d bytes", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}
