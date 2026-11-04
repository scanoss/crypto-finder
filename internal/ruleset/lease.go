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

// Package ruleset defines the X2 ruleset bundle format shared by the API
// (which signs leases and serves bundles with per-tenant marks) and the
// clients (which verify leases and keep bundles encrypted at rest).
package ruleset

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Format identifiers of a release description and of a lease.
const (
	ReleaseFormat = "scanoss-ruleset-release/1"
	LeaseFormat   = "scanoss-ruleset-lease/1"
)

// Release describes an immutable ruleset version as stored on the server.
type Release struct {
	Format      string    `json:"format"`
	Name        string    `json:"name"`
	Domain      string    `json:"domain"`
	Version     string    `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	Description string    `json:"description,omitempty"`
	PayloadSHA  string    `json:"payload_sha256"`
	PayloadSize int64     `json:"payload_size"`
}

// Lease binds one served bundle to a key, a time window and a signing key.
// On the wire a lease travels inside an Envelope; the signature covers the
// exact payload bytes, so adding fields later never breaks older verifiers.
type Lease struct {
	Format       string    `json:"format"`
	Name         string    `json:"name"`
	Domain       string    `json:"domain"`
	Version      string    `json:"version"`
	PayloadSHA   string    `json:"payload_sha256"`
	BundleSHA    string    `json:"bundle_sha256"`
	KeyRef       string    `json:"key_ref,omitempty"`
	Tenant       string    `json:"tenant,omitempty"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	SigningKeyID string    `json:"signing_key_id"`
}

// Envelope is the signed wire form of a Lease.
type Envelope struct {
	Format    string `json:"format"`
	Lease     []byte `json:"lease"`     // JSON of Lease, base64 in the wire form
	Signature []byte `json:"signature"` // Ed25519 over Lease bytes
}

// Errors returned by Sign, Parse and Check.
var (
	ErrBadSignature = errors.New("ruleset: lease signature does not verify")
	ErrUnknownKey   = errors.New("ruleset: lease signed by an unknown key")
	ErrExpired      = errors.New("ruleset: lease has expired")
	ErrHashMismatch = errors.New("ruleset: bundle hash does not match lease")
	ErrBadFormat    = errors.New("ruleset: unsupported lease format")
)

// Signer holds the server-side private key.
type Signer struct {
	KeyID string
	Key   ed25519.PrivateKey
}

// Verifier holds the public keys a client trusts, by key id.
type Verifier struct {
	Keys map[string]ed25519.PublicKey
	Now  func() time.Time // defaults to time.Now
}

// Sign sets SigningKeyID, signs the lease bytes and returns the envelope JSON.
func (s Signer) Sign(l Lease) ([]byte, error) {
	if l.Format != LeaseFormat {
		return nil, ErrBadFormat
	}
	l.SigningKeyID = s.KeyID
	payload, err := json.Marshal(l)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Envelope{
		Format:    LeaseFormat,
		Lease:     payload,
		Signature: ed25519.Sign(s.Key, payload),
	})
}

// Parse decodes an envelope and checks its signature against the trusted
// keys. It does not check expiry or the bundle hash; see Check.
func (v Verifier) Parse(data []byte) (Lease, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return Lease{}, fmt.Errorf("ruleset: decode lease envelope: %w", err)
	}
	if env.Format != LeaseFormat {
		return Lease{}, ErrBadFormat
	}
	var l Lease
	if err := json.Unmarshal(env.Lease, &l); err != nil {
		return Lease{}, fmt.Errorf("ruleset: decode lease: %w", err)
	}
	if l.Format != LeaseFormat {
		return Lease{}, ErrBadFormat
	}
	pub, ok := v.Keys[l.SigningKeyID]
	if !ok {
		return Lease{}, fmt.Errorf("%w: %q", ErrUnknownKey, l.SigningKeyID)
	}
	if !ed25519.Verify(pub, env.Lease, env.Signature) {
		return Lease{}, ErrBadSignature
	}
	return l, nil
}

// Check verifies that the lease is current and matches the bundle bytes.
func (v Verifier) Check(l Lease, bundle []byte) error {
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	if !now().Before(l.ExpiresAt) {
		return fmt.Errorf("%w: %s", ErrExpired, l.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if SHA256Hex(bundle) != l.BundleSHA {
		return ErrHashMismatch
	}
	return nil
}

// SHA256Hex returns the lowercase hex SHA-256 of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
