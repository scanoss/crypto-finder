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
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

const cacheInfo = "scanoss-ruleset-cache/1"

// cacheKey derives the at-rest key from the API key. Nothing new has to be
// distributed: a cache copied without the API key cannot be opened.
func cacheKey(apiKey, name string) ([]byte, error) {
	return hkdf.Key(sha256.New, []byte(apiKey), []byte(name), cacheInfo, 32)
}

// Seal encrypts a bundle for the on-disk cache: nonce || AES-256-GCM(bundle),
// with the ruleset name as additional data.
func Seal(apiKey, name string, bundle []byte) ([]byte, error) {
	aead, err := newAEAD(apiKey, name)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, bundle, []byte(name)), nil
}

// Open decrypts what Seal produced.
func Open(apiKey, name string, sealed []byte) ([]byte, error) {
	aead, err := newAEAD(apiKey, name)
	if err != nil {
		return nil, err
	}
	if len(sealed) < aead.NonceSize() {
		return nil, errors.New("ruleset: sealed cache too short")
	}
	nonce, ct := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, ct, []byte(name))
	if err != nil {
		return nil, fmt.Errorf("ruleset: open sealed cache: %w", err)
	}
	return pt, nil
}

func newAEAD(apiKey, name string) (cipher.AEAD, error) {
	if apiKey == "" {
		return nil, errors.New("ruleset: an API key is required to seal or open the cache")
	}
	key, err := cacheKey(apiKey, name)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
