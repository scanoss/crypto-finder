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

package converter

import (
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/scanoss/crypto-finder/internal/entities"
)

const scanossCryptoFunctionPropertyName = "scanoss:cryptoFunction"

func resolveRawCryptoFunction(asset *entities.CryptographicAsset) string {
	if asset == nil {
		return ""
	}

	if cryptoFunction := strings.TrimSpace(asset.Metadata["cryptoFunction"]); cryptoFunction != "" {
		return cryptoFunction
	}

	return strings.TrimSpace(asset.Metadata["operation"])
}

// rawCryptoFunctionMap maps normalized raw crypto function names to their
// CycloneDX equivalents. Any non-empty value absent from this map resolves to
// CryptoFunctionOther (see mapRawCryptoFunctionToCycloneDX).
var rawCryptoFunctionMap = map[string]cdx.CryptoFunction{
	"generate":      cdx.CryptoFunctionGenerate,
	"keygen":        cdx.CryptoFunctionKeygen,
	"keygeneration": cdx.CryptoFunctionKeygen,
	"encrypt":       cdx.CryptoFunctionEncrypt,
	"decrypt":       cdx.CryptoFunctionDecrypt,
	"digest":        cdx.CryptoFunctionDigest,
	"hash":          cdx.CryptoFunctionDigest,
	"tag":           cdx.CryptoFunctionTag,
	"keyderive":     cdx.CryptoFunctionKeyderive,
	"derive":        cdx.CryptoFunctionKeyderive,
	"derivekey":     cdx.CryptoFunctionKeyderive,
	"keyderivation": cdx.CryptoFunctionKeyderive,
	"sign":          cdx.CryptoFunctionSign,
	"signature":     cdx.CryptoFunctionSign,
	"verify":        cdx.CryptoFunctionVerify,
	"verification":  cdx.CryptoFunctionVerify,
	"keyver":        cdx.CryptoFunctionVerify,
	"encapsulate":   cdx.CryptoFunctionEncapsulate,
	"decapsulate":   cdx.CryptoFunctionDecapsulate,
	"other":         cdx.CryptoFunctionOther,
	"unknown":       cdx.CryptoFunctionUnknown,
}

func mapRawCryptoFunctionToCycloneDX(raw string) (cdx.CryptoFunction, bool) {
	if strings.TrimSpace(raw) == "" {
		return "", false
	}

	normalized := strings.ToLower(strings.TrimSpace(raw))
	normalized = strings.NewReplacer("-", "", "_", "", " ", "").Replace(normalized)

	if cryptoFunction, ok := rawCryptoFunctionMap[normalized]; ok {
		return cryptoFunction, true
	}

	// Unrecognized but non-empty values (e.g. keyexchange, handshake, load,
	// serialize, configure, init, instantiate, import, export) fall back to Other.
	return cdx.CryptoFunctionOther, true
}

func addCryptoFunctionProperty(component *cdx.Component, asset *entities.CryptographicAsset) {
	raw := resolveRawCryptoFunction(asset)
	if raw == "" {
		return
	}

	addCustomProperty(component, scanossCryptoFunctionPropertyName, raw)
}

func addCustomProperty(component *cdx.Component, name, value string) {
	if component == nil {
		return
	}

	if strings.TrimSpace(name) == "" || strings.TrimSpace(value) == "" {
		return
	}

	property := cdx.Property{Name: name, Value: value}
	if component.Properties == nil {
		properties := []cdx.Property{property}
		component.Properties = &properties
		return
	}

	properties := append(*component.Properties, property)
	component.Properties = &properties
}
