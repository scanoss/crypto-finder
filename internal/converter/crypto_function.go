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

func mapRawCryptoFunctionToCycloneDX(raw string) (cdx.CryptoFunction, bool) {
	if strings.TrimSpace(raw) == "" {
		return "", false
	}

	normalized := strings.ToLower(strings.TrimSpace(raw))
	normalized = strings.NewReplacer("-", "", "_", "", " ", "").Replace(normalized)

	switch normalized {
	case "generate":
		return cdx.CryptoFunctionGenerate, true
	case "keygen", "keygeneration":
		return cdx.CryptoFunctionKeygen, true
	case "encrypt":
		return cdx.CryptoFunctionEncrypt, true
	case "decrypt":
		return cdx.CryptoFunctionDecrypt, true
	case "digest", "hash":
		return cdx.CryptoFunctionDigest, true
	case "tag":
		return cdx.CryptoFunctionTag, true
	case "keyderive", "derive", "derivekey", "keyderivation":
		return cdx.CryptoFunctionKeyderive, true
	case "sign", "signature":
		return cdx.CryptoFunctionSign, true
	case "verify", "verification", "keyver":
		return cdx.CryptoFunctionVerify, true
	case "encapsulate":
		return cdx.CryptoFunctionEncapsulate, true
	case "decapsulate":
		return cdx.CryptoFunctionDecapsulate, true
	case "other":
		return cdx.CryptoFunctionOther, true
	case "unknown":
		return cdx.CryptoFunctionUnknown, true
	case "keyexchange", "keyagree", "handshake", "load", "serialize", "deserialize", "configure", "init", "instantiate", "import", "export":
		return cdx.CryptoFunctionOther, true
	default:
		return cdx.CryptoFunctionOther, true
	}
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
