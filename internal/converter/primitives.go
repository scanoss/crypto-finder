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
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// mapPrimitiveToCycloneDX maps interim primitive string to CycloneDX primitive enum.
func mapPrimitiveToCycloneDX(primitive string) (cdx.CryptoPrimitive, error) {
	// Normalize to lowercase for comparison
	primitiveLower := strings.ToLower(strings.TrimSpace(primitive))

	switch primitiveLower {
	case "ae":
		return cdx.CryptoPrimitiveAE, nil
	case "block-cipher":
		return cdx.CryptoPrimitiveBlockCipher, nil
	case "stream-cipher":
		return cdx.CryptoPrimitiveStreamCipher, nil
	case "hash":
		return cdx.CryptoPrimitiveHash, nil
	case "signature":
		return cdx.CryptoPrimitiveSignature, nil
	case "mac":
		return cdx.CryptoPrimitiveMAC, nil
	case "kdf":
		return cdx.CryptoPrimitiveKDF, nil
	case "pke":
		return cdx.CryptoPrimitivePKE, nil
	case "kem":
		return cdx.CryptoPrimitiveKEM, nil
	case "xof":
		return cdx.CryptoPrimitiveXOF, nil
	case "key-agree":
		return cdx.CryptoPrimitiveKeyAgree, nil
	case "combiner":
		return cdx.CryptoPrimitiveCombiner, nil
	case "drbg":
		return cdx.CryptoPrimitiveDRBG, nil
	case "other":
		return cdx.CryptoPrimitiveOther, nil
	default:
		return "", fmt.Errorf("unknown primitive type: %s (supported: ae, block-cipher, stream-cipher, hash, signature, mac, kdf, pke, kem, xof, key-agree, combiner, drbg, other)", primitive)
	}
}
