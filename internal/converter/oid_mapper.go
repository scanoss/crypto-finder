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

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// OIDMapper resolves cryptographic algorithm names to their OIDs.
type OIDMapper struct {
	// nameToOID maps specific algorithm names (e.g., "AES-128-CBC") to their OIDs.
	nameToOID map[string]string
	// familyToOID maps algorithm families (e.g., "AES") to their parent OIDs.
	familyToOID map[string]string
}

// NewOIDMapper creates a new OID mapper with all predefined mappings.
func NewOIDMapper() *OIDMapper {
	mapper := &OIDMapper{
		nameToOID:   make(map[string]string),
		familyToOID: make(map[string]string),
	}
	mapper.initializeMappings()
	return mapper
}

// initializeMappings populates the OID mapping tables.
//
//nolint:funlen // This function has many mappings by design.
func (m *OIDMapper) initializeMappings() {
	// AES Family (NIST CSOR).
	m.addFamilyMapping("AES", OIDAES)
	m.addNameMapping("AES-128-ECB", OIDAES128ECB)
	m.addNameMapping("AES-128-CBC", OIDAES128CBC)
	m.addNameMapping("AES-128-OFB", OIDAES128OFB)
	m.addNameMapping("AES-128-CFB", OIDAES128CFB)
	m.addNameMapping("AES-128-WRAP", OIDAES128WRAP)
	m.addNameMapping("AES-128-GCM", OIDAES128GCM)
	m.addNameMapping("AES-128-CCM", OIDAES128CCM)
	m.addNameMapping("AES-128-WRAP-PAD", OIDAES128WRAPPAD)
	m.addNameMapping("AES-192-ECB", OIDAES192ECB)
	m.addNameMapping("AES-192-CBC", OIDAES192CBC)
	m.addNameMapping("AES-192-OFB", OIDAES192OFB)
	m.addNameMapping("AES-192-CFB", OIDAES192CFB)
	m.addNameMapping("AES-192-WRAP", OIDAES192WRAP)
	m.addNameMapping("AES-192-GCM", OIDAES192GCM)
	m.addNameMapping("AES-192-CCM", OIDAES192CCM)
	m.addNameMapping("AES-192-WRAP-PAD", OIDAES192WRAPPAD)
	m.addNameMapping("AES-256-ECB", OIDAES256ECB)
	m.addNameMapping("AES-256-CBC", OIDAES256CBC)
	m.addNameMapping("AES-256-OFB", OIDAES256OFB)
	m.addNameMapping("AES-256-CFB", OIDAES256CFB)
	m.addNameMapping("AES-256-WRAP", OIDAES256WRAP)
	m.addNameMapping("AES-256-GCM", OIDAES256GCM)
	m.addNameMapping("AES-256-CCM", OIDAES256CCM)
	m.addNameMapping("AES-256-WRAP-PAD", OIDAES256WRAPPAD)

	// SHA-2 Family (NIST CSOR).
	m.addFamilyMapping("SHA", OIDHashAlgs)
	m.addFamilyMapping("SHA2", OIDHashAlgs)
	m.addNameMapping("SHA-224", OIDSHA224)
	m.addNameMapping("SHA-256", OIDSHA256)
	m.addNameMapping("SHA-384", OIDSHA384)
	m.addNameMapping("SHA-512", OIDSHA512)
	m.addNameMapping("SHA-512-224", OIDSHA512224)
	m.addNameMapping("SHA-512-256", OIDSHA512256)

	// SHA-3 Family (NIST CSOR).
	m.addFamilyMapping("SHA3", OIDHashAlgs)
	m.addNameMapping("SHA3-224", OIDSHA3224)
	m.addNameMapping("SHA3-256", OIDSHA3256)
	m.addNameMapping("SHA3-384", OIDSHA3384)
	m.addNameMapping("SHA3-512", OIDSHA3512)

	// SHAKE Family (NIST CSOR).
	m.addNameMapping("SHAKE128", OIDSHAKE128)
	m.addNameMapping("SHAKE256", OIDSHAKE256)

	// DSA Family (NIST CSOR).
	m.addFamilyMapping("DSA", OIDSigAlgs)
	m.addNameMapping("DSA-SHA224", OIDDSASHA224)
	m.addNameMapping("DSA-SHA256", OIDDSASHA256)

	// RSA Family (PKCS#1).
	m.addFamilyMapping("RSA", OIDRSA)
	m.addNameMapping("RSA", OIDRSA) // Base RSA OID.
	m.addNameMapping("RSA-MD5", OIDRSAMD5)
	m.addNameMapping("RSA-SHA1", OIDRSASHA1)
	m.addNameMapping("RSA-SHA256", OIDRSASHA256)
	m.addNameMapping("RSA-SHA384", OIDRSASHA384)
	m.addNameMapping("RSA-SHA512", OIDRSASHA512)
	m.addNameMapping("RSA-SHA224", OIDRSASHA224)

	// ECDSA Family (ANSI X9.62).
	m.addFamilyMapping("ECDSA", OIDECPublicKey)
	m.addNameMapping("ECDSA", OIDECPublicKey) // Base ECDSA OID.
	m.addNameMapping("ECDSA-SHA1", OIDECDSASHA1)
	m.addNameMapping("ECDSA-SHA224", OIDECDSASHA224)
	m.addNameMapping("ECDSA-SHA256", OIDECDSASHA256)
	m.addNameMapping("ECDSA-SHA384", OIDECDSASHA384)
	m.addNameMapping("ECDSA-SHA512", OIDECDSASHA512)

	// HMAC Family.
	m.addNameMapping("HMAC-MD5", OIDHMACMD5)
	m.addNameMapping("HMAC-SHA1", OIDHMACSHA1)
	m.addNameMapping("HMAC-SHA224", OIDHMACSHA224)
	m.addNameMapping("HMAC-SHA256", OIDHMACSHA256)
	m.addNameMapping("HMAC-SHA384", OIDHMACSHA384)
	m.addNameMapping("HMAC-SHA512", OIDHMACSHA512)

	// DES Family (OIW - deprecated).
	m.addFamilyMapping("DES", OIDDESCDC)
	m.addNameMapping("DES", OIDDESCDC) // Base DES (default to CBC).
	m.addNameMapping("DES-ECB", OIDDESECB)
	m.addNameMapping("DES-CBC", OIDDESCDC)
	m.addNameMapping("DES-OFB", OIDDESOFB)
	m.addNameMapping("DES-CFB", OIDDESCFB)

	// 3DES/Triple DES (OIW - deprecated).
	m.addFamilyMapping("3DES", OIDDESEDE)
	m.addFamilyMapping("DES-EDE", OIDDESEDE)
	m.addFamilyMapping("TRIPLEDES", OIDDESEDE)
	m.addNameMapping("3DES", OIDDESEDE)      // Base 3DES.
	m.addNameMapping("DES-EDE", OIDDESEDE)   // Base DES-EDE.
	m.addNameMapping("TRIPLEDES", OIDDESEDE) // TRIPLEDES alias.
	m.addNameMapping("3DES-EDE", OIDDESEDE)

	// Legacy Hash Algorithms (OIW - deprecated).
	// Note: We don't map "SHA" alone to OIDSHA (OIW SHA-0) because
	// "SHA" should be treated as a family that maps to OIDHashAlgs.
	m.addNameMapping("SHA-0", OIDSHA) // Original SHA (SHA-0).
	m.addNameMapping("SHA-1", OIDSHA1)

	// Legacy RSA Signatures (OIW - deprecated).
	m.addNameMapping("SHA1-WITH-RSA", OIDSHA1WithRSA)
}

// addNameMapping adds a specific algorithm name to OID mapping.
func (m *OIDMapper) addNameMapping(name, oid string) {
	normalized := normalizeAlgorithmName(name)
	m.nameToOID[normalized] = oid
}

// addFamilyMapping adds an algorithm family to parent OID mapping.
func (m *OIDMapper) addFamilyMapping(family, oid string) {
	normalized := normalizeAlgorithmName(family)
	m.familyToOID[normalized] = oid
}

// ResolveOID looks up the OID for an algorithm using hybrid strategy:
// 1. Try specific algorithmName (case-insensitive, normalized).
// 2. Construct name from family + parameterSet + mode and try again.
// 3. Fall back to algorithmFamily parent OID (case-insensitive).
// 4. Return empty string if not found (logs warning).
func (m *OIDMapper) ResolveOID(asset *entities.CryptographicAsset) string {
	// Priority 1: Check explicit algorithmName from metadata.
	if algoName, ok := asset.Metadata["algorithmName"]; ok && algoName != "" {
		normalized := normalizeAlgorithmName(algoName)
		if oid, found := m.nameToOID[normalized]; found {
			return oid
		}
	}

	// Priority 2: Construct name from components and check.
	family := asset.Metadata["algorithmFamily"]
	paramSet := asset.Metadata["algorithmParameterSetIdentifier"]
	mode := asset.Metadata["algorithmMode"]

	if family != "" && paramSet != "" && mode != "" {
		constructedName := constructAlgorithmName(family, paramSet, mode)
		normalizedConstructed := normalizeAlgorithmName(constructedName)
		if oid, found := m.nameToOID[normalizedConstructed]; found {
			return oid
		}
	}

	// Priority 3: Fall back to algorithmFamily parent OID.
	if family != "" {
		normalizedFamily := normalizeAlgorithmName(family)
		if oid, found := m.familyToOID[normalizedFamily]; found {
			return oid
		}
	}

	if family != "" {
		log.Warn().
			Str("algorithmFamily", family).
			Str("algorithmName", asset.Metadata["algorithmName"]).
			Str("parameterSet", paramSet).
			Str("mode", mode).
			Msg("Unknown algorithm detected, no OID assigned")
	}

	return ""
}

// normalizeAlgorithmName normalizes algorithm names for lookup:
// - Trims whitespace.
// - Converts to uppercase.
// - Normalizes separators (underscores, spaces to hyphens).
// - Applies family aliases (SHA2 -> SHA, 3DES -> DES-EDE, etc.).
func normalizeAlgorithmName(name string) string {
	// Step 1: Trim whitespace.
	name = strings.TrimSpace(name)

	// Step 2: Convert to uppercase.
	name = strings.ToUpper(name)

	// Step 3: Normalize separators (underscores and spaces to hyphens).
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, " ", "-")

	// Step 4: Remove duplicate hyphens.
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}

	// Step 5: Apply family aliases.
	aliases := map[string]string{
		"SHA2":       "SHA",
		"SHA-2":      "SHA",
		"SHA3":       "SHA",
		"SHA-3":      "SHA",
		"3DES":       "DES-EDE",
		"TRIPLEDES":  "DES-EDE",
		"3-DES":      "DES-EDE",
		"TRIPLE-DES": "DES-EDE",
	}

	if alias, ok := aliases[name]; ok {
		name = alias
	}

	return name
}

// constructAlgorithmName builds an algorithm name from components.
// Format: {family}[-{parameterSet}][-{mode}].
func constructAlgorithmName(family, paramSet, mode string) string {
	parts := []string{family}

	if paramSet != "" {
		parts = append(parts, paramSet)
	}

	if mode != "" {
		parts = append(parts, mode)
	}

	return strings.Join(parts, "-")
}

// IsKnownAlgorithm checks if an algorithm name is in the mapping.
func (m *OIDMapper) IsKnownAlgorithm(name string) bool {
	normalized := normalizeAlgorithmName(name)
	_, found := m.nameToOID[normalized]
	return found
}

// IsKnownFamily checks if an algorithm family is in the mapping.
func (m *OIDMapper) IsKnownFamily(family string) bool {
	normalized := normalizeAlgorithmName(family)
	_, found := m.familyToOID[normalized]
	return found
}

// GetNameOIDCount returns the number of specific name mappings.
func (m *OIDMapper) GetNameOIDCount() int {
	return len(m.nameToOID)
}

// GetFamilyOIDCount returns the number of family mappings.
func (m *OIDMapper) GetFamilyOIDCount() int {
	return len(m.familyToOID)
}
