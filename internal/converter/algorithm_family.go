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
	"encoding/json"
	"strings"
	"sync"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// scanossAlgorithmFamilyPropertyName carries a rule's algorithm family when
// CycloneDX's family registry has no entry for it (e.g. "RSA"), so the family
// is never lost from the CBOM.
const scanossAlgorithmFamilyPropertyName = "scanoss:algorithmFamily"

// algorithmFamilyAliases maps rule spellings of a family onto the registry
// entry that names the same family, keyed by lowercase rule spelling.
var algorithmFamilyAliases = map[string]string{
	"dh":             "FFDH",
	"dhe":            "FFDH",
	"diffie-hellman": "FFDH",
	"diffiehellman":  "FFDH",
	"desede":         "3DES",
	"tripledes":      "3DES",
	"tdea":           "3DES",
	"ed25519":        "EdDSA",
	"ed448":          "EdDSA",
	"x25519":         "ECDH",
	"x448":           "ECDH",
}

var cdxAlgorithmFamilies = sync.OnceValue(func() map[string]string {
	var defs struct {
		Definitions struct {
			AlgorithmFamiliesEnum struct {
				Enum []string `json:"enum"`
			} `json:"algorithmFamiliesEnum"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal([]byte(cycloneDX17CryptographySchema), &defs); err != nil {
		return map[string]string{}
	}
	families := make(map[string]string, len(defs.Definitions.AlgorithmFamiliesEnum.Enum))
	for _, family := range defs.Definitions.AlgorithmFamiliesEnum.Enum {
		families[strings.ToLower(family)] = family
	}
	return families
})

// addAlgorithmFamily writes the rule's algorithm family, in its registry
// spelling when the registry or an alias names it. The schema only accepts
// registry spellings in algorithmFamily, so any other family goes to a
// scanoss property instead of failing the whole BOM.
func addAlgorithmFamily(component *cdx.Component, props *cdx.CryptoAlgorithmProperties, family string) {
	family = strings.TrimSpace(family)
	if family == "" {
		return
	}
	key := strings.ToLower(family)
	if alias, ok := algorithmFamilyAliases[key]; ok {
		key = strings.ToLower(alias)
	}
	if registered, ok := cdxAlgorithmFamilies()[key]; ok {
		props.AlgorithmFamily = registered
		return
	}
	addCustomProperty(component, scanossAlgorithmFamilyPropertyName, family)
}
