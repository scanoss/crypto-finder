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

// addAlgorithmFamily writes the rule's algorithm family. The schema only
// accepts registry spellings in algorithmFamily, so any other family goes to
// a scanoss property instead of failing the whole BOM.
func addAlgorithmFamily(component *cdx.Component, props *cdx.CryptoAlgorithmProperties, family string) {
	family = strings.TrimSpace(family)
	if family == "" {
		return
	}
	if registered, ok := cdxAlgorithmFamilies()[strings.ToLower(family)]; ok {
		props.AlgorithmFamily = registered
		return
	}
	addCustomProperty(component, scanossAlgorithmFamilyPropertyName, family)
}
