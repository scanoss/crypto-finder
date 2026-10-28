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

// cdxEnumField is a cryptoProperties field whose values the CycloneDX 1.7
// schema restricts to an enum. Rule metadata feeds these fields, so a value
// outside the enum is written as "other" and kept verbatim in property.
type cdxEnumField struct {
	properties string
	field      string
	property   string
}

var (
	primitiveField              = cdxEnumField{"algorithmProperties", "primitive", "scanoss:algorithmPrimitive"}
	modeField                   = cdxEnumField{"algorithmProperties", "mode", "scanoss:algorithmMode"}
	paddingField                = cdxEnumField{"algorithmProperties", "padding", "scanoss:algorithmPadding"}
	executionEnvironmentField   = cdxEnumField{"algorithmProperties", "executionEnvironment", "scanoss:executionEnvironment"}
	implementationPlatformField = cdxEnumField{"algorithmProperties", "implementationPlatform", "scanoss:implementationPlatform"}
	materialTypeField           = cdxEnumField{"relatedCryptoMaterialProperties", "type", "scanoss:materialType"}
)

const cdxEnumOther = "other"

// cdxCryptoEnums reads the enums of cryptoProperties from the embedded
// official schema, keyed by "<properties>.<field>" and then by lowercase value.
var cdxCryptoEnums = sync.OnceValue(func() map[string]map[string]string {
	var schema struct {
		Definitions struct {
			CryptoProperties struct {
				Properties map[string]struct {
					Properties map[string]struct {
						Enum []string `json:"enum"`
					} `json:"properties"`
				} `json:"properties"`
			} `json:"cryptoProperties"`
		} `json:"definitions"`
	}
	enums := map[string]map[string]string{}
	if err := json.Unmarshal([]byte(cycloneDX17Schema), &schema); err != nil {
		return enums
	}
	for group, groupSchema := range schema.Definitions.CryptoProperties.Properties {
		for field, fieldSchema := range groupSchema.Properties {
			if len(fieldSchema.Enum) == 0 {
				continue
			}
			values := make(map[string]string, len(fieldSchema.Enum))
			for _, value := range fieldSchema.Enum {
				values[strings.ToLower(value)] = value
			}
			enums[group+"."+field] = values
		}
	}
	return enums
})

// value returns the schema spelling of raw. Any other non-empty value becomes
// "other", and raw is recorded on component under the field's property.
func (f cdxEnumField) value(component *cdx.Component, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if value, ok := cdxCryptoEnums()[f.properties+"."+f.field][strings.ToLower(raw)]; ok {
		return value
	}
	addCustomProperty(component, f.property, raw)
	return cdxEnumOther
}
