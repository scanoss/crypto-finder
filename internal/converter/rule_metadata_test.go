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
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func convertAssets(t *testing.T, files map[string][]entities.CryptographicAsset) map[string]cdx.Component {
	t.Helper()
	report := &entities.InterimReport{Version: "1.1", Tool: entities.ToolInfo{Name: "test", Version: "1.0"}}
	for path, assets := range files {
		report.Findings = append(report.Findings, entities.Finding{FilePath: path, Language: "java", CryptographicAssets: assets})
	}
	bom, err := NewConverter().Convert(preparedReport(t, report))
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	components := map[string]cdx.Component{}
	for _, component := range *bom.Components {
		if _, dup := components[component.Name]; dup {
			t.Fatalf("two components named %q", component.Name)
		}
		components[component.Name] = component
	}
	return components
}

func ruleAsset(line int, ruleID string, metadata map[string]string) entities.CryptographicAsset {
	return entities.CryptographicAsset{
		StartLine: line,
		EndLine:   line,
		Match:     "call()",
		Rules:     []entities.RuleInfo{{ID: ruleID, Severity: "INFO"}},
		Metadata:  metadata,
	}
}

func property(component cdx.Component, name string) string {
	if component.Properties == nil {
		return ""
	}
	for _, p := range *component.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

func occurrenceCount(component cdx.Component) int {
	if component.Evidence == nil || component.Evidence.Occurrences == nil {
		return 0
	}
	return len(*component.Evidence.Occurrences)
}

func TestConverter_OutOfEnumRuleMetadataBecomesOther(t *testing.T) {
	components := convertAssets(t, map[string][]entities.CryptographicAsset{"Cipher.java": {
		ruleAsset(3, "cipher", map[string]string{
			"assetType":              "algorithm",
			"algorithmName":          "RSA-OAEP",
			"algorithmFamily":        "RSAES-OAEP",
			"algorithmPrimitive":     "key-transport",
			"algorithmMode":          "XTS",
			"algorithmPadding":       "OAEPWithSHA-",
			"executionEnvironment":   "cloud-hsm",
			"implementationPlatform": "riscv64",
		}),
		ruleAsset(5, "key", map[string]string{
			"assetType":    "related-crypto-material",
			"materialType": "key-pair",
		}),
	}})

	algorithm := components["RSA-OAEP"].CryptoProperties.AlgorithmProperties
	if algorithm.Primitive != "other" || algorithm.Mode != "other" || algorithm.Padding != "other" ||
		algorithm.ExecutionEnvironment != "other" || algorithm.ImplementationPlatform != "other" {
		t.Errorf("algorithm enums = %q %q %q %q %q, want all other", algorithm.Primitive, algorithm.Mode,
			algorithm.Padding, algorithm.ExecutionEnvironment, algorithm.ImplementationPlatform)
	}
	for name, want := range map[string]string{
		"scanoss:algorithmPrimitive":     "key-transport",
		"scanoss:algorithmMode":          "XTS",
		"scanoss:algorithmPadding":       "OAEPWithSHA-",
		"scanoss:executionEnvironment":   "cloud-hsm",
		"scanoss:implementationPlatform": "riscv64",
	} {
		if got := property(components["RSA-OAEP"], name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}

	material := components["key-pair"]
	if got := material.CryptoProperties.RelatedCryptoMaterialProperties.Type; got != "other" {
		t.Errorf("material type = %q, want other", got)
	}
	if got := property(material, "scanoss:materialType"); got != "key-pair" {
		t.Errorf("scanoss:materialType = %q, want key-pair", got)
	}
}

func TestConverter_KeysGroupedByAlgorithmSizeAndCurve(t *testing.T) {
	key := func(line int, algorithm, size, curve string) entities.CryptographicAsset {
		return ruleAsset(line, "keygen", map[string]string{
			"assetType": "related-crypto-material", "materialType": "key",
			"materialAlgorithm": algorithm, "materialSize": size, "materialCurve": curve,
		})
	}
	secret := func(line int, algorithm, size string) entities.CryptographicAsset {
		return ruleAsset(line, "secret", map[string]string{
			"assetType": "related-crypto-material", "materialType": "secret-key",
			"materialAlgorithm": algorithm, "materialSize": size,
		})
	}
	components := convertAssets(t, map[string][]entities.CryptographicAsset{
		"A.java": {key(1, "RSA", "2048", ""), key(2, "RSA", "3072", ""), key(3, "EC", "384", "secp384r1"), secret(4, "AES", "256"), secret(5, "AES", "")},
		"B.java": {key(1, "RSA", "2048", ""), key(2, "", "", ""), secret(3, "", "128")},
	})

	for name, want := range map[string]struct {
		size        int
		occurrences int
		algorithm   string
		curve       string
	}{
		"RSA-2048-key":       {2048, 2, "RSA", ""},
		"RSA-3072-key":       {3072, 1, "RSA", ""},
		"EC-secp384r1-key":   {384, 1, "EC", "secp384r1"},
		"AES-256-secret-key": {256, 1, "AES", ""},
		"AES-secret-key":     {0, 1, "AES", ""},
		"128-secret-key":     {128, 1, "", ""},
		"key":                {0, 1, "", ""},
	} {
		component, ok := components[name]
		if !ok {
			t.Errorf("no component %q", name)
			continue
		}
		size := 0
		if s := component.CryptoProperties.RelatedCryptoMaterialProperties.Size; s != nil {
			size = *s
		}
		if size != want.size || occurrenceCount(component) != want.occurrences ||
			property(component, "scanoss:materialAlgorithm") != want.algorithm || property(component, "scanoss:curve") != want.curve {
			t.Errorf("%s: size %d, occurrences %d, algorithm %q, curve %q; want %+v", name, size, occurrenceCount(component),
				property(component, "scanoss:materialAlgorithm"), property(component, "scanoss:curve"), want)
		}
	}
	if len(components) != 7 {
		t.Errorf("got %d components, want 7", len(components))
	}
}

func TestConverter_RuleFamilySpellingsUseRegistryEntry(t *testing.T) {
	agreement := func(line int, name, family string) entities.CryptographicAsset {
		return ruleAsset(line, "agree", map[string]string{
			"assetType": "algorithm", "algorithmName": name, "algorithmFamily": family, "algorithmPrimitive": "key-agree",
		})
	}
	components := convertAssets(t, map[string][]entities.CryptographicAsset{"Agree.java": {
		agreement(1, "DH", "DH"),
		agreement(2, "DiffieHellman", "Diffie-Hellman"),
		agreement(3, "X25519", "X25519"),
	}})

	for name, want := range map[string]string{"DH": "FFDH", "DiffieHellman": "FFDH", "X25519": "ECDH"} {
		component := components[name]
		if got := component.CryptoProperties.AlgorithmProperties.AlgorithmFamily; got != want {
			t.Errorf("%s algorithmFamily = %q, want %q", name, got, want)
		}
		if got := property(component, scanossAlgorithmFamilyPropertyName); got != "" {
			t.Errorf("%s %s = %q, want none", name, scanossAlgorithmFamilyPropertyName, got)
		}
	}
}

func TestConverter_UnresolvedAlgorithmCallsKeptPerPrimitive(t *testing.T) {
	unresolved := func(line int, primitive string) entities.CryptographicAsset {
		return ruleAsset(line, "dynamic", map[string]string{
			"assetType": "algorithm", "algorithmPrimitive": primitive, "api": "getInstance",
		})
	}
	components := convertAssets(t, map[string][]entities.CryptographicAsset{
		"A.java": {unresolved(1, "block-cipher"), unresolved(2, "hash"), ruleAsset(3, "sha", map[string]string{
			"assetType": "algorithm", "algorithmName": "SHA-256", "algorithmFamily": "SHA-2", "algorithmPrimitive": "hash",
		})},
		"B.java": {unresolved(1, "block-cipher")},
	})

	for name, want := range map[string]struct {
		primitive   cdx.CryptoPrimitive
		occurrences int
		unresolved  string
	}{
		"unknown-block-cipher": {cdx.CryptoPrimitiveBlockCipher, 2, "true"},
		"unknown-hash":         {cdx.CryptoPrimitiveHash, 1, "true"},
		"SHA-256":              {cdx.CryptoPrimitiveHash, 1, ""},
	} {
		component, ok := components[name]
		if !ok {
			t.Errorf("no component %q", name)
			continue
		}
		if got := component.CryptoProperties.AlgorithmProperties.Primitive; got != want.primitive {
			t.Errorf("%s primitive = %q, want %q", name, got, want.primitive)
		}
		if got := occurrenceCount(component); got != want.occurrences {
			t.Errorf("%s occurrences = %d, want %d", name, got, want.occurrences)
		}
		if got := property(component, scanossUnresolvedPropertyName); got != want.unresolved {
			t.Errorf("%s %s = %q, want %q", name, scanossUnresolvedPropertyName, got, want.unresolved)
		}
	}
}
