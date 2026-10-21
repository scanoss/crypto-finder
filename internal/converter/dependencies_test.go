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
	"reflect"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func algorithmAsset(name, family, primitive string, dep *entities.DependencyInfo) entities.CryptographicAsset {
	return entities.CryptographicAsset{
		StartLine: 10,
		EndLine:   10,
		Match:     name + "()",
		Metadata: map[string]string{
			"assetType":          "algorithm",
			"algorithmName":      name,
			"algorithmFamily":    family,
			"algorithmPrimitive": primitive,
		},
		Rules:          []entities.RuleInfo{{ID: "rule." + name}},
		Source:         "dependency",
		DependencyInfo: dep,
	}
}

func TestConverter_LinksDependencyAssetsThroughTheGraph(t *testing.T) {
	bc := &entities.DependencyInfo{Module: "org.bouncycastle:bcprov-jdk18on", Version: "1.78", PURL: "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78"}
	codec := &entities.DependencyInfo{Module: "commons-codec:commons-codec", Version: "1.17.0", PURL: "pkg:maven/commons-codec/commons-codec@1.17.0"}
	report := &entities.InterimReport{
		Version: "1.7",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{
			{FilePath: "org/bouncycastle/A.java", Language: "java", CryptographicAssets: []entities.CryptographicAsset{
				algorithmAsset("AES", "AES", "block-cipher", bc),
				algorithmAsset("RSA", "RSA", "pke", bc),
			}},
			{FilePath: "org/apache/commons/codec/B.java", Language: "java", CryptographicAssets: []entities.CryptographicAsset{
				algorithmAsset("AES", "AES", "block-cipher", codec),
			}},
			{FilePath: "src/Main.java", Language: "java", CryptographicAssets: []entities.CryptographicAsset{
				algorithmAsset("MD5", "MD5", "hash", nil),
			}},
		},
	}

	bom, err := NewConverter().Convert(preparedReport(t, report))
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}

	refByName := map[string]string{}
	var libraries []cdx.Component
	for _, c := range *bom.Components {
		if c.Type == cdx.ComponentTypeLibrary {
			libraries = append(libraries, c)
			continue
		}
		refByName[c.Name] = c.BOMRef
	}
	if len(libraries) != 2 || libraries[0].PackageURL != codec.PURL || libraries[1].PackageURL != bc.PURL {
		t.Fatalf("libraries = %+v, want one per dependency, sorted by purl", libraries)
	}
	if libraries[1].BOMRef != bc.PURL || libraries[1].Name != bc.Module || libraries[1].Version != "1.78" {
		t.Errorf("bouncycastle library = %+v", libraries[1])
	}

	if bom.Dependencies == nil {
		t.Fatal("no dependency graph")
	}
	got := map[string][]string{}
	for _, d := range *bom.Dependencies {
		got[d.Ref] = *d.Dependencies
	}
	want := map[string][]string{
		codec.PURL: {refByName["AES"]},
		bc.PURL:    sortedRefs(refByName["AES"], refByName["RSA"]),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dependencies = %v, want %v (MD5 is project code and belongs to no library)", got, want)
	}
}

func TestConverter_NoDependencyGraphForProjectCode(t *testing.T) {
	report := &entities.InterimReport{
		Version: "1.7",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{FilePath: "src/Main.java", Language: "java", CryptographicAssets: []entities.CryptographicAsset{
			algorithmAsset("MD5", "MD5", "hash", nil),
		}}},
	}
	bom, err := NewConverter().Convert(preparedReport(t, report))
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if bom.Dependencies != nil || len(*bom.Components) != 1 {
		t.Errorf("components %d, dependencies %v; want the asset alone", len(*bom.Components), bom.Dependencies)
	}
}

func TestConverter_AlgorithmFamily(t *testing.T) {
	report := &entities.InterimReport{
		Version: "1.7",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{FilePath: "a.go", Language: "go", CryptographicAssets: []entities.CryptographicAsset{
			algorithmAsset("SHA-256", "sha-2", "hash", nil),
			algorithmAsset("RSA-2048", "RSA", "pke", nil),
		}}},
	}
	bom, err := NewConverter().Convert(preparedReport(t, report))
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	for _, c := range *bom.Components {
		family := c.CryptoProperties.AlgorithmProperties.AlgorithmFamily
		property := ""
		if c.Properties != nil {
			for _, p := range *c.Properties {
				if p.Name == scanossAlgorithmFamilyPropertyName {
					property = p.Value
				}
			}
		}
		switch c.Name {
		case "SHA-256":
			if family != "SHA-2" || property != "" {
				t.Errorf("SHA-256: algorithmFamily %q, property %q; want the registry spelling SHA-2", family, property)
			}
		case "RSA-2048":
			if family != "" || property != "RSA" {
				t.Errorf("RSA-2048: algorithmFamily %q, property %q; RSA is not in the registry, so it goes to the property", family, property)
			}
		default:
			t.Errorf("unexpected component %q", c.Name)
		}
	}
}

func sortedRefs(a, b string) []string {
	if a > b {
		a, b = b, a
	}
	return []string{a, b}
}

func TestValidator_RejectsDanglingDependencyRefs(t *testing.T) {
	components := []cdx.Component{{Type: cdx.ComponentTypeLibrary, BOMRef: "pkg:npm/a@1", Name: "a", PackageURL: "pkg:npm/a@1"}}
	for _, deps := range [][]cdx.Dependency{
		{{Ref: "pkg:npm/b@1"}},
		{{Ref: "pkg:npm/a@1", Dependencies: &[]string{"missing-asset"}}},
	} {
		bom := &cdx.BOM{Components: &components, Dependencies: &deps}
		if err := validateDependencyRefs(bom); err == nil {
			t.Errorf("%+v: want an error for a ref that names no component", deps)
		}
	}
}
