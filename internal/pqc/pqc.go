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

// Package pqc writes the shared PQC dataset's classification onto scan output.
package pqc

import (
	"strconv"
	"strings"

	pqcdataset "github.com/scanoss/crypto-pqc-dataset"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/oid"
)

// Classify classifies an asset from its metadata. It returns nil when the
// metadata names no algorithm.
func Classify(metadata map[string]string) *entities.PQCClassification {
	if !pqcdataset.NamesAlgorithm(metadata) {
		return nil
	}
	c := &entities.PQCClassification{Status: string(pqcdataset.Unassessed), DatasetVersion: pqcdataset.Version()}
	family, ok := pqcdataset.Classify(metadata)
	if !ok {
		return c
	}
	c.Status, c.Family = string(family.PQCStatus), family.Name
	c.Deadline, _ = family.EarliestDeadline()
	for _, d := range family.Deadlines {
		c.Deadlines = append(c.Deadlines, entities.PQCDeadline(d))
	}
	return c
}

// Current returns an asset's classification: the one it carries when this
// binary's dataset version or a newer one produced it, recomputed from the
// metadata otherwise.
func Current(asset *entities.CryptographicAsset) *entities.PQCClassification {
	if asset.PQC != nil && compareVersions(asset.PQC.DatasetVersion, pqcdataset.Version()) >= 0 {
		return asset.PQC
	}
	return Classify(asset.Metadata)
}

// compareVersions compares two MAJOR.MINOR.PATCH versions; an unparsable one
// sorts first, so it is recomputed.
func compareVersions(a, b string) int {
	pa, okA := parseVersion(a)
	pb, okB := parseVersion(b)
	switch {
	case !okA && !okB:
		return 0
	case !okA:
		return -1
	case !okB:
		return 1
	}
	for i := range 3 {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parseVersion(v string) ([]int, bool) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return nil, false
	}
	out := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

// Annotate sets the classification of every asset that names an algorithm.
func Annotate(report *oid.ResolvedReport) {
	if report == nil {
		return
	}
	for i := range report.Findings {
		assets := report.Findings[i].CryptographicAssets
		for j := range assets {
			assets[j].PQC = Classify(assets[j].Metadata)
		}
	}
}

// Property is one CBOM property of a classification.
type Property struct {
	Name  string
	Value string
}

// sourceKeys names the CBOM properties of each source's schedule; a source
// the dataset adds later is reported through the earliest deadline only.
var sourceKeys = map[string]struct{ deprecatedAfter, disallowedAfter, migrateBy, citation string }{
	pqcdataset.SourceNISTIR8547: {deprecatedAfter: "NISTDeprecatedAfter", disallowedAfter: "NISTDisallowedAfter", citation: "NISTCitation"},
	pqcdataset.SourceCNSA2:      {migrateBy: "CNSAMigrateBy", citation: "CNSACitation"},
}

// Properties flattens a classification into CBOM properties, in a stable
// order, since CycloneDX properties are flat name-value pairs.
func Properties(c *entities.PQCClassification) []Property {
	if c == nil {
		return nil
	}
	const prefix = "scanoss:pqc"
	props := []Property{{prefix + "Status", c.Status}}
	add := func(key, value string) {
		if key != "" && value != "" && value != "0" {
			props = append(props, Property{prefix + key, value})
		}
	}
	add("Family", c.Family)
	add("Deadline", strconv.Itoa(c.Deadline))
	for _, d := range c.Deadlines {
		keys, known := sourceKeys[d.Source]
		if !known {
			continue
		}
		add(keys.deprecatedAfter, strconv.Itoa(d.DeprecatedAfter))
		add(keys.disallowedAfter, strconv.Itoa(d.DisallowedAfter))
		add(keys.migrateBy, strconv.Itoa(d.MigrateBy))
		add(keys.citation, d.Citation)
	}
	return append(props, Property{prefix + "DatasetVersion", c.DatasetVersion})
}
