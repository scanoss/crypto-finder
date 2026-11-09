// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package pqc

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/oid"
)

func TestAnnotate(t *testing.T) {
	asset := func(m map[string]string) entities.CryptographicAsset { return entities.CryptographicAsset{Metadata: m} }
	report := &entities.InterimReport{Findings: []entities.Finding{{CryptographicAssets: []entities.CryptographicAsset{
		asset(map[string]string{"algorithmFamily": "RSAES-OAEP"}),
		asset(map[string]string{"algorithmName": "RSA-PKCS1v15-SHA256"}),
		asset(map[string]string{"algorithmFamily": "SHA-2"}),
		asset(map[string]string{"algorithmFamily": "HPKE"}),
		asset(map[string]string{"api": "no algorithm identity"}),
	}}}}
	Annotate((*oid.ResolvedReport)(report))
	a := report.Findings[0].CryptographicAssets

	for _, i := range []int{0, 1} {
		c := a[i].PQC
		if c == nil || c.Status != "vulnerable" || c.Family != "RSA" || c.Deadline != 2030 || len(c.Deadlines) != 2 || c.DatasetVersion == "" {
			t.Fatalf("asset %d: %+v", i, c)
		}
		if cnsa := c.Deadlines[0]; cnsa.Source != "CNSA 2.0" || cnsa.MigrateBy != 2030 || !strings.HasPrefix(cnsa.Citation, "CNSA 2.0") {
			t.Errorf("asset %d CNSA: %+v", i, cnsa)
		}
		if nist := c.Deadlines[1]; nist.Source != "NIST IR 8547" || nist.DeprecatedAfter != 2030 || nist.DisallowedAfter != 2035 {
			t.Errorf("asset %d NIST: %+v", i, nist)
		}
		for k := range a[i].Metadata {
			if strings.HasPrefix(k, "pqc") {
				t.Errorf("asset %d: classification written into metadata: %v", i, a[i].Metadata)
			}
		}
	}
	if c := a[2].PQC; c == nil || c.Status != "not_applicable" || c.Deadline != 0 || c.Deadlines != nil {
		t.Errorf("SHA-2: %+v", c)
	}
	if c := a[3].PQC; c == nil || c.Status != "unassessed" || c.Family != "" {
		t.Errorf("HPKE: %+v", c)
	}
	if a[4].PQC != nil {
		t.Errorf("an asset naming no algorithm was classified: %+v", a[4].PQC)
	}
}

func TestProperties(t *testing.T) {
	props := map[string]string{}
	for _, p := range Properties(Classify(map[string]string{"algorithmFamily": "RSAES-OAEP"})) {
		props[p.Name] = p.Value
	}
	for name, want := range map[string]string{
		"scanoss:pqcStatus": "vulnerable", "scanoss:pqcFamily": "RSA", "scanoss:pqcDeadline": "2030",
		"scanoss:pqcNISTDeprecatedAfter": "2030", "scanoss:pqcNISTDisallowedAfter": "2035", "scanoss:pqcCNSAMigrateBy": "2030",
	} {
		if props[name] != want {
			t.Errorf("%s = %q, want %q", name, props[name], want)
		}
	}
	if !strings.HasPrefix(props["scanoss:pqcCNSACitation"], "CNSA 2.0") || !strings.HasPrefix(props["scanoss:pqcNISTCitation"], "NIST IR 8547") {
		t.Errorf("citations = %q / %q", props["scanoss:pqcCNSACitation"], props["scanoss:pqcNISTCitation"])
	}
	if _, ok := props["scanoss:pqcNISTMigrateBy"]; ok || props["scanoss:pqcDatasetVersion"] == "" {
		t.Errorf("properties = %v", props)
	}
	if Properties(nil) != nil {
		t.Error("nil classification produced properties")
	}
}

func TestCurrent(t *testing.T) {
	metadata := map[string]string{"algorithmFamily": "RSAES-OAEP"}
	for _, version := range []string{"0.9.0", "", "bad"} {
		asset := &entities.CryptographicAsset{Metadata: metadata, PQC: &entities.PQCClassification{Status: "unassessed", DatasetVersion: version}}
		if c := Current(asset); c == nil || c.Status != "vulnerable" {
			t.Errorf("version %q: not recomputed: %+v", version, c)
		}
	}
	newer := &entities.PQCClassification{Status: "kept", DatasetVersion: "99.0.0"}
	if c := Current(&entities.CryptographicAsset{Metadata: metadata, PQC: newer}); c != newer {
		t.Errorf("newer classification replaced: %+v", c)
	}
	if c := Current(&entities.CryptographicAsset{Metadata: metadata}); c == nil || c.Status != "vulnerable" {
		t.Errorf("missing classification not computed: %+v", c)
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0}, {"1.0.0", "1.1.0", -1}, {"1.10.0", "1.9.0", 1}, {"bad", "1.0.0", -1}, {"1.0.0", "bad", 1},
	} {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
