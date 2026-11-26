// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package pqc

import (
	"encoding/json"
	"strings"
	"testing"

	pqcdataset "github.com/scanoss/crypto-pqc-dataset"
)

const rsaMetadata = `{"assetType":"algorithm","algorithmFamily":"RSAES-OAEP","algorithmName":"RSA-OAEP","materialSize":2048}`

func TestCurrentComputesMissingClassification(t *testing.T) {
	c := Current(nil, json.RawMessage(rsaMetadata))
	if c == nil || c.Status != "vulnerable" || c.Family != "RSA" || c.Deadline != 2030 ||
		len(c.Deadlines) != 2 || c.DatasetVersion != pqcdataset.Version() {
		t.Fatalf("RSA-OAEP = %+v", c)
	}
	if cnsa := c.Deadlines[0]; cnsa.Source != "CNSA 2.0" || cnsa.MigrateBy != 2030 || !strings.HasPrefix(cnsa.Citation, "CNSA 2.0") {
		t.Errorf("CNSA deadline = %+v", cnsa)
	}
	if nist := c.Deadlines[1]; nist.Source != "NIST IR 8547" || nist.DeprecatedAfter != 2030 || nist.DisallowedAfter != 2035 {
		t.Errorf("NIST deadline = %+v", nist)
	}
}

func TestCurrentKeepsCurrentOrNewerMinedClassification(t *testing.T) {
	for _, version := range []string{pqcdataset.Version(), "99.0.0"} {
		mined := &Classification{Status: "mined", DatasetVersion: version}
		if got := Current(mined, json.RawMessage(rsaMetadata)); got != mined {
			t.Errorf("version %s: mined classification replaced by %+v", version, got)
		}
	}
}

func TestCurrentRecomputesOlderMinedClassification(t *testing.T) {
	for _, version := range []string{"0.9.0", "", "not-a-version"} {
		mined := &Classification{Status: "unassessed", DatasetVersion: version}
		if got := Current(mined, json.RawMessage(rsaMetadata)); got == nil || got.Status != "vulnerable" || got.DatasetVersion != pqcdataset.Version() {
			t.Errorf("version %q: not recomputed: %+v", version, got)
		}
	}
}

// A hybrid KEM mined as safe under dataset 1.0.0, which read its ML-KEM family first.
func TestCurrentRecomputesAHybridKEMMinedAsSafe(t *testing.T) {
	metadata := json.RawMessage(`{"assetType":"algorithm","algorithmFamily":"ML-KEM","algorithmName":"X25519MLKEM768","classicalAlgorithm":"X25519"}`)
	mined := &Classification{Status: "safe", Family: "ML-KEM", DatasetVersion: "1.0.0"}
	got := Current(mined, metadata)
	if got == nil || got.Status != "hybrid" || got.Family != "X25519MLKEM768" || got.DatasetVersion != pqcdataset.Version() {
		t.Errorf("hybrid KEM = %+v", got)
	}
}

func TestCurrentWithoutAlgorithm(t *testing.T) {
	if c := Current(nil, json.RawMessage(`{"assetType":"protocol","protocolType":"tls"}`)); c != nil {
		t.Errorf("a protocol naming no algorithm was classified: %+v", c)
	}
	if c := Current(nil, json.RawMessage(`not json`)); c != nil {
		t.Errorf("malformed metadata was classified: %+v", c)
	}
	if c := Current(nil, json.RawMessage(`{"algorithmFamily":"Kupyna"}`)); c == nil || c.Status != "unassessed" || c.Family != "" {
		t.Errorf("unknown algorithm = %+v", c)
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.1.0", -1},
		{"1.10.0", "1.9.0", 1},
		{"2.0.0", "1.99.99", 1},
		{"bad", "1.0.0", -1},
		{"1.0.0", "bad", 1},
		{"1.0", "1.0.0", -1},
	} {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
