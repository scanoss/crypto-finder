// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package pqc classifies served findings for post-quantum risk with the shared
// PQC dataset, so a dataset release reaches mined findings without re-mining.
// The application reachability response (pkg/appreach) serves its blocks; the
// SCANOSS API and the offline client therefore classify alike.
package pqc

import (
	"encoding/json"
	"strconv"
	"strings"

	pqcdataset "github.com/scanoss/crypto-pqc-dataset"
)

// Classification is one finding's post-quantum block, as crypto-finder writes
// it into the scan report and the API serves it.
type Classification struct {
	Status string `json:"status"`
	Family string `json:"family,omitempty"`
	// Deadline is the earliest year any source sets: the worst case.
	Deadline       int        `json:"deadline,omitempty"`
	Deadlines      []Deadline `json:"deadlines,omitempty"`
	DatasetVersion string     `json:"dataset_version"`
}

// Deadline is one source's cited schedule for the finding's family.
type Deadline struct {
	Source          string `json:"source"`
	DeprecatedAfter int    `json:"deprecated_after,omitempty"`
	DisallowedAfter int    `json:"disallowed_after,omitempty"`
	MigrateBy       int    `json:"migrate_by,omitempty"`
	Citation        string `json:"citation"`
}

// Classify classifies crypto-finder metadata. It returns nil when the
// metadata names no algorithm.
func Classify(metadata map[string]string) *Classification {
	if !pqcdataset.NamesAlgorithm(metadata) {
		return nil
	}
	c := &Classification{Status: string(pqcdataset.Unassessed), DatasetVersion: pqcdataset.Version()}
	f, ok := pqcdataset.Classify(metadata)
	if !ok {
		return c
	}
	c.Status, c.Family = string(f.PQCStatus), f.Name
	c.Deadline, _ = f.EarliestDeadline()
	for _, d := range f.Deadlines {
		c.Deadlines = append(c.Deadlines, Deadline(d))
	}
	return c
}

// Current returns the finding's classification: the mined one when the API's
// dataset version or a newer one produced it, recomputed from the metadata
// otherwise. Metadata values that are not strings are ignored.
func Current(mined *Classification, metadata json.RawMessage) *Classification {
	if mined != nil && compareVersions(mined.DatasetVersion, pqcdataset.Version()) >= 0 {
		return mined
	}
	var fields map[string]any
	if err := json.Unmarshal(metadata, &fields); err != nil {
		return nil
	}
	strs := make(map[string]string, len(fields))
	for k, v := range fields {
		if s, ok := v.(string); ok {
			strs[k] = s
		}
	}
	return Classify(strs)
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
