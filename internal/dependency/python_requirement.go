// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/scanoss/reach/purl"
)

// pyRequirement is one PEP 508 requirement: requests[socks]>=2.0 ; python_version >= "3.8".
type pyRequirement struct {
	// Name is PEP 503 normalised.
	Name   string
	Extras []string
	// Specifier is the version constraint without spaces or parentheses;
	// empty for none.
	Specifier string
	// Marker is the environment marker as written, trimmed.
	Marker string
	// URL is a direct reference (name @ url).
	URL string
}

var pyRequirementPattern = regexp.MustCompile(`^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[([^\]]*)\])?\s*(.*)$`)

// parsePyRequirement reads a PEP 508 requirement string. It reports false for
// a line that names no distribution.
func parsePyRequirement(raw string) (pyRequirement, bool) {
	body, marker, _ := strings.Cut(raw, ";")
	m := pyRequirementPattern.FindStringSubmatch(strings.TrimSpace(body))
	if m == nil {
		return pyRequirement{}, false
	}
	req := pyRequirement{Name: purl.PyPIName(m[1]), Marker: strings.TrimSpace(marker)}
	for _, extra := range strings.Split(m[2], ",") {
		if extra = strings.TrimSpace(extra); extra != "" {
			req.Extras = append(req.Extras, purl.PyPIName(extra))
		}
	}
	rest := strings.TrimSpace(m[3])
	if url, ok := strings.CutPrefix(rest, "@"); ok {
		req.URL = strings.TrimSpace(url)
		return req, true
	}
	rest = strings.TrimSuffix(strings.TrimPrefix(rest, "("), ")")
	req.Specifier = strings.Join(strings.Fields(rest), "")
	return req, true
}

var pyPinPattern = regexp.MustCompile(`^===?([^,*<>=!~]+)$`)

// pinnedPyVersion returns the version an exact specifier (==X or ===X, one
// clause, no wildcard) pins, as written.
func pinnedPyVersion(specifier string) (string, bool) {
	m := pyPinPattern.FindStringSubmatch(specifier)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// pyExtraMarker is the marker of a requirement an extra brings in, joined to
// the requirement's own marker, in the form Requires-Dist writes it.
func pyExtraMarker(extra, marker string) string {
	if extra == "" {
		return marker
	}
	m := fmt.Sprintf("extra == %q", extra)
	switch {
	case marker == "":
		return m
	case strings.Contains(marker, " or "):
		return m + " and (" + marker + ")"
	default:
		return m + " and " + marker
	}
}

// addSorted adds values to set, keeping it sorted and without duplicates or
// empty strings.
func addSorted(set []string, values ...string) []string {
	for _, v := range values {
		if v == "" {
			continue
		}
		if i, found := slices.BinarySearch(set, v); !found {
			set = slices.Insert(set, i, v)
		}
	}
	return set
}
