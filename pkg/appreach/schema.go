// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// ErrUnsupportedSchema reports producer data newer than this binary can
// interpret safely.
type ErrUnsupportedSchema struct {
	Schema    string
	Got       string
	Supported string
}

func (e *ErrUnsupportedSchema) Error() string {
	return fmt.Sprintf("unsupported %s schema version %q (supports up to %q)", e.Schema, e.Got, e.Supported)
}

// ValidateSchemaVersion accepts got when it has supported's prefix and major
// version and is not newer; otherwise it returns an *ErrUnsupportedSchema.
func ValidateSchemaVersion(schema, got, supported string) error {
	gotPrefix, gotVersion, gotErr := parseSchemaVersion(got)
	supportedPrefix, supportedVersion, supportedErr := parseSchemaVersion(supported)
	if gotErr != nil || supportedErr != nil || gotPrefix != supportedPrefix || gotVersion.Major() != supportedVersion.Major() || gotVersion.GreaterThan(supportedVersion) {
		return &ErrUnsupportedSchema{Schema: schema, Got: got, Supported: supported}
	}
	return nil
}

func parseSchemaVersion(raw string) (string, *semver.Version, error) {
	prefix := ""
	version := raw
	if i := strings.LastIndex(raw, "-"); i >= 0 {
		prefix, version = raw[:i+1], raw[i+1:]
	}
	parsed, err := semver.NewVersion(version)
	return prefix, parsed, err
}
