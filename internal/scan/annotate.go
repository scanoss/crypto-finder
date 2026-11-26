// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/scanoss/reach/graphfrag"
)

// MarshalAnnotateExport serializes an annotate-only graph-fragment export as
// indented JSON, matching the formatting of ExportResolvedGraphFragment.
func MarshalAnnotateExport(payload *graphfrag.GraphFragmentExport) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return nil, fmt.Errorf("scan: failed to serialize annotation export: %w", err)
	}
	return buf.Bytes(), nil
}

// WriteAnnotateExport writes an annotate-only graph-fragment export to path as
// indented JSON, matching the formatting of ExportResolvedGraphFragment.
func WriteAnnotateExport(path string, payload *graphfrag.GraphFragmentExport) error {
	if err := writeIndentedJSONFile(path, payload); err != nil {
		return fmt.Errorf("scan: failed to write annotation to %s: %w", path, err)
	}
	return nil
}
