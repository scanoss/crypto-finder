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

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/static-engine/failure"
)

func TestConvertCommand_InputFailuresAreTyped(t *testing.T) {
	dir := t.TempDir()
	malformed := filepath.Join(dir, "results.json")
	if err := os.WriteFile(malformed, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	convertOutput = filepath.Join(dir, "cbom.json")
	t.Cleanup(func() { convertOutput = "" })

	for _, tc := range []struct {
		name  string
		input string
	}{
		{"malformed JSON", malformed},
		{"missing file", filepath.Join(dir, "missing.json")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := runConvert(convertCmd, []string{tc.input})
			if err == nil {
				t.Fatal("convert succeeded")
			}
			var out bytes.Buffer
			renderJSONError(&out, err)
			var payload failure.Payload
			if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
				t.Fatalf("payload %q: %v", out.String(), err)
			}
			if payload.Code != failure.CodeInvalidArguments || payload.Stage != failure.StageInput {
				t.Errorf("payload %s, want code %s at stage %s", out.String(), failure.CodeInvalidArguments, failure.StageInput)
			}
		})
	}
}
