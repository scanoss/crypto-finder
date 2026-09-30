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

package entrypoints

import (
	"strings"
	"testing"
	"testing/fstest"
)

const expressYAML = `schema_version: "1"
language: node
framework:
  name: express
entries:
  - shape: registration_call
    from: [express]
    names: [get, use]
    root_kind: framework_entry
`

// TestLoadEmbedded: the catalog built into the binary loads, and matching
// goes through the package, never the bare name.
func TestLoadEmbedded(t *testing.T) {
	t.Parallel()
	catalog, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	for _, tc := range []struct {
		language string
		shape    Shape
		pkg      string
		typeName string
		name     string
		want     bool
	}{
		{"java", ShapeDecorator, "org.springframework.web.bind.annotation", "", "GetMapping", true},
		{"java", ShapeDecorator, "com.acme.web", "", "GetMapping", false},
		{"java", ShapeSupertype, "jakarta.servlet.http", "HttpServlet", "doPost", true},
		{"java", ShapeSupertype, "com.acme.http", "HttpServlet", "doPost", false},
	} {
		if _, got := catalog.Match(tc.language, tc.shape, tc.pkg, tc.typeName, tc.name); got != tc.want {
			t.Errorf("Match(%s, %s, %q, %q, %q) = %v, want %v", tc.language, tc.shape, tc.pkg, tc.typeName, tc.name, got, tc.want)
		}
	}
}

// TestLoad_RejectsMalformedFiles: a file that the parsers would read
// differently from what it says, or not at all, fails to load.
func TestLoad_RejectsMalformedFiles(t *testing.T) {
	t.Parallel()
	header := "schema_version: \"1\"\nlanguage: node\nframework:\n  name: x\nentries:\n"
	for name, tc := range map[string]struct{ yaml, want string }{
		"yaml syntax":       {header + "  - shape: [\n", "yaml"},
		"schema version":    {strings.Replace(expressYAML, `"1"`, `"2"`, 1), "schema_version"},
		"unknown language":  {strings.Replace(expressYAML, "language: node", "language: cobol", 1), "unsupported language"},
		"no framework name": {strings.Replace(expressYAML, "name: express", "name: \"\"", 1), "framework.name"},
		"no entries":        {"schema_version: \"1\"\nlanguage: node\nframework:\n  name: x\n", "entries"},
		"unknown field":     {strings.Replace(expressYAML, "root_kind:", "method: get\n    root_kind:", 1), "method"},
		"shape for language": {
			header + "  - shape: handler_field\n    from: [x]\n    types: [T]\n    names: [Run]\n    root_kind: framework_entry\n",
			"not recognized for node",
		},
		"no from":       {strings.Replace(expressYAML, "    from: [express]\n", "", 1), "from"},
		"no names":      {strings.Replace(expressYAML, "    names: [get, use]\n", "", 1), "names"},
		"bad root kind": {strings.Replace(expressYAML, "framework_entry", "route", 1), "root_kind"},
		"bad path":      {strings.Replace(expressYAML, "root_kind:", "path: sometimes\n    root_kind:", 1), "path must be"},
		"field of other shape": {
			header + "  - shape: decorator\n    from: [x]\n    names: [Get]\n    path: required\n    root_kind: framework_entry\n",
			"not read by shape",
		},
		"wildcard outside supertype": {strings.Replace(expressYAML, "names: [get, use]", `names: ["*"]`, 1), "only valid"},
		"empty value":                {strings.Replace(expressYAML, "names: [get, use]", `names: [get, ""]`, 1), "empty value"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := Load("node/x.yaml", []byte(tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load error = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}

// TestLoadFS_DetectsConflicts: every name has one owner file, and a file's
// language is its directory.
func TestLoadFS_DetectsConflicts(t *testing.T) {
	t.Parallel()
	koaClaimingExpress := strings.Replace(expressYAML, "name: express", "name: koa", 1)
	for name, tc := range map[string]struct {
		files fstest.MapFS
		want  []string
	}{
		"same name from same package": {
			files: fstest.MapFS{"node/express.yaml": {Data: []byte(expressYAML)}, "node/koa.yaml": {Data: []byte(koaClaimingExpress)}},
			want:  []string{"node/express.yaml", "node/koa.yaml", `"get"`},
		},
		"same framework twice": {
			files: fstest.MapFS{"node/express.yaml": {Data: []byte(expressYAML)}, "node/express-4.yaml": {Data: []byte(strings.Replace(expressYAML, "[express]", "[express4]", 1))}},
			want:  []string{"node/express.yaml", "node/express-4.yaml", "node/express"},
		},
		"language is not the directory": {
			files: fstest.MapFS{"python/express.yaml": {Data: []byte(expressYAML)}},
			want:  []string{"does not match its directory"},
		},
		"malformed file": {
			files: fstest.MapFS{"node/express.yaml": {Data: []byte("schema_version: [")}},
			want:  []string{"node/express.yaml"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := LoadFS(tc.files)
			if err == nil {
				t.Fatal("LoadFS succeeded, want an error")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("LoadFS error = %v, want it to mention %q", err, want)
				}
			}
		})
	}

	// The same method name from two packages is two claims, not a conflict.
	koa := strings.NewReplacer("name: express", "name: koa", "[express]", "[koa]").Replace(expressYAML)
	catalog, err := LoadFS(fstest.MapFS{"node/express.yaml": {Data: []byte(expressYAML)}, "node/koa.yaml": {Data: []byte(koa)}})
	if err != nil {
		t.Fatalf("LoadFS: %v", err)
	}
	if entry, ok := catalog.Match("node", ShapeRegistrationCall, "koa", "", "get"); !ok || entry.Framework != "koa" || entry.Path != PathRequired {
		t.Errorf("Match(koa get) = %+v, %v; want the koa entry with the default path rule", entry, ok)
	}
}
