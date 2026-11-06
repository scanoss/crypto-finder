// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// Definition picks the first assignment of the file among every alias of the
// exports object, skips `void 0` forward declarations, follows an export
// assigned from another export, and takes the first of `Name.m` and
// `Name.prototype.m`.
func TestNodeShapesDefinitionTakesTheFirstAssignment(t *testing.T) {
	t.Parallel()
	root := writeShapeFiles(t, map[string]string{
		"index.js": "var nacl = exports;\n" + //                 1
			"function early() {}\n" + //                         2
			"function late() {}\n" + //                          3
			"nacl.sign = early;\n" + //                          4
			"exports.sign = late;\n" + //                        5
			"exports.box = void 0;\n" + //                       6
			"exports.box = function box() {};\n" + //            7
			"nacl.after = nacl.box;\n" + //                      8
			"function Ctor() {}\n" + //                          9
			"Ctor.prototype.m = function () {};\n" + //          10
			"Ctor.m = function () {};\n" + //                    11
			"exports.Ctor = Ctor;\n" + //                        12
			"module.exports.exports.exports = function () {};\n", // 13
	})
	s := NewNodeShapes()
	defer s.Close()
	file := filepath.Join(root, "index.js")

	for _, tc := range []struct {
		name    string
		members []string
		line    int
	}{
		{"sign", nil, 2},
		{"box", nil, 7},
		{"after", nil, 7},
		{"Ctor", []string{"m"}, 10},
		// The path is read from the first ".exports.exports": base "module", not an alias.
		{"exports", []string{"exports"}, 0},
	} {
		_, line, ok := s.Definition(file, tc.name, tc.members)
		if tc.line == 0 {
			if ok {
				t.Errorf("%s%v defined at line %d, want none", tc.name, tc.members, line)
			}
			continue
		}
		if !ok || line != tc.line {
			t.Errorf("%s%v defined at line %d (found %v), want %d", tc.name, tc.members, line, ok, tc.line)
		}
	}
}

// A bundle makes thousands of calls into itself that the parser cannot
// resolve, and each is looked up as an export of the bundle. The lookups must
// read the module's tree once, not once per call: per call, they made the call
// graph of a 1 MB bundle take 24 minutes.
func TestNodeShapesDefinitionWalksAModuleOnce(t *testing.T) {
	t.Parallel()
	var src strings.Builder
	src.WriteString("var lib = exports;\n")
	const exported = 200
	for i := range exported {
		fmt.Fprintf(&src, "function f%d() { return g%d(); }\nlib.f%d = f%d;\n", i, i, i, i)
	}
	root := writeShapeFiles(t, map[string]string{"bundle.js": src.String()})
	s := NewNodeShapes()
	defer s.Close()
	file := filepath.Join(root, "bundle.js")

	for i := range exported {
		if _, line, ok := s.Definition(file, fmt.Sprintf("f%d", i), nil); !ok || line != 2+2*i {
			t.Errorf("f%d defined at line %d (found %v), want %d", i, line, ok, 2+2*i)
		}
		if _, _, ok := s.Definition(file, fmt.Sprintf("g%d", i), nil); ok {
			t.Errorf("g%d resolved, want it left unresolved", i)
		}
	}
	if walks := s.modules[file].walks; walks != 1 {
		t.Errorf("%d Definition calls walked the module %d times, want 1", 2*exported, walks)
	}
}
