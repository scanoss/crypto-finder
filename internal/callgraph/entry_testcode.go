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

package callgraph

import (
	"path/filepath"
	"strings"
)

// testAnnotations mark Java test and test-fixture methods (JUnit 4 and 5,
// TestNG). A test runner calls them, but they are not the application.
var testAnnotations = map[string]bool{
	"Test": true, "ParameterizedTest": true, "RepeatedTest": true, "TestFactory": true,
	"TestTemplate": true, "BeforeEach": true, "AfterEach": true, "BeforeAll": true,
	"AfterAll": true, "Before": true, "After": true, "BeforeClass": true, "AfterClass": true,
	"BeforeMethod": true, "AfterMethod": true, "BeforeSuite": true, "AfterSuite": true,
	"BeforeTest": true, "AfterTest": true, "DataProvider": true,
}

// isTestDeclaration reports whether decl is test code: a test annotation, or
// a file in a test source location. A test is never an entry point, so a test
// method nothing calls stays a no_callers root and a test doing crypto inline
// stays unreachable. Test sources are only in the graph under --include-tests.
func isTestDeclaration(decl *FunctionDecl) bool {
	for _, annotation := range decl.Annotations {
		if testAnnotations[annotation] {
			return true
		}
	}
	return isTestSourcePath(decl.FilePath)
}

// isTestSourcePath follows the built-in test exclusions (skip.
// DefaultSkippedTestPatterns) plus the Node and Python test file names.
func isTestSourcePath(path string) bool {
	if path == "" {
		return false
	}
	slashed := "/" + filepath.ToSlash(path)
	for _, dir := range []string{"/test/", "/tests/", "/__tests__/"} {
		if strings.Contains(slashed, dir) {
			return true
		}
	}
	base := strings.ToLower(filepath.Base(slashed))
	switch {
	case strings.HasSuffix(base, "test.java"), strings.HasSuffix(base, "tests.java"),
		strings.HasSuffix(base, "_test.go"), strings.HasSuffix(base, "_test.py"),
		strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py"), base == "conftest.py",
		strings.Contains(base, ".test."), strings.Contains(base, ".spec."):
		return true
	}
	return false
}
