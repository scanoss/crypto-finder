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
	"testing"
)

// TestNewBuilderForEcosystem_Python_DoesNotPanic guards REQ-1.5.
// NewBuilderForEcosystem("python", ...) must construct a Builder without panicking.
// Full KB-load assertion is deferred to once the YAML exists (T-1.3); this test
// confirms the constructor wires correctly and is RED until the constructor is added.
func TestNewBuilderForEcosystem_Python_DoesNotPanic(t *testing.T) {
	t.Parallel()

	// Must not panic. NewBuilderForEcosystem does not exist yet — this test is RED
	// until T-1.4 implements it.
	builder := NewBuilderForEcosystem("python", NewPythonParser())
	if builder == nil {
		t.Fatal("NewBuilderForEcosystem(\"python\", ...) returned nil, expected non-nil *Builder")
	}
}

// TestNewBuilderForEcosystem_Java_Backward_Compat verifies that after the
// NewBuilderForEcosystem constructor is added, the existing NewBuilder
// still behaves identically (backward-compatible). Java tests must not regress.
func TestNewBuilderForEcosystem_Java_Backward_Compat(t *testing.T) {
	t.Parallel()

	// NewBuilder is the backward-compatible constructor (ecosystem="").
	builder := NewBuilder(NewJavaParser())
	if builder == nil {
		t.Fatal("NewBuilder returned nil — backward compat broken")
	}
}
