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

//go:build ignore

// generate_fixture.go generates the synthetic Python module corpus used by
// BenchmarkPythonParseDirectory_Bindings (python_perf_test.go). The generated
// corpus is intentionally NOT committed — it is large, purely mechanical,
// and reproducible on demand.
//
// Usage: go run generate_fixture.go
// Or via go generate: //go:generate go run generate_fixture.go
//
// Each generated module exercises every binder form added in T1-T3
// (parameter receivers, with/for/except/walrus/tuple-unpacking binders,
// self-attribute provenance) plus a module-level direct call (T4's
// <module> synthesis) and a nested try/except import (T5's recursive
// import walk), so the benchmark measures the combined per-file overhead of
// this change's binding table, class-attribute walk, synthetic-decl pruning
// walk, and recursive import walk together — not any one row in isolation.
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

//go:generate go run generate_fixture.go

// moduleCount is the number of synthetic .py files generated. Chosen to be
// large enough to make per-file parse overhead measurable while keeping
// BenchmarkPythonParseDirectory_Bindings fast enough to run routinely.
const moduleCount = 200

const moduleTemplate = `from crypto_lib import Cipher

CIPHER%[1]d = Cipher()
CIPHER%[1]d.setup()


class Worker%[1]d:
    def __init__(self):
        self.cipher = Cipher()

    def run(self, data):
        self.cipher.encrypt(data)

    def process(self, source, keys):
        with Cipher() as c:
            c.encrypt(source)
        for k in keys:
            k.derive(source)
        if (chained := Cipher()) is not None:
            chained.encrypt(source)
        a, *rest = keys
        a.encrypt(source)
        try:
            import fastcrypto as fc
        except ImportError:
            import crypto as fc
        return fc

    def guarded(self, keys):
        for k in keys:
            try:
                k.encrypt(b"data")
            except ValueError as e:
                e.args = ()
`

func main() {
	outDir := "modules"
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir %s: %v\n", outDir, err)
		os.Exit(1)
	}

	for i := 0; i < moduleCount; i++ {
		content := fmt.Sprintf(moduleTemplate, i)
		path := filepath.Join(outDir, fmt.Sprintf("module_%03d.py", i))
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", path, err)
			os.Exit(1)
		}
	}

	fmt.Printf("Generated %d modules under %s/\n", moduleCount, outDir)
}
