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
	"strings"
	"testing"
)

// TestDecorated_InertBuiltinsDoNotRegister: a lint, codegen or conditional
// compilation attribute, a standard-library decorator that wraps in place and
// a java.lang annotation register nothing; an unknown attribute, a symbol
// export, or a registering marker next to an inert one still does.
func TestDecorated_InertBuiltinsDoNotRegister(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		src  string
		want bool
	}{
		{"#[allow(dead_code)]\nfn run() {}", false},
		{"#[allow(unused, clippy::too_many_arguments)]\n#[inline]\nfn run() {}", false},
		{"#[must_use]\n#[doc = \"hashes\"]\n#[deprecated(since = \"1.0\")]\nfn run() {}", false},
		{"#[cfg(feature = \"fast\")]\n#[rustfmt::skip]\nfn run() {}", false},
		{"#[clippy::cognitive_complexity = \"100\"]\nfn run() {}", false},
		{"#[cfg_attr(feature = \"x\", allow(dead_code), inline)]\nfn run() {}", false},
		{"#[allow(\n    dead_code,\n)]\nfn run() {}", false},
		{"#[inline] #[allow(dead_code)] fn run() {}", false},
		{"#[cfg_attr(feature = \"web\", get(\"/\"))]\nfn run() {}", true},
		{"#[allow(dead_code)]\n#[get(\"/\")]\nfn run() {}", true},
		{"#[inline] #[get(\"/\")] fn run() {}", true},
		{"#[no_mangle]\npub extern \"C\" fn run() {}", true},
		{"#[export_name = \"run\"]\npub fn run() {}", true},
		{"#[instrument]\nfn run() {}", true},
		{"@functools.cache\ndef run(): pass", false},
		{"@lru_cache(maxsize=None)\ndef run(): pass", false},
		{"@contextlib.contextmanager\ndef run(): pass", false},
		{"@typing.overload\ndef run(x: int): pass", false},
		{"@app.route(\"/run\")\n@functools.cache\ndef run(): pass", true},
		{"@cache.memoize()\ndef run(): pass", true},
		{"@Deprecated\nstatic void run() {}", false},
		{"@SuppressWarnings(\"unchecked\") @Deprecated static void run() {}", false},
		{"@SuppressWarnings(\"unchecked\") @Scheduled(fixedRate = 1000) static void run() {}", true},
		{"@java.lang.Deprecated\nstatic void run() {}", false},
		{"@Bean\nstatic Object run() {}", true},
	} {
		lines := make([][]byte, 0, 4)
		for _, line := range strings.Split(tc.src, "\n") {
			lines = append(lines, []byte(line))
		}
		if got := decorated(lines, len(lines)); got != tc.want {
			t.Errorf("decorated(%q) = %v, want %v", tc.src, got, tc.want)
		}
	}
}

// TestUncalledRoots_RustLintAttributeIsNotARegistration: #[allow(dead_code)]
// on a function main never reaches says the author knows nothing calls it;
// it does not keep the function a root. An unknown attribute still does.
func TestUncalledRoots_RustLintAttributeIsNotARegistration(t *testing.T) {
	t.Parallel()
	crate := func(attr string) map[string]string {
		return map[string]string{
			"Cargo.toml": "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
			"src/main.rs": `use sha2::{Digest, Sha256};

fn digest(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

` + attr + `
fn run() -> Vec<u8> {
    digest(b"x")
}

fn main() {
    println!("hello");
}
`,
		}
	}
	wantUnreachable(t, scopeCase{ecosystem: ecosystemRust, parser: rustParser, target: "digest", dirs: []string{"src"}, files: crate("#[allow(dead_code)]")}.trace(t))
	wantNoCallersRoot(t, scopeCase{ecosystem: ecosystemRust, parser: rustParser, target: "digest", dirs: []string{"src"}, files: crate("#[register_hook]")}.trace(t), "run")
}

// TestUncalledRoots_InertDecoratorsInPythonAndJava: @functools.cache on a
// Python function and @Deprecated on a Java static method main never reaches
// leave it dead code.
func TestUncalledRoots_InertDecoratorsInPythonAndJava(t *testing.T) {
	t.Parallel()
	wantUnreachable(t, scopeCase{ecosystem: ecosystemPython, parser: pythonParser, target: "digest", files: map[string]string{
		"pyproject.toml":  "[project]\nname = \"app\"\n",
		"app/__init__.py": "",
		"app/main.py": `import functools
import hashlib


def digest(data):
    return hashlib.sha256(data).digest()


@functools.cache
def run(data):
    return digest(data)


def main():
    print("hello")


if __name__ == "__main__":
    main()
`,
	}}.trace(t))
	wantUnreachable(t, scopeCase{ecosystem: "java", parser: javaParser, target: "digest", dirs: []string{"src/main/java"}, files: map[string]string{
		"pom.xml": "<project/>\n",
		"src/main/java/app/Main.java": `package app;

import java.security.MessageDigest;

public final class Main {
    public static void main(String[] args) {
        System.out.println("hello");
    }

    static byte[] digest(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    @Deprecated
    @SuppressWarnings("unused")
    static byte[] run(byte[] data) throws Exception {
        return digest(data);
    }
}
`,
	}}.trace(t))
}
