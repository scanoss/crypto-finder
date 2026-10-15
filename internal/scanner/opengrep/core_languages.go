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

package opengrep

// language is one target language of OpenGrep 1.30.2, copied from the
// lang.json its CLI ships (semgrep_interfaces/lang.json): the analyzer id
// opengrep-core takes, the names rules may use for it, the file name
// suffixes it selects and the interpreters whose shebang selects a file
// without one. Core mode is pinned to the versions this table was checked
// against: 1.30.2, and 1.22.0 through the mode parity suites over the
// crypto_rules fixtures.
type language struct {
	id       string
	keys     []string
	exts     []string
	shebangs []string
}

var languages = []language{
	{id: "apex", keys: []string{"apex"}, exts: []string{".cls", ".trigger"}, shebangs: nil},
	{id: "bash", keys: []string{"bash", "sh"}, exts: []string{".bash", ".sh"}, shebangs: []string{"bash", "sh"}},
	{id: "c", keys: []string{"c"}, exts: []string{".c", ".h"}, shebangs: nil},
	{id: "cairo", keys: []string{"cairo"}, exts: []string{".cairo"}, shebangs: nil},
	{id: "circom", keys: []string{"circom"}, exts: []string{".circom"}, shebangs: nil},
	{id: "clojure", keys: []string{"clojure"}, exts: []string{".clj", ".cljs", ".cljc", ".edn"}, shebangs: nil},
	{id: "cpp", keys: []string{"cpp", "c++"}, exts: []string{".cc", ".cpp", ".cxx", ".c++", ".pcc", ".tpp", ".C", ".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp"}, shebangs: nil},
	{id: "crystal", keys: []string{"crystal"}, exts: []string{".cr"}, shebangs: []string{"crystal"}},
	{id: "csharp", keys: []string{"csharp", "c#"}, exts: []string{".cs"}, shebangs: nil},
	{id: "dart", keys: []string{"dart"}, exts: []string{".dart"}, shebangs: nil},
	{id: "dockerfile", keys: []string{"dockerfile", "docker"}, exts: []string{".dockerfile", ".Dockerfile", "Dockerfile", "dockerfile"}, shebangs: nil},
	{id: "elixir", keys: []string{"ex", "elixir"}, exts: []string{".ex", ".exs"}, shebangs: nil},
	{id: "go", keys: []string{"go", "golang"}, exts: []string{".go"}, shebangs: nil},
	{id: "hack", keys: []string{"hack"}, exts: []string{".hack", ".hck", ".hh"}, shebangs: []string{"hhvm"}},
	{id: "html", keys: []string{"html"}, exts: []string{".htm", ".html"}, shebangs: nil},
	{id: "java", keys: []string{"java"}, exts: []string{".java"}, shebangs: nil},
	{id: "js", keys: []string{"js", "javascript"}, exts: []string{".cjs", ".js", ".jsx", ".mjs"}, shebangs: []string{"node", "js", "nodejs"}},
	{id: "json", keys: []string{"json"}, exts: []string{".json", ".ipynb"}, shebangs: nil},
	{id: "jsonnet", keys: []string{"jsonnet"}, exts: []string{".jsonnet", ".libsonnet"}, shebangs: nil},
	{id: "julia", keys: []string{"julia"}, exts: []string{".jl"}, shebangs: nil},
	{id: "kotlin", keys: []string{"kt", "kotlin"}, exts: []string{".kt", ".kts", ".ktm"}, shebangs: nil},
	{id: "lisp", keys: []string{"lisp"}, exts: []string{".lisp", ".cl", ".el"}, shebangs: nil},
	{id: "lua", keys: []string{"lua"}, exts: []string{".lua"}, shebangs: []string{"lua"}},
	{id: "move_on_sui", keys: []string{"move_on_sui"}, exts: []string{".move"}, shebangs: nil},
	{id: "move_on_aptos", keys: []string{"move_on_aptos"}, exts: []string{".move"}, shebangs: nil},
	{id: "ocaml", keys: []string{"ocaml"}, exts: []string{".ml", ".mli"}, shebangs: []string{"ocaml", "ocamlscript"}},
	{id: "php", keys: []string{"php"}, exts: []string{".php", ".tpl", ".phtml"}, shebangs: []string{"php"}},
	{id: "promql", keys: []string{"promql"}, exts: []string{".promql"}, shebangs: nil},
	{id: "protobuf", keys: []string{"proto", "protobuf", "proto3"}, exts: []string{".proto"}, shebangs: nil},
	{id: "python2", keys: []string{"python2"}, exts: []string{".py", ".pyi"}, shebangs: []string{"python", "python2"}},
	{id: "python3", keys: []string{"python3"}, exts: []string{".py", ".pyi"}, shebangs: []string{"python", "python3"}},
	{id: "python", keys: []string{"py", "python"}, exts: []string{".py", ".pyi"}, shebangs: []string{"python", "python2", "python3"}},
	{id: "ql", keys: []string{"ql"}, exts: []string{".ql", ".qll"}, shebangs: nil},
	{id: "r", keys: []string{"r"}, exts: []string{".r", ".R"}, shebangs: nil},
	{id: "ruby", keys: []string{"ruby"}, exts: []string{".rb"}, shebangs: []string{"ruby"}},
	{id: "rust", keys: []string{"rust"}, exts: []string{".rs"}, shebangs: []string{"run-cargo-script"}},
	{id: "scala", keys: []string{"scala"}, exts: []string{".scala"}, shebangs: []string{"scala"}},
	{id: "scheme", keys: []string{"scheme"}, exts: []string{".scm", ".ss"}, shebangs: nil},
	{id: "solidity", keys: []string{"solidity", "sol"}, exts: []string{".sol"}, shebangs: nil},
	{id: "swift", keys: []string{"swift"}, exts: []string{".swift"}, shebangs: nil},
	{id: "terraform", keys: []string{"tf", "hcl", "terraform"}, exts: []string{".tf", ".hcl", ".tfvars"}, shebangs: nil},
	{id: "ts", keys: []string{"ts", "typescript"}, exts: []string{".ts", ".tsx"}, shebangs: []string{"ts-node"}},
	{id: "vb", keys: []string{"vb"}, exts: []string{".vb"}, shebangs: nil},
	{id: "vue", keys: []string{"vue"}, exts: []string{".vue"}, shebangs: nil},
	{id: "xml", keys: []string{"xml"}, exts: []string{".xml", ".plist"}, shebangs: nil},
	{id: "yaml", keys: []string{"yaml"}, exts: []string{".yml", ".yaml"}, shebangs: nil},
}

// languageByKey maps every name a rule may give a language to its entry.
var languageByKey = func() map[string]*language {
	byKey := make(map[string]*language)
	for i := range languages {
		for _, key := range languages[i].keys {
			byKey[key] = &languages[i]
		}
	}
	return byKey
}()
