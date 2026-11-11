// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// parseInlinePythonProject builds the graph the way `scan` does for a project
// without a root module, so app/cfg/settings.py is the module app.cfg.settings.
func parseInlinePythonProject(t *testing.T, files map[string]string) *CallGraph {
	t.Helper()
	dir := t.TempDir()
	for rel, src := range files {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := NewBuilder(NewPythonParser()).BuildFromDirectories([]PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

const pythonSettingsModule = `from enum import Enum, StrEnum
import enum

ALG = "sha256"
TWICE = "sha256"
TWICE = "md5"

class Alg(Enum):
    SHA = "sha256"
    SHA_ALIAS = "sha256"
    MD = 'md5'
    BITS = 256

class Named(StrEnum):
    SHA = "sha384"

class Mixed(str, enum.Enum):
    SHA = "sha512"

class Custom(Base):
    SHA = "sha1"
`

const pythonMainModule = `import hashlib
from app.cfg.settings import ALG, TWICE, Alg, Named, Mixed, Custom
from app.cfg.settings import ALG as ALIASED
from app.cfg import settings
import app.cfg.settings as s
import app.cfg.settings

def from_import():
    return hashlib.new(ALG)

def aliased_import():
    return hashlib.new(ALIASED)

def module_attribute():
    return hashlib.new(s.ALG)

def package_from_import():
    return hashlib.new(settings.ALG)

def dotted_module():
    return hashlib.new(app.cfg.settings.ALG)

def enum_value():
    return hashlib.new(Alg.SHA.value)

def enum_name():
    return hashlib.new(Alg.SHA.name)

def enum_alias_name():
    return hashlib.new(Alg.SHA_ALIAS.name)

def str_enum_member():
    return hashlib.new(Named.SHA)

def str_mixin_member():
    return hashlib.new(Mixed.SHA)

def plain_enum_member():
    return hashlib.new(Alg.SHA)

def int_member_value():
    return hashlib.new(Alg.BITS.value)

def unknown_base_value():
    return hashlib.new(Custom.SHA.value)

def assigned_twice():
    return hashlib.new(TWICE)

def shadowed_local():
    ALG = compute()
    return hashlib.new(ALG)

def shadowed_param(s):
    return hashlib.new(s.ALG)

def other_module():
    return hashlib.new(hashlib.sha256)
`

func pythonNewArgument(t *testing.T, graph *CallGraph, function string) []SourceNode {
	t.Helper()
	for _, fn := range graph.Functions {
		if fn.ID.Name != function {
			continue
		}
		call := findPythonCallByMethod(fn, "new")
		if call == nil || len(call.ArgumentSources) == 0 {
			t.Fatalf("hashlib.new call in %s has no argument sources: %+v", function, call)
		}
		return call.ArgumentSources[0]
	}
	t.Fatalf("function %s not found", function)
	return nil
}

func TestPythonNamedValues_CrossModule(t *testing.T) {
	graph := parseInlinePythonProject(t, map[string]string{
		"app/__init__.py":       "",
		"app/cfg/__init__.py":   "",
		"app/cfg/settings.py":   pythonSettingsModule,
		"app/main.py":           pythonMainModule,
		"other/cfg/__init__.py": "",
		"other/cfg/settings.py": "ALG = \"md5\"\n",
	})
	folded := []struct {
		function, expr string
		line           int
		value          string
	}{
		{"from_import", "ALG", 4, `"sha256"`},
		{"aliased_import", "ALIASED", 4, `"sha256"`},
		{"module_attribute", "s.ALG", 4, `"sha256"`},
		{"package_from_import", "settings.ALG", 4, `"sha256"`},
		{"dotted_module", "app.cfg.settings.ALG", 4, `"sha256"`},
		{"enum_value", "Alg.SHA.value", 9, `"sha256"`},
		{"enum_name", "Alg.SHA.name", 9, `"SHA"`},
		{"enum_alias_name", "Alg.SHA_ALIAS.name", 10, `"SHA"`},
		{"str_enum_member", "Named.SHA", 15, `"sha384"`},
		{"str_mixin_member", "Mixed.SHA", 18, `"sha512"`},
	}
	for _, tt := range folded {
		t.Run(tt.function, func(t *testing.T) {
			sources := pythonNewArgument(t, graph, tt.function)
			if len(sources) != 1 {
				t.Fatalf("argument sources = %+v, want one FIELD", sources)
			}
			assertFoldedConstant(t, sources[0], tt.expr, "settings.py", tt.line, tt.value)
			if !strings.HasSuffix(filepath.ToSlash(sources[0].Location.FilePath), "/app/cfg/settings.py") {
				t.Errorf("declaration = %s, want app/cfg/settings.py", sources[0].Location.FilePath)
			}
		})
	}
	for _, function := range []string{
		"plain_enum_member", "int_member_value", "unknown_base_value",
		"assigned_twice", "shadowed_local", "shadowed_param", "other_module",
	} {
		t.Run(function, func(t *testing.T) {
			if sources := pythonNewArgument(t, graph, function); len(sources) != 0 {
				t.Fatalf("argument sources = %+v, want none", sources)
			}
		})
	}
}

func TestPythonNamedValues_SameFileEnum(t *testing.T) {
	graph := parseInlinePythonProject(t, map[string]string{
		"app/main.py": `import hashlib
from enum import Enum

class Alg(Enum):
    SHA = "sha256"

def enum_value():
    return hashlib.new(Alg.SHA.value)
`,
		"app/rebound.py": `import hashlib
from enum import Enum

class Alg(Enum):
    SHA = "sha256"

Alg = make_alg()

def enum_value():
    return hashlib.new(Alg.SHA.value)
`,
	})
	for _, fn := range graph.Functions {
		if fn.ID.Name != "enum_value" {
			continue
		}
		sources := findPythonCallByMethod(fn, "new").ArgumentSources[0]
		switch fn.ID.Package {
		case "app.main":
			if len(sources) != 1 {
				t.Fatalf("app.main sources = %+v, want one FIELD", sources)
			}
			assertFoldedConstant(t, sources[0], "Alg.SHA.value", "main.py", 5, `"sha256"`)
		case "app.rebound":
			if len(sources) != 0 {
				t.Fatalf("app.rebound sources = %+v, want none for a rebound class name", sources)
			}
		default:
			t.Fatalf("unexpected package %s", fn.ID.Package)
		}
	}
}

// A module constant another module may write at runtime resolves to nothing,
// while an Enum member, which no write can reassign, still resolves unless
// its class is rebound.
func TestPythonNamedValues_WrittenByAnotherModule(t *testing.T) {
	const settings = "from enum import Enum\n\nALG = \"sha256\"\n\nclass Alg(Enum):\n    SHA = \"sha256\"\n"
	const main = "import hashlib\nfrom app.cfg.settings import ALG, Alg\n\n" +
		"def from_import():\n    return hashlib.new(ALG)\n\n" +
		"def enum_value():\n    return hashlib.new(Alg.SHA.value)\n"
	tests := []struct {
		name, settings, bootstrap string
		constant, member          bool
	}{
		{"reads only", "", "import hashlib\nfrom app.cfg import settings\nhashlib.new(settings.ALG)\nprint(settings.Alg.SHA.value, settings.Alg)\n", true, true},
		{"local rebinding of the imported name", "", "from app.cfg.settings import ALG\nALG = 'md5'\n", true, true},
		{"module alias attribute", "", "import os\nimport app.cfg.settings as s\ns.ALG = os.environ['X']\n", false, true},
		{"package from-import attribute", "", "import os\nfrom app.cfg import settings\nsettings.ALG = os.environ['X']\n", false, true},
		{"dotted module attribute", "", "import app.cfg.settings\n\ndef boot(v):\n    app.cfg.settings.ALG = v\n", false, true},
		{"augmented assignment", "", "from app.cfg import settings\nsettings.ALG += '-x'\n", false, true},
		{"tuple target", "", "from app.cfg import settings\nsettings.ALG, other = load()\n", false, true},
		{"del", "", "from app.cfg import settings\ndel settings.ALG\n", false, true},
		{"setattr", "", "from app.cfg import settings\nsetattr(settings, 'ALG', load())\n", false, false},
		{"module passed as an argument", "", "from app.cfg import settings\nconfigure(settings)\n", false, false},
		{"module aliased", "", "from app.cfg import settings\ncfg = settings\n", false, false},
		{"module returned", "", "import app.cfg.settings as s\n\ndef get():\n    return s\n", false, false},
		{"module dict", "", "from app.cfg import settings\nsettings.__dict__['ALG'] = load()\n", false, false},
		{"module vars", "", "from app.cfg import settings\nvars(settings)['ALG'] = load()\n", false, false},
		{"enum class rebound", "", "from app.cfg import settings\nsettings.Alg = load()\n", true, false},
		{"enum member assigned or passed", "", "from app.cfg.settings import Alg\nAlg.SHA = 'md5'\nchoices = list(Alg)\n\ndef check(v: Alg):\n    return isinstance(v, Alg)\n", true, true},
		{"global in the declaring module", settings + "\ndef reset(v):\n    global ALG\n    ALG = v\n", "", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			declaring := settings
			if tt.settings != "" {
				declaring = tt.settings
			}
			graph := parseInlinePythonProject(t, map[string]string{
				"app/__init__.py":     "",
				"app/cfg/__init__.py": "",
				"app/cfg/settings.py": declaring,
				"app/main.py":         main,
				"app/bootstrap.py":    tt.bootstrap,
			})
			if got := len(pythonNewArgument(t, graph, "from_import")) == 1; got != tt.constant {
				t.Errorf("ALG resolved = %v, want %v", got, tt.constant)
			}
			if got := len(pythonNewArgument(t, graph, "enum_value")) == 1; got != tt.member {
				t.Errorf("Alg.SHA.value resolved = %v, want %v", got, tt.member)
			}
		})
	}
}
