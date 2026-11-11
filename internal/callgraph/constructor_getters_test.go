// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"fmt"
	"testing"
)

const javaHolderSrc = `package lib.cfg;
public class Holder {
    private final String alg;
    public Holder(String alg) { this.alg = alg; }
    public String getAlg() { return alg; }
}
`

const javaAlgoGetterEnumSrc = `package lib.cfg;
public enum Algo {
    SHA("SHA-256"),
    LEGACY("MD5") { @Override public String getValue() { return "SHA-1"; } };
    private final String v;
    Algo(String v) { this.v = v; }
    public String getValue() { return v; }
    @Override public String toString() { return v; }
}
`

func javaGetterCaller(body string) string {
	return fmt.Sprintf(`package app;
import lib.cfg.*;
import java.security.MessageDigest;
public class Caller {
    void digest() throws Exception {
        %s
    }
}
`, body)
}

func TestJavaConstructorGetter_Resolves(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, body, expr, file, value string
		line                          int
	}{
		{"getter on a construction", `MessageDigest.getInstance(new Holder("SHA-256").getAlg());`, `new Holder("SHA-256").getAlg()`, "Holder.java", `"SHA-256"`, 4},
		{"getter on a local bound once", `Holder h = new Holder("SHA-256"); MessageDigest.getInstance(h.getAlg());`, "h.getAlg()", "Holder.java", `"SHA-256"`, 4},
		{"constructor argument names a constant", `MessageDigest.getInstance(new Holder(Names.ALG).getAlg());`, `new Holder(Names.ALG).getAlg()`, "Holder.java", `"SHA-512"`, 4},
		{"enum constant getter", `MessageDigest.getInstance(Algo.SHA.getValue());`, "Algo.SHA.getValue()", "Algo.java", `"SHA-256"`, 3},
		{"enum toString returning the field", `MessageDigest.getInstance(Algo.LEGACY.toString());`, "Algo.LEGACY.toString()", "Algo.java", `"MD5"`, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			graph := parseInlineJavaFiles(t, map[string]string{
				"lib/cfg/Holder.java": javaHolderSrc,
				"lib/cfg/Algo.java":   javaAlgoGetterEnumSrc,
				"lib/cfg/Names.java":  "package lib.cfg;\npublic class Names { public static final String ALG = \"SHA-512\"; }\n",
				"app/Caller.java":     javaGetterCaller(tt.body),
			})
			node := digestArgumentSource(t, graph)
			if node.Type == sourceNodeField && len(node.SourceNodes) == 1 && node.SourceNodes[0].Type == sourceNodeField {
				// A constant argument folds to its own FIELD{VALUE}.
				node.SourceNodes = node.SourceNodes[0].SourceNodes
			}
			assertFoldedConstant(t, node, tt.expr, tt.file, tt.line, tt.value)
		})
	}
}

func TestJavaConstructorGetter_StaysUnresolved(t *testing.T) {
	t.Parallel()
	holder := func(members string) string {
		return "package lib.cfg;\npublic class Holder {\n" + members + "\n}\n"
	}
	const fieldAndCtor = "    private String alg;\n    public Holder(String alg) { this.alg = alg; }\n    public String getAlg() { return alg; }\n"
	direct := `MessageDigest.getInstance(new Holder("SHA-256").getAlg());`
	tests := []struct{ name, holder, body string }{
		{"setter", holder(fieldAndCtor + "    public void setAlg(String a) { this.alg = a; }"), direct},
		{"reassigned in another method", holder(fieldAndCtor + "    void reset() { alg = \"MD5\"; }"), direct},
		{"field other classes can write", holder("    String alg;\n    public Holder(String alg) { this.alg = alg; }\n    public String getAlg() { return alg; }"), direct},
		{"two constructors assign different values", holder(fieldAndCtor + "    public Holder(String a, String b) { this.alg = b; }"), direct},
		{"construction by a constructor that does not assign it", holder("    private final String alg;\n    public Holder(String alg) { this.alg = alg; }\n    public Holder(String alg, int n) { this(alg.toLowerCase()); }\n    public String getAlg() { return alg; }"), `MessageDigest.getInstance(new Holder("SHA-256", 1).getAlg());`},
		{"getter with logic", holder("    private final String alg;\n    public Holder(String alg) { this.alg = alg; }\n    public String getAlg() { return alg.toUpperCase(); }"), direct},
		{"receiver local rebound", javaHolderSrc, `Holder h = new Holder("SHA-256"); h = new Holder("MD5"); MessageDigest.getInstance(h.getAlg());`},
		{"receiver of a subclass that overrides the getter", javaHolderSrc, `Holder h = new Sub("SHA-256"); MessageDigest.getInstance(h.getAlg());`},
		{"enum constant body overrides the getter", javaHolderSrc, `MessageDigest.getInstance(Algo.LEGACY.getValue());`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			graph := parseInlineJavaFiles(t, map[string]string{
				"lib/cfg/Holder.java": tt.holder,
				"lib/cfg/Sub.java":    "package lib.cfg;\npublic class Sub extends Holder {\n    public Sub(String alg) { super(alg); }\n    @Override public String getAlg() { return \"MD5\"; }\n}\n",
				"lib/cfg/Algo.java":   javaAlgoGetterEnumSrc,
				"app/Caller.java":     javaGetterCaller(tt.body),
			})
			if node := digestArgumentSource(t, graph); node.Type != sourceNodeCallResult {
				t.Fatalf("argument source = %+v, want the unresolved call", node)
			}
		})
	}
}

const pythonHolderModule = `class Holder:
    def __init__(self, alg, mode="cbc"):
        """Keeps the algorithm."""
        self.alg = alg
        self.mode = mode

    def get_alg(self):
        """The algorithm."""
        return self.alg

    def get_upper(self):
        return self.alg.upper()


class Sub(Holder):
    def get_alg(self):
        return "md5"
`

func TestPythonConstructorGetter(t *testing.T) {
	t.Parallel()
	main := `import hashlib
from app.cfg.holder import Holder, Sub

def direct():
    return hashlib.new(Holder("sha256").get_alg())

def local():
    h = Holder("sha256")
    return hashlib.new(h.get_alg())

def keyword():
    return hashlib.new(Holder(mode="ecb", alg="sha256").get_alg())

def rebound():
    h = Holder("sha256")
    h = Holder("md5")
    return hashlib.new(h.get_alg())

def mutated():
    h = Holder("sha256")
    h.alg = "md5"
    return hashlib.new(h.get_alg())

def parameter(h):
    return hashlib.new(h.get_alg())

def logic():
    return hashlib.new(Holder("sha256").get_upper())

def subclass():
    return hashlib.new(Sub("sha256").get_alg())

def splat(args):
    return hashlib.new(Holder(*args).get_alg())
`
	graph := parseInlinePythonProject(t, map[string]string{
		"app/__init__.py":     "",
		"app/cfg/__init__.py": "",
		"app/cfg/holder.py":   pythonHolderModule,
		"app/main.py":         main,
	})
	for _, function := range []string{"direct", "local", "keyword"} {
		t.Run(function, func(t *testing.T) {
			sources := pythonNewArgument(t, graph, function)
			if len(sources) != 1 {
				t.Fatalf("sources = %+v, want one", sources)
			}
			assertFoldedConstant(t, sources[0], sources[0].Name, "holder.py", 4, `"sha256"`)
		})
	}
	for _, function := range []string{"rebound", "mutated", "parameter", "logic", "subclass", "splat"} {
		t.Run(function, func(t *testing.T) {
			for _, fn := range graph.Functions {
				if fn.ID.Name != function {
					continue
				}
				if sources := pythonNewArgument(t, graph, function); len(sources) != 1 || sources[0].Type != sourceNodeCallResult {
					t.Fatalf("argument sources = %+v, want the unresolved call", sources)
				}
			}
		})
	}
}

// Two writers of the field, or two __init__ definitions, leave the getter
// without a single constructor value.
func TestPythonConstructorGetter_FieldWrittenElsewhere(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"setter":           "    def set_alg(self, a):\n        self.alg = a\n",
		"other method":     "    def reset(self):\n        self.alg = \"md5\"\n",
		"second __init__":  "    def __init__(self, other):\n        self.alg = other\n",
		"dynamic setattr":  "    def load(self, k, v):\n        setattr(self, k, v)\n",
		"rebound argument": "",
	}
	for name, extra := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			init := "    def __init__(self, alg):\n        self.alg = alg\n"
			if name == "rebound argument" {
				init = "    def __init__(self, alg):\n        alg = alg.lower()\n        self.alg = alg\n"
			}
			holder := "class Holder:\n" + init + "    def get_alg(self):\n        return self.alg\n" + extra
			graph := parseInlinePythonProject(t, map[string]string{
				"app/__init__.py": "",
				"app/holder.py":   holder,
				"app/main.py":     "import hashlib\nfrom app.holder import Holder\n\ndef direct():\n    return hashlib.new(Holder(\"sha256\").get_alg())\n",
			})
			if sources := pythonNewArgument(t, graph, "direct"); len(sources) != 1 || sources[0].Type != sourceNodeCallResult {
				t.Fatalf("argument sources = %+v, want the unresolved call", sources)
			}
		})
	}
}
