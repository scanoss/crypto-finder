// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"slices"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
)

func javaKeyGenClass(name, imports, body string) string {
	return "package app;\nimport java.security.KeyPairGenerator;\n" + imports + "\npublic class " + name + " {\n    void gen() throws Exception {\n        " + body + "\n    }\n}\n"
}

// A getter of a field the constructor sets, declared in another package,
// specializes a dynamic key-pair finding with the argument the receiver was
// constructed with: on a construction, a local, an enum constant, and through
// a helper's parameter.
func TestMaterializeConditionedFindings_JavaConstructorGetter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, file, match string
		wantRules         []string
	}{
		{"getter on a construction", "app/Direct.java", `KeyPairGenerator.getInstance(new Holder("EC").getAlg())`, []string{"java.kpg.ec"}},
		{"getter on a local", "app/Local.java", "KeyPairGenerator.getInstance(h.getAlg())", []string{"java.kpg.ec"}},
		{"enum constant getter", "app/EnumGetter.java", "KeyPairGenerator.getInstance(Curve.EC.getValue())", []string{"java.kpg.ec"}},
		{"enum toString returning the field", "app/EnumString.java", "KeyPairGenerator.getInstance(Curve.EC.toString())", []string{"java.kpg.ec"}},
		{"getter passed to a helper in another file", "app/Keys.java", "KeyPairGenerator.getInstance(alg)", []string{"java.kpg.ec"}},
		{"setter keeps the anchor", "app/Setter.java", `KeyPairGenerator.getInstance(new Mutable("EC").getAlg())`, nil},
	}
	dir := writeSourceTree(t, map[string]string{
		"lib/cfg/Holder.java":  "package lib.cfg;\npublic class Holder {\n    private final String alg;\n    public Holder(String alg) { this.alg = alg; }\n    public String getAlg() { return alg; }\n}\n",
		"lib/cfg/Mutable.java": "package lib.cfg;\npublic class Mutable {\n    private String alg;\n    public Mutable(String alg) { this.alg = alg; }\n    public void setAlg(String alg) { this.alg = alg; }\n    public String getAlg() { return alg; }\n}\n",
		"lib/cfg/Curve.java":   "package lib.cfg;\npublic enum Curve {\n    EC(\"EC\");\n    private final String v;\n    Curve(String v) { this.v = v; }\n    public String getValue() { return v; }\n    @Override public String toString() { return v; }\n}\n",
		"app/Direct.java":      javaKeyGenClass("Direct", "import lib.cfg.Holder;", `KeyPairGenerator.getInstance(new Holder("EC").getAlg());`),
		"app/Local.java":       javaKeyGenClass("Local", "import lib.cfg.Holder;", `Holder h = new Holder("EC");`+"\n        KeyPairGenerator.getInstance(h.getAlg());"),
		"app/EnumGetter.java":  javaKeyGenClass("EnumGetter", "import lib.cfg.Curve;", "KeyPairGenerator.getInstance(Curve.EC.getValue());"),
		"app/EnumString.java":  javaKeyGenClass("EnumString", "import lib.cfg.Curve;", "KeyPairGenerator.getInstance(Curve.EC.toString());"),
		"app/Setter.java":      javaKeyGenClass("Setter", "import lib.cfg.Mutable;", `KeyPairGenerator.getInstance(new Mutable("EC").getAlg());`),
		"app/Keys.java":        "package app;\nimport java.security.KeyPairGenerator;\npublic class Keys {\n    static void gen(String alg) throws Exception {\n        KeyPairGenerator.getInstance(alg);\n    }\n}\n",
		"app/Main.java":        "package app;\nimport lib.cfg.Holder;\npublic class Main {\n    void run() throws Exception {\n        Keys.gen(new Holder(\"EC\").getAlg());\n    }\n}\n",
	})
	graph, err := callgraph.NewBuilderForEcosystem("java", callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "com.app:app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	rules := writeConditionedRules(t, javaKeyPairRules)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := namedValueAnchor(t, dir, tt.file, tt.match, "java.kpg.dynamic", "java", "java.security.KeyPairGenerator.getInstance")
			MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: graph, Ecosystem: "java", ProjectRoot: dir, RootModule: "com.app:app"}, []string{rules})
			got, anchor := specializedRules(report, "java.kpg.dynamic")
			if !slices.Equal(got, tt.wantRules) || anchor != (len(tt.wantRules) == 0) {
				t.Fatalf("specialized rules = %v, generic anchor = %v; want %v", got, anchor, tt.wantRules)
			}
		})
	}
}

// A Python getter of an attribute __init__ sets, declared in another module,
// specializes a dynamic digest finding, at the call and through a parameter.
func TestMaterializeConditionedFindings_PythonConstructorGetter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, file, match string
		wantRules         []string
	}{
		{"getter on a construction", "app/direct.py", `hashlib.new(Holder("sha256").get_alg(), data)`, []string{"py.hash.sha256"}},
		{"getter on a local", "app/local.py", "hashlib.new(h.get_alg(), data)", []string{"py.hash.sha256"}},
		{"getter passed to a helper in another module", "app/hasher.py", "hashlib.new(alg, data)", []string{"py.hash.md5"}},
		{"rebound local keeps the anchor", "app/rebound.py", "hashlib.new(h.get_alg(), data)", nil},
	}
	dir := writeSourceTree(t, map[string]string{
		"app/__init__.py":     "",
		"app/cfg/__init__.py": "",
		"app/cfg/holder.py":   "class Holder:\n    def __init__(self, alg):\n        self.alg = alg\n\n    def get_alg(self):\n        return self.alg\n",
		"app/direct.py":       "import hashlib\nfrom app.cfg.holder import Holder\n\ndef run(data):\n    return hashlib.new(Holder(\"sha256\").get_alg(), data)\n",
		"app/local.py":        "import hashlib\nfrom app.cfg.holder import Holder\n\ndef run(data):\n    h = Holder(\"sha256\")\n    return hashlib.new(h.get_alg(), data)\n",
		"app/rebound.py":      "import hashlib\nfrom app.cfg.holder import Holder\n\ndef run(data, weak):\n    h = Holder(\"sha256\")\n    if weak:\n        h = Holder(\"md5\")\n    return hashlib.new(h.get_alg(), data)\n",
		"app/hasher.py":       pythonHasherModule,
		"app/main.py":         "from app.hasher import digest\nfrom app.cfg.holder import Holder\n\ndigest(b\"x\", Holder(\"md5\").get_alg())\n",
	})
	graph, err := callgraph.NewBuilderForEcosystem("python", callgraph.NewPythonParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	rules := writeConditionedRules(t, pythonDigestRules)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := namedValueAnchor(t, dir, tt.file, tt.match, "py.hash.dynamic", "python", "hashlib.new")
			MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: graph, Ecosystem: "python", ProjectRoot: dir}, []string{rules})
			got, anchor := specializedRules(report, "py.hash.dynamic")
			if !slices.Equal(got, tt.wantRules) || anchor != (len(tt.wantRules) == 0) {
				t.Fatalf("specialized rules = %v, generic anchor = %v; want %v", got, anchor, tt.wantRules)
			}
		})
	}
}
