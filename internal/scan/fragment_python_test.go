// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/oid"
)

// buildPythonProject builds the call graph of a Python source tree.
func buildPythonProject(t *testing.T, files map[string]string) *engine.DepScanResult {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := callgraph.NewBuilderForEcosystem("python", callgraph.NewPythonParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: root}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return &engine.DepScanResult{CallGraph: graph, Ecosystem: "python", ProjectRoot: root}
}

// decodeFragmentFile reads a fragment a writer wrote.
func decodeFragmentFile(t *testing.T, path string) graphfrag.GraphFragmentExport {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var export graphfrag.GraphFragmentExport
	if err := json.Unmarshal(data, &export); err != nil {
		t.Fatal(err)
	}
	return export
}

// A Python fragment lists each file's import bindings under the path its
// functions name the file by, whichever writer produces it.
func TestGraphFragmentImports_Python(t *testing.T) {
	t.Parallel()
	result := buildPythonProject(t, map[string]string{
		"app/__init__.py": "from .core import Signer\n",
		"app/core.py":     "import hmac as _hmac\n\n\nclass Signer:\n    def sign(self, k, d):\n        import hashlib\n        return _hmac.new(k, d, hashlib.sha256).digest()\n",
		"app/empty.py":    "X = 1\n",
	})
	want := map[string][]graphfrag.GraphFragmentImport{
		"app/__init__.py": {{Line: 1, Module: "app.core", Name: "Signer"}},
		"app/core.py":     {{Line: 1, Module: "hmac", Alias: "_hmac"}, {Line: 6, Module: "hashlib", Local: true}},
	}
	dir := t.TempDir()
	streamed, raw := filepath.Join(dir, "resolved.json"), filepath.Join(dir, "raw.json")
	if err := ExportResolvedGraphFragment(streamed, "json", result, &oid.ResolvedReport{}); err != nil {
		t.Fatal(err)
	}
	if err := exportGraphFragment(raw, result); err != nil {
		t.Fatal(err)
	}
	for name, export := range map[string]graphfrag.GraphFragmentExport{
		"resolved writer":     decodeFragmentFile(t, streamed),
		"raw writer":          decodeFragmentFile(t, raw),
		"resolved projection": BuildGraphFragmentExport(result, &oid.ResolvedReport{}),
		"raw projection":      buildGraphFragmentExport(result),
	} {
		if !reflect.DeepEqual(export.Imports, want) {
			t.Errorf("%s: imports\n got %+v\nwant %+v", name, export.Imports, want)
		}
	}
}

// A graph without Python imports writes no imports section.
func TestGraphFragmentImports_NoneWritesNothing(t *testing.T) {
	t.Parallel()
	result := buildPythonProject(t, map[string]string{"app/mod.py": "def f():\n    return 1\n"})
	path := filepath.Join(t.TempDir(), "f.json")
	if err := ExportResolvedGraphFragment(path, "json", result, &oid.ResolvedReport{}); err != nil {
		t.Fatal(err)
	}
	var sections map[string]json.RawMessage
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &sections); err != nil {
		t.Fatal(err)
	}
	if _, ok := sections["imports"]; ok {
		t.Fatalf("fragment without imports has an imports section: %s", sections["imports"])
	}
}

// A Python fragment carries the component's exports, whichever writer
// produces it, and a component without any writes no exports section.
func TestGraphFragmentExports_Python(t *testing.T) {
	t.Parallel()
	result := buildPythonProject(t, map[string]string{
		"jwt/__init__.py": "from .api_jwt import encode, PyJWT\n",
		"jwt/api_jwt.py":  "class PyJWT:\n    def encode(self, p):\n        return p\n\n\n_jwt_global_obj = PyJWT()\nencode = _jwt_global_obj.encode\n",
	})
	want := map[string]string{
		"jwt.encode":         "jwt.api_jwt.(PyJWT).encode",
		"jwt.PyJWT":          "jwt.api_jwt.(PyJWT)",
		"jwt.api_jwt.encode": "jwt.api_jwt.(PyJWT).encode",
	}
	dir := t.TempDir()
	streamed, raw := filepath.Join(dir, "resolved.json"), filepath.Join(dir, "raw.json")
	if err := ExportResolvedGraphFragment(streamed, "json", result, &oid.ResolvedReport{}); err != nil {
		t.Fatal(err)
	}
	if err := exportGraphFragment(raw, result); err != nil {
		t.Fatal(err)
	}
	for name, export := range map[string]graphfrag.GraphFragmentExport{
		"resolved writer":     decodeFragmentFile(t, streamed),
		"raw writer":          decodeFragmentFile(t, raw),
		"resolved projection": BuildGraphFragmentExport(result, &oid.ResolvedReport{}),
		"raw projection":      buildGraphFragmentExport(result),
	} {
		if !reflect.DeepEqual(export.Exports, want) {
			t.Errorf("%s: exports %v, want %v", name, export.Exports, want)
		}
	}

	plain := buildPythonProject(t, map[string]string{"app/mod.py": "def f():\n    return 1\n"})
	path := filepath.Join(dir, "plain.json")
	if err := ExportResolvedGraphFragment(path, "json", plain, &oid.ResolvedReport{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var sections map[string]json.RawMessage
	if err := json.Unmarshal(data, &sections); err != nil {
		t.Fatal(err)
	}
	if _, ok := sections["exports"]; ok {
		t.Fatalf("fragment without exports has an exports section: %s", sections["exports"])
	}
}

// pythonFragmentWriters exports result through each fragment writer and
// projection and returns the documents a reader decodes.
func pythonFragmentWriters(t *testing.T, result *engine.DepScanResult) map[string]graphfrag.GraphFragmentExport {
	t.Helper()
	dir := t.TempDir()
	streamed, raw := filepath.Join(dir, "resolved.json"), filepath.Join(dir, "raw.json")
	if err := ExportResolvedGraphFragment(streamed, "json", result, &oid.ResolvedReport{}); err != nil {
		t.Fatal(err)
	}
	if err := exportGraphFragment(raw, result); err != nil {
		t.Fatal(err)
	}
	resolved, rawDoc := decodeFragmentFile(t, streamed), decodeFragmentFile(t, raw)
	resolved.RestoreElided()
	rawDoc.RestoreElided()
	return map[string]graphfrag.GraphFragmentExport{
		"resolved writer":     resolved,
		"raw writer":          rawDoc,
		"resolved projection": BuildGraphFragmentExport(result, &oid.ResolvedReport{}),
		"raw projection":      buildGraphFragmentExport(result),
	}
}

// A Python fragment lists the constants the code references outside a call,
// with the operand a comparison traces, whichever writer produces it; the
// written ones elide the operand's file, which a reader restores.
func TestGraphFragmentConstantRefs_Python(t *testing.T) {
	t.Parallel()
	result := buildPythonProject(t, map[string]string{
		"app/tls.py": "import ssl\n\nTLS11 = ssl.PROTOCOL_TLSv1_1\n\n\ndef pick(version):\n    if version == ssl.PROTOCOL_TLSv1:\n        return None\n",
	})
	for name, export := range pythonFragmentWriters(t, result) {
		var got []string
		for _, ref := range export.ConstantRefs {
			s := export.Functions[ref.Function].Key + " " + ref.Text + " " + ref.Context
			if ref.Operand != nil {
				s += " " + ref.Operand.ArgumentExpression
				for _, node := range ref.Operand.SourceNodes {
					if node.Location != nil {
						s += " " + node.Type + "@" + node.Location.FilePath
					}
				}
			}
			got = append(got, s)
		}
		want := []string{
			"app.tls.<module> ssl.PROTOCOL_TLSv1_1 init",
			"app.tls.pick ssl.PROTOCOL_TLSv1 compare version PARAMETER@app/tls.py",
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: constant refs\n got %q\nwant %q", name, got, want)
		}
	}
}

// A Python fragment lists the attribute stores with their traced value,
// whichever writer produces it, and the literals a variable written more
// than once may hold reach the stored value's provenance.
func TestGraphFragmentAttributeStores_Python(t *testing.T) {
	t.Parallel()
	result := buildPythonProject(t, map[string]string{
		"app/tls.py": "import ssl\n\n\ndef harden(ctx, strict):\n    ctx.verify_mode = ssl.CERT_NONE\n    name = \"TLSv1_2\"\n    if strict:\n        name = \"TLSv1_3\"\n    ctx.minimum_version = name\n",
	})
	for writer, export := range pythonFragmentWriters(t, result) {
		var got []string
		for _, store := range export.AttributeStores {
			s := fmt.Sprintf("%s %d:%d-%d %s.%s %s %s", export.Functions[store.Function].Key, store.Line, store.StartCol, store.EndCol,
				store.Receiver, store.Attribute, store.Operator, store.Value.ArgumentExpression)
			for _, node := range store.Value.SourceNodes {
				s += fmt.Sprintf(" %s%v", node.Type, node.MayValues)
				if node.Location != nil {
					s += "@" + node.Location.FilePath
				}
			}
			got = append(got, s)
		}
		want := []string{
			"app.tls.harden 5:5-36 ctx.verify_mode = ssl.CERT_NONE EXPRESSION[]@app/tls.py",
			`app.tls.harden 9:5-31 ctx.minimum_version = name VARIABLE["TLSv1_2" "TLSv1_3"]@app/tls.py`,
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: attribute stores\n got %q\nwant %q", writer, got, want)
		}
	}
}

// A Python fragment lists annotated assignments as declarations and typing
// casts of a call as casts, marks abstract methods and says so in
// scan_metadata, whichever writer produces it.
func TestGraphFragmentDeclarationsAndAbstract_Python(t *testing.T) {
	t.Parallel()
	result := buildPythonProject(t, map[string]string{
		"app/keys.py": "import abc\nfrom typing import cast\nfrom cryptography.hazmat.primitives.asymmetric import rsa\n\n\n" +
			"class Store(abc.ABC):\n    @abc.abstractmethod\n    def load(self, raw):\n        ...\n\n" +
			"    def key(self, raw):\n        k: rsa.RSAPrivateKey = cast(rsa.RSAPrivateKey, self.load(raw))\n        return k\n",
	})
	for writer, export := range pythonFragmentWriters(t, result) {
		var got []string
		for _, d := range export.Declarations {
			got = append(got, fmt.Sprintf("decl %s %d:%d %s %s %s", export.Functions[d.Function].Key, d.Line, d.StartCol, d.Type, d.Name, d.Init))
		}
		for _, c := range export.Casts {
			got = append(got, fmt.Sprintf("cast %s %d:%d %s %d:%d", export.Functions[c.Function].Key, c.Line, c.StartCol, c.Type, c.InnerLine, c.InnerCol))
		}
		for _, fn := range export.Functions {
			if fn.Abstract {
				got = append(got, "abstract "+fn.Key)
			}
		}
		want := []string{
			"decl app.keys.(Store).key 12:9 rsa.RSAPrivateKey k cast",
			"cast app.keys.(Store).key 12:32 rsa.RSAPrivateKey 12:56",
			"abstract app.keys.(Store).load",
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %q\nwant %q", writer, got, want)
		}
		if !export.ScanMetadata.AbstractMethods {
			t.Errorf("%s: scan_metadata.abstract_methods not recorded", writer)
		}
	}
}

// pythonRoundTripFixture exercises the call shapes a Python scan's passes
// read: keyword and nested-call arguments, typed and self-field receivers, a
// fluent chain, a call spanning lines, literal locals, a name written twice,
// a returned call, an abstract method and a buffer rebound between calls.
var pythonRoundTripFixture = map[string]string{
	"app/__init__.py": "from .util import Loader\n",
	"app/crypto.py": `import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from app import Loader

ALG = "sha256"


class Box:
    def __init__(self, key):
        self.aead = AESGCM(key)

    def seal(self, data, strict):
        nonce = os.urandom(12)
        name = "a"
        if strict:
            name = "b"
        out = self.aead.encrypt(nonce, data, associated_data=name.encode())
        nonce = bytes(12)
        self.aead.decrypt(nonce,
                          out,
                          None)
        return out

    def digest(self, data):
        return hashlib.new(ALG, data).hexdigest()


def sign(data):
    key = ec.generate_private_key(ec.SECP256R1())
    return key.sign(data, ec.ECDSA(hashes.SHA256()))


def make(key, data):
    box = Box(key)
    loaded = Loader.load(data)
    ldr = Loader()
    out = ldr.process(
        data)
    return box, loaded, Loader().process(data).hex(), out
`,
	"app/util.py": `class Loader:
    @classmethod
    def load(cls, data):
        return cls()

    def process(self, data):
        return data
`,
}

// pythonRoundTripCall is what the passes read of a call, the call graph's
// unexported fields left out.
type pythonRoundTripCall struct {
	Callee, Raw, ReceiverVar, AssignedVar, ChainID, ASTKind, Path string
	Line, StartCol, EndCol, EndLine                               int
	Arguments                                                     []string
	ArgumentSources                                               string
}

// A Python fragment carries what a source-free annotate reads of the call
// graph (graph-fragment-1.21 / 1.23): the graph FragmentScanResult rebuilds
// from it has the calls, arguments and their provenance, parameter names,
// return provenance and abstract marks of the graph built from source, and
// the rebind lines of the variables the calls pass.
func TestFragmentScanResult_PythonRoundTrip(t *testing.T) {
	t.Parallel()
	result := buildPythonProject(t, pythonRoundTripFixture)
	path := filepath.Join(t.TempDir(), "fragment.json")
	if err := ExportResolvedGraphFragment(path, "json", result, &oid.ResolvedReport{}); err != nil {
		t.Fatal(err)
	}
	doc := decodeFragmentFile(t, path)
	// As annotate loads a stored fragment (loadImportedFragment).
	doc.RestoreElided()
	doc.ExpandInternalEdges()
	rebuilt := FragmentScanResult(&doc, result.ProjectRoot, &entities.InterimReport{})

	sources := func(nodes any) string {
		data, err := json.Marshal(nodes)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	calls := func(fn *callgraph.FunctionDecl) []pythonRoundTripCall {
		out := make([]pythonRoundTripCall, len(fn.Calls))
		for i := range fn.Calls {
			c := &fn.Calls[i]
			out[i] = pythonRoundTripCall{
				Callee: c.Callee.String(), Raw: c.Raw, ReceiverVar: c.ReceiverVar, AssignedVar: c.AssignedVar, ChainID: c.ChainID,
				ASTKind: c.ASTKind, Path: c.NamedASTPath, Line: c.Line, StartCol: c.StartCol, EndCol: c.EndCol,
				// The parser writes a one-line call's end line, the fragment
				// leaves it out.
				EndLine:   max(c.EndLine, c.Line),
				Arguments: c.Arguments, ArgumentSources: sources(c.ArgumentSources),
			}
		}
		return out
	}
	if len(rebuilt.CallGraph.Functions) != len(result.CallGraph.Functions) {
		t.Fatalf("rebuilt %d functions, want %d", len(rebuilt.CallGraph.Functions), len(result.CallGraph.Functions))
	}
	var withCalls int
	for key, want := range result.CallGraph.Functions {
		got := rebuilt.CallGraph.Functions[key]
		if got == nil {
			t.Errorf("%s: not rebuilt", key)
			continue
		}
		if !reflect.DeepEqual(calls(got), calls(want)) {
			t.Errorf("%s: calls\n got %+v\nwant %+v", key, calls(got), calls(want))
		}
		withCalls += min(len(want.Calls), 1)
		if !reflect.DeepEqual(got.Parameters, want.Parameters) {
			t.Errorf("%s: parameters %+v, want %+v", key, got.Parameters, want.Parameters)
		}
		if g, w := sources(got.ReturnSources), sources(want.ReturnSources); g != w {
			t.Errorf("%s: return sources\n got %s\nwant %s", key, g, w)
		}
		if got.Abstract != want.Abstract || got.FilePath != want.FilePath || got.StartLine != want.StartLine || got.EndLine != want.EndLine {
			t.Errorf("%s: abstract/file/lines %v %s %d-%d, want %v %s %d-%d", key, got.Abstract, got.FilePath, got.StartLine, got.EndLine,
				want.Abstract, want.FilePath, want.StartLine, want.EndLine)
		}
	}
	if withCalls < 4 {
		t.Fatalf("only %d functions with calls compared", withCalls)
	}
	// The lines a scan's related-material pass reads as rebinding each
	// variable seal passes: its own assignments, and line 21, whose keyword
	// argument `associated_data=` reads as an assignment there too.
	want := map[string][]int{"data": {21}, "nonce": {17, 21, 22}, "out": {21}}
	if got := rebuilt.CallGraph.RebindLines["app.crypto.(Box).seal"]; !reflect.DeepEqual(got, want) {
		t.Errorf("rebind lines of seal = %v, want %v", got, want)
	}
}
