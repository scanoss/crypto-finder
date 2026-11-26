// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/oid"
)

const pythonResolutionSource = `import hashlib

from cryptography.hazmat.primitives.asymmetric import ec


class Base:
    def run(self, data):
        return self.step(data)

    def step(self, data):
        return data

    @classmethod
    def create(cls):
        return cls()


class Fast(Base):
    def step(self, data):
        return hashlib.sha256(data).digest()


class Slow(Base):
    def step(self, data):
        return hashlib.sha1(data).digest()


class Plain(Base):
    pass


def duck(sink, data, fn):
    sink.write(data)
    sink.out.flush()
    fn(data)
    Base.create().run(data)
    Plain.create()
    run(data)
    return hashlib.new("md5", data)


run = Fast().run


def typed(data):
    key = ec.generate_private_key(ec.SECP256R1())
    return key.sign(data, ec.ECDSA(None))
`

// exportPythonSource builds the call graph of one module and exports its
// fragment, with the Python type resolver chain the scanner runs.
func exportPythonSource(t *testing.T, source string) graphfrag.GraphFragmentExport {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"app/__init__.py": "", "app/mod.py": source} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	builder := callgraph.NewBuilderForEcosystem("python", callgraph.NewPythonParser())
	builder.SetTypeResolver(callgraph.NewPythonTypeResolverChain())
	graph, err := builder.BuildFromDirectories([]callgraph.PackageDir{{Dir: root}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	export := BuildGraphFragmentExport(&engine.DepScanResult{CallGraph: graph, Ecosystem: "python", ProjectRoot: root}, &oid.ResolvedReport{})
	export.RestoreElided()
	return export
}

// A Python call nothing typed is exported name_only, with its method name and
// argument count, so a stitcher matches it by name and reads what it reaches
// as unknown: a method on a parameter or on a parameter's attribute, a call of
// a parameter, a method on a call's result. A call through an import, of a
// module-level name (`run = Fast().run`, an alias the module exports), on a
// class the graph declares, or on a local typed from a contract stays exact.
func TestExportGraphFragment_PythonUntypedCallsAreNameOnly(t *testing.T) {
	t.Parallel()
	export := exportPythonSource(t, pythonResolutionSource)
	type want struct {
		resolution string
		method     string
		arity      int
	}
	wants := map[string]want{
		"app.mod.(sink).write":        {string(callgraph.EdgeKindNameOnly), "write", 1},
		"app.mod.(sink.out).flush":    {string(callgraph.EdgeKindNameOnly), "flush", 0},
		"app.mod.fn":                  {string(callgraph.EdgeKindNameOnly), "fn", 1},
		"app.mod.(Base.create()).run": {string(callgraph.EdgeKindNameOnly), "run", 1},
		"app.mod.(Plain).create":      {string(callgraph.EdgeKindExact), "", -1},
		"hashlib.new":                 {string(callgraph.EdgeKindExact), "", -1},
		"app.mod.run":                 {string(callgraph.EdgeKindExact), "", -1},
		"cryptography.hazmat.primitives.asymmetric.ec.(EllipticCurvePrivateKey).sign": {string(callgraph.EdgeKindExact), "", -1},
	}
	seen := map[string]bool{}
	for _, e := range export.ExternalCalls {
		w, ok := wants[e.TargetKey]
		if !ok {
			continue
		}
		seen[e.TargetKey] = true
		if e.Resolution != w.resolution {
			t.Errorf("%s (%s) resolution %q, want %q", e.TargetKey, e.Raw, e.Resolution, w.resolution)
		}
		if w.arity >= 0 && (e.MethodName != w.method || e.Arity != w.arity) {
			t.Errorf("%s method %q arity %d, want %q %d", e.TargetKey, e.MethodName, e.Arity, w.method, w.arity)
		}
	}
	for key := range wants {
		if !seen[key] {
			t.Errorf("no external call %s", key)
		}
	}
	for _, e := range export.InternalEdges {
		if e.CallerKey == "app.mod.duck" && e.CalleeKey == "app.mod.(Base).create" && e.Resolution != string(callgraph.EdgeKindExact) {
			t.Errorf("Base.create() on a declared class reads %q, want exact", e.Resolution)
		}
	}
}

// A base method's call that dispatches to the overrides of its subclasses is
// exported interface_dispatch, the kind the stitch groups per call site; the
// edge to the base's own declaration stays exact. The fragment decoder reads
// any other kind as untrusted and dropped the overrides.
func TestExportGraphFragment_PythonSubclassDispatchIsInterfaceDispatch(t *testing.T) {
	t.Parallel()
	export := exportPythonSource(t, pythonResolutionSource)
	got := map[string]string{}
	for _, e := range export.InternalEdges {
		if e.CallerKey == "app.mod.(Base).run" {
			got[e.CalleeKey] = e.Resolution
		}
	}
	want := map[string]string{
		"app.mod.(Base).step": string(callgraph.EdgeKindExact),
		"app.mod.(Fast).step": string(graphfrag.ResolutionInterfaceDispatch),
		"app.mod.(Slow).step": string(graphfrag.ResolutionInterfaceDispatch),
	}
	for callee, resolution := range want {
		if got[callee] != resolution {
			t.Errorf("app.mod.(Base).run -> %s resolution %q, want %q (all: %v)", callee, got[callee], resolution, got)
		}
	}
}

// A call on a chain whose receiver text holds a call with arguments
// (`b64encode(x).decode("utf-8").replace(..)`) is keyed by that text, `).`
// included. The export still finds the call at its site: the site keeps its
// text and arguments and, nothing having typed the receiver, reads
// name_only.
func TestExportGraphFragment_PythonChainedReceiverKeepsItsCall(t *testing.T) {
	t.Parallel()
	export := exportPythonSource(t, `import base64


def token(user):
    return base64.b64encode(user.encode()).decode("utf-8").replace("\n", "")
`)
	const target = `app.mod.(base64.b64encode(user.encode()).decode("utf-8")).replace`
	for _, e := range export.ExternalCalls {
		if e.TargetKey != target {
			continue
		}
		if e.Raw != `base64.b64encode(user.encode()).decode("utf-8").replace` || e.Resolution != string(callgraph.EdgeKindNameOnly) {
			t.Errorf("raw %q resolution %q, want the call's text and name_only", e.Raw, e.Resolution)
		}
		if e.EntryCall == nil || len(e.EntryCall.Parameters) != 2 {
			t.Errorf("entry call %+v, want 2 parameters", e.EntryCall)
		}
		return
	}
	t.Fatalf("no external call %s", target)
}
