// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// A Java fragment marks its methods without a body abstract and says so in
// scan_metadata, so the stitch can tell PdfWriter's empty flushAcroFields, a
// body a call on a PdfWriter runs, from an interface method; the stored
// fragment decodes with both, and a re-annotation keeps the metadata.
func TestGraphFragment_MarksAbstractMethods(t *testing.T) {
	dir := t.TempDir()
	src := `package p;
interface Sink { void write(); }
class PdfWriter implements Sink {
	public void write() {}
	protected void flushAcroFields() {}
}
class PdfCopy extends PdfWriter {
	protected void flushAcroFields() { write(); }
}
`
	if err := os.WriteFile(filepath.Join(dir, "P.java"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilderForEcosystem(ecosystemJava, callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "p"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := &engine.DepScanResult{Report: &entities.InterimReport{}, CallGraph: graph, ProjectRoot: dir, Ecosystem: ecosystemJava}
	file := filepath.Join(t.TempDir(), "fragment.json")
	if err := writeGraphFragmentJSONFile(file, result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var doc graphfrag.GraphFragmentExport
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.ScanMetadata.AbstractMethods {
		t.Fatalf("scan_metadata.abstract_methods not recorded: %+v", doc.ScanMetadata)
	}
	want := map[string]bool{
		"p.(Sink).write#0":                true,
		"p.(PdfWriter).write#0":           false,
		"p.(PdfWriter).flushAcroFields#0": false,
		"p.(PdfCopy).flushAcroFields#0":   false,
	}
	got := map[string]bool{}
	for _, fn := range doc.Functions {
		got[fn.Key] = fn.Abstract
	}
	for key, abstract := range want {
		if a, ok := got[key]; !ok || a != abstract {
			t.Errorf("%s: abstract = %v (listed %v), want %v", key, a, ok, abstract)
		}
	}

	frag, err := graphfrag.DecodeFragment(graphfrag.ComponentKey{Purl: "pkg:maven/p/p", Version: "1"}, data)
	if err != nil {
		t.Fatal(err)
	}
	if !frag.AbstractMethods {
		t.Error("decoded fragment lost abstract_methods")
	}
	for _, fn := range frag.Functions {
		if want, ok := want[fn.Signature]; ok && fn.Abstract != want {
			t.Errorf("decoded %s: abstract = %v, want %v", fn.Signature, fn.Abstract, want)
		}
	}

	annotation := BuildGraphAnnotateExport(FragmentScanResult(&doc, t.TempDir(), &entities.InterimReport{}), prepareOIDFixtureReport(t, &entities.InterimReport{}), &doc)
	if !annotation.ScanMetadata.AbstractMethods {
		t.Error("re-annotation dropped abstract_methods")
	}
	doc.ScanMetadata.AbstractMethods = false
	annotation = BuildGraphAnnotateExport(FragmentScanResult(&doc, t.TempDir(), &entities.InterimReport{}), prepareOIDFixtureReport(t, &entities.InterimReport{}), &doc)
	if annotation.ScanMetadata.AbstractMethods {
		t.Error("re-annotation of a fragment that marks no abstract method claims abstract_methods")
	}
}

// Only a Java, Python or Rust graph marks its abstract methods (a Rust
// trait's required methods, graph-algo-rs-15).
func TestGraphFragmentScanMetadata_AbstractMethodsJavaAndPython(t *testing.T) {
	graph := &callgraph.CallGraph{}
	for _, ecosystem := range []string{ecosystemJava, ecosystemPython, ecosystemRust} {
		if !buildGraphFragmentScanMetadata(&engine.DepScanResult{CallGraph: graph, Ecosystem: ecosystem}).AbstractMethods {
			t.Errorf("%s: abstract_methods not recorded", ecosystem)
		}
	}
	if buildGraphFragmentScanMetadata(&engine.DepScanResult{CallGraph: graph, Ecosystem: "go"}).AbstractMethods {
		t.Error("go: abstract_methods recorded; its interface methods are not marked")
	}
}
