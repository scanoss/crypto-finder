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
	"github.com/scanoss/crypto-finder/internal/oid"
)

// annotateGraphSource exercises what the crypto export reads from the graph
// beyond the edges: an overloaded constructor the parser names by arity, a
// returned constant the argument traces into, a call on an inherited method,
// and the object's lifecycle calls.
const annotateGraphSource = `package app;
import javax.crypto.Cipher;
public class Box {
    static class Base { byte[] wrap(byte[] d) { return d; } }
    static class Sub extends Base {}
    static class Key {
        Key(byte[] b) {}
        Key(String s) {}
    }
    static String algo() { return "AES"; }

    public byte[] seal(byte[] data) throws Exception {
        Key k = new Key(data);
        Cipher c = Cipher.getInstance(algo());
        c.init(Cipher.ENCRYPT_MODE, null);
        Sub s = new Sub();
        return c.doFinal(s.wrap(data));
    }

    public byte[] open(byte[] data) throws Exception {
        return seal(data);
    }
}
`

// The annotation of a stored graph is what the scan's export wrote for it:
// the crypto sections built from the graph rebuilt out of the fragment equal
// those built from the parsed graph, field by field. Without what 1.21 adds
// they do not.
func TestAnnotationOfAStoredGraphIsTheScans(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "app", "Box.java")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(annotateGraphSource), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilder(callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "com.app:app"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The signatures a scan reads from the platform for a method outside the
	// graph.
	graph.ExternalMethodSignatures = map[string][]callgraph.ExternalMethodSignature{
		callgraph.ExternalMethodSignatureKey(callgraph.FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "doFinal#1"}): {
			{ParameterTypes: []string{"byte[]"}, ReturnType: "byte[]"},
		},
	}
	report := &entities.InterimReport{
		Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules: entities.RulesInfo{Version: "v-test"},
		Findings: []entities.Finding{{
			FilePath: "app/Box.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 14, EndLine: 14, Match: "Cipher.getInstance(algo())",
				Rules:    []entities.RuleInfo{{ID: "test.cipher"}},
				Metadata: map[string]string{"api": "javax.crypto.Cipher.getInstance", "assetType": "algorithm"},
			}, {
				StartLine: 17, EndLine: 17, Match: "c.doFinal(s.wrap(data))",
				Rules:    []entities.RuleInfo{{ID: "test.dofinal"}},
				Metadata: map[string]string{"api": "javax.crypto.Cipher.doFinal", "assetType": "algorithm"},
			}},
		}},
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)
	result := &engine.DepScanResult{Report: report, CallGraph: graph, ProjectRoot: dir, RootModule: "com.app:app", Ecosystem: "java"}
	AssignOccurrenceKeys(result)
	resolved := prepareOIDFixtureReport(t, report)

	file := filepath.Join(t.TempDir(), "fragment.json")
	if err := writeResolvedGraphFragmentJSONFile(file, result, resolved); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var scanned graphfrag.GraphFragmentExport
	if err := json.Unmarshal(data, &scanned); err != nil {
		t.Fatal(err)
	}
	want := cryptoSections(t, &scanned)
	if len(scanned.CryptoAnnotations) != 2 || len(scanned.SupportingCalls) == 0 || len(scanned.CryptoEntryPoints) == 0 {
		t.Fatalf("fixture writes %d annotations, %d supporting calls, %d entry points; want 2 and some of each",
			len(scanned.CryptoAnnotations), len(scanned.SupportingCalls), len(scanned.CryptoEntryPoints))
	}

	annotate := func(stored graphfrag.GraphFragmentExport) string {
		stored.CryptoAnnotations, stored.SupportingCalls, stored.CryptoEntryPoints = nil, nil, nil
		stored.ExpandInternalEdges()
		rebuilt := FragmentScanResult(&stored, dir, report)
		out := BuildGraphAnnotateExport(rebuilt, resolved, &stored)
		return cryptoSections(t, &out)
	}
	var stored graphfrag.GraphFragmentExport
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	stored.RestoreElided()
	if got := annotate(stored); got != want {
		t.Errorf("annotation of the stored graph differs from the scan's:\n got: %s\nwant: %s", got, want)
	}

	// A 1.20 fragment holds neither the parser's calls, nor parameter names,
	// return provenance or external signatures.
	var older graphfrag.GraphFragmentExport
	if err := json.Unmarshal(data, &older); err != nil {
		t.Fatal(err)
	}
	older.RestoreElided()
	older.ExternalSignatures = nil
	for i := range older.Functions {
		older.Functions[i].ReturnSources, older.Functions[i].ParameterNames = nil, nil
	}
	var anchors []graphfrag.GraphFragmentCallAnchor
	for _, a := range older.CallAnchors {
		if a.Kind != "" {
			anchors = append(anchors, graphfrag.GraphFragmentCallAnchor{Function: a.Function, Line: a.Line, StartCol: a.StartCol, EndCol: a.EndCol, Kind: a.Kind, Path: a.Path, ChainID: a.ChainID})
		}
	}
	older.CallAnchors = anchors
	if got := annotate(older); got == want {
		t.Error("a 1.20 fragment gives the scan's annotation too; the test no longer covers what 1.21 carries")
	}
}

// cryptoSections renders the crypto sections of an export and the counts its
// metadata keeps of them.
func cryptoSections(t *testing.T, export *graphfrag.GraphFragmentExport) string {
	t.Helper()
	data, err := json.Marshal(struct {
		A []graphfrag.GraphFragmentCryptoOp
		S []graphfrag.GraphFragmentSupporting
		E []graphfrag.GraphFragmentCryptoEntryPoint
		N [3]int
	}{
		export.CryptoAnnotations, export.SupportingCalls, export.CryptoEntryPoints,
		[3]int{export.ScanMetadata.CryptoOps, export.ScanMetadata.SupportingCalls, export.ScanMetadata.CryptoEntryPoints},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// annotateStoredGraph is what `annotate` writes for full, a scan's graph
// fragment of the source under root, re-detected into report: the fragment's
// crypto sections are dropped, its graph rebuilt, and report annotated onto
// it.
func annotateStoredGraph(t *testing.T, full *graphfrag.GraphFragmentExport, root string, report *entities.InterimReport, resolved *oid.ResolvedReport) graphfrag.GraphFragmentExport {
	t.Helper()
	data, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	var stored graphfrag.GraphFragmentExport
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	stored.RestoreElided()
	stored.CryptoAnnotations, stored.SupportingCalls, stored.CryptoEntryPoints = nil, nil, nil
	stored.ExpandInternalEdges()
	return BuildGraphAnnotateExport(FragmentScanResult(&stored, root, report), resolved, &stored)
}
