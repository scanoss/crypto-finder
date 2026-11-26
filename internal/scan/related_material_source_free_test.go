// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// javaGappedMaterialSource puts lines that are no call site between a draw
// and its use, and between a helper's first line and its use of the
// parameter: a fragment's source_lines does not hold them.
const javaGappedMaterialSource = `package app;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class B {
    private Cipher init(byte[] key, byte[] iv) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return c;
    }

    private Cipher later(byte[] key, byte[] iv) throws Exception {
        int mode = 1;

        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return c;
    }

    private Cipher overwritten(byte[] key, byte[] iv) throws Exception {
        iv = key;
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return c;
    }

    public void run(byte[] key) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[16];
        random.nextBytes(nonce);
        int rounds = 3;
        // a comment
        init(key, nonce);
        byte[] pepper = new byte[16];
        random.nextBytes(pepper);
        pepper = key;
        init(key, pepper);
        byte[] tail = new byte[16];
        random.nextBytes(tail);
        later(key, tail);
        byte[] last = new byte[16];
        random.nextBytes(last);
        overwritten(key, last);
    }
}
`

// sourceFreeMaterialsAtDraw stores the fixture's graph as a fragment, as a
// scan exports it, and reports, sorted, the material types the pass adds at
// the draw on the call graph rebuilt from that fragment without the source.
// unread deletes the source before the export, which then cannot read it.
func sourceFreeMaterialsAtDraw(t *testing.T, fx materialFixture, unread bool) []string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, fx.file)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(fx.src), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilderForEcosystem(ecosystemJava, callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: fx.importPath}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := &engine.DepScanResult{Report: &entities.InterimReport{}, CallGraph: graph, ProjectRoot: dir, Ecosystem: fx.ecosystem}
	if unread {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
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
	doc.RestoreElided()
	doc.ExpandInternalEdges()
	inMemory := buildGraphFragmentExport(result)
	if !doc.ScanMetadata.RebindLines || !reflect.DeepEqual(doc.RebindLines, inMemory.RebindLines) || !inMemory.ScanMetadata.RebindLines {
		t.Fatalf("rebind_lines: streamed %v %+v, in memory %v %+v; want both recorded and equal",
			doc.ScanMetadata.RebindLines, doc.RebindLines, inMemory.ScanMetadata.RebindLines, inMemory.RebindLines)
	}

	// No source under the root the graph is rebuilt at.
	root := t.TempDir()
	line, col := drawPosition(t, fx)
	draw := entities.CryptographicAsset{
		StartLine: line, EndLine: line, StartCol: col, EndCol: col + len(fx.draw),
		Match:    fx.draw,
		Rules:    []entities.RuleInfo{{ID: "test.crypto.random.drbg"}},
		Metadata: map[string]string{"assetType": "algorithm", "algorithmPrimitive": "drbg", "algorithmName": "CSPRNG"},
	}
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath: filepath.Join(root, fx.file), Language: fx.ecosystem, CryptographicAssets: []entities.CryptographicAsset{draw},
	}}}
	MaterializeRelatedMaterial(report, FragmentScanResult(&doc, root, report))
	var got []string
	for _, a := range report.Findings[0].CryptographicAssets {
		if a.Metadata["assetType"] == "related-crypto-material" {
			got = append(got, a.Metadata["materialType"])
		}
	}
	slices.Sort(got)
	return got
}

func drawPosition(t *testing.T, fx materialFixture) (line, col int) {
	t.Helper()
	if strings.Count(fx.src, fx.draw) != 1 {
		t.Fatalf("draw %q must occur once in the fixture", fx.draw)
	}
	for i, text := range strings.Split(fx.src, "\n") {
		if c := strings.Index(text, fx.draw); c >= 0 {
			return i + 1, c + 1
		}
	}
	return 0, 0
}

// A stored fragment re-annotated without the source reports the material a
// scan with the source reports, also when lines that are no call site stand
// between the draw and its use: the buffer filled, then used after a
// declaration and a comment; or reassigned first; or passed to a helper that
// uses it after other lines or overwrites it first.
func TestMaterializeRelatedMaterial_SourceFreeMatchesScan(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		draw string
		want []string
	}{
		"used after lines that are no call":   {draw: "random.nextBytes(nonce)", want: []string{"initialization-vector"}},
		"reassigned before the use":           {draw: "random.nextBytes(pepper)"},
		"helper uses it after other lines":    {draw: "random.nextBytes(tail)", want: []string{"initialization-vector"}},
		"helper overwrites it before the use": {draw: "random.nextBytes(last)"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fx := materialFixture{ecosystem: ecosystemJava, file: "app/B.java", importPath: "app", draw: tc.draw, src: javaGappedMaterialSource}
			if got := materialsAtDraw(t, fx); !slices.Equal(got, tc.want) {
				t.Fatalf("scan with the source: materials = %q, want %q", got, tc.want)
			}
			if got := sourceFreeMaterialsAtDraw(t, fx, false); !slices.Equal(got, tc.want) {
				t.Errorf("without the source: materials = %q, want %q", got, tc.want)
			}
		})
	}
}

// A function whose source the export could not read is recorded unread, and
// the pass then follows no buffer in it over lines it cannot see, as a scan
// without that source does.
func TestMaterializeRelatedMaterial_SourceFreeUnreadFunction(t *testing.T) {
	t.Parallel()
	fx := materialFixture{ecosystem: ecosystemJava, file: "app/B.java", importPath: "app", draw: "random.nextBytes(nonce)", src: javaGappedMaterialSource}
	if got := sourceFreeMaterialsAtDraw(t, fx, true); len(got) != 0 {
		t.Errorf("materials = %q, want none: the lines between draw and use were never read", got)
	}
}
