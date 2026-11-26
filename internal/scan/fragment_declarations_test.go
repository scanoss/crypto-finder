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
)

const declarationsSource = `package app;
import java.security.cert.*;
public class Certs {
    Object pick(CertificateFactory f, Object o) throws Exception {
        X509Certificate cert = null;
        int n = 0;
        cert = (X509Certificate) f.generateCertificate(null);
        return cert;
    }
}
`

// A fragment lists each function's declarations and casts, and carries the
// lines they stand on; both export paths agree, and the streamed form decodes
// back to the same records.
func TestGraphFragmentCarriesDeclarationsAndCasts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "app", "Certs.java")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(declarationsSource), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilder(callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "com.app:app"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := &engine.DepScanResult{Report: &entities.InterimReport{}, CallGraph: graph, ProjectRoot: dir, RootModule: "com.app:app", Ecosystem: "java"}

	inMemory := buildGraphFragmentExport(result)
	file := filepath.Join(t.TempDir(), "fragment.json")
	if err := writeGraphFragmentJSONFile(file, result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var streamed graphfrag.GraphFragmentExport
	if err := json.Unmarshal(data, &streamed); err != nil {
		t.Fatal(err)
	}
	streamed.RestoreElided()
	for name, fragment := range map[string]graphfrag.GraphFragmentExport{"in memory": inMemory, "streamed": streamed} {
		var got []string
		for _, d := range fragment.Declarations {
			got = append(got, fmt.Sprintf("%s decl %s %s %s %d:%d-%d", fragment.Functions[d.Function].FunctionName, d.Type, d.Name, d.Init, d.Line, d.StartCol, d.EndCol))
		}
		for _, c := range fragment.Casts {
			got = append(got, fmt.Sprintf("%s cast %s %d:%d-%d at %d:%d", fragment.Functions[c.Function].FunctionName, c.Type, c.Line, c.StartCol, c.EndCol, c.InnerLine, c.InnerCol))
		}
		want := []string{"app.Certs.pick decl X509Certificate cert null 5:9-37", "app.Certs.pick cast X509Certificate 7:16-61 at 7:34"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: declarations and casts = %v, want %v", name, got, want)
		}
		if line := fragment.SourceLines["app/Certs.java"][5]; line != "        X509Certificate cert = null;" {
			t.Errorf("%s: source line 5 = %q, want the declaration", name, line)
		}
	}
}
