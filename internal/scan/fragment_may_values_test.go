// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/scanoss/reach/callgraph"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// The literals a variable written more than once may hold reach the
// fragment's argument provenance, where a detector reads them.
func TestGraphFragmentCarriesMayValues(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "app", "Y.java")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	src := `package app;
import java.security.Signature;
public class Y {
    Signature get(int alg) throws Exception {
        String jcaAlg;
        if (alg == 1) {
            jcaAlg = "SHA256withECDSA";
        } else {
            jcaAlg = "SHA384withECDSA";
        }
        return Signature.getInstance(jcaAlg);
    }
}
`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilder(callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "com.app:app"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fragment := buildGraphFragmentExport(&engine.DepScanResult{
		Report: &entities.InterimReport{}, CallGraph: graph, ProjectRoot: dir, RootModule: "com.app:app", Ecosystem: "java",
	})
	for _, call := range fragment.ExternalCalls {
		if call.MethodName != "getInstance" || call.EntryCall == nil || len(call.EntryCall.Parameters) == 0 {
			continue
		}
		nodes := call.EntryCall.Parameters[0].SourceNodes
		if len(nodes) != 1 || !reflect.DeepEqual(nodes[0].MayValues, []string{`"SHA256withECDSA"`, `"SHA384withECDSA"`}) {
			t.Fatalf("argument provenance = %#v, want the variable with both literals", nodes)
		}
		return
	}
	t.Fatal("Signature.getInstance not exported")
}
