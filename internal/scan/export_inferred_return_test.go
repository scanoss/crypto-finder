package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// ---------------------------------------------------------------------------
// T5.1 — Schema version 5.2
// ---------------------------------------------------------------------------

// TestExportSchema_Is52 asserts that the exported call graph carries
// callGraphSchemaVersion = "5.2".
func TestExportSchema_Is52(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{},
		Callers:   map[string][]string{},
	}

	report := &entities.InterimReport{
		Version: "1.3",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath: "src/main/java/com/app/App.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 5,
				EndLine:   5,
				Match:     "Cipher.getInstance(\"AES\")",
				Rules:     []entities.RuleInfo{{ID: "java.crypto.cipher", Message: "cipher", Severity: "INFO"}},
				Status:    "pending",
				FindingID: "schema52-test",
				Source:    "direct",
			}},
		}},
	}

	result := &engine.DepScanResult{
		CallGraph:   graph,
		Report:      report,
		RootModule:  "com.app",
		Ecosystem:   "java",
		ProjectRoot: projectRoot,
	}

	out := filepath.Join(t.TempDir(), "cg-schema52.json")
	if err := ExportCallGraph(out, "json", result); err != nil {
		t.Fatalf("ExportCallGraph: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	var payload callGraphExportV2
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("invalid json: %v", err)
	}

	if payload.SchemaVersion != "5.2" {
		t.Fatalf("schema_version = %q, want 5.2", payload.SchemaVersion)
	}
}

// ---------------------------------------------------------------------------
// T5.3 — exportFunctionMetadata.InferredReturn omitted when nil
// ---------------------------------------------------------------------------

// TestExportFunctionMetadata_InferredReturnOmittedWhenNil asserts that when
// FunctionDecl.InferredReturn is nil the exported JSON contains no
// "inferred_return" key for that function.
func TestExportFunctionMetadata_InferredReturnOmittedWhenNil(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()
	filePath := joinTestPath(projectRoot, "src/main/java/com/app/App.java")

	wrapperID := callgraph.FunctionID{Package: "com.app", Type: "App", Name: "doWork#0"}
	cryptoID := callgraph.FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "getInstance#1"}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			wrapperID.String(): {
				ID:         wrapperID,
				FilePath:   filePath,
				StartLine:  10,
				EndLine:    15,
				ReturnType: "Object",
				// InferredReturn deliberately left nil
			},
		},
		Callers: map[string][]string{
			cryptoID.String(): {wrapperID.String()},
		},
	}

	report := &entities.InterimReport{
		Version: "1.3",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath: filePath,
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 12,
				EndLine:   12,
				Match:     "Cipher.getInstance(\"AES\")",
				Rules:     []entities.RuleInfo{{ID: "java.crypto.cipher", Message: "cipher", Severity: "INFO"}},
				Status:    "pending",
				FindingID: "omit-nil-test",
				Source:    "direct",
			}},
		}},
	}

	result := &engine.DepScanResult{
		CallGraph:   graph,
		Report:      report,
		RootModule:  "com.app",
		Ecosystem:   "java",
		ProjectRoot: projectRoot,
	}

	out := filepath.Join(t.TempDir(), "cg-nil-inferred.json")
	if err := ExportCallGraph(out, "json", result); err != nil {
		t.Fatalf("ExportCallGraph: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	if strings.Contains(string(data), `"inferred_return"`) {
		t.Fatalf("expected no 'inferred_return' key in JSON when InferredReturn is nil, got:\n%s", data)
	}
}

// ---------------------------------------------------------------------------
// T5.5 — exportFunctionMetadata.InferredReturn populated when inference fires
// ---------------------------------------------------------------------------

// TestExportFunctionMetadata_InferredReturnPopulated asserts that when
// FunctionDecl.InferredReturn is non-nil with a valid origin (not join-failed),
// the exported JSON contains the correct inferred_return object.
//
// Also verifies that origin "join-failed" causes the field to be absent.
func TestExportFunctionMetadata_InferredReturnPopulated(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()
	filePath := joinTestPath(projectRoot, "src/main/java/com/app/App.java")

	wrapperID := callgraph.FunctionID{Package: "com.app", Type: "App", Name: "unwrapKey#3"}
	cryptoID := callgraph.FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "unwrap#3"}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			wrapperID.String(): {
				ID:         wrapperID,
				FilePath:   filePath,
				StartLine:  20,
				EndLine:    25,
				ReturnType: "Object",
				InferredReturn: &callgraph.InferredReturn{
					Type:       "javax.crypto.SecretKey",
					Confidence: "high",
					Origin:     "kb-direct",
				},
			},
		},
		Callers: map[string][]string{
			cryptoID.String(): {wrapperID.String()},
		},
	}

	report := &entities.InterimReport{
		Version: "1.3",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath: filePath,
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 22,
				EndLine:   22,
				Match:     "Cipher.unwrap(...)",
				Rules:     []entities.RuleInfo{{ID: "java.crypto.cipher", Message: "cipher", Severity: "INFO"}},
				Status:    "pending",
				FindingID: "inferred-populated-test",
				Source:    "direct",
			}},
		}},
	}

	result := &engine.DepScanResult{
		CallGraph:   graph,
		Report:      report,
		RootModule:  "com.app",
		Ecosystem:   "java",
		ProjectRoot: projectRoot,
	}

	out := filepath.Join(t.TempDir(), "cg-inferred-populated.json")
	if err := ExportCallGraph(out, "json", result); err != nil {
		t.Fatalf("ExportCallGraph: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	if !strings.Contains(string(data), `"inferred_return"`) {
		t.Fatalf("expected 'inferred_return' key in JSON when InferredReturn is set, got:\n%s", data)
	}
	if !strings.Contains(string(data), `"javax.crypto.SecretKey"`) {
		t.Fatalf("expected inferred_return.type in JSON, got:\n%s", data)
	}
	if !strings.Contains(string(data), `"kb-direct"`) {
		t.Fatalf("expected inferred_return.origin in JSON, got:\n%s", data)
	}

	// Subtest: join-failed origin must be absent
	t.Run("join-failed-omitted", func(t *testing.T) {
		t.Parallel()

		joinFailedID := callgraph.FunctionID{Package: "com.app", Type: "App", Name: "joinFailed#0"}
		cryptoID2 := callgraph.FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "doFinal#0"}

		g2 := &callgraph.CallGraph{
			Functions: map[string]*callgraph.FunctionDecl{
				joinFailedID.String(): {
					ID:         joinFailedID,
					FilePath:   filePath,
					StartLine:  30,
					EndLine:    35,
					ReturnType: "Object",
					InferredReturn: &callgraph.InferredReturn{
						Type:       "",
						Confidence: "",
						Origin:     "join-failed", // must be suppressed in export
					},
				},
			},
			Callers: map[string][]string{
				cryptoID2.String(): {joinFailedID.String()},
			},
		}

		r2 := &entities.InterimReport{
			Version: "1.3",
			Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
			Findings: []entities.Finding{{
				FilePath: filePath,
				Language: "java",
				CryptographicAssets: []entities.CryptographicAsset{{
					StartLine: 32,
					EndLine:   32,
					Match:     "Cipher.doFinal()",
					Rules:     []entities.RuleInfo{{ID: "java.crypto.cipher", Message: "cipher", Severity: "INFO"}},
					Status:    "pending",
					FindingID: "join-failed-omit",
					Source:    "direct",
				}},
			}},
		}

		res2 := &engine.DepScanResult{
			CallGraph:   g2,
			Report:      r2,
			RootModule:  "com.app",
			Ecosystem:   "java",
			ProjectRoot: projectRoot,
		}

		out2 := filepath.Join(t.TempDir(), "cg-join-failed.json")
		if err := ExportCallGraph(out2, "json", res2); err != nil {
			t.Fatalf("ExportCallGraph: %v", err)
		}

		d2, err := os.ReadFile(out2)
		if err != nil {
			t.Fatalf("read: %v", err)
		}

		if strings.Contains(string(d2), `"inferred_return"`) {
			t.Fatalf("join-failed origin must NOT emit inferred_return in JSON, got:\n%s", d2)
		}
	})
}
