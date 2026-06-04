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

	if payload.SchemaVersion != "6.1" {
		t.Fatalf("schema_version = %q, want 6.1", payload.SchemaVersion)
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

// ---------------------------------------------------------------------------
// Issue 2 — Suppress inferred_return when inferred type equals declared type
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Schema version 6.0
// ---------------------------------------------------------------------------

// TestExportSchemaVersionIs53 asserts that the call graph export carries
// callGraphSchemaVersion = "6.0" (schema bump from 5.2, Batch 7).
func TestExportSchemaVersionIs53(t *testing.T) {
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
				FindingID: "schema53-test",
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

	out := filepath.Join(t.TempDir(), "cg-schema53.json")
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

	if payload.SchemaVersion != "6.1" {
		t.Fatalf("schema_version = %q, want 6.1", payload.SchemaVersion)
	}
}

// ---------------------------------------------------------------------------
// Issue 2 — Suppress inferred_return when inferred type equals declared type
// ---------------------------------------------------------------------------

// TestExportFunctionMetadata_SuppressesInferredReturnWhenEqualsDeclared verifies
// that when InferredReturn.Type equals FunctionDecl.ReturnType the exported JSON
// does NOT contain an "inferred_return" key (redundant emission suppression).
//
// This de-noises the export: an inferred type that exactly matches the declared
// type carries zero information for consumers.
func TestExportFunctionMetadata_SuppressesInferredReturnWhenEqualsDeclared(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()
	filePath := joinTestPath(projectRoot, "src/main/java/com/app/App.java")

	wrapperID := callgraph.FunctionID{Package: "com.app", Type: "App", Name: "doDigest#1"}
	cryptoID := callgraph.FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "doFinal#1"}

	// Declared return type == inferred type → should be suppressed.
	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			wrapperID.String(): {
				ID:         wrapperID,
				FilePath:   filePath,
				StartLine:  10,
				EndLine:    15,
				ReturnType: "byte[]", // declared
				InferredReturn: &callgraph.InferredReturn{
					Type:       "byte[]", // same as declared → suppress
					Confidence: "high",
					Origin:     "constructor",
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
				StartLine: 12,
				EndLine:   12,
				Match:     "Cipher.doFinal(...)",
				Rules:     []entities.RuleInfo{{ID: "java.crypto.cipher", Message: "cipher", Severity: "INFO"}},
				Status:    "pending",
				FindingID: "suppress-equal-declared",
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

	out := filepath.Join(t.TempDir(), "cg-suppress-equal.json")
	if err := ExportCallGraph(out, "json", result); err != nil {
		t.Fatalf("ExportCallGraph: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	if strings.Contains(string(data), `"inferred_return"`) {
		t.Fatalf("expected NO 'inferred_return' in JSON when inferred type == declared type, got:\n%s", data)
	}
}

// ---------------------------------------------------------------------------
// Issue 1e — call_target_inferred_return on CALL_RESULT source nodes
// ---------------------------------------------------------------------------

// TestExportSourceNode_PopulatesCallTargetInferredReturn verifies that a
// CALL_RESULT SourceNode whose call_target function has an InferredReturn
// (different from the function's declared type) is decorated with
// call_target_inferred_return in the exported JSON.
func TestExportSourceNode_PopulatesCallTargetInferredReturn(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()
	filePath := joinTestPath(projectRoot, "src/main/java/com/app/AESCBC.java")

	// RSA.unwrapSecretKey has InferredReturn = SecretKey (declared = Key)
	unwrapID := callgraph.FunctionID{Package: "com.mastercard.rsa", Type: "RSA", Name: "unwrapSecretKey#1"}
	cipherID := callgraph.FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "getInstance#1"}
	callerID := callgraph.FunctionID{Package: "com.app", Type: "AESCBC", Name: "cipher#1"}

	unwrapFn := &callgraph.FunctionDecl{
		ID:         unwrapID,
		ReturnType: "java.security.Key",
		InferredReturn: &callgraph.InferredReturn{
			Type:       "javax.crypto.SecretKey",
			Confidence: "high",
			Origin:     "kb-conditional",
		},
	}

	// callerFn calls Cipher.getInstance (the crypto finding) at line 15.
	// The first argument to getInstance is the key returned by RSA.unwrapSecretKey,
	// which appears as a CALL_RESULT SourceNode in the argument provenance.
	callerFn := &callgraph.FunctionDecl{
		ID:         callerID,
		FilePath:   filePath,
		StartLine:  10,
		EndLine:    20,
		ReturnType: "Object",
		Calls: []callgraph.FunctionCall{{
			Callee:    cipherID,
			Line:      15,
			Arguments: []string{"RSA.unwrapSecretKey(wrappedKey)", "\"AES\""},
			ArgumentSources: [][]callgraph.SourceNode{
				{
					// Argument 0 provenance: came from RSA.unwrapSecretKey call
					{
						Type:         "CALL_RESULT",
						Value:        "RSA.unwrapSecretKey(wrappedKey)",
						CallTarget:   &unwrapID,
						DeclaredType: "java.security.Key",
					},
				},
				{
					{Type: "VALUE", Value: `"AES"`},
				},
			},
		}},
	}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			unwrapID.String(): unwrapFn,
			callerID.String(): callerFn,
		},
		Callers: map[string][]string{
			cipherID.String(): {callerID.String()},
		},
	}

	report := &entities.InterimReport{
		Version: "1.3",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath: filePath,
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 15,
				EndLine:   15,
				Match:     "Cipher.getInstance(\"AES\")",
				Rules:     []entities.RuleInfo{{ID: "java.crypto.cipher", Message: "cipher", Severity: "INFO"}},
				Status:    "pending",
				FindingID: "call-target-inferred-test",
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

	out := filepath.Join(t.TempDir(), "cg-call-target-inferred.json")
	if err := ExportCallGraph(out, "json", result); err != nil {
		t.Fatalf("ExportCallGraph: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	if !strings.Contains(string(data), `"call_target_inferred_return"`) {
		t.Fatalf("expected 'call_target_inferred_return' in exported JSON, got:\n%s", data)
	}
	if !strings.Contains(string(data), `"javax.crypto.SecretKey"`) {
		t.Fatalf("expected inferred type 'javax.crypto.SecretKey' in call_target_inferred_return, got:\n%s", data)
	}
}

// TestExportSourceNode_SuppressesCallTargetInferredReturnWhenEqualsDeclared verifies
// that when a call_target's inferred type equals the declared return type of that
// function, call_target_inferred_return is omitted (same suppression rule as Issue 2).
func TestExportSourceNode_SuppressesCallTargetInferredReturnWhenEqualsDeclared(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()
	filePath := joinTestPath(projectRoot, "src/main/java/com/app/AESCBC.java")

	targetID := callgraph.FunctionID{Package: "com.app", Type: "KeyHelper", Name: "getKey#0"}
	cipherID := callgraph.FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "getInstance#1"}
	callerID := callgraph.FunctionID{Package: "com.app", Type: "AESCBC", Name: "cipher#0"}

	// Declared == Inferred → suppress call_target_inferred_return.
	targetFn := &callgraph.FunctionDecl{
		ID:         targetID,
		ReturnType: "byte[]",
		InferredReturn: &callgraph.InferredReturn{
			Type:       "byte[]", // same as declared
			Confidence: "high",
			Origin:     "constructor",
		},
	}

	// callerFn calls Cipher.getInstance (the crypto finding) at line 10.
	// The argument provenance includes a CALL_RESULT pointing to KeyHelper.getKey
	// whose inferred type == declared type (byte[]) → suppressed.
	callerFn := &callgraph.FunctionDecl{
		ID:         callerID,
		FilePath:   filePath,
		StartLine:  5,
		EndLine:    15,
		ReturnType: "Object",
		Calls: []callgraph.FunctionCall{{
			Callee:    cipherID,
			Line:      10,
			Arguments: []string{"KeyHelper.getKey()"},
			ArgumentSources: [][]callgraph.SourceNode{
				{
					{
						Type:         "CALL_RESULT",
						Value:        "KeyHelper.getKey()",
						CallTarget:   &targetID,
						DeclaredType: "byte[]",
					},
				},
			},
		}},
	}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			targetID.String(): targetFn,
			callerID.String(): callerFn,
		},
		Callers: map[string][]string{
			cipherID.String(): {callerID.String()},
		},
	}

	report := &entities.InterimReport{
		Version: "1.3",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath: filePath,
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 10,
				EndLine:   10,
				Match:     "Cipher.getInstance(\"AES\")",
				Rules:     []entities.RuleInfo{{ID: "java.crypto.cipher", Message: "cipher", Severity: "INFO"}},
				Status:    "pending",
				FindingID: "call-target-suppress-equal",
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

	out := filepath.Join(t.TempDir(), "cg-call-target-suppress.json")
	if err := ExportCallGraph(out, "json", result); err != nil {
		t.Fatalf("ExportCallGraph: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	if strings.Contains(string(data), `"call_target_inferred_return"`) {
		t.Fatalf("expected NO 'call_target_inferred_return' when inferred==declared, got:\n%s", data)
	}
}

// TestExportFunctionMetadata_EmitsInferredReturnWhenDifferentFromDeclared verifies
// that when InferredReturn.Type differs from the declared type, the field IS emitted.
func TestExportFunctionMetadata_EmitsInferredReturnWhenDifferentFromDeclared(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()
	filePath := joinTestPath(projectRoot, "src/main/java/com/app/App.java")

	wrapperID := callgraph.FunctionID{Package: "com.app", Type: "App", Name: "unwrap#1"}
	cryptoID := callgraph.FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "unwrap#3"}

	// Declared = "Key", inferred = "javax.crypto.SecretKey" → EMIT.
	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			wrapperID.String(): {
				ID:         wrapperID,
				FilePath:   filePath,
				StartLine:  20,
				EndLine:    25,
				ReturnType: "Key", // declared
				InferredReturn: &callgraph.InferredReturn{
					Type:       "javax.crypto.SecretKey", // different → emit
					Confidence: "high",
					Origin:     "kb-conditional",
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
				FindingID: "emit-different-declared",
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

	out := filepath.Join(t.TempDir(), "cg-emit-different.json")
	if err := ExportCallGraph(out, "json", result); err != nil {
		t.Fatalf("ExportCallGraph: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	if !strings.Contains(string(data), `"inferred_return"`) {
		t.Fatalf("expected 'inferred_return' in JSON when inferred type != declared type, got:\n%s", data)
	}
	if !strings.Contains(string(data), `"javax.crypto.SecretKey"`) {
		t.Fatalf("expected inferred type in JSON, got:\n%s", data)
	}
}
