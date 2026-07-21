package callgraph

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCPPParser_ParseDirectory(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "crypto.cpp")
	src := `#include <botan/hash.h>
#include "crypto/local.hpp"

Botan::HashFunction* build_hash() {
    auto hash = Botan::HashFunction::create("SHA-256");
    hash->update("message");
    CryptoPP::AutoSeededRandomPool rng;
	CryptoPP::OS_GenerateRandomBlock(false, buffer, 16);
    return hash;
}
`
	if err := os.WriteFile(filePath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	analyses, err := NewCPPParser().ParseDirectory(dir, "example/crypto")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("analyses = %d, want 1", len(analyses))
	}

	analysis := analyses[0]
	if analysis.Imports["botan/hash.h"] != "botan/hash.h" || analysis.Imports["crypto/local.hpp"] != "crypto/local.hpp" {
		t.Fatalf("imports = %#v, want both include paths", analysis.Imports)
	}
	if len(analysis.Functions) != 1 {
		t.Fatalf("functions = %d, want 1", len(analysis.Functions))
	}
	calls := make(map[string]FunctionCall, len(analysis.Functions[0].Calls))
	for _, call := range analysis.Functions[0].Calls {
		calls[call.Raw] = call
	}

	create, ok := calls["Botan::HashFunction::create"]
	if !ok {
		t.Fatalf("create call missing from %#v", analysis.Functions[0].Calls)
	}
	if create.Callee != (FunctionID{Package: "example/crypto", Type: "Botan::HashFunction", Name: "create"}) || create.AssignedVar != "hash" || create.ChainID != "" {
		t.Fatalf("create call = %#v", create)
	}
	if create.Line != 5 {
		t.Fatalf("create line = %d, want 5", create.Line)
	}

	update, ok := calls["hash->update"]
	if !ok || update.Callee.Name != "update" || update.ReceiverVar != "hash" || update.ChainID != "" {
		t.Fatalf("update call = %#v", update)
	}

	random, ok := calls["CryptoPP::OS_GenerateRandomBlock"]
	if !ok || random.Callee != (FunctionID{Package: "example/crypto", Type: "CryptoPP", Name: "OS_GenerateRandomBlock"}) || random.ChainID != "" {
		t.Fatalf("CryptoPP call = %#v", random)
	}
}

// TestCPPParser_ColumnConventionPinning compares C++ parser output against a
// real opengrep/semgrep match, which defines the 1-based, end-exclusive
// coordinates used to anchor findings to call-graph calls.
func TestCPPParser_ColumnConventionPinning(t *testing.T) {
	bin, err := exec.LookPath("opengrep")
	if err != nil {
		if bin, err = exec.LookPath("semgrep"); err != nil {
			t.Skip("neither opengrep nor semgrep in PATH; skipping column-convention pin")
		}
	}

	dir := t.TempDir()
	filePath := filepath.Join(dir, "crypto.cpp")
	src := `void hash_message() {
    auto hash = Botan::HashFunction::create("SHA-256");
}
`
	if err := os.WriteFile(filePath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	rulePath := filepath.Join(dir, "rule.yaml")
	rule := "rules:\n- id: cpp-column-pin\n  languages: [cpp]\n  message: pin\n  severity: INFO\n  pattern: Botan::HashFunction::create(\"SHA-256\")\n"
	if err := os.WriteFile(rulePath, []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}

	var args []string
	if filepath.Base(bin) == "opengrep" {
		args = []string{"scan", "--json", "--config", rulePath, dir}
	} else {
		args = []string{"--json", "--metrics", "off", "--config", rulePath, dir}
	}
	out, err := exec.CommandContext(context.Background(), bin, args...).Output()
	if err != nil {
		t.Skipf("%s present but unusable: %v", bin, err)
	}
	var result struct {
		Results []struct {
			Start struct {
				Line int `json:"line"`
				Col  int `json:"col"`
			} `json:"start"`
			End struct {
				Col int `json:"col"`
			} `json:"end"`
		} `json:"results"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("decode scanner output: %v", err)
	}
	if len(result.Results) != 1 {
		t.Fatalf("scanner results = %d, want 1", len(result.Results))
	}

	analyses, err := NewCPPParser().ParseDirectory(dir, "example/crypto")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	call := analyses[0].Functions[0].Calls[0]
	match := result.Results[0]
	if call.Line != match.Start.Line || call.StartCol != match.Start.Col || call.EndCol != match.End.Col {
		t.Fatalf("parser position = %d, %d:%d; scanner position = %d, %d:%d", call.Line, call.StartCol, call.EndCol, match.Start.Line, match.Start.Col, match.End.Col)
	}
}

func TestCPPParser_FluentChainContext(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "crypto.cpp")
	src := `void hash_message() {
    auto hash = Botan::HashFunction::create("SHA-256")->update("message");
}
`
	if err := os.WriteFile(filePath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	analyses, err := NewCPPParser().ParseDirectory(dir, "example/crypto")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	calls := analyses[0].Functions[0].Calls
	if len(calls) != 2 {
		t.Fatalf("calls = %#v, want create and update", calls)
	}

	var create, update FunctionCall
	for _, call := range calls {
		switch call.Callee.Name {
		case "create":
			create = call
		case "update":
			update = call
		}
	}
	if create.ChainID == "" || create.ChainID != update.ChainID {
		t.Fatalf("chain IDs = create %q, update %q, want one non-empty shared ID", create.ChainID, update.ChainID)
	}
	if create.AssignedVar != "" || update.AssignedVar != "hash" {
		t.Fatalf("assigned vars = create %q, update %q, want only outer call assigned to hash", create.AssignedVar, update.AssignedVar)
	}
}

func TestCPPParser_QualifiedDeclarationsResolveCalls(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "crypto.cpp")
	src := `void Botan::hash() {}

void Botan::caller() {
    Botan::hash();
}
`
	if err := os.WriteFile(filePath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	graph, err := NewBuilderForEcosystem("cpp", NewCPPParser()).BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "example/crypto"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories error: %v", err)
	}
	target := (FunctionID{Package: "example/crypto", Type: "Botan", Name: "hash"}).String()
	caller := (FunctionID{Package: "example/crypto", Type: "Botan", Name: "caller"}).String()
	if !containsString(graph.Callers[target], caller) {
		t.Fatalf("Callers[%q] = %#v, want %q", target, graph.Callers[target], caller)
	}
}

func TestCPPParser_Registered(t *testing.T) {
	if _, ok := NewParserForEcosystem("cpp").(*CPPParser); !ok {
		t.Fatalf("NewParserForEcosystem(cpp) = %T, want *CPPParser", NewParserForEcosystem("cpp"))
	}
}
