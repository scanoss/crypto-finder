package callgraph

import (
	"os"
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
	if create.Callee != (FunctionID{Package: "example/crypto", Type: "Botan::HashFunction", Name: "create"}) || create.AssignedVar != "hash" {
		t.Fatalf("create call = %#v", create)
	}
	if create.Line != 5 || create.StartCol != 17 || create.EndCol != 55 {
		t.Fatalf("create position = %d, %d:%d, want 5, 17:55", create.Line, create.StartCol, create.EndCol)
	}

	update, ok := calls["hash->update"]
	if !ok || update.Callee.Name != "update" || update.ReceiverVar != "hash" {
		t.Fatalf("update call = %#v", update)
	}

	random, ok := calls["CryptoPP::OS_GenerateRandomBlock"]
	if !ok || random.Callee != (FunctionID{Package: "example/crypto", Type: "CryptoPP", Name: "OS_GenerateRandomBlock"}) {
		t.Fatalf("CryptoPP call = %#v", random)
	}
}

func TestCPPParser_Registered(t *testing.T) {
	if _, ok := NewParserForEcosystem("cpp").(*CPPParser); !ok {
		t.Fatalf("NewParserForEcosystem(cpp) = %T, want *CPPParser", NewParserForEcosystem("cpp"))
	}
}
