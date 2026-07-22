package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

const cParitySource = `#include <openssl/evp.h>
#include "local/crypto.h"

EVP_CIPHER_CTX *new_context(void) {
    return EVP_CIPHER_CTX_new();
}

EVP_CIPHER_CTX *relay_context(void) {
    return new_context();
}

void *unknown_context(void) {
    return missing_factory();
}

int initialize(void) {
    EVP_CIPHER_CTX *ctx = new_context();
    return EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
}
`

func writeCParityFixture(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "crypto.c"), []byte(cParitySource), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return dir
}

func TestCParity_ParserCallNodesAndIncludes(t *testing.T) {
	dir := writeCParityFixture(t)
	analyses, err := NewCParser().ParseDirectory(dir, "example/crypto")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("analyses = %d, want 1", len(analyses))
	}

	analysis := analyses[0]
	for _, include := range []string{"openssl/evp.h", "local/crypto.h"} {
		if analysis.Imports[include] != include {
			t.Errorf("imports = %#v, missing %q", analysis.Imports, include)
		}
	}

	initialize := findCFunction(t, analysis, "initialize")
	if len(initialize.Calls) != 3 {
		t.Fatalf("initialize calls = %#v, want new_context, EVP_EncryptInit_ex, and EVP_aes_256_gcm", initialize.Calls)
	}
	calls := make(map[string]FunctionCall, len(initialize.Calls))
	for _, call := range initialize.Calls {
		calls[call.Callee.Name] = call
	}
	if got := calls["new_context"]; got.AssignedVar != "ctx" || got.Callee.Linkage != LinkageExternal {
		t.Errorf("new_context call = %#v, want assigned ctx with external linkage", got)
	}
	if got := calls["EVP_EncryptInit_ex"]; got.Line != 18 || got.StartCol != 12 || got.EndCol != 72 || len(got.Arguments) != 5 {
		t.Errorf("EVP_EncryptInit_ex call = %#v, want line 18, cols 12:72, and 5 arguments", got)
	}
}

func TestCParity_InferenceAndGracefulDegradation(t *testing.T) {
	dir := writeCParityFixture(t)
	builder := NewBuilderForEcosystem("c", NewCParser())
	builder.SetTypeResolver(NewCContractTypeResolverFromEmbedded())
	graph, err := builder.BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "example/crypto"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	newContext := graph.Functions[(FunctionID{Package: "example/crypto", Name: "new_context", Linkage: LinkageExternal}).String()]
	if newContext == nil {
		t.Fatal("new_context not found")
	}
	if len(newContext.ReturnSources) != 1 || newContext.ReturnSources[0].CallTarget == nil || newContext.ReturnSources[0].CallTarget.Name != "EVP_CIPHER_CTX_new#0" {
		t.Fatalf("new_context ReturnSources = %#v, want EVP_CIPHER_CTX_new#0 call result", newContext.ReturnSources)
	}
	if newContext.InferredReturn == nil || newContext.InferredReturn.Type != "EVP_CIPHER_CTX*" || newContext.InferredReturn.Origin != OriginKBDirect {
		t.Fatalf("new_context InferredReturn = %#v, want KB-direct EVP_CIPHER_CTX*", newContext.InferredReturn)
	}

	relay := graph.Functions[(FunctionID{Package: "example/crypto", Name: "relay_context", Linkage: LinkageExternal}).String()]
	if relay == nil || relay.InferredReturn == nil || relay.InferredReturn.Type != "EVP_CIPHER_CTX*" || relay.InferredReturn.Origin != OriginPropagated {
		t.Fatalf("relay_context = %#v, want propagated EVP_CIPHER_CTX*", relay)
	}

	unknown := graph.Functions[(FunctionID{Package: "example/crypto", Name: "unknown_context", Linkage: LinkageExternal}).String()]
	if unknown == nil || len(unknown.ReturnSources) != 1 || unknown.InferredReturn != nil {
		t.Fatalf("unknown_context = %#v, want unresolved call source without inferred type", unknown)
	}
}
