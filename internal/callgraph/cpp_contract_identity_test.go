// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestCPPContractInferenceUsesProjectIndependentQualifiedIdentity(t *testing.T) {
	t.Parallel()

	kb := &contracts.KnowledgeBase{Ecosystem: ecosystemCPP, Contracts: map[string][]contracts.Contract{
		"CryptoPP.SHA256#0": {{Return: contracts.ContractReturn{Type: "CryptoPP::SHA256", Confidence: "high"}}},
	}}
	for _, pkg := range []string{"app/one", "app/two"} {
		t.Run(pkg, func(t *testing.T) {
			t.Parallel()
			target := FunctionID{Package: pkg, Type: "CryptoPP", Name: "SHA256#0"}
			wrapper := &FunctionDecl{
				ID:            FunctionID{Package: pkg, Name: "digest"},
				ReturnSources: []SourceNode{{Type: sourceNodeCallResult, CallTarget: &target}},
			}
			if err := InferReturnTypes(buildTestCallGraph(wrapper), kb); err != nil {
				t.Fatal(err)
			}
			if wrapper.InferredReturn == nil || wrapper.InferredReturn.Type != "CryptoPP::SHA256" {
				t.Fatalf("InferredReturn = %#v, want project-independent Crypto++ contract", wrapper.InferredReturn)
			}
		})
	}
}

func TestCPPContractInferencePreservesLocalQualifiedDeclaration(t *testing.T) {
	t.Parallel()

	kb := &contracts.KnowledgeBase{Ecosystem: ecosystemCPP, Contracts: map[string][]contracts.Contract{
		"CryptoPP.SHA256#0": {{Return: contracts.ContractReturn{Type: "CryptoPP::SHA256", Confidence: "high"}}},
	}}
	target := FunctionID{Package: "app", Type: "CryptoPP", Name: "SHA256#0"}
	localID := FunctionID{Package: "app", Type: "CryptoPP", Name: "SHA256"}
	wrapper := &FunctionDecl{
		ID:            FunctionID{Package: "app", Name: "digest"},
		ReturnSources: []SourceNode{{Type: sourceNodeCallResult, CallTarget: &target}},
	}
	graph := buildTestCallGraph(wrapper, &FunctionDecl{ID: localID})
	if err := InferReturnTypes(graph, kb); err != nil {
		t.Fatal(err)
	}
	if wrapper.InferredReturn != nil {
		t.Fatalf("InferredReturn = %#v, want local declaration to suppress library fallback", wrapper.InferredReturn)
	}
}

func TestCPPParserResolvesTypedReceiverIdentity(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := `void digest(const CryptoPP::byte *in, size_t len, CryptoPP::byte *out) {
    CryptoPP::SHA256 hash;
    hash.Update(in, len);
	{
		Local::SHA256 hash;
		hash.Final(out);
	}
}`
	if err := os.WriteFile(filepath.Join(dir, "digest.cpp"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCPPParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	calls := analyses[0].Functions[0].Calls
	if len(calls) != 2 || calls[0].Callee.Type != "CryptoPP::SHA256" || calls[1].Callee.Type != "Local::SHA256" {
		t.Fatalf("calls = %#v, want lexical receiver types", calls)
	}
}

func TestCPPParserPreservesInlineLocalTypePrecedence(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := `namespace CryptoPP {
class SHA256 {
public:
    void Update(const void *, int) {}
};
}
void digest(const void *input, int length) {
    CryptoPP::SHA256 hash;
    hash.Update(input, length);
}`
	if err := os.WriteFile(filepath.Join(dir, "local.cpp"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	graph, err := NewBuilderForEcosystem(ecosystemCPP, NewCPPParser()).BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	method := FunctionID{Package: "app", Type: "CryptoPP::SHA256", Name: "Update"}
	if graph.Functions[method.String()] == nil {
		t.Fatalf("functions = %#v, want inline %s", graph.Functions, method.String())
	}
	digest := graph.Functions[(FunctionID{Package: "app", Name: "digest"}).String()]
	if len(digest.Calls) != 1 || digest.Calls[0].Callee.Linkage != LinkageInternal {
		t.Fatalf("digest calls = %#v, want project-local receiver", digest.Calls)
	}
}

func TestCPPParserPreservesCrossFileLocalTypePrecedence(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	header := `namespace CryptoPP {
class SHA256 {
public:
    void Update(const void *, int);
};
}`
	source := `void digest(const void *input, int length) {
    CryptoPP::SHA256 hash;
    hash.Update(input, length);
}`
	for name, content := range map[string]string{"local.hpp": header, "digest.cpp": source} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := NewBuilderForEcosystem(ecosystemCPP, NewCPPParser()).BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := graph.Functions[(FunctionID{Package: "app", Name: "digest"}).String()]
	if len(digest.Calls) != 1 || digest.Calls[0].Callee.Linkage != LinkageInternal {
		t.Fatalf("digest calls = %#v, want header-declared project-local receiver", digest.Calls)
	}
}

func TestCPPParserPreservesCrossPackageLocalNamespaceFunction(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	libDir := filepath.Join(root, "lib")
	appDir := filepath.Join(root, "app")
	for _, dir := range []string{libDir, appDir} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(libDir, "local.cpp"), []byte(`namespace CryptoPP { int SHA256() { return 7; } }`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "digest.cpp"), []byte(`int digest() { return CryptoPP::SHA256(); }`), 0o644); err != nil {
		t.Fatal(err)
	}
	graph, err := NewBuilderForEcosystem(ecosystemCPP, NewCPPParser()).BuildFromDirectories([]PackageDir{
		{Dir: libDir, ImportPath: "project/lib"},
		{Dir: appDir, ImportPath: "project/app"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := graph.Functions[(FunctionID{Package: "project/app", Name: "digest"}).String()]
	if len(digest.Calls) != 1 || digest.Calls[0].Callee.Linkage != LinkageInternal {
		t.Fatalf("digest calls = %#v, want cross-package project-local namespace function", digest.Calls)
	}
	if len(digest.ReturnSources) != 1 || digest.ReturnSources[0].CallTarget == nil || digest.ReturnSources[0].CallTarget.Linkage != LinkageInternal {
		t.Fatalf("digest return sources = %#v, want cross-package project-local namespace function", digest.ReturnSources)
	}
}

func TestCPPParserDoesNotTreatDependencyTypesAsProjectLocal(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	depDir := filepath.Join(root, "dependency")
	appDir := filepath.Join(root, "app")
	for _, dir := range []string{depDir, appDir} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	dependency := `namespace CryptoPP { class SHA256 {}; }
auto dependencyDigest() { return CryptoPP::SHA256(); }`
	if err := os.WriteFile(filepath.Join(depDir, "sha.cpp"), []byte(dependency), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "digest.cpp"), []byte(`auto digest() { return CryptoPP::SHA256(); }`), 0o644); err != nil {
		t.Fatal(err)
	}
	graph, err := NewBuilderForEcosystem(ecosystemCPP, NewCPPParser()).BuildFromDirectories([]PackageDir{
		{Dir: appDir, ImportPath: "app"},
		{Dir: depDir, ImportPath: "cryptopp", Version: "8.9.0"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := graph.Functions[(FunctionID{Package: "app", Name: "digest"}).String()]
	if len(digest.Calls) != 1 || digest.Calls[0].Callee.Linkage == LinkageInternal {
		t.Fatalf("digest calls = %#v, want versioned dependency receiver to remain external", digest.Calls)
	}
	dependencyDigest := graph.Functions[(FunctionID{Package: "cryptopp", Name: "dependencyDigest"}).String()]
	if len(dependencyDigest.Calls) != 1 || dependencyDigest.Calls[0].Callee.Linkage == LinkageInternal {
		t.Fatalf("dependency calls = %#v, want versioned dependency self-call to remain external", dependencyDigest.Calls)
	}
}

func TestCPPParserNormalizesGlobalQualifierOnReceiverTypes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := `void update(::CryptoPP::SHA256 &hash, const void *input) {
    hash.Update(input);
}
void digest(const void *input) {
    ::CryptoPP::SHA256 hash;
    hash.Update(input);
}`
	if err := os.WriteFile(filepath.Join(dir, "global.cpp"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCPPParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	for _, function := range analyses[0].Functions {
		if len(function.Calls) != 1 || function.Calls[0].Callee.Type != "CryptoPP::SHA256" {
			t.Fatalf("%s parameters = %#v calls = %#v, want normalized receiver type", function.ID, function.Parameters, function.Calls)
		}
	}
}

func TestCPPContractResolutionUsesCallArityAndGlobalQualifier(t *testing.T) {
	t.Parallel()

	kb := &contracts.KnowledgeBase{Ecosystem: ecosystemCPP, Contracts: map[string][]contracts.Contract{
		"CryptoPP.SHA256#0":         {{Return: contracts.ContractReturn{Type: "CryptoPP::SHA256", Confidence: "high"}}},
		"CryptoPP::SHA256.Update#1": {{Return: contracts.ContractReturn{Type: "CryptoPP::SHA256", Confidence: "high"}}},
	}}
	fn := &FunctionDecl{
		ID: FunctionID{Package: "app", Name: "digest"},
		Calls: []FunctionCall{
			{Callee: FunctionID{Package: "app", Type: "CryptoPP", Name: "SHA256"}, Arguments: nil, ChainID: "1", Raw: "::CryptoPP::SHA256"},
			{Callee: FunctionID{Package: "app", Name: "Update"}, Arguments: []string{"input"}, ChainID: "1", Raw: "::CryptoPP::SHA256().Update"},
		},
	}
	graph := buildTestCallGraph(fn)
	resolveFluentChainCalleesByContract(graph, kb)
	if fn.Calls[1].Callee.Type != "CryptoPP::SHA256" {
		t.Fatalf("resolved call = %#v, want arity-aware CryptoPP::SHA256.Update", fn.Calls[1])
	}

	dir := t.TempDir()
	src := `auto digest() { return ::CryptoPP::SHA256(); }`
	if err := os.WriteFile(filepath.Join(dir, "global.cpp"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCPPParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	if got := analyses[0].Functions[0].Calls[0].Callee.Type; got != "CryptoPP" {
		t.Fatalf("global qualifier type = %q, want CryptoPP", got)
	}
}
