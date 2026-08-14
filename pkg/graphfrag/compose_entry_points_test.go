package graphfrag

import "testing"

// composeFixture builds a two-component closure where the root's public API
// transitively calls (via a super() constructor edge) a dependency function
// that the dependency's own mine-time annotation marks as a crypto entry
// point. The stitched trace itself finds nothing (the dependency's internal
// path to the crypto op is deliberately absent), so every served signal must
// come from entry-point composition.
func composeFixture() (ComponentKey, DependencyGraph, map[ComponentKey]Fragment) {
	root := ComponentKey{Purl: "pkg:maven/org.example/wrapper", Version: "1.0.0"}
	dep := ComponentKey{Purl: "pkg:maven/org.example/client", Version: "2.0.0"}

	rootFragment := Fragment{
		Component: root,
		Module:    "org.example.wrapper",
		Functions: []Function{
			{Signature: "org.example.wrapper.(Factory).create#0", FunctionName: "org.example.wrapper.Factory.create",
				CanonicalSignature: "org.example.wrapper.Factory.create(): Client", Visibility: "public", OwnerVisibility: "public"},
			{Signature: "org.example.wrapper.(Factory.Extended).<init>#1", FunctionName: "org.example.wrapper.Factory.Extended.<init>",
				CanonicalSignature: "org.example.wrapper.Factory.Extended.<init>(Map): Factory.Extended", Visibility: "public", OwnerVisibility: "public"},
		},
		InternalEdges: []InternalEdge{
			{Caller: "org.example.wrapper.(Factory).create#0", Callee: "org.example.wrapper.(Factory.Extended).<init>#1", Resolution: ResolutionExact},
		},
		ExternalCalls: []ExternalCall{
			// The super(configs) constructor-delegation edge into the dependency.
			{Caller: "org.example.wrapper.(Factory.Extended).<init>#1", TargetSignature: "org.example.client.(Client).<init>#1",
				TargetCanonicalSignature: "org.example.client.Client.<init>(java.util.Map): Client", Resolution: ResolutionExact, MethodName: "<init>", Arity: 1},
		},
	}

	depFragment := Fragment{
		Component: dep,
		Module:    "org.example.client",
		Functions: []Function{
			// Two same-arity constructor overloads: the alias join must
			// disambiguate by the call's canonical parameter type (Map).
			{Signature: "org.example.client.(Client).<init>#1$Map", FunctionName: "org.example.client.Client.<init>",
				CanonicalSignature: "org.example.client.Client.<init>(Map): Client", Visibility: "public", OwnerVisibility: "public"},
			{Signature: "org.example.client.(Client).<init>#1$Properties", FunctionName: "org.example.client.Client.<init>",
				CanonicalSignature: "org.example.client.Client.<init>(Properties): Client", Visibility: "public", OwnerVisibility: "public"},
		},
		CryptoOperations: []CryptoOperation{
			{Function: "org.example.client.(Ssl).init#0", FindingID: "aaaa1111", RuleID: "rule.tls",
				Symbol: "javax.net.ssl.SSLContext.getInstance", FilePath: "org/example/client/Ssl.java", StartLine: 10},
		},
		CryptoEntryPoints: []CryptoEntryPoint{
			{FunctionKey: "org.example.client.(Client).<init>#1$Map", FunctionName: "org.example.client.Client.<init>",
				CanonicalSignature: "org.example.client.Client.<init>(Map): Client", Visibility: "public", OwnerVisibility: "public",
				ReachableFindings: []ReachableFinding{{FindingID: "aaaa1111", ChainDepth: 4, FindingGraphRef: "aaaa1111"}}},
		},
	}

	fragments := map[ComponentKey]Fragment{root: rootFragment, dep: depFragment}
	return root, DependencyGraph{root: {dep}}, fragments
}

func TestComposeDependencyEntryPoints(t *testing.T) {
	root, deps, fragments := composeFixture()
	res, err := StitchWithOptions(root, deps, fragments, StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	cg := res.ToCallgraphExport(root, ScanMeta{Ecosystem: "java", RootModule: "org.example.wrapper"})

	var create *ExportCryptoEntryPoint
	for i := range cg.CryptoEntryPoints {
		if cg.CryptoEntryPoints[i].FunctionKey == "org.example.wrapper.(Factory).create#0" {
			create = &cg.CryptoEntryPoints[i]
		}
	}
	if create == nil {
		t.Fatalf("composed root entry point not served; got %d entry points", len(cg.CryptoEntryPoints))
	}
	if !create.Root {
		t.Error("in-degree-zero composed entry point must be root")
	}
	if create.CanonicalSignature != "org.example.wrapper.Factory.create(): Client" {
		t.Errorf("canonical_signature = %q", create.CanonicalSignature)
	}
	if len(create.ReachableFindings) != 1 {
		t.Fatalf("reachable findings = %d, want 1", len(create.ReachableFindings))
	}
	rf := create.ReachableFindings[0]
	// create -> Extended.<init> -> Client.<init> is 2 hops; the entry point's
	// own mine-time depth is 4.
	if rf.ChainDepth != 6 {
		t.Errorf("composed chain depth = %d, want 6", rf.ChainDepth)
	}
	// The served ID must be the dep-prefixed recomputation, not the
	// annotation-local mine-time hash.
	want := computeFindingID("org.example.client@2.0.0/org/example/client/Ssl.java", 10, "rule.tls")
	if rf.FindingID != want {
		t.Errorf("composed finding id = %q, want served-form %q", rf.FindingID, want)
	}
	if rf.FindingID == "aaaa1111" {
		t.Error("composed finding id must not be the annotation-local hash")
	}
}
