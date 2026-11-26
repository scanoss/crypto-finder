// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"encoding/json"
	"testing"
)

// filterFindings is a two-asset component where one finding is reachable from an
// entry point that heads no emitted chain — the shape #116 got wrong. Chains are
// capped per finding upstream, so the index routinely carries entries the chain
// set does not start at.
const filterFindings = `{
	"version":"1.4",
	"findings":[{"language":"java","file_path":"Tls.java","cryptographic_assets":[{
		"finding_id":"finding-tls","match":"getDefault()","source":"direct","start_line":95,"end_line":95,"metadata":{}
	}]},{"language":"java","file_path":"Hashing.java","cryptographic_assets":[{
		"finding_id":"finding-md5","match":"getInstance(\"MD5\")","source":"direct","start_line":12,"end_line":12,"metadata":{}
	}]}]
}`

const filterCallgraph = `{
	"schema_version":"6.9",
	"finding_graphs":[
		{"finding_id":"finding-tls","call_chains":[[
			{"canonical_signature":"example.Internal.dispatch(): void"},
			{"canonical_signature":"example.Socket.connect(): void"}
		]]},
		{"finding_id":"finding-md5","call_chains":[[
			{"canonical_signature":"example.Other.run(): void"}
		]]}
	],
	"crypto_entry_points":[
		{"canonical_signature":"example.Api.doWork(): void","root":true,
		 "reachable_findings":[{"finding_id":"finding-tls","chain_depth":5}]},
		{"canonical_signature":"example.Internal.dispatch(): void",
		 "reachable_findings":[{"finding_id":"finding-tls","chain_depth":2}]},
		{"canonical_signature":"example.Other.run(): void","root":true,
		 "reachable_findings":[{"finding_id":"finding-md5","chain_depth":1}]}
	]
}`

func TestComponentBlockFiltersOnTheEntryPointIndex(t *testing.T) {
	cases := []struct {
		name          string
		signature     string
		wantAssets    int
		wantUnmatched bool
	}{
		{
			name:      "entry point that heads no chain still selects its finding",
			signature: "example.Api.doWork(): void",
			// The pre-#116 chain-head match returned zero assets here and echoed
			// the signature back as if it were a typo.
			wantAssets: 1,
		},
		{
			name:       "chain head keeps working",
			signature:  "example.Internal.dispatch(): void",
			wantAssets: 1,
		},
		{
			name:       "filter selects only the findings its entry reaches",
			signature:  "example.Other.run(): void",
			wantAssets: 1,
		},
		{
			name:          "signature absent from the component is still reported",
			signature:     "example.Absent.method(): void",
			wantAssets:    0,
			wantUnmatched: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			block, report, err := ComponentBlock(ComponentInput{
				Purl: "pkg:maven/example/crypto", Version: "1.0.0",
				Findings: []byte(filterFindings), Callgraph: []byte(filterCallgraph),
				EntryPointSignatures: []string{tc.signature},
				IncludeCallChains:    true,
			})
			if err != nil {
				t.Fatalf("ComponentBlock: %v", err)
			}
			if block.FindingCount != tc.wantAssets {
				t.Errorf("finding_count = %d, want %d", block.FindingCount, tc.wantAssets)
			}
			if got := len(report.UnmatchedSignatures) > 0; got != tc.wantUnmatched {
				t.Errorf("unmatched_signatures = %v, want present=%v", report.UnmatchedSignatures, tc.wantUnmatched)
			}
		})
	}
}

// TestComponentBlockNeverReportsAnIndexedSignatureAsUnmatched pins the invariant
// behind #116: unmatched_signatures is a typo diagnostic, so a signature the
// response itself publishes as an entry point must never appear in it.
func TestComponentBlockNeverReportsAnIndexedSignatureAsUnmatched(t *testing.T) {
	var cg struct {
		CryptoEntryPoints []struct {
			CanonicalSignature string `json:"canonical_signature"`
		} `json:"crypto_entry_points"`
	}
	if err := json.Unmarshal([]byte(filterCallgraph), &cg); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(cg.CryptoEntryPoints) == 0 {
		t.Fatal("fixture publishes no entry points")
	}

	for _, entry := range cg.CryptoEntryPoints {
		_, report, err := ComponentBlock(ComponentInput{
			Purl: "pkg:maven/example/crypto", Version: "1.0.0",
			Findings: []byte(filterFindings), Callgraph: []byte(filterCallgraph),
			EntryPointSignatures: []string{entry.CanonicalSignature},
		})
		if err != nil {
			t.Fatalf("%s: ComponentBlock: %v", entry.CanonicalSignature, err)
		}
		if len(report.UnmatchedSignatures) != 0 {
			t.Errorf("%s: reported unmatched %v, want none — it is in crypto_entry_points",
				entry.CanonicalSignature, report.UnmatchedSignatures)
		}
	}
}

// TestComponentBlockNarrowsChainsToTheRequestedEntry documents the deliberate
// consequence of selecting on the index: the asset survives, and call_chains
// carries only the routes that start at a requested entry — which is empty when
// the entry heads none of the emitted chains. The reachability verdict and the
// index entry's chain_depth remain the evidence in that case.
func TestComponentBlockNarrowsChainsToTheRequestedEntry(t *testing.T) {
	block, _, err := ComponentBlock(ComponentInput{
		Purl: "pkg:maven/example/crypto", Version: "1.0.0",
		Findings: []byte(filterFindings), Callgraph: []byte(filterCallgraph),
		EntryPointSignatures: []string{"example.Api.doWork(): void"},
		IncludeCallChains:    true,
	})
	if err != nil {
		t.Fatalf("ComponentBlock: %v", err)
	}
	if len(block.Findings) != 1 {
		t.Fatalf("findings = %d, want the one finding the entry reaches", len(block.Findings))
	}
	var chains []json.RawMessage
	if err := json.Unmarshal(block.Findings[0].CryptographicAssets[0].CallChains, &chains); err != nil {
		t.Fatalf("decode call_chains: %v", err)
	}
	if len(chains) != 0 {
		t.Errorf("call_chains = %d, want none: no emitted chain starts at the requested entry", len(chains))
	}
}

func TestComponentBlockProjectsForwardCallsOnlyWhenRequested(t *testing.T) {
	findings := []byte(`{
		"version":"1.4",
		"findings":[{"language":"java","file_path":"Crypto.java","cryptographic_assets":[{
			"finding_id":"finding-1","match":"run()","source":"direct","start_line":1,"end_line":1,"metadata":{}
		}]}]
	}`)
	callgraph := []byte(`{
		"schema_version":"6.6",
		"finding_graphs":[{"finding_id":"finding-1","forward_calls":{
			"anchor":{"function_key":"example.Crypto.run#0"},
			"max_depth":1,
			"truncated":true,
			"nodes":[
				{"function_key":"example.Crypto.processBlock#bytes","depth":1},
				{"function_key":"example.Crypto.processBlock#string","depth":1}
			],
			"edges":[
				{"from":"example.Crypto.run#0","to":"example.Crypto.processBlock#bytes"},
				{"from":"example.Crypto.run#0","to":"example.Crypto.processBlock#string"}
			]
		}}]
	}`)

	for _, include := range []bool{false, true} {
		block, _, err := ComponentBlock(ComponentInput{
			Purl: "pkg:maven/example/crypto", Version: "1.0.0",
			Findings: findings, Callgraph: callgraph, IncludeForwardCalls: include,
		})
		if err != nil {
			t.Fatalf("include=%v: ComponentBlock: %v", include, err)
		}
		forward := block.Findings[0].CryptographicAssets[0].ForwardCalls
		if !include {
			if len(forward) != 0 {
				t.Fatalf("disabled forward_calls = %s, want omitted", forward)
			}
			continue
		}
		var got struct {
			MaxDepth  int               `json:"max_depth"`
			Truncated bool              `json:"truncated"`
			Nodes     []json.RawMessage `json:"nodes"`
		}
		if err := json.Unmarshal(forward, &got); err != nil {
			t.Fatalf("decode forward_calls: %v", err)
		}
		if got.MaxDepth != 1 || !got.Truncated || len(got.Nodes) != 2 {
			t.Fatalf("forward_calls = %+v, want depth cap, truncation, and both candidates", got)
		}
	}
}

// genericEntryCallgraph publishes one generic wrapper API. Its canonical
// signature carries the declaring class's type variables, which no call site can
// reproduce, so a consumer joining from erased bytecode can only supply the
// erased spelling.
const genericEntryCallgraph = `{
	"schema_version":"6.10",
	"finding_graphs":[
		{"finding_id":"finding-tls","reachability":"reachable",
		 "analysis":{"call_chains":"partial"},
		 "call_chains":[[{"canonical_signature":"dep.Ssl.create(): SSLEngine"}]]}
	],
	"crypto_entry_points":[
		{"canonical_signature":"example.Template.send(String, K, V): Future",
		 "erased_signature":"example.Template.send(String, Object, Object): Future",
		 "root":true,
		 "reachable_findings":[{"finding_id":"finding-tls","chain_depth":7}]}
	]
}`

// TestComponentBlockAcceptsErasedSignature: erased_signature is published on
// every entry point precisely so a bytecode-level consumer can join on the normal
// form its own analysis produces. Rejecting it made the field unusable for the
// generic APIs it exists for.
func TestComponentBlockAcceptsErasedSignature(t *testing.T) {
	for _, tc := range []struct {
		name string
		sig  string
	}{
		{"canonical", "example.Template.send(String, K, V): Future"},
		{"erased", "example.Template.send(String, Object, Object): Future"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			block, report, err := ComponentBlock(ComponentInput{
				Purl: "pkg:maven/example/crypto", Version: "1.0.0",
				Findings: []byte(filterFindings), Callgraph: []byte(genericEntryCallgraph),
				EntryPointSignatures: []string{tc.sig},
				IncludeCallChains:    true,
			})
			if err != nil {
				t.Fatalf("ComponentBlock: %v", err)
			}
			if len(report.UnmatchedSignatures) != 0 {
				t.Errorf("unmatched_signatures = %v, want none", report.UnmatchedSignatures)
			}
			if len(block.Findings) != 1 {
				t.Fatalf("findings = %d, want the one the entry reaches", len(block.Findings))
			}
			asset := block.Findings[0].CryptographicAssets[0]
			if asset.FindingID != "finding-tls" {
				t.Errorf("finding_id = %q, want finding-tls", asset.FindingID)
			}
			if asset.Reachability != "reachable" {
				t.Errorf("reachability = %q, want reachable", asset.Reachability)
			}
		})
	}
}

// TestComponentBlockErasedSignatureDoesNotWiden: a signature matching neither
// published spelling is still unmatched. Accepting the erased form widens the
// accepted input, not the answer.
func TestComponentBlockErasedSignatureDoesNotWiden(t *testing.T) {
	_, report, err := ComponentBlock(ComponentInput{
		Purl: "pkg:maven/example/crypto", Version: "1.0.0",
		Findings: []byte(filterFindings), Callgraph: []byte(genericEntryCallgraph),
		EntryPointSignatures: []string{"example.Template.send(String, String, String): Future"},
		IncludeCallChains:    true,
	})
	if err != nil {
		t.Fatalf("ComponentBlock: %v", err)
	}
	if len(report.UnmatchedSignatures) != 1 {
		t.Errorf("unmatched_signatures = %v, want the one supplied signature", report.UnmatchedSignatures)
	}
}

// internedCallgraph is schema 6.15: catalog identity lives in functions[] plus
// call_chain_indexes, not on the frames. Render must join before
// entry_point_signatures reads canonical_signature off the first frame.
const internedCallgraph = `{
	"schema_version":"6.15",
	"functions":[
		{"function_key":"dispatch#0","function_name":"example.Internal.dispatch","canonical_signature":"example.Internal.dispatch(): void"},
		{"function_key":"connect#0","function_name":"example.Socket.connect","canonical_signature":"example.Socket.connect(): void"},
		{"function_key":"other#0","function_name":"example.Other.run","canonical_signature":"example.Other.run(): void"}
	],
	"finding_graphs":[
		{"finding_id":"finding-tls","call_chain_indexes":[[0,1]],
		 "call_chains":[[{},{"crypto_call":{"line":95}}]]},
		{"finding_id":"finding-md5","call_chain_indexes":[[2]],
		 "call_chains":[[{}]]}
	],
	"crypto_entry_points":[
		{"canonical_signature":"example.Internal.dispatch(): void","root":true,
		 "reachable_findings":[{"finding_id":"finding-tls","chain_depth":2}]},
		{"canonical_signature":"example.Other.run(): void","root":true,
		 "reachable_findings":[{"finding_id":"finding-md5","chain_depth":1}]}
	]
}`

func TestComponentBlockHydratesInternedFramesForEntryPointFilter(t *testing.T) {
	block, report, err := ComponentBlock(ComponentInput{
		Purl: "pkg:maven/example/crypto", Version: "1.0.0",
		Findings: []byte(filterFindings), Callgraph: []byte(internedCallgraph),
		EntryPointSignatures: []string{"example.Internal.dispatch(): void"},
		IncludeCallChains:    true,
	})
	if err != nil {
		t.Fatalf("ComponentBlock: %v", err)
	}
	if len(report.UnmatchedSignatures) != 0 {
		t.Errorf("unmatched_signatures = %v, want none after hydrate", report.UnmatchedSignatures)
	}
	if block.FindingCount != 1 {
		t.Fatalf("finding_count = %d, want the interned tls finding", block.FindingCount)
	}
	asset := block.Findings[0].CryptographicAssets[0]
	if asset.FindingID != "finding-tls" {
		t.Fatalf("finding_id = %q, want finding-tls", asset.FindingID)
	}
	var chains [][]struct {
		FunctionName       string `json:"function_name"`
		CanonicalSignature string `json:"canonical_signature"`
	}
	if err := json.Unmarshal(asset.CallChains, &chains); err != nil {
		t.Fatalf("decode call_chains: %v", err)
	}
	if len(chains) != 1 || len(chains[0]) != 2 {
		t.Fatalf("call_chains = %v, want one two-frame route", chains)
	}
	if chains[0][0].FunctionName != "example.Internal.dispatch" {
		t.Errorf("head function_name = %q, want catalog identity", chains[0][0].FunctionName)
	}
	if chains[0][0].CanonicalSignature != "example.Internal.dispatch(): void" {
		t.Errorf("head canonical_signature = %q, want catalog identity", chains[0][0].CanonicalSignature)
	}
	if chains[0][1].FunctionName != "example.Socket.connect" {
		t.Errorf("hop function_name = %q, want catalog identity", chains[0][1].FunctionName)
	}
}

func TestComponentBlockInternedRoutesDoNotCollapse(t *testing.T) {
	block, _, err := ComponentBlock(ComponentInput{
		Purl: "pkg:maven/example/crypto", Version: "1.0.0",
		Findings: []byte(filterFindings), Callgraph: []byte(internedCallgraph),
		IncludeCallChains: true,
	})
	if err != nil {
		t.Fatalf("ComponentBlock: %v", err)
	}
	if block.FindingCount != 2 {
		t.Fatalf("finding_count = %d, want both interned findings", block.FindingCount)
	}
	got := map[string]string{}
	for _, file := range block.Findings {
		for _, asset := range file.CryptographicAssets {
			var chains [][]struct {
				FunctionName string `json:"function_name"`
			}
			if err := json.Unmarshal(asset.CallChains, &chains); err != nil {
				t.Fatalf("%s: decode call_chains: %v", asset.FindingID, err)
			}
			if len(chains) != 1 || len(chains[0]) == 0 {
				t.Fatalf("%s: call_chains = %v, want one hydrated route", asset.FindingID, chains)
			}
			got[asset.FindingID] = chains[0][0].FunctionName
		}
	}
	if got["finding-tls"] != "example.Internal.dispatch" {
		t.Errorf("tls head = %q, want example.Internal.dispatch", got["finding-tls"])
	}
	if got["finding-md5"] != "example.Other.run" {
		t.Errorf("md5 head = %q, want example.Other.run", got["finding-md5"])
	}
}

func TestComponentBlockRejectsInternedFramesWithoutIndexes(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(internedCallgraph), &doc); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	graphs := doc["finding_graphs"].([]any)
	tls := graphs[0].(map[string]any)
	delete(tls, "call_chain_indexes")
	payload, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	_, _, err = ComponentBlock(ComponentInput{
		Purl: "pkg:maven/example/crypto", Version: "1.0.0",
		Findings: []byte(filterFindings), Callgraph: payload,
		IncludeCallChains: true,
	})
	if err == nil {
		t.Fatal("ComponentBlock = nil, want interned frames without indexes to fail closed")
	}
}

func TestComponentBlockRejectsInvalidCallChainIndexes(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(internedCallgraph), &doc); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	graphs := doc["finding_graphs"].([]any)
	tls := graphs[0].(map[string]any)
	tls["call_chain_indexes"] = []any{[]any{99, 1}}
	payload, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	_, _, err = ComponentBlock(ComponentInput{
		Purl: "pkg:maven/example/crypto", Version: "1.0.0",
		Findings: []byte(filterFindings), Callgraph: payload,
		IncludeCallChains: true,
	})
	if err == nil {
		t.Fatal("ComponentBlock = nil, want invalid indexes to fail closed")
	}
}

func TestComponentBlockLeavesInlinedFramesWithCatalogUntouched(t *testing.T) {
	const inlinedWithCatalog = `{
		"schema_version":"6.14",
		"functions":[
			{"function_key":"dispatch#0","function_name":"example.Internal.dispatch","canonical_signature":"example.Internal.dispatch(): void"}
		],
		"finding_graphs":[
			{"finding_id":"finding-tls","call_chain_indexes":[[0]],
			 "call_chains":[[{"canonical_signature":"example.Internal.dispatch(): void","keep_me":true}]]}
		]
	}`
	block, _, err := ComponentBlock(ComponentInput{
		Purl: "pkg:maven/example/crypto", Version: "1.0.0",
		Findings: []byte(filterFindings), Callgraph: []byte(inlinedWithCatalog),
		IncludeCallChains: true,
	})
	if err != nil {
		t.Fatalf("ComponentBlock: %v", err)
	}
	var chains [][]map[string]any
	if err := json.Unmarshal(block.Findings[0].CryptographicAssets[0].CallChains, &chains); err != nil {
		t.Fatalf("decode call_chains: %v", err)
	}
	if len(chains) != 1 || len(chains[0]) != 1 {
		t.Fatalf("call_chains = %v, want the original inlined frame", chains)
	}
	if _, ok := chains[0][0]["keep_me"]; !ok {
		t.Fatalf("call_chains = %v, remashal dropped inlined extra fields", chains)
	}
}

// Findings rebuilt from annotations carry no mined PQC block, so it is
// computed; metadata is served unchanged and an asset naming no algorithm
// gets no block.
func TestComponentBlockComputesPQCBlock(t *testing.T) {
	findings := `{"version":"1.4","findings":[{"language":"rust","file_path":"rsa.rs","cryptographic_assets":[
		{"finding_id":"f-rsa","match":"Oaep::new()","source":"direct","start_line":1,"end_line":1,
		 "metadata":{"assetType":"algorithm","algorithmFamily":"RSAES-OAEP","algorithmName":"RSA-OAEP"}},
		{"finding_id":"f-tls","match":"tls()","source":"direct","start_line":2,"end_line":2,
		 "metadata":{"assetType":"protocol","protocolType":"tls"}}]}]}`
	block, _, err := ComponentBlock(ComponentInput{Purl: "pkg:cargo/example", Version: "1.0.0", Findings: []byte(findings)})
	if err != nil {
		t.Fatalf("ComponentBlock: %v", err)
	}
	assets := block.Findings[0].CryptographicAssets
	if c := assets[0].PQC; c == nil || c.Status != "vulnerable" || c.Family != "RSA" || c.Deadline != 2030 || len(c.Deadlines) != 2 {
		t.Errorf("RSA-OAEP pqc = %+v", c)
	}
	var metadata map[string]any
	if err := json.Unmarshal(assets[0].Metadata, &metadata); err != nil || len(metadata) != 3 {
		t.Errorf("metadata changed: %s", assets[0].Metadata)
	}
	if c := assets[1].PQC; c != nil {
		t.Errorf("a protocol naming no algorithm was classified: %+v", c)
	}
}
