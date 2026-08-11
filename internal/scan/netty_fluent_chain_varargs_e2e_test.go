// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// netty_fluent_chain_varargs_e2e_test.go — scanoss/crypto-finder#195 regression.
//
// A fluent SslContextBuilder chain whose protocols(...) link passes MORE than
// one literal argument (`.protocols("TLSv1.3", "TLSv1.2")`) loses resolution
// for that link and every link after it: the netty-tls.yaml contract models
// the varargs method protocols(String...) at arity 1 (varargs collapse to one
// slot), the parser emits the call at its literal top-level argument count
// (arity 2), Java contract lookup is exact-arity, and the fluent-chain
// contract pass stopped walking the chain on the first miss. The consequence
// is formatting-independent (single-line and multi-line 2-arg chains fail
// identically), and the unresolved links leak their raw — possibly
// multi-line — receiver expression into exported symbols and canonical
// signatures.
//
// This test mines a netty-shaped SslContextBuilder stub plus a consumer that
// builds the forServer(...).sslProvider(...).protocols("TLSv1.3","TLSv1.2")
// .build() chain in BOTH multi-line and single-line forms, then asserts on
// the call-graph export that (a) every chain link resolves and carries its
// contract role — protocols=config, build=operation — in both forms, and
// (b) no exported supporting-call symbol or canonical_signature contains a
// newline or raw receiver text.

package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// nettyFluentChainConsumerSource builds the issue-195 chain in both forms.
// The multi-line form reproduces the exact formatting from the issue report:
// the receiver on its own line and the multi-argument forServer(...) link
// spanning lines. Both forms pass TWO protocol literals so the varargs
// protocols(String...) link sits at literal arity 2 while the contract keys
// it at arity 1.
const nettyFluentChainConsumerSource = `package com.example;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import java.io.File;

public class TlsSetup {

    Object multiLine(File cert, File key) throws Exception {
        SslContext ctx = SslContextBuilder
                .forServer(cert, key)
                .sslProvider(SslProvider.OPENSSL)
                .protocols("TLSv1.3", "TLSv1.2")
                .build();
        return ctx;
    }

    Object singleLine(File cert, File key) throws Exception {
        SslContext ctx = SslContextBuilder.forServer(cert, key).sslProvider(SslProvider.OPENSSL).protocols("TLSv1.3", "TLSv1.2").build();
        return ctx;
    }
}
`

func TestNettyFluentChain_VarargsProtocols_ResolvesRolesInBothForms(t *testing.T) {
	t.Parallel()

	nettyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(nettyDir, "SslContextBuilder.java"), []byte(nettySslContextBuilderSource), 0o600); err != nil {
		t.Fatal(err)
	}
	consumerDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(consumerDir, "TlsSetup.java"), []byte(nettyFluentChainConsumerSource), 0o600); err != nil {
		t.Fatal(err)
	}

	graph, err := callgraph.NewBuilderForEcosystem("java", callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{
			{Dir: nettyDir, ImportPath: "io.netty.handler.ssl"},
			{Dir: consumerDir, ImportPath: "com.example"},
		}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories(netty stub + consumer): %v", err)
	}

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	// Locate the two consumer methods and the line their chain starts on.
	forms := map[string]*callgraph.FunctionDecl{}
	for _, fn := range graph.Functions {
		base := callgraph.BaseFunctionName(fn.ID.Name)
		if fn.ID.Package == "com.example" && (base == "multiLine" || base == "singleLine") {
			forms[base] = fn
		}
	}
	if len(forms) != 2 {
		t.Fatalf("consumer methods not found in graph: %v", forms)
	}

	report := &entities.InterimReport{
		Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules: entities.RulesInfo{Version: "v-test"},
	}
	chainLineByForm := map[string]int{}
	for _, form := range []string{"multiLine", "singleLine"} {
		fn := forms[form]
		line := 0
		for i := range fn.Calls {
			if fn.Calls[i].ChainID != "" {
				line = fn.Calls[i].Line
				break
			}
		}
		if line == 0 {
			t.Fatalf("%s: no fluent chain calls found in %v", form, fn.Calls)
		}
		chainLineByForm[form] = line
		report.Findings = append(report.Findings, entities.Finding{
			FilePath: fn.FilePath,
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				FindingID: "netty-forserver-" + form,
				StartLine: line,
				EndLine:   line,
				Match:     "SslContextBuilder.forServer(cert, key)",
				Rules:     []entities.RuleInfo{{ID: "java.netty.protocol.tls.context-builder-server"}},
				Metadata: map[string]string{
					"api":          "io.netty.handler.ssl.SslContextBuilder.forServer",
					"assetType":    "protocol",
					"protocolType": "tls",
				},
			}},
		})
	}

	for _, form := range []string{"multiLine", "singleLine"} {
		fn := forms[form]

		// (a) Graph-level: every chain link, including the ones after the
		// 2-arg varargs protocols(...) call, must resolve to the netty
		// builder type. protocols(String...) collapses to the contract's
		// declared arity 1; build() terminates the chain.
		wantResolved := map[string]string{
			"forServer":   "io.netty.handler.ssl.(SslContextBuilder).forServer#2",
			"sslProvider": "io.netty.handler.ssl.(SslContextBuilder).sslProvider#1",
			"protocols":   "io.netty.handler.ssl.(SslContextBuilder).protocols#1",
			"build":       "io.netty.handler.ssl.(SslContextBuilder).build#0",
		}
		gotResolved := map[string]string{}
		for i := range fn.Calls {
			if fn.Calls[i].ChainID == "" {
				continue
			}
			gotResolved[callgraph.BaseFunctionName(fn.Calls[i].Callee.Name)] = fn.Calls[i].Callee.String()
		}
		for base, want := range wantResolved {
			got, ok := gotResolved[base]
			if !ok {
				// The unresolved link keeps its raw receiver blob as the
				// callee package, so its base name lookup misses too.
				t.Errorf("%s: chain link %q not resolved; resolved links: %v", form, base, gotResolved)
				continue
			}
			if got != want {
				t.Errorf("%s: chain link %q callee = %q, want %q", form, base, got, want)
			}
		}

		// The resolved terminal links must carry their contract roles.
		wantRoles := map[string]struct {
			method string
			arity  int
			role   string
		}{
			"protocols": {method: "io.netty.handler.ssl.SslContextBuilder.protocols", arity: 1, role: "config"},
			"build":     {method: "io.netty.handler.ssl.SslContextBuilder.build", arity: 0, role: "operation"},
		}
		for base, want := range wantRoles {
			ctrs := kb.ContractsForTolerant(want.method, want.arity)
			if len(ctrs) == 0 || ctrs[0].Role != want.role {
				t.Errorf("%s: KB contract for %s#%d missing or role != %q: %+v", form, want.method, want.arity, want.role, ctrs)
			}
			if gotResolved[base] != wantResolved[base] {
				t.Errorf("%s: %q does not carry its %q contract role: callee %q is not the contracted method %s#%d",
					form, base, want.role, gotResolved[base], want.method, want.arity)
			}
		}
	}

	engine.EnsureFindingSources(report)
	payload := buildCallGraphExportV2(&engine.DepScanResult{
		Report:    report,
		CallGraph: graph,
		Ecosystem: "java",
	})

	// (a) Export-level: the consumer call-site supporting calls (derived from
	// the fluent chain, i.e. located in TlsSetup.java) must carry contract
	// roles for every non-terminal link in both forms. The terminal build()
	// call is the finding's crypto call, not a supporting call; its role is
	// asserted at the graph/KB level above.
	for _, form := range []string{"multiLine", "singleLine"} {
		line := chainLineByForm[form]
		gotCategories := map[string]string{}
		for _, sc := range payload.SupportingCalls {
			if !strings.HasSuffix(sc.FilePath, "TlsSetup.java") || sc.StartLine != line {
				continue
			}
			if sc.SupportingCall == nil {
				continue
			}
			name := sc.SupportingCall.FunctionName
			base := name[strings.LastIndex(name, ".")+1:]
			gotCategories[base] = sc.Category
		}
		for base, wantCategory := range map[string]string{
			"forServer":   "factory",
			"sslProvider": "config",
			"protocols":   "config",
		} {
			if got := gotCategories[base]; got != wantCategory {
				t.Errorf("%s: supporting call %q category = %q, want %q (all: %v)", form, base, got, wantCategory, gotCategories)
			}
		}
	}

	// (b) No exported supporting-call symbol or signature may contain a
	// newline (or any raw multi-line receiver text): the multi-line form's
	// unresolved links used to leak "SslContextBuilder\n        .forServer(..."
	// into function_name, matched_operation.symbol and canonical_signature.
	assertNoNewline := func(kind, value string) {
		t.Helper()
		if strings.ContainsAny(value, "\r\n") {
			t.Errorf("%s contains a newline: %q", kind, value)
		}
	}
	for _, sc := range payload.SupportingCalls {
		assertNoNewline("supporting_call.function_name", sc.FunctionName)
		assertNoNewline("supporting_call.canonical_signature", sc.CanonicalSignature)
		if sc.MatchedOperation != nil {
			assertNoNewline("supporting_call.matched_operation.symbol", sc.MatchedOperation.Symbol)
		}
		if sc.SupportingCall != nil {
			assertNoNewline("supporting_call.supporting_call.function_name", sc.SupportingCall.FunctionName)
			assertNoNewline("supporting_call.supporting_call.canonical_signature", sc.SupportingCall.CanonicalSignature)
		}
	}
	for _, fg := range payload.FindingGraphs {
		if fg.MatchedOperation != nil {
			assertNoNewline("finding_graph.matched_operation.symbol", fg.MatchedOperation.Symbol)
		}
	}
}

// TestFullFunctionName_SanitizesPackage locks the export-layer half of
// scanoss/crypto-finder#195: a callee whose Package carries a raw multi-line
// receiver expression (the parser's fallback for unresolved static-rooted
// fluent chain links) must not leak newlines or whitespace into the exported
// symbol, whatever the resolution outcome was.
func TestFullFunctionName_SanitizesPackage(t *testing.T) {
	t.Parallel()

	id := callgraph.FunctionID{
		Package: "SslContextBuilder\n                .forServer(cert, key)\n                .sslProvider(SslProvider.(OPENSSL))",
		Name:    "protocols#2",
	}
	got := fullFunctionName(id)
	if strings.ContainsAny(got, "\r\n\t ") {
		t.Errorf("fullFunctionName leaked raw receiver whitespace: %q", got)
	}
}
