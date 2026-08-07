// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// netty_tls_e2e_integration_test.go — scanoss/crypto-finder#183 scan-layer proof.
//
// Proves that entry-point synthesis (engine.SynthesizeRuleCryptoEntryPoints)
// JOINS the scanoss/crypto_rules#168 Netty TLS rule api anchors
// (io.netty.handler.ssl.SslContextBuilder.{forClient,forServer,sslProvider,
// protocols,ciphers} plus the server PEM key-material rule, which shares the
// forServer anchor) against a netty-shaped source file mined with the real
// Java parser + callgraph builder — the same path `crypto-finder scan
// --export-callgraph` uses when mining netty-handler itself. This is the
// public-export proof that the netty-tls.yaml contract's method+arity keys
// (internal/callgraph/contracts/java/netty-tls.yaml) match what the Java
// parser actually emits for SslContextBuilder's factory/config/build methods,
// not just the embedded-contract loader assertions in java_libraries_test.go.

package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// nettySslContextBuilderSource is a netty-shaped stub of
// io/netty/handler/ssl/SslContextBuilder.java (4.2.15.Final): the same
// factory (forClient/forServer), fluent-config (sslProvider/protocols/
// ciphers), and terminal (build) method shapes the real class declares, at
// the same arities the netty-tls.yaml contract keys on. It is a stub (not a
// full compilable copy) because the tree-sitter-based Java parser extracts
// declarations syntactically and does not require SslProvider/SslContext to
// be resolvable types.
const nettySslContextBuilderSource = `package io.netty.handler.ssl;

import java.io.File;

public final class SslContextBuilder {

    public static SslContextBuilder forClient() {
        return new SslContextBuilder();
    }

    public static SslContextBuilder forServer(File keyCertChainFile, File keyFile) {
        return new SslContextBuilder();
    }

    public SslContextBuilder sslProvider(SslProvider provider) {
        return this;
    }

    public SslContextBuilder protocols(String... protocols) {
        return this;
    }

    public SslContextBuilder ciphers(Iterable<String> ciphers) {
        return this;
    }

    public SslContext build() throws Exception {
        return new SslContext();
    }
}
`

// nettyTLSRulesYAML mirrors the scanoss/crypto_rules#168 rule shapes anchored
// on SslContextBuilder: the client/server factory split, the two
// value-variant sslProvider selection rules (OpenSSL vs JDK, sharing one api
// per the crypto-kb-author skill's literal-argument convention), the
// protocol-version and cipher-config rules, and the server PEM key-material
// rule (which shares the forServer anchor with the factory rule above it —
// proving two independently-authored rules on the same api both resolve).
const nettyTLSRulesYAML = `rules:
  - id: java.netty.protocol.tls.context-builder-client
    metadata:
      crypto:
        assetType: protocol
        protocolType: tls
        protocolName: TLS
        library: Netty
        api: io.netty.handler.ssl.SslContextBuilder.forClient
  - id: java.netty.protocol.tls.context-builder-server
    metadata:
      crypto:
        assetType: protocol
        protocolType: tls
        protocolName: TLS
        library: Netty
        api: io.netty.handler.ssl.SslContextBuilder.forServer
  - id: java.netty.related-crypto-material.key.server-pem-key-material
    metadata:
      crypto:
        assetType: related-crypto-material
        materialType: private-key
        materialFormat: PEM
        library: Netty
        api: io.netty.handler.ssl.SslContextBuilder.forServer
  - id: java.netty.protocol.tls.provider-selection-openssl
    metadata:
      crypto:
        assetType: protocol
        protocolType: tls
        provider: OpenSSL
        library: Netty
        api: io.netty.handler.ssl.SslContextBuilder.sslProvider
  - id: java.netty.protocol.tls.provider-selection-jdk
    metadata:
      crypto:
        assetType: protocol
        protocolType: tls
        provider: JDK
        library: Netty
        api: io.netty.handler.ssl.SslContextBuilder.sslProvider
  - id: java.netty.protocol.tls.protocol-version-selection
    metadata:
      crypto:
        assetType: protocol
        protocolType: tls
        protocolName: TLS
        library: Netty
        api: io.netty.handler.ssl.SslContextBuilder.protocols
  - id: java.netty.protocol.tls.cipher-config
    metadata:
      crypto:
        assetType: protocol
        protocolType: tls
        library: Netty
        api: io.netty.handler.ssl.SslContextBuilder.ciphers
`

// TestNettyTLS_E2E_SynthesizeRuleCryptoEntryPoints_JoinsRuleAPIAnchors proves
// that mining netty-handler's own SslContextBuilder source produces a
// synthesized crypto entry point for every scanoss/crypto_rules#168 api
// anchor: forClient, forServer (shared by two independent rules), sslProvider
// (shared by two value-variant rules), protocols, and ciphers.
func TestNettyTLS_E2E_SynthesizeRuleCryptoEntryPoints_JoinsRuleAPIAnchors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SslContextBuilder.java"), []byte(nettySslContextBuilderSource), 0o600); err != nil {
		t.Fatal(err)
	}

	graph, err := callgraph.NewBuilder(callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "io.netty.handler.ssl"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories(netty SslContextBuilder stub): %v", err)
	}

	ruleDir := t.TempDir()
	rulePath := filepath.Join(ruleDir, "netty-tls.yaml")
	if err := os.WriteFile(rulePath, []byte(nettyTLSRulesYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	report := &entities.InterimReport{}
	n := engine.SynthesizeRuleCryptoEntryPoints(report, graph, []string{rulePath}, "java")

	// forClient (1 rule) + forServer (2 rules: factory + key-material) +
	// sslProvider (2 rules: OpenSSL + JDK) + protocols (1 rule) + ciphers
	// (1 rule) = 7 synthesized entry points, one per (definition, rule-block)
	// pair.
	const want = 7
	if n != want {
		fqns := make([]string, 0, len(graph.Functions))
		for k := range graph.Functions {
			fqns = append(fqns, k)
		}
		t.Fatalf("synthesized %d entry points, want %d; graph FQNs: %v", n, want, fqns)
	}

	byAPIAndRule := map[string]map[string]bool{}
	for _, finding := range report.Findings {
		for _, asset := range finding.CryptographicAssets {
			api := asset.Metadata["api"]
			if byAPIAndRule[api] == nil {
				byAPIAndRule[api] = map[string]bool{}
			}
			for _, r := range asset.Rules {
				byAPIAndRule[api][r.ID] = true
			}
		}
	}

	wantRulesByAPI := map[string][]string{
		"io.netty.handler.ssl.SslContextBuilder.forClient": {
			engine.SyntheticEntryPointRuleID,
		},
		"io.netty.handler.ssl.SslContextBuilder.forServer": {
			engine.SyntheticEntryPointRuleID,
		},
		"io.netty.handler.ssl.SslContextBuilder.sslProvider": {
			engine.SyntheticEntryPointRuleID,
		},
		"io.netty.handler.ssl.SslContextBuilder.protocols": {
			engine.SyntheticEntryPointRuleID,
		},
		"io.netty.handler.ssl.SslContextBuilder.ciphers": {
			engine.SyntheticEntryPointRuleID,
		},
	}
	for api, wantRuleIDs := range wantRulesByAPI {
		if len(byAPIAndRule[api]) == 0 {
			t.Errorf("no synthesized entry point for rule anchor api %q; got apis: %v", api, byAPIAndRule)
			continue
		}
		for _, wantRuleID := range wantRuleIDs {
			if !byAPIAndRule[api][wantRuleID] {
				t.Errorf("api %q missing expected rule %q; got rules: %v", api, wantRuleID, byAPIAndRule[api])
			}
		}
	}

	// forServer must carry BOTH the factory rule and the PEM key-material rule
	// at the same definition site -- proving two independently-authored
	// crypto_rules#168 rules sharing one api both resolve, not just the first.
	forServerRuleIDs := map[string]bool{}
	forClientRuleIDs := map[string]bool{}
	sslProviderValues := map[string]bool{}
	for _, finding := range report.Findings {
		for _, asset := range finding.CryptographicAssets {
			switch asset.Metadata["api"] {
			case "io.netty.handler.ssl.SslContextBuilder.forServer":
				for _, r := range asset.Rules {
					forServerRuleIDs[r.ID] = true
				}
			case "io.netty.handler.ssl.SslContextBuilder.forClient":
				for _, r := range asset.Rules {
					forClientRuleIDs[r.ID] = true
				}
			case "io.netty.handler.ssl.SslContextBuilder.sslProvider":
				sslProviderValues[asset.Metadata["provider"]] = true
			}
		}
	}
	if len(forServerRuleIDs) != 1 {
		// Both rules use crypto-finder.api-entry-point as the synthesized rule
		// ID (SyntheticEntryPointRuleID); the distinguishing signal is the two
		// DISTINCT metadata blocks (assetType=protocol vs
		// assetType=related-crypto-material), asserted below via asset count.
		t.Errorf("forServer synthesized rule IDs = %v", forServerRuleIDs)
	}
	if len(forClientRuleIDs) != 1 {
		t.Errorf("forClient synthesized rule IDs = %v", forClientRuleIDs)
	}
	if !sslProviderValues["OpenSSL"] || !sslProviderValues["JDK"] {
		t.Errorf("sslProvider provider values = %v, want both OpenSSL and JDK present", sslProviderValues)
	}

	// forServer must have exactly 2 distinct assets (factory + key-material);
	// sslProvider must have exactly 2 distinct assets (OpenSSL + JDK).
	forServerAssets, sslProviderAssets := 0, 0
	for _, finding := range report.Findings {
		for _, asset := range finding.CryptographicAssets {
			switch asset.Metadata["api"] {
			case "io.netty.handler.ssl.SslContextBuilder.forServer":
				forServerAssets++
			case "io.netty.handler.ssl.SslContextBuilder.sslProvider":
				sslProviderAssets++
			}
		}
	}
	if forServerAssets != 2 {
		t.Errorf("forServer synthesized assets = %d, want 2 (factory + key-material)", forServerAssets)
	}
	if sslProviderAssets != 2 {
		t.Errorf("sslProvider synthesized assets = %d, want 2 (OpenSSL + JDK)", sslProviderAssets)
	}
}
