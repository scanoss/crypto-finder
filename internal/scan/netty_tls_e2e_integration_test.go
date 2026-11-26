// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// netty_tls_e2e_integration_test.go — scanoss/crypto-finder#183 scan-layer proof.
//
// Proves that entry-point synthesis (engine.SynthesizeRuleCryptoEntryPoints)
// joins rule api anchors on a netty-shaped TLS context builder against a
// source file mined with the real Java parser and callgraph builder: the
// client/server factory split, two rules sharing one api, and two
// value-variant rules sharing one api. The rules and the class name are
// invented.

package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/reach/callgraph"

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

// nettyTLSRulesYAML holds invented rules anchored on TlsContextBuilder: the client/server factory split, the two
// value-variant sslProvider selection rules (OpenSSL vs JDK, sharing one api
// per the crypto-kb-author skill's literal-argument convention), the
// protocol-version and cipher-config rules, and the server PEM key-material
// rule (which shares the forServer anchor with the factory rule above it —
// proving two independently-authored rules on the same api both resolve).
const nettyTLSRulesYAML = `rules:
  - id: fixture.java.netty.context-builder-client
    metadata:
      crypto:
        assetType: protocol
        protocolType: tls
        protocolName: TLS
        library: Netty
        api: io.netty.handler.ssl.TlsContextBuilder.forClient
  - id: fixture.java.netty.context-builder-server
    metadata:
      crypto:
        assetType: protocol
        protocolType: tls
        protocolName: TLS
        library: Netty
        api: io.netty.handler.ssl.TlsContextBuilder.forServer
  - id: fixture.java.netty.server-pem-key-material
    metadata:
      crypto:
        assetType: related-crypto-material
        materialType: private-key
        materialFormat: PEM
        library: Netty
        api: io.netty.handler.ssl.TlsContextBuilder.forServer
  - id: fixture.java.netty.provider-selection-openssl
    metadata:
      crypto:
        assetType: protocol
        protocolType: tls
        provider: OpenSSL
        library: Netty
        api: io.netty.handler.ssl.TlsContextBuilder.sslProvider
  - id: fixture.java.netty.provider-selection-jdk
    metadata:
      crypto:
        assetType: protocol
        protocolType: tls
        provider: JDK
        library: Netty
        api: io.netty.handler.ssl.TlsContextBuilder.sslProvider
  - id: fixture.java.netty.protocol-version-selection
    metadata:
      crypto:
        assetType: protocol
        protocolType: tls
        protocolName: TLS
        library: Netty
        api: io.netty.handler.ssl.TlsContextBuilder.protocols
  - id: fixture.java.netty.cipher-config
    metadata:
      crypto:
        assetType: protocol
        protocolType: tls
        library: Netty
        api: io.netty.handler.ssl.TlsContextBuilder.ciphers
`

// TestNettyTLS_E2E_SynthesizeRuleCryptoEntryPoints_JoinsRuleAPIAnchors proves
// that mining netty-handler's own TlsContextBuilder source produces a
// synthesized crypto entry point for every rule api
// anchor: forClient, forServer (shared by two independent rules), sslProvider
// (shared by two value-variant rules), protocols, and ciphers.
func TestNettyTLS_E2E_SynthesizeRuleCryptoEntryPoints_JoinsRuleAPIAnchors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "TlsContextBuilder.java"), []byte(strings.ReplaceAll(nettySslContextBuilderSource, "SslContextBuilder", "TlsContextBuilder")), 0o600); err != nil {
		t.Fatal(err)
	}

	graph, err := callgraph.NewBuilder(callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "io.netty.handler.ssl"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories(netty TlsContextBuilder stub): %v", err)
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
		"io.netty.handler.ssl.TlsContextBuilder.forClient": {
			engine.SyntheticEntryPointRuleID,
		},
		"io.netty.handler.ssl.TlsContextBuilder.forServer": {
			engine.SyntheticEntryPointRuleID,
		},
		"io.netty.handler.ssl.TlsContextBuilder.sslProvider": {
			engine.SyntheticEntryPointRuleID,
		},
		"io.netty.handler.ssl.TlsContextBuilder.protocols": {
			engine.SyntheticEntryPointRuleID,
		},
		"io.netty.handler.ssl.TlsContextBuilder.ciphers": {
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
	// rules sharing one api both resolve, not just the first.
	forServerRuleIDs := map[string]bool{}
	forClientRuleIDs := map[string]bool{}
	sslProviderValues := map[string]bool{}
	for _, finding := range report.Findings {
		for _, asset := range finding.CryptographicAssets {
			switch asset.Metadata["api"] {
			case "io.netty.handler.ssl.TlsContextBuilder.forServer":
				for _, r := range asset.Rules {
					forServerRuleIDs[r.ID] = true
				}
			case "io.netty.handler.ssl.TlsContextBuilder.forClient":
				for _, r := range asset.Rules {
					forClientRuleIDs[r.ID] = true
				}
			case "io.netty.handler.ssl.TlsContextBuilder.sslProvider":
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
			case "io.netty.handler.ssl.TlsContextBuilder.forServer":
				forServerAssets++
			case "io.netty.handler.ssl.TlsContextBuilder.sslProvider":
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
