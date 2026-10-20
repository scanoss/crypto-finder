// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"sort"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

const truststoreLibrary = "truststore"

const (
	truststoreProtocolParam = "0:protocol:operation-determining:-:-"
	truststoreCipherParam   = "0:cipherlist:operation-determining:-:-"
)

// wantTruststoreContracts is written BY HAND from truststore 0.10.5 and 0.1.0,
// never derived from the YAML: a derived expectation goes green on a corrupted
// contract.
func wantTruststoreContracts() []string {
	return []string{
		// Both import spellings of the 0.3.0+ class and of the 0.1.0-0.2.0 one.
		"truststore.SSLContext#0 truststore.SSLContext/factory/truststore._api.SSLContext/high/-/params=" + truststoreProtocolParam + "/varargs=false/when=-/lib=truststore",
		"truststore.SSLContext.<init>#0 truststore.SSLContext.<init>/factory/truststore._api.SSLContext/high/-/params=" + truststoreProtocolParam + "/varargs=false/when=-/lib=truststore",
		"truststore.TruststoreSSLContext#0 truststore.TruststoreSSLContext/factory/truststore.TruststoreSSLContext/high/-/params=" + truststoreProtocolParam + "/varargs=false/when=-/lib=truststore",
		"truststore.TruststoreSSLContext.<init>#0 truststore.TruststoreSSLContext.<init>/factory/truststore.TruststoreSSLContext/high/-/params=" + truststoreProtocolParam + "/varargs=false/when=-/lib=truststore",
		"truststore.inject_into_ssl#0 truststore.inject_into_ssl/config/builtins.NoneType/high/-/params=-/varargs=false/when=-/lib=truststore",
		"truststore.extract_from_ssl#0 truststore.extract_from_ssl/config/builtins.NoneType/high/-/params=-/varargs=false/when=-/lib=truststore",
		"truststore._api.SSLContext.wrap_socket#1 truststore._api.SSLContext.wrap_socket/factory/ssl.SSLSocket/high/-/params=-/varargs=false/when=-/lib=truststore",
		"truststore._api.SSLContext.wrap_bio#2 truststore._api.SSLContext.wrap_bio/factory/ssl.SSLObject/high/-/params=-/varargs=false/when=-/lib=truststore",
		"truststore._api.SSLContext.load_verify_locations#0 truststore._api.SSLContext.load_verify_locations/config/builtins.NoneType/high/-/params=-/varargs=false/when=-/lib=truststore",
		"truststore._api.SSLContext.load_cert_chain#1 truststore._api.SSLContext.load_cert_chain/config/builtins.NoneType/high/-/params=-/varargs=false/when=-/lib=truststore",
		"truststore._api.SSLContext.load_default_certs#0 truststore._api.SSLContext.load_default_certs/config/builtins.NoneType/high/-/params=-/varargs=false/when=-/lib=truststore",
		"truststore._api.SSLContext.set_default_verify_paths#0 truststore._api.SSLContext.set_default_verify_paths/config/builtins.NoneType/high/-/params=-/varargs=false/when=-/lib=truststore",
		"truststore._api.SSLContext.set_ciphers#1 truststore._api.SSLContext.set_ciphers/config/builtins.NoneType/high/-/params=" + truststoreCipherParam + "/varargs=false/when=-/lib=truststore",
		"truststore._api.SSLContext.get_ciphers#0 truststore._api.SSLContext.get_ciphers/output/builtins.list/high/-/params=-/varargs=false/when=-/lib=truststore",
		"truststore._api.SSLContext.get_ca_certs#0 truststore._api.SSLContext.get_ca_certs/output/builtins.list/high/-/params=-/varargs=false/when=-/lib=truststore",
		"truststore.TruststoreSSLContext.wrap_socket#1 truststore.TruststoreSSLContext.wrap_socket/factory/ssl.SSLSocket/high/-/params=-/varargs=false/when=-/lib=truststore",
		"truststore.TruststoreSSLContext.wrap_bio#2 truststore.TruststoreSSLContext.wrap_bio/factory/ssl.SSLObject/high/-/params=-/varargs=false/when=-/lib=truststore",
		"truststore.TruststoreSSLContext.load_verify_locations#0 truststore.TruststoreSSLContext.load_verify_locations/config/builtins.NoneType/high/-/params=-/varargs=false/when=-/lib=truststore",
	}
}

func TestPythonTruststoreContract_ExactSet(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	var got []string
	for key, list := range kb.Contracts {
		for i := range list {
			if list[i].SourceLibrary == truststoreLibrary {
				got = append(got, renderPyotpContract(key, list[i]))
			}
		}
	}
	want := wantTruststoreContracts()
	sort.Strings(got)
	sort.Strings(want)

	gotSet := map[string]bool{}
	for _, line := range got {
		gotSet[line] = true
	}
	wantSet := map[string]bool{}
	for _, line := range want {
		wantSet[line] = true
		if !gotSet[line] {
			t.Errorf("declared in the expectation but NOT loaded from the YAML:\n\t%q,", line)
		}
	}
	for _, line := range got {
		if !wantSet[line] {
			t.Errorf("loaded but not expected; if intended, add it to wantTruststoreContracts():\n\t%q,", line)
		}
	}
}

// Both context classes must stay ssl.SSLContext subtypes so a join with a
// stdlib context does not widen to builtins.object.
func TestPythonTruststoreContract_ContextsAreSSLContexts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	for _, child := range []string{"truststore._api.SSLContext", "truststore.TruststoreSSLContext"} {
		parents := kb.Hierarchy[child]
		if len(parents) != 1 || parents[0] != "ssl.SSLContext" {
			t.Errorf("hierarchy[%s] = %v, want [ssl.SSLContext]", child, parents)
		}
	}
}
