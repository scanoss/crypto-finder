// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"sort"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

const pykmipLibrary = "pykmip"

const (
	pykmipAlgorithmLengthParams = "0:algorithm:operation-determining:algorithm:argument_value," +
		"1:length:metadata-contributing:keySize:argument_value"
	pykmipKeyParams = pykmipAlgorithmLengthParams +
		",2:value:metadata-contributing:keyMaterial:argument_value"
	pykmipCryptoParams = "2:cryptographic_parameters:operation-determining:algorithm:argument_value"
)

// wantPykmipContracts is written BY HAND from pykmip 0.11.0, never derived
// from the YAML: a derived expectation goes green on a corrupted contract.
func wantPykmipContracts() []string {
	const client = "kmip.pie.client.ProxyKmipClient"
	return []string{
		// Every constructor spelling builds the same client.
		"kmip.pie.client.ProxyKmipClient#0 kmip.pie.client.ProxyKmipClient/factory/" + client + "/high/-/params=-/varargs=false/when=-/lib=pykmip",
		"kmip.pie.client.ProxyKmipClient.<init>#0 kmip.pie.client.ProxyKmipClient.<init>/factory/" + client + "/high/-/params=-/varargs=false/when=-/lib=pykmip",
		"kmip.pie.ProxyKmipClient#0 kmip.pie.ProxyKmipClient/factory/" + client + "/high/-/params=-/varargs=false/when=-/lib=pykmip",
		"kmip.pie.ProxyKmipClient.<init>#0 kmip.pie.ProxyKmipClient.<init>/factory/" + client + "/high/-/params=-/varargs=false/when=-/lib=pykmip",
		"kmip.KmipClient#0 kmip.KmipClient/factory/" + client + "/high/-/params=-/varargs=false/when=-/lib=pykmip",
		"kmip.KmipClient.<init>#0 kmip.KmipClient.<init>/factory/" + client + "/high/-/params=-/varargs=false/when=-/lib=pykmip",
		// `with ProxyKmipClient(..) as c` types c through __enter__.
		"kmip.pie.client.ProxyKmipClient.__enter__#0 kmip.pie.client.ProxyKmipClient.__enter__/factory/" + client + "/high/-/params=-/varargs=false/when=-/lib=pykmip",
		"kmip.pie.client.ProxyKmipClient.open#0 kmip.pie.client.ProxyKmipClient.open/operation/builtins.NoneType/high/-/params=-/varargs=false/when=-/lib=pykmip",

		"kmip.pie.client.ProxyKmipClient.create#2 kmip.pie.client.ProxyKmipClient.create/operation/builtins.str/high/-/params=" + pykmipAlgorithmLengthParams + "/varargs=false/when=-/lib=pykmip",
		"kmip.pie.client.ProxyKmipClient.create_key_pair#2 kmip.pie.client.ProxyKmipClient.create_key_pair/operation/builtins.tuple/high/-/params=" + pykmipAlgorithmLengthParams + "/varargs=false/when=-/lib=pykmip",
		"kmip.pie.client.ProxyKmipClient.rekey#0 kmip.pie.client.ProxyKmipClient.rekey/operation/builtins.str/high/-/params=-/varargs=false/when=-/lib=pykmip",
		"kmip.pie.client.ProxyKmipClient.derive_key#4 kmip.pie.client.ProxyKmipClient.derive_key/operation/builtins.str/high/-/params=2:derivation_method:operation-determining:algorithm:argument_value/varargs=false/when=-/lib=pykmip",

		"kmip.pie.client.ProxyKmipClient.register#1 kmip.pie.client.ProxyKmipClient.register/factory/builtins.str/high/-/params=-/varargs=false/when=-/lib=pykmip",
		"kmip.pie.client.ProxyKmipClient.get#0 kmip.pie.client.ProxyKmipClient.get/factory/kmip.pie.objects.ManagedObject/high/-/params=-/varargs=false/when=-/lib=pykmip",

		"kmip.pie.client.ProxyKmipClient.encrypt#1 kmip.pie.client.ProxyKmipClient.encrypt/operation/builtins.tuple/high/-/params=" + pykmipCryptoParams + "/varargs=false/when=-/lib=pykmip",
		"kmip.pie.client.ProxyKmipClient.decrypt#1 kmip.pie.client.ProxyKmipClient.decrypt/operation/builtins.bytes/high/-/params=" + pykmipCryptoParams + "/varargs=false/when=-/lib=pykmip",
		"kmip.pie.client.ProxyKmipClient.sign#1 kmip.pie.client.ProxyKmipClient.sign/operation/builtins.bytes/high/-/params=" + pykmipCryptoParams + "/varargs=false/when=-/lib=pykmip",
		// signature_verify(message, signature, uid, cryptographic_parameters).
		"kmip.pie.client.ProxyKmipClient.signature_verify#2 kmip.pie.client.ProxyKmipClient.signature_verify/operation/kmip.core.enums.ValidityIndicator/high/-/params=3:cryptographic_parameters:operation-determining:algorithm:argument_value/varargs=false/when=-/lib=pykmip",
		"kmip.pie.client.ProxyKmipClient.mac#1 kmip.pie.client.ProxyKmipClient.mac/operation/builtins.tuple/high/-/params=2:algorithm:operation-determining:algorithm:argument_value/varargs=false/when=-/lib=pykmip",

		// Key objects built for register; PrivateKey also requires format_type.
		"kmip.pie.objects.SymmetricKey#3 kmip.pie.objects.SymmetricKey/factory/kmip.pie.objects.SymmetricKey/high/-/params=" + pykmipKeyParams + "/varargs=false/when=-/lib=pykmip",
		"kmip.pie.objects.SymmetricKey.<init>#3 kmip.pie.objects.SymmetricKey.<init>/factory/kmip.pie.objects.SymmetricKey/high/-/params=" + pykmipKeyParams + "/varargs=false/when=-/lib=pykmip",
		"kmip.pie.objects.PublicKey#3 kmip.pie.objects.PublicKey/factory/kmip.pie.objects.PublicKey/high/-/params=" + pykmipKeyParams + "/varargs=false/when=-/lib=pykmip",
		"kmip.pie.objects.PublicKey.<init>#3 kmip.pie.objects.PublicKey.<init>/factory/kmip.pie.objects.PublicKey/high/-/params=" + pykmipKeyParams + "/varargs=false/when=-/lib=pykmip",
		"kmip.pie.objects.PrivateKey#4 kmip.pie.objects.PrivateKey/factory/kmip.pie.objects.PrivateKey/high/-/params=" + pykmipKeyParams + "/varargs=false/when=-/lib=pykmip",
		"kmip.pie.objects.PrivateKey.<init>#4 kmip.pie.objects.PrivateKey.<init>/factory/kmip.pie.objects.PrivateKey/high/-/params=" + pykmipKeyParams + "/varargs=false/when=-/lib=pykmip",
		"kmip.pie.objects.X509Certificate#1 kmip.pie.objects.X509Certificate/factory/kmip.pie.objects.X509Certificate/high/-/params=-/varargs=false/when=-/lib=pykmip",
		"kmip.pie.objects.X509Certificate.<init>#1 kmip.pie.objects.X509Certificate.<init>/factory/kmip.pie.objects.X509Certificate/high/-/params=-/varargs=false/when=-/lib=pykmip",
	}
}

func TestPythonPykmipContract_ExactSet(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	var got []string
	for key, list := range kb.Contracts {
		for i := range list {
			if list[i].SourceLibrary == pykmipLibrary {
				got = append(got, renderPyotpContract(key, list[i]))
			}
		}
	}
	want := wantPykmipContracts()
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
			t.Errorf("loaded but not expected; if intended, add it to wantPykmipContracts():\n\t%q,", line)
		}
	}
}

// The key classes chain to ManagedObject, the type get returns, so a key
// built for register and a key read back by get join on one ancestor.
func TestPythonPykmipContract_KeyHierarchy(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	for _, child := range []string{
		"kmip.pie.objects.SymmetricKey",
		"kmip.pie.objects.PublicKey",
		"kmip.pie.objects.PrivateKey",
		"kmip.pie.objects.X509Certificate",
	} {
		if !pykmipReaches(kb.Hierarchy, child, "kmip.pie.objects.ManagedObject") {
			t.Errorf("%s does not reach kmip.pie.objects.ManagedObject through the hierarchy", child)
		}
	}
}

func pykmipReaches(h map[string][]string, from, to string) bool {
	seen := map[string]bool{}
	stack := []string{from}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if n == to {
			return true
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		stack = append(stack, h[n]...)
	}
	return false
}
