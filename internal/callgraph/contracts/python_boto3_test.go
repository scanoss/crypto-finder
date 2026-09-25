// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"sort"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

const boto3Library = "boto3"

// wantBoto3Contracts is written BY HAND from boto3 1.43.102 and the botocore
// KMS service model, never derived from the YAML: a derived expectation goes
// green on a corrupted contract.
func wantBoto3Contracts() []string {
	return []string{
		// The four import spellings of one Session class.
		"boto3.Session#0 boto3.Session/factory/boto3.session.Session/high/-/-/params=-/varargs=false/when=-/lib=boto3",
		"boto3.Session.<init>#0 boto3.Session.<init>/factory/boto3.session.Session/high/-/-/params=-/varargs=false/when=-/lib=boto3",
		"boto3.session.Session#0 boto3.session.Session/factory/boto3.session.Session/high/-/-/params=-/varargs=false/when=-/lib=boto3",
		"boto3.session.Session.<init>#0 boto3.session.Session.<init>/factory/boto3.session.Session/high/-/-/params=-/varargs=false/when=-/lib=boto3",
		// client(service_name, ..) binds a KMS client only for the literal 'kms'.
		"boto3.client#1 boto3.client/factory/botocore.client.KMS/high/-/-/params=-/varargs=false/when=conditional/lib=boto3",
		"boto3.session.Session.client#1 boto3.session.Session.client/factory/botocore.client.KMS/high/-/-/params=-/varargs=false/when=conditional/lib=boto3",
		// KMS operations take keyword arguments only, so every call has arity 0.
		"botocore.client.KMS.encrypt#0 botocore.client.KMS.encrypt/operation/builtins.dict/high/-/-/params=-/varargs=false/when=-/lib=boto3",
		"botocore.client.KMS.decrypt#0 botocore.client.KMS.decrypt/operation/builtins.dict/high/-/-/params=-/varargs=false/when=-/lib=boto3",
		"botocore.client.KMS.re_encrypt#0 botocore.client.KMS.re_encrypt/operation/builtins.dict/high/-/-/params=-/varargs=false/when=-/lib=boto3",
		"botocore.client.KMS.generate_data_key#0 botocore.client.KMS.generate_data_key/operation/builtins.dict/high/-/-/params=-/varargs=false/when=-/lib=boto3",
		"botocore.client.KMS.generate_data_key_without_plaintext#0 botocore.client.KMS.generate_data_key_without_plaintext/operation/builtins.dict/high/-/-/params=-/varargs=false/when=-/lib=boto3",
		"botocore.client.KMS.generate_data_key_pair#0 botocore.client.KMS.generate_data_key_pair/operation/builtins.dict/high/-/-/params=-/varargs=false/when=-/lib=boto3",
		"botocore.client.KMS.generate_data_key_pair_without_plaintext#0 botocore.client.KMS.generate_data_key_pair_without_plaintext/operation/builtins.dict/high/-/-/params=-/varargs=false/when=-/lib=boto3",
		"botocore.client.KMS.generate_random#0 botocore.client.KMS.generate_random/operation/builtins.dict/high/-/-/params=-/varargs=false/when=-/lib=boto3",
		"botocore.client.KMS.generate_mac#0 botocore.client.KMS.generate_mac/operation/builtins.dict/high/-/-/params=-/varargs=false/when=-/lib=boto3",
		"botocore.client.KMS.verify_mac#0 botocore.client.KMS.verify_mac/operation/builtins.dict/high/-/-/params=-/varargs=false/when=-/lib=boto3",
		"botocore.client.KMS.derive_shared_secret#0 botocore.client.KMS.derive_shared_secret/operation/builtins.dict/high/-/-/params=-/varargs=false/when=-/lib=boto3",
		"botocore.client.KMS.sign#0 botocore.client.KMS.sign/operation/builtins.dict/high/-/-/params=-/varargs=false/when=-/lib=boto3",
		"botocore.client.KMS.verify#0 botocore.client.KMS.verify/operation/builtins.dict/high/-/-/params=-/varargs=false/when=-/lib=boto3",
		"botocore.client.KMS.get_public_key#0 botocore.client.KMS.get_public_key/output/builtins.dict/high/-/-/params=-/varargs=false/when=-/lib=boto3",
	}
}

func TestPythonBoto3Contract_ExactSet(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	var got []string
	for key, list := range kb.Contracts {
		for i := range list {
			if list[i].SourceLibrary == boto3Library {
				got = append(got, renderPyjwtContract(key, list[i]))
			}
		}
	}
	want := wantBoto3Contracts()
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
			t.Errorf("loaded but not expected; if intended, add it to wantBoto3Contracts():\n\t%q,", line)
		}
	}
}

// The render above only says a client contract is conditional. The literals
// are what the Python resolver compares a call's first argument against.
func TestPythonBoto3Contract_KMSClientLiterals(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	for _, method := range []string{"boto3.client", "boto3.session.Session.client"} {
		list := kb.ContractsFor(method, 1)
		if len(list) != 1 || list[0].When == nil {
			t.Fatalf("%s#1: want one conditional contract, got %+v", method, list)
		}
		literals := append([]string(nil), list[0].When.ArgValueIn...)
		sort.Strings(literals)
		if list[0].When.ArgIndex != 0 || len(literals) != 3 ||
			literals[0] != `"kms"` || literals[1] != "'kms'" || literals[2] != "kms" {
			t.Errorf("%s#1 condition = arg %d in %q, want arg 0 in [\"kms\" 'kms' kms]",
				method, list[0].When.ArgIndex, literals)
		}
	}
}
