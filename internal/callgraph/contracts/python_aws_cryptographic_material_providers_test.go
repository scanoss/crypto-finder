// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"sort"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

const (
	mplLibrary   = "aws-cryptographic-material-providers"
	mplPublic    = "aws_cryptographic_material_providers.mpl"
	mplGenerated = "aws_cryptographic_material_providers.smithygenerated.aws_cryptography_materialproviders"
	mplClient    = mplGenerated + ".client.AwsCryptographicMaterialProviders"
	mplKeyring   = mplGenerated + ".references.Keyring"
	mplCMM       = mplGenerated + ".references.CryptographicMaterialsManager"
	mplTail      = "/high/-/params=-/varargs=false/when=-/lib=" + mplLibrary
)

func mplLine(key, method, role, ret string) string {
	return key + " " + method + "/" + role + "/" + ret + mplTail
}

// wantMPLContracts is written BY HAND from aws-cryptographic-material-providers
// 1.11.3, never derived from the YAML: a derived expectation goes green on a
// corrupted contract.
func wantMPLContracts() []string {
	lines := []string{
		mplLine(mplPublic+".AwsCryptographicMaterialProviders#0", mplPublic+".AwsCryptographicMaterialProviders", "factory", mplClient),
		mplLine(mplPublic+".AwsCryptographicMaterialProviders.<init>#0", mplPublic+".AwsCryptographicMaterialProviders.<init>", "factory", mplClient),
		mplLine(mplPublic+".client.AwsCryptographicMaterialProviders#0", mplPublic+".client.AwsCryptographicMaterialProviders", "factory", mplClient),
		mplLine(mplPublic+".client.AwsCryptographicMaterialProviders.<init>#0", mplPublic+".client.AwsCryptographicMaterialProviders.<init>", "factory", mplClient),
		mplLine(mplClient+".create_default_cryptographic_materials_manager#1", mplClient+".create_default_cryptographic_materials_manager", "factory", mplCMM),
		mplLine(mplClient+".create_required_encryption_context_cmm#1", mplClient+".create_required_encryption_context_cmm", "factory", mplCMM),
	}
	for _, m := range []string{
		"create_aws_kms_keyring",
		"create_aws_kms_discovery_keyring",
		"create_aws_kms_multi_keyring",
		"create_aws_kms_discovery_multi_keyring",
		"create_aws_kms_mrk_keyring",
		"create_aws_kms_mrk_multi_keyring",
		"create_aws_kms_mrk_discovery_keyring",
		"create_aws_kms_mrk_discovery_multi_keyring",
		"create_aws_kms_hierarchical_keyring",
		"create_aws_kms_rsa_keyring",
		"create_aws_kms_ecdh_keyring",
		"create_multi_keyring",
		"create_raw_aes_keyring",
		"create_raw_rsa_keyring",
		"create_raw_ecdh_keyring",
	} {
		lines = append(lines, mplLine(mplClient+"."+m+"#1", mplClient+"."+m, "factory", mplKeyring))
	}
	// Keyword-only input constructors, under both spellings of mpl.models.
	for _, in := range []string{
		"CreateRawAesKeyringInput",
		"CreateRawRsaKeyringInput",
		"CreateRawEcdhKeyringInput",
		"CreateAwsKmsKeyringInput",
		"CreateAwsKmsRsaKeyringInput",
		"CreateAwsKmsEcdhKeyringInput",
	} {
		ret := mplGenerated + ".models." + in
		lines = append(lines,
			mplLine(mplPublic+".models."+in+"#0", mplPublic+".models."+in, "factory", ret),
			mplLine(mplPublic+".models."+in+".<init>#0", mplPublic+".models."+in+".<init>", "factory", ret),
		)
	}
	return lines
}

func TestPythonMPLContract_ExactSet(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	var got []string
	for key, list := range kb.Contracts {
		for i := range list {
			if list[i].SourceLibrary == mplLibrary {
				got = append(got, renderPyotpContract(key, list[i]))
			}
		}
	}
	want := wantMPLContracts()
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
			t.Errorf("loaded but not expected; if intended, add it to wantMPLContracts():\n\t%q,", line)
		}
	}
}

// A keyring and a CMM must stay subtypes of their interfaces, which consumers
// annotate with (mpl.references.IKeyring).
func TestPythonMPLContract_InterfaceHierarchy(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	for child, parent := range map[string]string{
		mplKeyring: mplGenerated + ".references.IKeyring",
		mplCMM:     mplGenerated + ".references.ICryptographicMaterialsManager",
	} {
		if parents := kb.Hierarchy[child]; len(parents) != 1 || parents[0] != parent {
			t.Errorf("hierarchy[%s] = %v, want [%s]", child, parents, parent)
		}
	}
}
