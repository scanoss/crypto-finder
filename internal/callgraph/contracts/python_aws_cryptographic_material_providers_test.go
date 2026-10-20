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
	ksPublic     = "aws_cryptographic_material_providers.keystore"
	ksGenerated  = "aws_cryptographic_material_providers.smithygenerated.aws_cryptography_keystore"
	ksClient     = ksGenerated + ".client.KeyStore"
)

// mplCtor renders both import spellings of a constructor.
func mplCtor(spelling, arity, ret string) []string {
	return []string{
		mplLine(spelling+"#"+arity, spelling, "factory", ret),
		mplLine(spelling+".<init>#"+arity, spelling+".<init>", "factory", ret),
	}
}

func mplLine(key, method, role, ret string) string {
	return key + " " + method + "/" + role + "/" + ret + mplTail
}

// wantMPLContracts is written BY HAND from aws-cryptographic-material-providers
// 1.11.3, never derived from the YAML: a derived expectation goes green on a
// corrupted contract.
func wantMPLContracts() []string {
	lines := make([]string, 0, 128)
	lines = append(lines,
		mplLine(mplPublic+".AwsCryptographicMaterialProviders#0", mplPublic+".AwsCryptographicMaterialProviders", "factory", mplClient),
		mplLine(mplPublic+".AwsCryptographicMaterialProviders.<init>#0", mplPublic+".AwsCryptographicMaterialProviders.<init>", "factory", mplClient),
		mplLine(mplPublic+".client.AwsCryptographicMaterialProviders#0", mplPublic+".client.AwsCryptographicMaterialProviders", "factory", mplClient),
		mplLine(mplPublic+".client.AwsCryptographicMaterialProviders.<init>#0", mplPublic+".client.AwsCryptographicMaterialProviders.<init>", "factory", mplClient),
		mplLine(mplClient+".create_default_cryptographic_materials_manager#1", mplClient+".create_default_cryptographic_materials_manager", "factory", mplCMM),
		mplLine(mplClient+".create_required_encryption_context_cmm#1", mplClient+".create_required_encryption_context_cmm", "factory", mplCMM),
	)
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
		lines = append(lines, mplCtor(mplPublic+".models."+in, "0", ret)...)
	}
	// ECDH static configurations: keyword-only inner inputs, one-`value` unions.
	for in, arity := range map[string]string{
		"CreateAwsKmsHierarchicalKeyringInput":                            "0",
		"RawPrivateKeyToStaticPublicKeyInput":                             "0",
		"EphemeralPrivateKeyToStaticPublicKeyInput":                       "0",
		"PublicKeyDiscoveryInput":                                         "0",
		"KmsPrivateKeyToStaticPublicKeyInput":                             "0",
		"KmsPublicKeyDiscoveryInput":                                      "0",
		"RawEcdhStaticConfigurationsRawPrivateKeyToStaticPublicKey":       "1",
		"RawEcdhStaticConfigurationsEphemeralPrivateKeyToStaticPublicKey": "1",
		"RawEcdhStaticConfigurationsPublicKeyDiscovery":                   "1",
		"KmsEcdhStaticConfigurationsKmsPrivateKeyToStaticPublicKey":       "1",
		"KmsEcdhStaticConfigurationsKmsPublicKeyDiscovery":                "1",
	} {
		lines = append(lines, mplCtor(mplPublic+".models."+in, arity, mplGenerated+".models."+in)...)
	}
	lines = append(lines,
		mplLine(mplKeyring+".on_encrypt#1", mplKeyring+".on_encrypt", "operation", mplGenerated+".models.OnEncryptOutput"),
		mplLine(mplKeyring+".on_decrypt#1", mplKeyring+".on_decrypt", "operation", mplGenerated+".models.OnDecryptOutput"),
		mplLine(mplCMM+".get_encryption_materials#1", mplCMM+".get_encryption_materials", "operation", mplGenerated+".models.GetEncryptionMaterialsOutput"),
		mplLine(mplCMM+".decrypt_materials#1", mplCMM+".decrypt_materials", "operation", mplGenerated+".models.DecryptMaterialsOutput"),
	)
	// KeyStore, from aws_cryptographic_material_providers.keystore.
	lines = append(lines, mplCtor(ksPublic+".KeyStore", "0", ksClient)...)
	lines = append(lines, mplCtor(ksPublic+".client.KeyStore", "0", ksClient)...)
	lines = append(lines, mplCtor(ksPublic+".config.KeyStoreConfig", "0", ksGenerated+".config.KeyStoreConfig")...)
	for in, arity := range map[string]string{
		"KMSConfigurationKmsKeyArn":   "1",
		"KMSConfigurationKmsMRKeyArn": "1",
		"KMSConfigurationDiscovery":   "1",
		"KMSConfigurationMrDiscovery": "1",
		"CreateKeyInput":              "0",
		"VersionKeyInput":             "0",
	} {
		lines = append(lines, mplCtor(ksPublic+".models."+in, arity, ksGenerated+".models."+in)...)
	}
	lines = append(lines,
		mplLine(ksClient+".create_key#1", ksClient+".create_key", "operation", ksGenerated+".models.CreateKeyOutput"),
		mplLine(ksClient+".version_key#1", ksClient+".version_key", "operation", ksGenerated+".models.VersionKeyOutput"),
		mplLine(ksClient+".get_active_branch_key#1", ksClient+".get_active_branch_key", "output", ksGenerated+".models.GetActiveBranchKeyOutput"),
		mplLine(ksClient+".get_branch_key_version#1", ksClient+".get_branch_key_version", "output", ksGenerated+".models.GetBranchKeyVersionOutput"),
		mplLine(ksClient+".get_beacon_key#1", ksClient+".get_beacon_key", "output", ksGenerated+".models.GetBeaconKeyOutput"),
	)
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

// A keyring and a CMM must stay subtypes of their smithygenerated interfaces.
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
