// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

const awsESDKLibrary = "aws-encryption-sdk"

const (
	esdk           = "aws_encryption_sdk"
	esdkKMS        = esdk + ".key_providers.kms"
	esdkBase       = esdk + ".key_providers.base"
	esdkStream     = esdk + ".streaming_client"
	esdkWrapping   = esdk + ".internal.crypto.wrapping_keys.WrappingKey"
	esdkWrapParams = "0:wrapping_algorithm:operation-determining:algorithm:argument_value," +
		"1:wrapping_key:metadata-contributing:keyMaterial:argument_value"
)

func esdkLine(method string, arity int, role, typ, paramRoles string) string {
	return fmt.Sprintf("%s#%d %s/%s/%s/high/-/-/params=%s/varargs=false/when=-/lib=%s",
		method, arity, method, role, typ, paramRoles, awsESDKLibrary)
}

// esdkCtor expands one constructor into its attribute-path and from-import keys.
func esdkCtor(method string, arity int, typ, paramRoles string) []string {
	return []string{
		esdkLine(method, arity, "factory", typ, paramRoles),
		esdkLine(method+".<init>", arity, "factory", typ, paramRoles),
	}
}

// wantAwsESDKContracts is written BY HAND from aws-encryption-sdk 4.0.7 and
// the 1.x releases, never derived from the YAML.
func wantAwsESDKContracts() []string {
	var want []string
	add := func(lines ...string) { want = append(want, lines...) }

	add(esdkCtor(esdk+".EncryptionSDKClient", 0, esdk+".EncryptionSDKClient", "-")...)
	add(
		esdkLine(esdk+".EncryptionSDKClient.encrypt", 0, "operation", "builtins.tuple", "-"),
		esdkLine(esdk+".EncryptionSDKClient.decrypt", 0, "operation", "builtins.tuple", "-"),
		esdkLine(esdk+".EncryptionSDKClient.stream", 0, "factory", esdkStream+"._EncryptionStream", "-"),
		// 1.x module functions.
		esdkLine(esdk+".encrypt", 0, "operation", "builtins.tuple", "-"),
		esdkLine(esdk+".decrypt", 0, "operation", "builtins.tuple", "-"),
		esdkLine(esdk+".stream", 0, "factory", esdkStream+"._EncryptionStream", "-"),
		esdkLine(esdkStream+"._EncryptionStream.read", 0, "operation", "builtins.bytes", "-"),
		// read() is inherited, and Python lookup does not walk the hierarchy.
		esdkLine(esdkStream+".StreamEncryptor.read", 0, "operation", "builtins.bytes", "-"),
		esdkLine(esdkStream+".StreamDecryptor.read", 0, "operation", "builtins.bytes", "-"),
	)
	for _, cls := range []string{"StreamEncryptor", "StreamDecryptor"} {
		add(esdkCtor(esdk+"."+cls, 0, esdkStream+"."+cls, "-")...)
		add(esdkCtor(esdkStream+"."+cls, 0, esdkStream+"."+cls, "-")...)
	}
	for _, cls := range []string{"StrictAwsKmsMasterKeyProvider", "DiscoveryAwsKmsMasterKeyProvider", "KMSMasterKeyProvider"} {
		add(esdkCtor(esdk+"."+cls, 0, esdkKMS+"."+cls, "-")...)
		add(esdkCtor(esdkKMS+"."+cls, 0, esdkKMS+"."+cls, "-")...)
	}
	for _, cls := range []string{"MRKAwareStrictAwsKmsMasterKeyProvider", "MRKAwareDiscoveryAwsKmsMasterKeyProvider", "KMSMasterKey"} {
		add(esdkCtor(esdkKMS+"."+cls, 0, esdkKMS+"."+cls, "-")...)
	}
	add(esdkCtor(esdk+".key_providers.raw.RawMasterKey", 0, esdk+".key_providers.raw.RawMasterKey", "-")...)
	add(
		esdkLine(esdkBase+".MasterKeyProvider.add_master_key", 1, "config", "builtins.NoneType", "-"),
		esdkLine(esdkBase+".MasterKeyProvider.add_master_keys_from_list", 1, "config", "builtins.NoneType", "-"),
		esdkLine(esdkBase+".MasterKeyProvider.add_master_key_provider", 1, "config", "builtins.NoneType", "-"),
		esdkLine(esdkBase+".MasterKeyProvider.add_master_key_providers_from_list", 1, "config", "builtins.NoneType", "-"),
		esdkLine(esdkBase+".MasterKeyProvider.decrypt_data_key", 3, "operation", esdk+".structures.DataKey", "-"),
		esdkLine(esdkBase+".MasterKeyProvider.decrypt_data_key_from_list", 3, "operation", esdk+".structures.DataKey", "-"),
		esdkLine(esdkBase+".MasterKey.generate_data_key", 2, "operation", esdk+".structures.DataKey", "-"),
		esdkLine(esdkBase+".MasterKey.encrypt_data_key", 3, "operation", esdk+".structures.EncryptedDataKey", "-"),
		esdkLine(esdkBase+".MasterKey.decrypt_data_key", 3, "operation", esdk+".structures.DataKey", "-"),
	)
	// base.py MasterKeyProvider methods, inherited by every concrete provider.
	for _, cls := range []string{
		"StrictAwsKmsMasterKeyProvider", "DiscoveryAwsKmsMasterKeyProvider",
		"MRKAwareStrictAwsKmsMasterKeyProvider", "MRKAwareDiscoveryAwsKmsMasterKeyProvider",
		"KMSMasterKeyProvider",
	} {
		p := esdkKMS + "." + cls
		add(
			esdkLine(p+".add_master_key", 1, "config", "builtins.NoneType", "-"),
			esdkLine(p+".add_master_keys_from_list", 1, "config", "builtins.NoneType", "-"),
			esdkLine(p+".add_master_key_provider", 1, "config", "builtins.NoneType", "-"),
			esdkLine(p+".add_master_key_providers_from_list", 1, "config", "builtins.NoneType", "-"),
			esdkLine(p+".decrypt_data_key", 3, "operation", esdk+".structures.DataKey", "-"),
			esdkLine(p+".decrypt_data_key_from_list", 3, "operation", esdk+".structures.DataKey", "-"),
		)
	}
	// base.py MasterKey data-key methods, inherited by both master keys.
	for _, key := range []string{esdkKMS + ".KMSMasterKey", esdk + ".key_providers.raw.RawMasterKey"} {
		add(
			esdkLine(key+".generate_data_key", 2, "operation", esdk+".structures.DataKey", "-"),
			esdkLine(key+".encrypt_data_key", 3, "operation", esdk+".structures.EncryptedDataKey", "-"),
			esdkLine(key+".decrypt_data_key", 3, "operation", esdk+".structures.DataKey", "-"),
		)
	}
	add(esdkCtor(esdk+".internal.crypto.WrappingKey", 3, esdkWrapping, esdkWrapParams)...)
	add(esdkCtor(esdkWrapping, 3, esdkWrapping, esdkWrapParams)...)
	add(
		esdkLine(esdkWrapping+".encrypt", 2, "operation", esdk+".internal.structures.EncryptedData", "-"),
		esdkLine(esdkWrapping+".decrypt", 2, "operation", "builtins.bytes", "-"),
	)
	for _, cmm := range []struct {
		module, cls string
		arity       int
	}{{"default", "DefaultCryptoMaterialsManager", 1}, {"caching", "CachingCryptoMaterialsManager", 2}} {
		typ := esdk + ".materials_managers." + cmm.module + "." + cmm.cls
		add(esdkCtor(esdk+"."+cmm.cls, cmm.arity, typ, "-")...)
		add(esdkCtor(typ, cmm.arity, typ, "-")...)
		// Both CMMs override the base materials calls.
		add(
			esdkLine(typ+".get_encryption_materials", 1, "operation", esdk+".materials_managers.EncryptionMaterials", "-"),
			esdkLine(typ+".decrypt_materials", 1, "operation", esdk+".materials_managers.DecryptionMaterials", "-"),
		)
	}
	add(
		esdkLine(esdk+".materials_managers.base.CryptoMaterialsManager.get_encryption_materials", 1,
			"operation", esdk+".materials_managers.EncryptionMaterials", "-"),
		esdkLine(esdk+".materials_managers.base.CryptoMaterialsManager.decrypt_materials", 1,
			"operation", esdk+".materials_managers.DecryptionMaterials", "-"),
	)
	return want
}

func TestPythonAwsEncryptionSDKContract_ExactSet(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	var got []string
	for key, list := range kb.Contracts {
		for i := range list {
			if list[i].SourceLibrary == awsESDKLibrary {
				got = append(got, renderPyjwtContract(key, list[i]))
			}
		}
	}
	want := wantAwsESDKContracts()
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
			t.Errorf("loaded but not expected; if intended, add it to wantAwsESDKContracts():\n\t%q,", line)
		}
	}
}

func TestPythonAwsEncryptionSDKContract_LibraryBlock(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("python", "aws-encryption-sdk.yaml"))
	if err != nil {
		t.Fatalf("read aws-encryption-sdk.yaml: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(aws-encryption-sdk.yaml): %v", err)
	}
	if kb.Library == nil || kb.Library.Name != awsESDKLibrary {
		t.Fatalf("library block = %+v, want name %s", kb.Library, awsESDKLibrary)
	}
	// 1.3.0 and earlier lack wrapping_keys.py, so the range starts at 1.3.1.
	if got := kb.Library.VersionRange; got != ">=1.3.1" {
		t.Errorf("library.version_range = %q, want >=1.3.1", got)
	}
}
