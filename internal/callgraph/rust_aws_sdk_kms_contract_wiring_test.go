// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// Every aws-sdk-kms call is a fluent chain, so this test's job is to hold the
// line on the whole chain resolving rather than just its first link.
//
// MEASURED on the source below, through the FULL BUILDER:
//
//	before this contract existed   6 of 21 call sites resolved
//	with the setters declared     21 of 21
//
// The fifteen that were lost came out as `<scanned crate>.key_id`,
// `<scanned crate>.plaintext`, `<scanned crate>.signing_algorithm` and so on --
// the consumer's own package named as the owner of a third-party call, which is
// a WRONG identity and not merely a missing one, because it looks resolved and
// matches no contract.
//
// It runs through BuildFromDirectories, not the parser alone.
// rust_fluent_chain_qualifier_test.go records why: "the parser resolved the case
// above correctly and a post-build pass undid it, so a parser-only helper
// asserts nothing about this defect.".
func TestAwsSdkKmsContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	dir := t.TempDir()
	src := `use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{EncryptionAlgorithmSpec, MacAlgorithmSpec, SigningAlgorithmSpec};
use aws_sdk_kms::Client;

async fn ops(client: &Client, key_id: &str, pt: Vec<u8>) {
    let _ = client.encrypt().key_id(key_id).plaintext(Blob::new(pt)).encryption_algorithm(EncryptionAlgorithmSpec::RsaesOaepSha256).send().await;
    let _ = client.sign().key_id(key_id).signing_algorithm(SigningAlgorithmSpec::EcdsaSha384).send().await;
    let _ = client.generate_mac().key_id(key_id).mac_algorithm(MacAlgorithmSpec::HmacSha256).send().await;
    let _ = client.generate_data_key().key_id(key_id).send().await;
    let _ = client.generate_random().number_of_bytes(32).send().await;
}

async fn ctor(conf: &aws_config::SdkConfig) {
    let _c = aws_sdk_kms::Client::new(conf);
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	b := NewBuilderForEcosystem("rust", NewRustParser())
	graph, err := b.BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	// THE ROLES MATCH THE GO KMS KBs FOR THE SAME SERVICE. `generate_data_key`
	// and `generate_data_key_pair` are `factory` and `generate_random` is
	// `output` in go/aws-kms-v2.yaml and go/aws-kms.yaml, which were merged for
	// the same API. Role flows to the served surface as Category, so labeling
	// them `operation` here would have given the identical KMS call a different
	// category purely by consumer language. A review caught it.
	type expect struct {
		arity int
		role  string
	}
	// The identities the builder really emits for the source above, with the
	// role each must carry. Keys are the call-site spelling; ContractsFor
	// bridges it to the authored "::" form.
	want := map[string]expect{
		"aws_sdk_kms.Client.encrypt":           {arity: 0, role: "operation"},
		"aws_sdk_kms.Client.generate_data_key": {arity: 0, role: "factory"},
		"aws_sdk_kms.Client.generate_mac":      {arity: 0, role: "operation"},
		"aws_sdk_kms.Client.generate_random":   {arity: 0, role: "output"},
		"aws_sdk_kms.Client.new":               {arity: 1, role: "factory"},
		"aws_sdk_kms.Client.sign":              {arity: 0, role: "operation"},
		"aws_sdk_kms::operation::encrypt::builders.EncryptFluentBuilder.encryption_algorithm":           {arity: 1, role: "config"},
		"aws_sdk_kms::operation::encrypt::builders.EncryptFluentBuilder.key_id":                         {arity: 1, role: "config"},
		"aws_sdk_kms::operation::encrypt::builders.EncryptFluentBuilder.plaintext":                      {arity: 1, role: "config"},
		"aws_sdk_kms::operation::encrypt::builders.EncryptFluentBuilder.send":                           {arity: 0, role: "output"},
		"aws_sdk_kms::operation::generate_data_key::builders.GenerateDataKeyFluentBuilder.key_id":       {arity: 1, role: "config"},
		"aws_sdk_kms::operation::generate_data_key::builders.GenerateDataKeyFluentBuilder.send":         {arity: 0, role: "output"},
		"aws_sdk_kms::operation::generate_mac::builders.GenerateMacFluentBuilder.key_id":                {arity: 1, role: "config"},
		"aws_sdk_kms::operation::generate_mac::builders.GenerateMacFluentBuilder.mac_algorithm":         {arity: 1, role: "config"},
		"aws_sdk_kms::operation::generate_mac::builders.GenerateMacFluentBuilder.send":                  {arity: 0, role: "output"},
		"aws_sdk_kms::operation::generate_random::builders.GenerateRandomFluentBuilder.number_of_bytes": {arity: 1, role: "config"},
		"aws_sdk_kms::operation::generate_random::builders.GenerateRandomFluentBuilder.send":            {arity: 0, role: "output"},
		"aws_sdk_kms::operation::sign::builders.SignFluentBuilder.key_id":                               {arity: 1, role: "config"},
		"aws_sdk_kms::operation::sign::builders.SignFluentBuilder.send":                                 {arity: 0, role: "output"},
		"aws_sdk_kms::operation::sign::builders.SignFluentBuilder.signing_algorithm":                    {arity: 1, role: "config"},
	}

	seen := map[string]bool{}
	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			call := &fn.Calls[i]
			callee := call.Callee
			method, arity := splitMethodArity(&callee)
			exp, ok := want[method]
			if !ok {
				continue
			}
			seen[method] = true
			got := kb.ContractsFor(method, arity)
			if len(got) != 1 {
				t.Errorf("%s#%d: ContractsFor returned %d contracts, want exactly 1",
					method, arity, len(got))
				continue
			}
			if got[0].SourceLibrary != "aws-sdk-kms" {
				t.Errorf("%s: SourceLibrary=%q, want aws-sdk-kms", method, got[0].SourceLibrary)
			}
			if got[0].Role != exp.role {
				t.Errorf("%s: role=%q, want %q", method, got[0].Role, exp.role)
			}
		}
	}
	for method := range want {
		if !seen[method] {
			t.Errorf("the builder never produced %q; either the source above stopped "+
				"exercising it or the resolver's identity for it changed", method)
		}
	}

	// THE OTHER DIRECTION: no aws-sdk-kms entry may be unaccounted for. A
	// review of another Rust KB deleted an entry, flipped a role, changed an
	// arity and appended a contract for a module that does not exist -- four
	// hostile mutations at once -- and the whole suite stayed green, because
	// the table above only guards what it names.
	//
	// An entry the source does not exercise is fine and is listed below; an
	// entry in NEITHER list fails, so adding a contract without deciding which
	// it is cannot pass unnoticed.
	// EVERY entry, with its arity, role, declared return and canonical return.
	// An earlier revision split this into an `exercised` table that asserted
	// role and an `unexercised` map of names whose int values were DEAD DATA --
	// the map was only read as a set, so setting all 72 of them to 99 changed
	// nothing, and flipping a role on any of those 72 (78% of the KB) passed
	// silently. A review found both. Everything is asserted for everything now,
	// and the arity column is read from the crate rather than copied from the
	// YAML: the same review found six `*encryption_context` setters declared at
	// arity 1 when the crate declares `(mut self, k: impl Into<String>, v: impl
	// Into<String>)` -- arity 2 -- and the old table hardcoded the wrong value,
	// so it actively BLOCKED the fix.
	//
	// Arity is not documentation-only after all, which is why this matters: the
	// call-graph path arrives with -1 and resolves by name, but the export path
	// passes the real argument count (see rust_contract_export_test.go), and
	// `rustContractsFor` bails before the name fallback when arity >= 0. A wrong
	// arity there means the contract simply does not match.
	all := map[string]struct {
		arity int
		role  string
		ret   string
		canon string
	}{
		"aws_sdk_kms.Client.decrypt":                {arity: 0, role: "operation", ret: "aws_sdk_kms::operation::decrypt::builders::DecryptFluentBuilder", canon: ""},
		"aws_sdk_kms.Client.derive_shared_secret":   {arity: 0, role: "operation", ret: "aws_sdk_kms::operation::derive_shared_secret::builders::DeriveSharedSecretFluentBuilder", canon: ""},
		"aws_sdk_kms.Client.encrypt":                {arity: 0, role: "operation", ret: "aws_sdk_kms::operation::encrypt::builders::EncryptFluentBuilder", canon: ""},
		"aws_sdk_kms.Client.from_conf":              {arity: 1, role: "factory", ret: "aws_sdk_kms::Client", canon: ""},
		"aws_sdk_kms.Client.generate_data_key":      {arity: 0, role: "factory", ret: "aws_sdk_kms::operation::generate_data_key::builders::GenerateDataKeyFluentBuilder", canon: ""},
		"aws_sdk_kms.Client.generate_data_key_pair": {arity: 0, role: "factory", ret: "aws_sdk_kms::operation::generate_data_key_pair::builders::GenerateDataKeyPairFluentBuilder", canon: ""},
		"aws_sdk_kms.Client.generate_mac":           {arity: 0, role: "operation", ret: "aws_sdk_kms::operation::generate_mac::builders::GenerateMacFluentBuilder", canon: ""},
		"aws_sdk_kms.Client.generate_random":        {arity: 0, role: "output", ret: "aws_sdk_kms::operation::generate_random::builders::GenerateRandomFluentBuilder", canon: ""},
		"aws_sdk_kms.Client.new":                    {arity: 1, role: "factory", ret: "aws_sdk_kms::Client", canon: ""},
		"aws_sdk_kms.Client.re_encrypt":             {arity: 0, role: "operation", ret: "aws_sdk_kms::operation::re_encrypt::builders::ReEncryptFluentBuilder", canon: ""},
		"aws_sdk_kms.Client.sign":                   {arity: 0, role: "operation", ret: "aws_sdk_kms::operation::sign::builders::SignFluentBuilder", canon: ""},
		"aws_sdk_kms.Client.verify":                 {arity: 0, role: "operation", ret: "aws_sdk_kms::operation::verify::builders::VerifyFluentBuilder", canon: ""},
		"aws_sdk_kms.Client.verify_mac":             {arity: 0, role: "operation", ret: "aws_sdk_kms::operation::verify_mac::builders::VerifyMacFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::decrypt::builders.DecryptFluentBuilder.ciphertext_blob":                                     {arity: 1, role: "config", ret: "aws_sdk_kms::operation::decrypt::builders::DecryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::decrypt::builders.DecryptFluentBuilder.customize":                                           {arity: 0, role: "config", ret: "aws_sdk_kms::client::customize::CustomizableOperation", canon: ""},
		"aws_sdk_kms::operation::decrypt::builders.DecryptFluentBuilder.dry_run":                                             {arity: 1, role: "config", ret: "aws_sdk_kms::operation::decrypt::builders::DecryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::decrypt::builders.DecryptFluentBuilder.encryption_algorithm":                                {arity: 1, role: "config", ret: "aws_sdk_kms::operation::decrypt::builders::DecryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::decrypt::builders.DecryptFluentBuilder.encryption_context":                                  {arity: 2, role: "config", ret: "aws_sdk_kms::operation::decrypt::builders::DecryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::decrypt::builders.DecryptFluentBuilder.grant_tokens":                                        {arity: 1, role: "config", ret: "aws_sdk_kms::operation::decrypt::builders::DecryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::decrypt::builders.DecryptFluentBuilder.key_id":                                              {arity: 1, role: "config", ret: "aws_sdk_kms::operation::decrypt::builders::DecryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::decrypt::builders.DecryptFluentBuilder.recipient":                                           {arity: 1, role: "config", ret: "aws_sdk_kms::operation::decrypt::builders::DecryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::decrypt::builders.DecryptFluentBuilder.send":                                                {arity: 0, role: "output", ret: "aws_sdk_kms::operation::decrypt::DecryptOutput", canon: "core::result::Result<aws_sdk_kms::operation::decrypt::DecryptOutput, aws_sdk_kms::error::SdkError>"},
		"aws_sdk_kms::operation::decrypt::builders.DecryptFluentBuilder.set_ciphertext_blob":                                 {arity: 1, role: "config", ret: "aws_sdk_kms::operation::decrypt::builders::DecryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::decrypt::builders.DecryptFluentBuilder.set_dry_run":                                         {arity: 1, role: "config", ret: "aws_sdk_kms::operation::decrypt::builders::DecryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::decrypt::builders.DecryptFluentBuilder.set_encryption_algorithm":                            {arity: 1, role: "config", ret: "aws_sdk_kms::operation::decrypt::builders::DecryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::decrypt::builders.DecryptFluentBuilder.set_encryption_context":                              {arity: 2, role: "config", ret: "aws_sdk_kms::operation::decrypt::builders::DecryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::decrypt::builders.DecryptFluentBuilder.set_grant_tokens":                                    {arity: 1, role: "config", ret: "aws_sdk_kms::operation::decrypt::builders::DecryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::decrypt::builders.DecryptFluentBuilder.set_key_id":                                          {arity: 1, role: "config", ret: "aws_sdk_kms::operation::decrypt::builders::DecryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::decrypt::builders.DecryptFluentBuilder.set_recipient":                                       {arity: 1, role: "config", ret: "aws_sdk_kms::operation::decrypt::builders::DecryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::derive_shared_secret::builders.DeriveSharedSecretFluentBuilder.customize":                   {arity: 0, role: "config", ret: "aws_sdk_kms::client::customize::CustomizableOperation", canon: ""},
		"aws_sdk_kms::operation::derive_shared_secret::builders.DeriveSharedSecretFluentBuilder.dry_run":                     {arity: 1, role: "config", ret: "aws_sdk_kms::operation::derive_shared_secret::builders::DeriveSharedSecretFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::derive_shared_secret::builders.DeriveSharedSecretFluentBuilder.grant_tokens":                {arity: 1, role: "config", ret: "aws_sdk_kms::operation::derive_shared_secret::builders::DeriveSharedSecretFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::derive_shared_secret::builders.DeriveSharedSecretFluentBuilder.key_agreement_algorithm":     {arity: 1, role: "config", ret: "aws_sdk_kms::operation::derive_shared_secret::builders::DeriveSharedSecretFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::derive_shared_secret::builders.DeriveSharedSecretFluentBuilder.key_id":                      {arity: 1, role: "config", ret: "aws_sdk_kms::operation::derive_shared_secret::builders::DeriveSharedSecretFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::derive_shared_secret::builders.DeriveSharedSecretFluentBuilder.public_key":                  {arity: 1, role: "config", ret: "aws_sdk_kms::operation::derive_shared_secret::builders::DeriveSharedSecretFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::derive_shared_secret::builders.DeriveSharedSecretFluentBuilder.recipient":                   {arity: 1, role: "config", ret: "aws_sdk_kms::operation::derive_shared_secret::builders::DeriveSharedSecretFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::derive_shared_secret::builders.DeriveSharedSecretFluentBuilder.send":                        {arity: 0, role: "output", ret: "aws_sdk_kms::operation::derive_shared_secret::DeriveSharedSecretOutput", canon: "core::result::Result<aws_sdk_kms::operation::derive_shared_secret::DeriveSharedSecretOutput, aws_sdk_kms::error::SdkError>"},
		"aws_sdk_kms::operation::derive_shared_secret::builders.DeriveSharedSecretFluentBuilder.set_dry_run":                 {arity: 1, role: "config", ret: "aws_sdk_kms::operation::derive_shared_secret::builders::DeriveSharedSecretFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::derive_shared_secret::builders.DeriveSharedSecretFluentBuilder.set_grant_tokens":            {arity: 1, role: "config", ret: "aws_sdk_kms::operation::derive_shared_secret::builders::DeriveSharedSecretFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::derive_shared_secret::builders.DeriveSharedSecretFluentBuilder.set_key_agreement_algorithm": {arity: 1, role: "config", ret: "aws_sdk_kms::operation::derive_shared_secret::builders::DeriveSharedSecretFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::derive_shared_secret::builders.DeriveSharedSecretFluentBuilder.set_key_id":                  {arity: 1, role: "config", ret: "aws_sdk_kms::operation::derive_shared_secret::builders::DeriveSharedSecretFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::derive_shared_secret::builders.DeriveSharedSecretFluentBuilder.set_public_key":              {arity: 1, role: "config", ret: "aws_sdk_kms::operation::derive_shared_secret::builders::DeriveSharedSecretFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::derive_shared_secret::builders.DeriveSharedSecretFluentBuilder.set_recipient":               {arity: 1, role: "config", ret: "aws_sdk_kms::operation::derive_shared_secret::builders::DeriveSharedSecretFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::encrypt::builders.EncryptFluentBuilder.customize":                                           {arity: 0, role: "config", ret: "aws_sdk_kms::client::customize::CustomizableOperation", canon: ""},
		"aws_sdk_kms::operation::encrypt::builders.EncryptFluentBuilder.dry_run":                                             {arity: 1, role: "config", ret: "aws_sdk_kms::operation::encrypt::builders::EncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::encrypt::builders.EncryptFluentBuilder.encryption_algorithm":                                {arity: 1, role: "config", ret: "aws_sdk_kms::operation::encrypt::builders::EncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::encrypt::builders.EncryptFluentBuilder.encryption_context":                                  {arity: 2, role: "config", ret: "aws_sdk_kms::operation::encrypt::builders::EncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::encrypt::builders.EncryptFluentBuilder.grant_tokens":                                        {arity: 1, role: "config", ret: "aws_sdk_kms::operation::encrypt::builders::EncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::encrypt::builders.EncryptFluentBuilder.key_id":                                              {arity: 1, role: "config", ret: "aws_sdk_kms::operation::encrypt::builders::EncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::encrypt::builders.EncryptFluentBuilder.plaintext":                                           {arity: 1, role: "config", ret: "aws_sdk_kms::operation::encrypt::builders::EncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::encrypt::builders.EncryptFluentBuilder.send":                                                {arity: 0, role: "output", ret: "aws_sdk_kms::operation::encrypt::EncryptOutput", canon: "core::result::Result<aws_sdk_kms::operation::encrypt::EncryptOutput, aws_sdk_kms::error::SdkError>"},
		"aws_sdk_kms::operation::encrypt::builders.EncryptFluentBuilder.set_dry_run":                                         {arity: 1, role: "config", ret: "aws_sdk_kms::operation::encrypt::builders::EncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::encrypt::builders.EncryptFluentBuilder.set_encryption_algorithm":                            {arity: 1, role: "config", ret: "aws_sdk_kms::operation::encrypt::builders::EncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::encrypt::builders.EncryptFluentBuilder.set_encryption_context":                              {arity: 2, role: "config", ret: "aws_sdk_kms::operation::encrypt::builders::EncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::encrypt::builders.EncryptFluentBuilder.set_grant_tokens":                                    {arity: 1, role: "config", ret: "aws_sdk_kms::operation::encrypt::builders::EncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::encrypt::builders.EncryptFluentBuilder.set_key_id":                                          {arity: 1, role: "config", ret: "aws_sdk_kms::operation::encrypt::builders::EncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::encrypt::builders.EncryptFluentBuilder.set_plaintext":                                       {arity: 1, role: "config", ret: "aws_sdk_kms::operation::encrypt::builders::EncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key::builders.GenerateDataKeyFluentBuilder.customize":                         {arity: 0, role: "config", ret: "aws_sdk_kms::client::customize::CustomizableOperation", canon: ""},
		"aws_sdk_kms::operation::generate_data_key::builders.GenerateDataKeyFluentBuilder.dry_run":                           {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_data_key::builders::GenerateDataKeyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key::builders.GenerateDataKeyFluentBuilder.encryption_context":                {arity: 2, role: "config", ret: "aws_sdk_kms::operation::generate_data_key::builders::GenerateDataKeyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key::builders.GenerateDataKeyFluentBuilder.grant_tokens":                      {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_data_key::builders::GenerateDataKeyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key::builders.GenerateDataKeyFluentBuilder.key_id":                            {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_data_key::builders::GenerateDataKeyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key::builders.GenerateDataKeyFluentBuilder.key_spec":                          {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_data_key::builders::GenerateDataKeyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key::builders.GenerateDataKeyFluentBuilder.number_of_bytes":                   {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_data_key::builders::GenerateDataKeyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key::builders.GenerateDataKeyFluentBuilder.recipient":                         {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_data_key::builders::GenerateDataKeyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key::builders.GenerateDataKeyFluentBuilder.send":                              {arity: 0, role: "output", ret: "aws_sdk_kms::operation::generate_data_key::GenerateDataKeyOutput", canon: "core::result::Result<aws_sdk_kms::operation::generate_data_key::GenerateDataKeyOutput, aws_sdk_kms::error::SdkError>"},
		"aws_sdk_kms::operation::generate_data_key::builders.GenerateDataKeyFluentBuilder.set_dry_run":                       {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_data_key::builders::GenerateDataKeyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key::builders.GenerateDataKeyFluentBuilder.set_encryption_context":            {arity: 2, role: "config", ret: "aws_sdk_kms::operation::generate_data_key::builders::GenerateDataKeyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key::builders.GenerateDataKeyFluentBuilder.set_grant_tokens":                  {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_data_key::builders::GenerateDataKeyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key::builders.GenerateDataKeyFluentBuilder.set_key_id":                        {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_data_key::builders::GenerateDataKeyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key::builders.GenerateDataKeyFluentBuilder.set_key_spec":                      {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_data_key::builders::GenerateDataKeyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key::builders.GenerateDataKeyFluentBuilder.set_number_of_bytes":               {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_data_key::builders::GenerateDataKeyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key::builders.GenerateDataKeyFluentBuilder.set_recipient":                     {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_data_key::builders::GenerateDataKeyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key_pair::builders.GenerateDataKeyPairFluentBuilder.customize":                {arity: 0, role: "config", ret: "aws_sdk_kms::client::customize::CustomizableOperation", canon: ""},
		"aws_sdk_kms::operation::generate_data_key_pair::builders.GenerateDataKeyPairFluentBuilder.dry_run":                  {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_data_key_pair::builders::GenerateDataKeyPairFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key_pair::builders.GenerateDataKeyPairFluentBuilder.encryption_context":       {arity: 2, role: "config", ret: "aws_sdk_kms::operation::generate_data_key_pair::builders::GenerateDataKeyPairFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key_pair::builders.GenerateDataKeyPairFluentBuilder.grant_tokens":             {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_data_key_pair::builders::GenerateDataKeyPairFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key_pair::builders.GenerateDataKeyPairFluentBuilder.key_id":                   {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_data_key_pair::builders::GenerateDataKeyPairFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key_pair::builders.GenerateDataKeyPairFluentBuilder.key_pair_spec":            {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_data_key_pair::builders::GenerateDataKeyPairFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key_pair::builders.GenerateDataKeyPairFluentBuilder.recipient":                {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_data_key_pair::builders::GenerateDataKeyPairFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key_pair::builders.GenerateDataKeyPairFluentBuilder.send":                     {arity: 0, role: "output", ret: "aws_sdk_kms::operation::generate_data_key_pair::GenerateDataKeyPairOutput", canon: "core::result::Result<aws_sdk_kms::operation::generate_data_key_pair::GenerateDataKeyPairOutput, aws_sdk_kms::error::SdkError>"},
		"aws_sdk_kms::operation::generate_data_key_pair::builders.GenerateDataKeyPairFluentBuilder.set_dry_run":              {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_data_key_pair::builders::GenerateDataKeyPairFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key_pair::builders.GenerateDataKeyPairFluentBuilder.set_encryption_context":   {arity: 2, role: "config", ret: "aws_sdk_kms::operation::generate_data_key_pair::builders::GenerateDataKeyPairFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key_pair::builders.GenerateDataKeyPairFluentBuilder.set_grant_tokens":         {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_data_key_pair::builders::GenerateDataKeyPairFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key_pair::builders.GenerateDataKeyPairFluentBuilder.set_key_id":               {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_data_key_pair::builders::GenerateDataKeyPairFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key_pair::builders.GenerateDataKeyPairFluentBuilder.set_key_pair_spec":        {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_data_key_pair::builders::GenerateDataKeyPairFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_data_key_pair::builders.GenerateDataKeyPairFluentBuilder.set_recipient":            {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_data_key_pair::builders::GenerateDataKeyPairFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_mac::builders.GenerateMacFluentBuilder.customize":                                  {arity: 0, role: "config", ret: "aws_sdk_kms::client::customize::CustomizableOperation", canon: ""},
		"aws_sdk_kms::operation::generate_mac::builders.GenerateMacFluentBuilder.dry_run":                                    {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_mac::builders::GenerateMacFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_mac::builders.GenerateMacFluentBuilder.grant_tokens":                               {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_mac::builders::GenerateMacFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_mac::builders.GenerateMacFluentBuilder.key_id":                                     {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_mac::builders::GenerateMacFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_mac::builders.GenerateMacFluentBuilder.mac_algorithm":                              {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_mac::builders::GenerateMacFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_mac::builders.GenerateMacFluentBuilder.message":                                    {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_mac::builders::GenerateMacFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_mac::builders.GenerateMacFluentBuilder.send":                                       {arity: 0, role: "output", ret: "aws_sdk_kms::operation::generate_mac::GenerateMacOutput", canon: "core::result::Result<aws_sdk_kms::operation::generate_mac::GenerateMacOutput, aws_sdk_kms::error::SdkError>"},
		"aws_sdk_kms::operation::generate_mac::builders.GenerateMacFluentBuilder.set_dry_run":                                {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_mac::builders::GenerateMacFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_mac::builders.GenerateMacFluentBuilder.set_grant_tokens":                           {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_mac::builders::GenerateMacFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_mac::builders.GenerateMacFluentBuilder.set_key_id":                                 {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_mac::builders::GenerateMacFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_mac::builders.GenerateMacFluentBuilder.set_mac_algorithm":                          {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_mac::builders::GenerateMacFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_mac::builders.GenerateMacFluentBuilder.set_message":                                {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_mac::builders::GenerateMacFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_random::builders.GenerateRandomFluentBuilder.custom_key_store_id":                  {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_random::builders::GenerateRandomFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_random::builders.GenerateRandomFluentBuilder.customize":                            {arity: 0, role: "config", ret: "aws_sdk_kms::client::customize::CustomizableOperation", canon: ""},
		"aws_sdk_kms::operation::generate_random::builders.GenerateRandomFluentBuilder.number_of_bytes":                      {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_random::builders::GenerateRandomFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_random::builders.GenerateRandomFluentBuilder.recipient":                            {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_random::builders::GenerateRandomFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_random::builders.GenerateRandomFluentBuilder.send":                                 {arity: 0, role: "output", ret: "aws_sdk_kms::operation::generate_random::GenerateRandomOutput", canon: "core::result::Result<aws_sdk_kms::operation::generate_random::GenerateRandomOutput, aws_sdk_kms::error::SdkError>"},
		"aws_sdk_kms::operation::generate_random::builders.GenerateRandomFluentBuilder.set_custom_key_store_id":              {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_random::builders::GenerateRandomFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_random::builders.GenerateRandomFluentBuilder.set_number_of_bytes":                  {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_random::builders::GenerateRandomFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::generate_random::builders.GenerateRandomFluentBuilder.set_recipient":                        {arity: 1, role: "config", ret: "aws_sdk_kms::operation::generate_random::builders::GenerateRandomFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::re_encrypt::builders.ReEncryptFluentBuilder.ciphertext_blob":                                {arity: 1, role: "config", ret: "aws_sdk_kms::operation::re_encrypt::builders::ReEncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::re_encrypt::builders.ReEncryptFluentBuilder.customize":                                      {arity: 0, role: "config", ret: "aws_sdk_kms::client::customize::CustomizableOperation", canon: ""},
		"aws_sdk_kms::operation::re_encrypt::builders.ReEncryptFluentBuilder.destination_encryption_algorithm":               {arity: 1, role: "config", ret: "aws_sdk_kms::operation::re_encrypt::builders::ReEncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::re_encrypt::builders.ReEncryptFluentBuilder.destination_encryption_context":                 {arity: 2, role: "config", ret: "aws_sdk_kms::operation::re_encrypt::builders::ReEncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::re_encrypt::builders.ReEncryptFluentBuilder.destination_key_id":                             {arity: 1, role: "config", ret: "aws_sdk_kms::operation::re_encrypt::builders::ReEncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::re_encrypt::builders.ReEncryptFluentBuilder.dry_run":                                        {arity: 1, role: "config", ret: "aws_sdk_kms::operation::re_encrypt::builders::ReEncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::re_encrypt::builders.ReEncryptFluentBuilder.grant_tokens":                                   {arity: 1, role: "config", ret: "aws_sdk_kms::operation::re_encrypt::builders::ReEncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::re_encrypt::builders.ReEncryptFluentBuilder.send":                                           {arity: 0, role: "output", ret: "aws_sdk_kms::operation::re_encrypt::ReEncryptOutput", canon: "core::result::Result<aws_sdk_kms::operation::re_encrypt::ReEncryptOutput, aws_sdk_kms::error::SdkError>"},
		"aws_sdk_kms::operation::re_encrypt::builders.ReEncryptFluentBuilder.set_ciphertext_blob":                            {arity: 1, role: "config", ret: "aws_sdk_kms::operation::re_encrypt::builders::ReEncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::re_encrypt::builders.ReEncryptFluentBuilder.set_destination_encryption_algorithm":           {arity: 1, role: "config", ret: "aws_sdk_kms::operation::re_encrypt::builders::ReEncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::re_encrypt::builders.ReEncryptFluentBuilder.set_destination_encryption_context":             {arity: 2, role: "config", ret: "aws_sdk_kms::operation::re_encrypt::builders::ReEncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::re_encrypt::builders.ReEncryptFluentBuilder.set_destination_key_id":                         {arity: 1, role: "config", ret: "aws_sdk_kms::operation::re_encrypt::builders::ReEncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::re_encrypt::builders.ReEncryptFluentBuilder.set_dry_run":                                    {arity: 1, role: "config", ret: "aws_sdk_kms::operation::re_encrypt::builders::ReEncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::re_encrypt::builders.ReEncryptFluentBuilder.set_grant_tokens":                               {arity: 1, role: "config", ret: "aws_sdk_kms::operation::re_encrypt::builders::ReEncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::re_encrypt::builders.ReEncryptFluentBuilder.set_source_encryption_algorithm":                {arity: 1, role: "config", ret: "aws_sdk_kms::operation::re_encrypt::builders::ReEncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::re_encrypt::builders.ReEncryptFluentBuilder.set_source_encryption_context":                  {arity: 2, role: "config", ret: "aws_sdk_kms::operation::re_encrypt::builders::ReEncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::re_encrypt::builders.ReEncryptFluentBuilder.set_source_key_id":                              {arity: 1, role: "config", ret: "aws_sdk_kms::operation::re_encrypt::builders::ReEncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::re_encrypt::builders.ReEncryptFluentBuilder.source_encryption_algorithm":                    {arity: 1, role: "config", ret: "aws_sdk_kms::operation::re_encrypt::builders::ReEncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::re_encrypt::builders.ReEncryptFluentBuilder.source_encryption_context":                      {arity: 2, role: "config", ret: "aws_sdk_kms::operation::re_encrypt::builders::ReEncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::re_encrypt::builders.ReEncryptFluentBuilder.source_key_id":                                  {arity: 1, role: "config", ret: "aws_sdk_kms::operation::re_encrypt::builders::ReEncryptFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::sign::builders.SignFluentBuilder.customize":                                                 {arity: 0, role: "config", ret: "aws_sdk_kms::client::customize::CustomizableOperation", canon: ""},
		"aws_sdk_kms::operation::sign::builders.SignFluentBuilder.dry_run":                                                   {arity: 1, role: "config", ret: "aws_sdk_kms::operation::sign::builders::SignFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::sign::builders.SignFluentBuilder.grant_tokens":                                              {arity: 1, role: "config", ret: "aws_sdk_kms::operation::sign::builders::SignFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::sign::builders.SignFluentBuilder.key_id":                                                    {arity: 1, role: "config", ret: "aws_sdk_kms::operation::sign::builders::SignFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::sign::builders.SignFluentBuilder.message":                                                   {arity: 1, role: "config", ret: "aws_sdk_kms::operation::sign::builders::SignFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::sign::builders.SignFluentBuilder.message_type":                                              {arity: 1, role: "config", ret: "aws_sdk_kms::operation::sign::builders::SignFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::sign::builders.SignFluentBuilder.send":                                                      {arity: 0, role: "output", ret: "aws_sdk_kms::operation::sign::SignOutput", canon: "core::result::Result<aws_sdk_kms::operation::sign::SignOutput, aws_sdk_kms::error::SdkError>"},
		"aws_sdk_kms::operation::sign::builders.SignFluentBuilder.set_dry_run":                                               {arity: 1, role: "config", ret: "aws_sdk_kms::operation::sign::builders::SignFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::sign::builders.SignFluentBuilder.set_grant_tokens":                                          {arity: 1, role: "config", ret: "aws_sdk_kms::operation::sign::builders::SignFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::sign::builders.SignFluentBuilder.set_key_id":                                                {arity: 1, role: "config", ret: "aws_sdk_kms::operation::sign::builders::SignFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::sign::builders.SignFluentBuilder.set_message":                                               {arity: 1, role: "config", ret: "aws_sdk_kms::operation::sign::builders::SignFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::sign::builders.SignFluentBuilder.set_message_type":                                          {arity: 1, role: "config", ret: "aws_sdk_kms::operation::sign::builders::SignFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::sign::builders.SignFluentBuilder.set_signing_algorithm":                                     {arity: 1, role: "config", ret: "aws_sdk_kms::operation::sign::builders::SignFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::sign::builders.SignFluentBuilder.signing_algorithm":                                         {arity: 1, role: "config", ret: "aws_sdk_kms::operation::sign::builders::SignFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify::builders.VerifyFluentBuilder.customize":                                             {arity: 0, role: "config", ret: "aws_sdk_kms::client::customize::CustomizableOperation", canon: ""},
		"aws_sdk_kms::operation::verify::builders.VerifyFluentBuilder.dry_run":                                               {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify::builders::VerifyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify::builders.VerifyFluentBuilder.grant_tokens":                                          {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify::builders::VerifyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify::builders.VerifyFluentBuilder.key_id":                                                {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify::builders::VerifyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify::builders.VerifyFluentBuilder.message":                                               {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify::builders::VerifyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify::builders.VerifyFluentBuilder.message_type":                                          {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify::builders::VerifyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify::builders.VerifyFluentBuilder.send":                                                  {arity: 0, role: "output", ret: "aws_sdk_kms::operation::verify::VerifyOutput", canon: "core::result::Result<aws_sdk_kms::operation::verify::VerifyOutput, aws_sdk_kms::error::SdkError>"},
		"aws_sdk_kms::operation::verify::builders.VerifyFluentBuilder.set_dry_run":                                           {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify::builders::VerifyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify::builders.VerifyFluentBuilder.set_grant_tokens":                                      {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify::builders::VerifyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify::builders.VerifyFluentBuilder.set_key_id":                                            {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify::builders::VerifyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify::builders.VerifyFluentBuilder.set_message":                                           {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify::builders::VerifyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify::builders.VerifyFluentBuilder.set_message_type":                                      {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify::builders::VerifyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify::builders.VerifyFluentBuilder.set_signature":                                         {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify::builders::VerifyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify::builders.VerifyFluentBuilder.set_signing_algorithm":                                 {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify::builders::VerifyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify::builders.VerifyFluentBuilder.signature":                                             {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify::builders::VerifyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify::builders.VerifyFluentBuilder.signing_algorithm":                                     {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify::builders::VerifyFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify_mac::builders.VerifyMacFluentBuilder.customize":                                      {arity: 0, role: "config", ret: "aws_sdk_kms::client::customize::CustomizableOperation", canon: ""},
		"aws_sdk_kms::operation::verify_mac::builders.VerifyMacFluentBuilder.dry_run":                                        {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify_mac::builders::VerifyMacFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify_mac::builders.VerifyMacFluentBuilder.grant_tokens":                                   {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify_mac::builders::VerifyMacFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify_mac::builders.VerifyMacFluentBuilder.key_id":                                         {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify_mac::builders::VerifyMacFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify_mac::builders.VerifyMacFluentBuilder.mac":                                            {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify_mac::builders::VerifyMacFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify_mac::builders.VerifyMacFluentBuilder.mac_algorithm":                                  {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify_mac::builders::VerifyMacFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify_mac::builders.VerifyMacFluentBuilder.message":                                        {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify_mac::builders::VerifyMacFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify_mac::builders.VerifyMacFluentBuilder.send":                                           {arity: 0, role: "output", ret: "aws_sdk_kms::operation::verify_mac::VerifyMacOutput", canon: "core::result::Result<aws_sdk_kms::operation::verify_mac::VerifyMacOutput, aws_sdk_kms::error::SdkError>"},
		"aws_sdk_kms::operation::verify_mac::builders.VerifyMacFluentBuilder.set_dry_run":                                    {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify_mac::builders::VerifyMacFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify_mac::builders.VerifyMacFluentBuilder.set_grant_tokens":                               {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify_mac::builders::VerifyMacFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify_mac::builders.VerifyMacFluentBuilder.set_key_id":                                     {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify_mac::builders::VerifyMacFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify_mac::builders.VerifyMacFluentBuilder.set_mac":                                        {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify_mac::builders::VerifyMacFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify_mac::builders.VerifyMacFluentBuilder.set_mac_algorithm":                              {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify_mac::builders::VerifyMacFluentBuilder", canon: ""},
		"aws_sdk_kms::operation::verify_mac::builders.VerifyMacFluentBuilder.set_message":                                    {arity: 1, role: "config", ret: "aws_sdk_kms::operation::verify_mac::builders::VerifyMacFluentBuilder", canon: ""},
	}
	for key, cs := range kb.Contracts {
		for _, c := range cs {
			if c.SourceLibrary != "aws-sdk-kms" {
				continue
			}
			emitted := key
			if i := strings.LastIndex(key, "::"); i >= 0 {
				emitted = key[:i] + "." + key[i+2:]
			}
			if h := strings.LastIndex(emitted, "#"); h >= 0 {
				emitted = emitted[:h]
			}
			exp, ok := all[emitted]
			if !ok {
				t.Errorf("KB holds aws-sdk-kms contract %q (emitted %q) that this "+
					"test does not name. Add it with its arity, role and return, or "+
					"delete it from the contract.", key, emitted)
				continue
			}
			h := strings.LastIndex(key, "#")
			if h < 0 {
				t.Errorf("contract key %q carries no arity suffix", key)
				continue
			}
			gotArity, convErr := strconv.Atoi(key[h+1:])
			if convErr != nil {
				t.Errorf("contract key %q has a non-numeric arity", key)
				continue
			}
			if gotArity != exp.arity {
				t.Errorf("%s: declared arity %d, but the crate declares %d",
					emitted, gotArity, exp.arity)
			}
			if c.Role != exp.role {
				t.Errorf("%s: role=%q, want %q", emitted, c.Role, exp.role)
			}
			if c.Return.Type != exp.ret {
				t.Errorf("%s: return.type=%q, want %q", emitted, c.Return.Type, exp.ret)
			}
			if c.CanonicalReturnType != exp.canon {
				t.Errorf("%s: canonical_return_type=%q, want %q",
					emitted, c.CanonicalReturnType, exp.canon)
			}
		}
	}
	for method := range all {
		if !kbHasAwsKmsMethod(kb, method) {
			t.Errorf("this test names %q but the KB does not declare it", method)
		}
	}
}

// kbHasAwsKmsMethod reports whether the KB declares an aws-sdk-kms contract
// whose emitted spelling is method.
func kbHasAwsKmsMethod(kb *contracts.KnowledgeBase, method string) bool {
	for key, cs := range kb.Contracts {
		for i := range cs {
			if cs[i].SourceLibrary != "aws-sdk-kms" {
				continue
			}
			emitted := key
			if j := strings.LastIndex(key, "::"); j >= 0 {
				emitted = key[:j] + "." + key[j+2:]
			}
			if h := strings.LastIndex(emitted, "#"); h >= 0 {
				emitted = emitted[:h]
			}
			if emitted == method {
				return true
			}
		}
	}
	return false
}

// NOTHING IN A REALISTIC CONSUMER MAY FALL BACK TO THE SCANNED CRATE. This is
// the assertion that would have caught the state this KB started in, where 15
// of 21 call sites came out owned by the consumer's own package.
func TestAwsSdkKmsNoCallSiteFallsBackToTheScannedCrate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := `use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{EncryptionAlgorithmSpec, MacAlgorithmSpec, SigningAlgorithmSpec};
use aws_sdk_kms::Client;

async fn ops(client: &Client, key_id: &str, pt: Vec<u8>) {
    let _ = client.encrypt().key_id(key_id).plaintext(Blob::new(pt)).encryption_algorithm(EncryptionAlgorithmSpec::RsaesOaepSha256).send().await;
    let _ = client.sign().key_id(key_id).signing_algorithm(SigningAlgorithmSpec::EcdsaSha384).send().await;
    let _ = client.generate_mac().key_id(key_id).mac_algorithm(MacAlgorithmSpec::HmacSha256).send().await;
    let _ = client.generate_random().number_of_bytes(32).send().await;
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	b := NewBuilderForEcosystem("rust", NewRustParser())
	graph, err := b.BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	kmsMethods := map[string]bool{
		"encrypt": true, "decrypt": true, "sign": true, "verify": true,
		"generate_mac": true, "verify_mac": true, "generate_data_key": true,
		"generate_random": true, "key_id": true, "plaintext": true,
		"ciphertext_blob": true, "encryption_algorithm": true,
		"signing_algorithm": true, "mac_algorithm": true,
		"number_of_bytes": true, "grant_tokens": true,
	}
	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			call := &fn.Calls[i]
			callee := call.Callee
			method, _ := splitMethodArity(&callee)
			if !strings.HasPrefix(method, "app.") {
				continue
			}
			if kmsMethods[strings.TrimPrefix(method, "app.")] {
				t.Errorf("call site %q fell back to the scanned crate: an aws-sdk-kms "+
					"method attributed to the consumer's own package is a WRONG "+
					"identity, not a missing one, and it matches no contract. Check "+
					"the return type declared for the link before it in the chain.",
					method)
			}
		}
	}
}
