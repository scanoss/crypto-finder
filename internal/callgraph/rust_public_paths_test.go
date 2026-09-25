// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"reflect"
	"testing"
)

// A crate declares a type in a private module and re-exports it: rsa declares
// SigningKey in src/pkcs1v15/signing_key.rs and consumers import
// rsa::pkcs1v15::SigningKey. Contracts name that public path, so the graph has
// to know it for the declaration keyed by the declaring module.
func TestRustBuilder_RecordsPublicPathsOfReExportedTypes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for name, content := range map[string]string{
		"Cargo.toml": "[package]\nname = \"rsa\"\nversion = \"0.9.8\"\n",
		"src/lib.rs": `pub mod pkcs1v15;
pub mod pss;
mod key;
mod internal;
pub mod traits;
pub use crate::key::RsaPrivateKey;
pub use crate::pkcs1v15::SigningKey as Pkcs1v15SigningKey;
pub(crate) use crate::internal::Hidden;
use crate::internal::AlsoHidden;
`,
		"src/key.rs":      "pub struct RsaPrivateKey;\nimpl RsaPrivateKey { pub fn new() -> Self { RsaPrivateKey } }\n",
		"src/internal.rs": "pub struct Hidden;\npub struct AlsoHidden;\n",
		"src/pkcs1v15.rs": `mod signing_key;
mod verifying_key;
pub use self::{signing_key::SigningKey, verifying_key::VerifyingKey};
`,
		"src/pkcs1v15/signing_key.rs":   "pub struct SigningKey;\nimpl SigningKey { pub fn new() -> Self { SigningKey } }\n",
		"src/pkcs1v15/verifying_key.rs": "pub struct VerifyingKey;\n",
		"src/pss.rs":                    "mod signing_key;\npub use signing_key::SigningKey;\n",
		"src/pss/signing_key.rs":        "pub struct SigningKey;\nimpl SigningKey { pub fn new() -> Self { SigningKey } }\n",
		"src/traits.rs":                 "mod keys;\npub use keys::PublicKeyParts;\n",
		"src/traits/keys.rs":            "pub trait PublicKeyParts {}\n",
	} {
		writeRustFile(t, dir, name, content)
	}

	graph, err := NewBuilderForEcosystem(ecosystemRust, NewRustParser()).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "rsa"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	want := map[string][]string{
		"rsa::key::RsaPrivateKey":                    {"rsa::RsaPrivateKey"},
		"rsa::pkcs1v15::signing_key::SigningKey":     {"rsa::Pkcs1v15SigningKey", "rsa::pkcs1v15::SigningKey"},
		"rsa::pkcs1v15::verifying_key::VerifyingKey": {"rsa::pkcs1v15::VerifyingKey"},
		"rsa::pss::signing_key::SigningKey":          {"rsa::pss::SigningKey"},
		"rsa::traits::keys::PublicKeyParts":          {"rsa::traits::PublicKeyParts"},
	}
	if !reflect.DeepEqual(graph.PublicTypePaths, want) {
		t.Errorf("PublicTypePaths = %v\nwant %v", graph.PublicTypePaths, want)
	}

	// The declaring key must be the one the declaration carries, or the map
	// joins nothing.
	for _, fn := range graph.Functions {
		if fn.ID.Name != "new" {
			continue
		}
		if _, ok := graph.PublicTypePaths[fn.ID.Package+"::"+fn.ID.Type]; !ok {
			t.Errorf("declaration %s has no public path under %q", fn.ID.String(), fn.ID.Package+"::"+fn.ID.Type)
		}
	}
}
