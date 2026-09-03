package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

// The Rust parser was the only one of the seven that populated neither ChainID
// nor AssignedVar, and set ReceiverVar only on the two shapes whose receiver had
// NOT resolved. AGENTS.md names all three as what a parser must emit for full
// reachability, and every downstream reader treats an empty value as "no chain
// here" rather than "unknown": resolveChainCalleesInFunction skips a call whose
// ChainID is empty, chainRootIndexAmong and longestChainIndexAmong return -1,
// and deriveObjectLifecycleCalls walks up from the terminal's ReceiverVar. The
// passes did not degrade for Rust, they were off.
func TestRustParser_ChainIdentityIsPopulated(t *testing.T) {
	t.Parallel()

	src := `use schannel::schannel_cred::{SchannelCred, Direction, Protocol};
use aes_gcm::Aes256Gcm;

fn fluent() {
    let cred = SchannelCred::builder()
        .enabled_protocols(&[Protocol::Tls12])
        .acquire(Direction::Outbound)
        .unwrap();
}

fn through_try(socket: std::net::TcpStream) -> std::io::Result<()> {
    let s = schannel::tls_stream::Builder::new().domain("example.com")?.connect(socket)?;
    Ok(())
}

fn typed_var(key: &[u8], nonce: &[u8], pt: &[u8]) {
    let cipher = Aes256Gcm::new(key.into());
    let _ct = cipher.encrypt(nonce.into(), pt);
}

fn standalone(key: &[u8]) {
    let _c = Aes256Gcm::new(key.into());
}
`
	calls := rustCallsByFunction(t, src)

	t.Run("every link of a fluent chain shares one id", func(t *testing.T) {
		ids := map[string]int{}
		var root *FunctionCall
		for i, c := range calls["fluent"] {
			if c.ChainID == "" {
				t.Errorf("link %d (%q) carries no ChainID", i, c.Raw)
				continue
			}
			ids[c.ChainID]++
			if c.AssignedVar != "" {
				root = &calls["fluent"][i]
			}
		}
		if len(ids) != 1 {
			t.Errorf("the chain was split into %d ids, want 1: %v", len(ids), ids)
		}
		if root == nil {
			t.Fatal("no link carried AssignedVar; the chain root binds `cred`")
		}
		if root.AssignedVar != "cred" {
			t.Errorf("root AssignedVar = %q, want \"cred\"", root.AssignedVar)
		}
		// Only the root binds. A middle link that also claimed the variable
		// would make deriveObjectLifecycleCalls treat each link as its own
		// object.
		bound := 0
		for _, c := range calls["fluent"] {
			if c.AssignedVar != "" {
				bound++
			}
		}
		if bound != 1 {
			t.Errorf("%d links carry AssignedVar, want exactly 1 (the root)", bound)
		}
	})

	t.Run("a `?` between links does not split the chain", func(t *testing.T) {
		ids := map[string]bool{}
		for _, c := range calls["through_try"] {
			if c.ChainID != "" {
				ids[c.ChainID] = true
			}
		}
		if len(ids) != 1 {
			t.Errorf("`a().b()?.c()?` produced %d chains, want 1: %v", len(ids), ids)
		}
	})

	t.Run("a typed-variable object is linked to the call that produced it", func(t *testing.T) {
		var ctor, use *FunctionCall
		for i, c := range calls["typed_var"] {
			switch c.Callee.Name {
			case "new":
				ctor = &calls["typed_var"][i]
			case "encrypt":
				use = &calls["typed_var"][i]
			}
		}
		if ctor == nil || use == nil {
			t.Fatalf("fixture did not produce both calls: ctor=%v use=%v", ctor, use)
		}
		if ctor.AssignedVar != "cipher" {
			t.Errorf("Aes256Gcm::new AssignedVar = %q, want \"cipher\"", ctor.AssignedVar)
		}
		// Without this the terminal has no object identity at all and
		// selectAncestors never reaches the constructor, so the finding is
		// reported with no supporting calls.
		if use.ReceiverVar != "cipher" {
			t.Errorf("cipher.encrypt ReceiverVar = %q, want \"cipher\"", use.ReceiverVar)
		}
	})

	t.Run("a lone call is not a chain", func(t *testing.T) {
		for _, c := range calls["standalone"] {
			if c.Callee.Name == "new" && c.ChainID != "" {
				t.Errorf("`Aes256Gcm::new(..)` alone carries ChainID %q; marking it "+
					"makes terminal_selection treat a single call as a chain", c.ChainID)
			}
		}
	})
}

// TestRustFluentChainRewriteKeepsRustIdentitySpelling pins the second half of
// the same defect. resolveChainLinkCallees builds the rewritten callee with
// splitQualifiedTypeName, which splits on the last "." — right for Java, wrong
// for Rust, whose KB spells a type `schannel::tls_stream::Builder`. Splitting
// that on "." leaves the package empty and the whole path in the type field, and
// it appends Java's "#<arity>" suffix, which Rust callee names never carry:
// `.schannel::tls_stream::Builder.connect#-1` instead of
// `schannel::tls_stream.Builder.connect`. The pass was unreachable for Rust
// until ChainID was populated, so nothing had ever exercised it.
func TestRustFluentChainRewriteKeepsRustIdentitySpelling(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := `use schannel::crypt_prov::{AcquireOptions, ProviderType};
use schannel::tls_stream;

fn keys(der: &[u8]) {
    let mut prov = AcquireOptions::new()
        .container("scanoss")
        .acquire(ProviderType::rsa_full())
        .unwrap();
    let _k = prov.import().import(der).unwrap();
}

fn client(socket: std::net::TcpStream, cred: schannel::schannel_cred::SchannelCred) {
    let _s = tls_stream::Builder::new().domain("example.com").connect(cred, socket).unwrap();
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	// The full builder, not the parser: the rewrite is a post-build pass.
	b := NewBuilderForEcosystem("rust", NewRustParser())
	graph, err := b.BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	want := map[string]bool{
		"schannel::crypt_prov.AcquireOptions.container": false,
		"schannel::crypt_prov.AcquireOptions.acquire":   false,
		"schannel::crypt_prov.ImportOptions.import":     false,
		"schannel::tls_stream.Builder.domain":           false,
		"schannel::tls_stream.Builder.connect":          false,
	}
	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			id := fn.Calls[i].Callee
			key := id.Package + "." + id.Type + "." + id.Name
			if _, ok := want[key]; ok {
				want[key] = true
			}
			if id.Package == "" && id.Type != "" && len(id.Type) > 2 &&
				id.Type[0] != '&' && containsRustPathSep(id.Type) {
				t.Errorf("callee %q has an empty package and a \"::\" path in the type "+
					"field — the Java-shaped split leaked into a Rust identity", key)
			}
		}
	}
	for key, seen := range want {
		if !seen {
			t.Errorf("chain link %q was not produced; the contract rewrite regressed", key)
		}
	}
}

func containsRustPathSep(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == ':' && s[i+1] == ':' {
			return true
		}
	}
	return false
}

// rustCallsByFunction parses one Rust source and returns its calls keyed by the
// declaring function's name.
func rustCallsByFunction(t *testing.T, src string) map[string][]FunctionCall {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "probe.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "probe")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	out := map[string][]FunctionCall{}
	for _, a := range analyses {
		for i := range a.Functions {
			fn := &a.Functions[i]
			out[fn.ID.Name] = append(out[fn.ID.Name], fn.Calls...)
		}
	}
	return out
}

// TestRustAssociatedFunctionTypeComesFromTheContract pins the third defect.
// rustScopedCallType typed `Type::assoc()` from the PATH it was called on,
// which is right for a constructor and wrong for every builder accessor:
// `SchannelCred::builder()` came out as `SchannelCred`, so the next hop looked
// for methods on a type that does not have them.
//
// The shape below is deliberately NOT a fluent chain. Chain grouping cannot
// reach it — each call is its own statement — so this is the case that isolates
// the contract lookup from everything else on this branch.
//
// schannel.yaml carried four entries declared on `SchannelCred` for methods
// that type does not own, solely so the wrong identity would join. They are
// deleted; if this test fails with `SchannelCred.*` identities, the lookup
// regressed and those mirrors are the wrong way to bring it back.
func TestRustAssociatedFunctionTypeComesFromTheContract(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := `use schannel::schannel_cred::{Algorithm, Direction, Protocol, SchannelCred};

fn bound_builder() {
    let mut b = SchannelCred::builder();
    b.enabled_protocols(&[Protocol::Tls12]);
    b.supported_algorithms(&[Algorithm::Aes256]);
    let _c = b.acquire(Direction::Outbound);
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

	want := map[string]bool{
		// `builder` IS an associated function of SchannelCred, so it keeps that
		// receiver. Everything after it is a method on the Builder it returns.
		"schannel::schannel_cred.SchannelCred.builder":         false,
		"schannel::schannel_cred.Builder.enabled_protocols":    false,
		"schannel::schannel_cred.Builder.supported_algorithms": false,
		"schannel::schannel_cred.Builder.acquire":              false,
	}
	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			id := fn.Calls[i].Callee
			key := id.Package + "." + id.Type + "." + id.Name
			if _, ok := want[key]; ok {
				want[key] = true
			}
			if id.Type == "SchannelCred" && id.Name != "builder" {
				t.Errorf("%q kept the path's type; the associated function's "+
					"contract return was not consulted", key)
			}
		}
	}
	for key, seen := range want {
		if !seen {
			t.Errorf("%q was not produced", key)
		}
	}
}

// TestRustBareWrapperReturnIsNotTakenAsAReceiver pins the guard that makes the
// contract lookup above safe, and it is the reason the lookup is not
// unconditional.
//
// A KB may honestly declare `blowfish::Blowfish.new_from_slice -> core::result::Result`:
// that IS the signature, and the contract has no inner type to give. But a bare
// `Result` is not a receiver anything resolves against, and taking it discards
// the `Blowfish` the path already supplied — `.unwrap()` cannot recover it
// either, because rustUnwrappedPatternType needs a generic argument to peel.
//
// Without the guard this exact fixture regressed to `core::result.Result.encrypt_block`,
// and so did the turbofish, re-export and glob-import suites. A wrapper that
// DOES carry its argument stays usable and is not affected.
func TestRustBareWrapperReturnIsNotTakenAsAReceiver(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := `use blowfish::Blowfish;
use blowfish::cipher::KeyInit;

fn roundtrip(key: &[u8], block: &mut [u8]) {
    let cipher = Blowfish::new_from_slice(key).unwrap();
    cipher.encrypt_block(block.into());
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

	found := false
	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			id := fn.Calls[i].Callee
			key := id.Package + "." + id.Type + "." + id.Name
			if key == "blowfish.Blowfish.encrypt_block" {
				found = true
			}
			if id.Type == "Result" && id.Name == "encrypt_block" {
				t.Errorf("the block cipher was typed as %q: a bare wrapper return "+
					"was taken as the receiver and the path's type was lost", key)
			}
		}
	}
	if !found {
		t.Error("blowfish.Blowfish.encrypt_block was not produced; the receiver " +
			"lost the type the path supplied")
	}
}
