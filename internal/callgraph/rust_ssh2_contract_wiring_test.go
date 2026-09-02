// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The ssh2 KB is keyed on what the Rust parser emits, so a parser identity
// change must fail here rather than leaving the contracts silently unmatched.
func TestSSH2ContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	dir := t.TempDir()
	src := `use ssh2::{HashType, Session};

fn connect_and_authenticate(key: &std::path::Path) {
    let mut sess = Session::new().unwrap();
    sess.handshake().unwrap();
    sess.userauth_pubkey_file("user", None, key, None).unwrap();
    sess.userauth_agent("user").unwrap();
    sess.userauth_password("user", "secret").unwrap();
}

fn inspect_host_key(sess: &Session) {
    let _key = sess.host_key();
    let _fp = sess.host_key_hash(HashType::Sha256);
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	// Call-site keys join segments with "."; the KB keeps Rust's "::" module
	// separator and ContractsFor bridges the two.
	want := map[string]struct {
		role  string
		arity int
	}{
		"ssh2.Session.new":                  {"factory", 0},
		"ssh2.Session.handshake":            {"operation", 0},
		"ssh2.Session.userauth_pubkey_file": {"operation", 4},
		"ssh2.Session.userauth_agent":       {"operation", 1},
		"ssh2.Session.userauth_password":    {"operation", 2},
		"ssh2.Session.host_key":             {"operation", 0},
		"ssh2.Session.host_key_hash":        {"operation", 1},
	}
	seen := map[string]bool{}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method, _ := splitMethodArity(&callee)
				expect, ok := want[method]
				if !ok {
					continue
				}
				arity := len(call.Arguments)
				if arity != expect.arity {
					t.Fatalf("parsed %q at arity %d, want %d", method, arity, expect.arity)
				}
				got := kb.ContractsFor(method, arity)
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one contract", method, arity, len(got))
				}
				if got[0].SourceLibrary != "ssh2" {
					t.Fatalf("contract for %q came from %q, want ssh2", method, got[0].SourceLibrary)
				}
				if got[0].Role != expect.role {
					t.Fatalf("contract for %q role = %q, want %q", method, got[0].Role, expect.role)
				}
				seen[method] = true
			}
		}
	}

	for method := range want {
		if !seen[method] {
			t.Fatalf("parsed calls did not cover %q; seen = %v", method, seen)
		}
	}
}

// The channel surface must stay out of the KB. Typing it would route ordinary
// remote-command traffic through the crypto call graph, which is precisely the
// split this family exists to keep.
func TestSSH2ChannelSurfaceIsAbsentFromTheKB(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, absent := range []struct {
		method string
		arity  int
	}{
		{"ssh2.Session.channel_session", 0},
		{"ssh2.Channel.exec", 1},
		{"ssh2.Channel.shell", 0},
		{"ssh2.Session.sftp", 0},
		{"ssh2.Session.method_pref", 2},
		{"ssh2.Session.supported_algs", 1},
	} {
		if got := kb.ContractsFor(absent.method, absent.arity); len(got) != 0 {
			t.Errorf("%s/%d resolved to %d contracts; the channel and negotiation "+
				"surfaces must stay absent", absent.method, absent.arity, len(got))
		}
	}
}

// EVERY entry in the KB must be exercised, and its declared shape asserted.
//
// The first version of this test named only seven of the entries and asserted
// neither parameter_types nor return types. A review showed six entries could be
// deleted outright and every return type replaced with a bogus one while it
// still passed -- and that is what let the `handshake` arity defect through. The
// table below is therefore derived from the KB itself, so an entry cannot be
// added or removed without this test noticing.
func TestSSH2EveryContractEntryIsExercisedAndWellFormed(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	// method -> arity -> role, transcribed from the declarations in
	// src/session.rs, src/knownhosts.rs and src/agent.rs.
	want := []struct {
		method string
		arity  int
		role   string
		params int
		ret    string
	}{
		{"ssh2.Session.new", 0, "factory", 0, "core::result::Result"},
		{"ssh2.Session.known_hosts", 0, "factory", 0, "core::result::Result"},
		{"ssh2.Session.agent", 0, "factory", 0, "core::result::Result"},
		{"ssh2.Session.handshake", 0, "operation", 0, "core::result::Result"},
		{"ssh2.Session.handshake", 1, "operation", 1, "core::result::Result"},
		{"ssh2.Session.userauth_pubkey_file", 4, "operation", 4, "core::result::Result"},
		{"ssh2.Session.userauth_pubkey_memory", 4, "operation", 4, "core::result::Result"},
		{"ssh2.Session.userauth_hostbased_file", 6, "operation", 6, "core::result::Result"},
		{"ssh2.Session.userauth_agent", 1, "operation", 1, "core::result::Result"},
		{"ssh2.Session.userauth_password", 2, "operation", 2, "core::result::Result"},
		{"ssh2.Session.userauth_keyboard_interactive", 2, "operation", 2, "core::result::Result"},
		{"ssh2.Session.host_key", 0, "operation", 0, "core::option::Option"},
		{"ssh2.Session.host_key_hash", 1, "operation", 1, "core::option::Option"},
		{"ssh2.KnownHosts.check", 2, "operation", 2, "ssh2::CheckResult"},
		{"ssh2.KnownHosts.check_port", 3, "operation", 3, "ssh2::CheckResult"},
		{"ssh2.Agent.userauth", 2, "operation", 2, "core::result::Result"},
	}

	for _, w := range want {
		got := kb.ContractsFor(w.method, w.arity)
		if len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d) = %d, want exactly one", w.method, w.arity, len(got))
			continue
		}
		c := got[0]
		if c.SourceLibrary != "ssh2" {
			t.Errorf("%s/%d came from %q, want ssh2", w.method, w.arity, c.SourceLibrary)
		}
		if c.Role != w.role {
			t.Errorf("%s/%d role = %q, want %q", w.method, w.arity, c.Role, w.role)
		}
		// parameter_types was asserted nowhere before, which is what the PR
		// leaned on when it argued the entries were "read from the source and
		// correct".
		if len(c.ParameterTypes) != w.params {
			t.Errorf("%s/%d has %d parameter types, want %d", w.method, w.arity, len(c.ParameterTypes), w.params)
		}
		// The return type is asserted, not merely checked non-empty: replacing
		// every return with a bogus type passed the first version of this test.
		if c.Return.Type != w.ret {
			t.Errorf("%s/%d return = %q, want %q", w.method, w.arity, c.Return.Type, w.ret)
		}
	}
}

// `handshake` CHANGED SIGNATURE INSIDE THE DECLARED RANGE, and both spellings
// must resolve: 0.1.0 takes a raw socket and 0.2.0-0.3.3 take a &TcpStream
// (arity 1), while 0.4.0-0.9.5 take nothing (arity 0). The KB declares
// >=0.1.0, so recording only the modern arity left more than half the range
// unresolved for the one call this family is named after.
func TestSSH2HandshakeResolvesAtBothArities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	dir := t.TempDir()
	src := `use ssh2::Session;

fn modern(sess: &mut Session) {
    sess.handshake().unwrap();
}

fn legacy(sess: &mut Session, tcp: &std::net::TcpStream) {
    sess.handshake(tcp).unwrap();
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	seen := map[int]bool{}
	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method, _ := splitMethodArity(&callee)
				if method != "ssh2.Session.handshake" {
					continue
				}
				arity := len(call.Arguments)
				if got := kb.ContractsFor(method, arity); len(got) != 1 {
					t.Fatalf("handshake at arity %d resolved to %d contracts, want one", arity, len(got))
				}
				seen[arity] = true
			}
		}
	}
	for _, arity := range []int{0, 1} {
		if !seen[arity] {
			t.Fatalf("the pre-0.4.0/post-0.4.0 pair was not both parsed; seen = %v", seen)
		}
	}
}

// THE KnownHosts ENTRIES DO RESOLVE — from the two spellings that give the
// receiver a type. An earlier version of this file claimed flatly that they did
// not, which was wrong: only a receiver bound from a bare method call fails.
func TestSSH2KnownHostsResolvesWhenTheReceiverIsTyped(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, tc := range []struct {
		label string
		src   string
	}{
		{"explicit type annotation", `use ssh2::{KnownHosts, Session};
fn f(sess: &Session, h: &str, k: &[u8]) {
    let known: KnownHosts = sess.known_hosts().unwrap();
    let _ = known.check(h, k);
}`},
		{"typed parameter", `use ssh2::KnownHosts;
fn f(known: &KnownHosts, h: &str, k: &[u8]) {
    let _ = known.check(h, k);
}`},
	} {
		t.Run(tc.label, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(tc.src), 0o644); err != nil {
				t.Fatal(err)
			}
			analyses, err := NewRustParser().ParseDirectory(dir, "app")
			if err != nil {
				t.Fatal(err)
			}
			var resolved bool
			for _, analysis := range analyses {
				for _, fn := range analysis.Functions {
					for _, call := range fn.Calls {
						callee := call.Callee
						method, _ := splitMethodArity(&callee)
						if method != "ssh2.KnownHosts.check" {
							continue
						}
						if got := kb.ContractsFor(method, len(call.Arguments)); len(got) == 1 {
							resolved = true
						}
					}
				}
			}
			if !resolved {
				t.Errorf("%s did not resolve ssh2.KnownHosts.check", tc.label)
			}
		})
	}
}

// `Agent::userauth` has the same hole, and it matters more: the bare spelling is
// what the crate's own tests and async-ssh2-lite actually write.
func TestSSH2AgentUserauthResolvesOnlyWhenTheReceiverIsTyped(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, tc := range []struct {
		label string
		src   string
		typed bool
	}{
		{"typed parameter", `use ssh2::{Agent, PublicKey};
fn f(agent: &Agent, user: &str, id: &PublicKey) {
    agent.userauth(user, id).unwrap();
}`, true},
		{"bare method-bound receiver", `use ssh2::{PublicKey, Session};
fn f(sess: &Session, user: &str, id: &PublicKey) {
    let agent = sess.agent().unwrap();
    agent.userauth(user, id).unwrap();
}`, false},
	} {
		t.Run(tc.label, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(tc.src), 0o644); err != nil {
				t.Fatal(err)
			}
			analyses, err := NewRustParser().ParseDirectory(dir, "app")
			if err != nil {
				t.Fatal(err)
			}
			var resolved bool
			for _, analysis := range analyses {
				for _, fn := range analysis.Functions {
					for _, call := range fn.Calls {
						callee := call.Callee
						method, _ := splitMethodArity(&callee)
						if method != "ssh2.Agent.userauth" {
							continue
						}
						if got := kb.ContractsFor(method, len(call.Arguments)); len(got) == 1 {
							resolved = true
						}
					}
				}
			}
			if resolved != tc.typed {
				t.Errorf("%s: resolved = %v, want %v", tc.label, resolved, tc.typed)
			}
		})
	}
}

// The one spelling that does NOT resolve, recorded as current behavior. A
// receiver bound from a bare method call has no type, so the call is attributed
// to the consumer's own crate. If the parser learns to type these, this FAILS —
// which is the signal to delete it, not to relax it.
func TestSSH2KnownHostsDoesNotResolveFromAMethodBoundReceiver(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := `use ssh2::Session;

fn verify(sess: &Session, host: &str, key: &[u8]) {
    let known = sess.known_hosts().unwrap();
    let _r = known.check(host, key);
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method, _ := splitMethodArity(&callee)
				if method == "ssh2.KnownHosts.check" {
					t.Fatalf("the parser now types a method-bound receiver — delete this test")
				}
			}
		}
	}
}
