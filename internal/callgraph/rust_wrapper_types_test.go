// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"
	"testing"
)

// The Reference builds a method call's candidate receiver types by dereferencing
// the receiver repeatedly. For a static parser the practical equivalent is to
// see through the ownership wrappers, which is what real crypto code is written
// with: `Arc<Mutex<Cipher>>` in async servers, `Box<dyn Digest>` in dispatch
// tables, `Option<Cipher>` in builders. Before this the wrapper itself landed in
// the key's type field — `std::sync.(Arc).encrypt_block` — which matches no
// contract and reads like a resolved identity.
func TestRustParser_WrappersDoNotHideTheReceiverIdentity(t *testing.T) {
	t.Parallel()

	const header = `use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};
use std::sync::{Arc, Mutex};
use std::rc::Rc;
use std::cell::RefCell;

fn mk() -> Aes128 { Aes128::new(&Default::default()) }
`

	for _, tc := range []struct {
		name string
		body string
	}{
		{"Box", `let c = Box::new(mk()); c.encrypt_block(b);`},
		{"Arc", `let c = Arc::new(mk()); c.encrypt_block(b);`},
		{"Rc", `let c = Rc::new(mk()); c.encrypt_block(b);`},
		{"Arc of Mutex, locked and unwrapped", `let c = Arc::new(Mutex::new(mk())); c.lock().unwrap().encrypt_block(b);`},
		{"Rc of RefCell, borrowed", `let c = Rc::new(RefCell::new(mk())); c.borrow().encrypt_block(b);`},
		{"Option unwrapped", `let c = Some(mk()); c.unwrap().encrypt_block(b);`},
		{"annotated Box", `let c: Box<Aes128> = Box::new(mk()); c.encrypt_block(b);`},
		{"annotated Arc of Mutex", `let c: Arc<Mutex<Aes128>> = Arc::new(Mutex::new(mk())); c.lock().unwrap().encrypt_block(b);`},
		{"explicit deref of a Box", `let c = Box::new(mk()); (*c).encrypt_block(b);`},
		{"cloned", `let c = mk(); c.clone().encrypt_block(b);`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseRustCalleeFQNs(t, header+"\nfn go(b: &mut [u8]) {\n    "+tc.body+"\n}\n")
			asserted := 0
			for raw, key := range got {
				if !strings.HasSuffix(raw, "encrypt_block") {
					continue
				}
				asserted++
				if key != "aes.Aes128.encrypt_block" {
					t.Errorf("%s resolved to %q, want %q", raw, key, "aes.Aes128.encrypt_block")
				}
			}
			if asserted == 0 {
				t.Errorf("no encrypt_block call parsed; got %v", got)
			}
		})
	}
}

// A call ON a wrapper type itself is not a wrapper to see through: `Vec::new()`
// is a call on Vec. Unwrapping must not be so eager that it loses that.
func TestRustParser_CallOnTheWrapperItselfKeepsTheWrapper(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `fn go() {
    let v: Vec<u8> = Vec::new();
    let _ = v.len();
}
`)
	// Vec is a prelude type: in scope with no import, and owned by the standard
	// library rather than by the crate being analyzed.
	if got["Vec::new"] != "std.Vec.new" {
		t.Errorf("Vec::new resolved to %q, want %q", got["Vec::new"], "std.Vec.new")
	}
}

// A wrapper's OWN methods belong to the wrapper, not to what it holds. The
// constructor used to collapse the chain — `Arc::new(Mutex::new(c))` typed the
// variable as the cipher — so `lock`, `unwrap` and `borrow` were reported as
// methods of the cipher's type. And only the standard library's locks can be
// poisoned: tokio's are awaited and hand back the guard directly, so modeling
// them alike left an awaited value typed as a Result.
func TestRustParser_WrapperMethodsBelongToTheWrapper(t *testing.T) {
	t.Parallel()

	const src = `use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};
use std::rc::Rc;
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

fn mk() -> Aes128 { Aes128::new(&Default::default()) }

pub fn chained_borrow(b: &mut [u8]) {
    let shared = Rc::new(RefCell::new(mk()));
    shared.borrow().encrypt_block(b.into());
}

pub fn std_lock(b: &mut [u8]) {
    let shared = Arc::new(Mutex::new(mk()));
    let g = shared.lock().unwrap();
    g.encrypt_block(b.into());
}

pub async fn tokio_lock(b: &mut [u8]) {
    let shared = Arc::new(tokio::sync::Mutex::new(mk()));
    let g = shared.lock().await;
    g.encrypt_block(b.into());
}

pub fn sized_vec() {
    let v: Vec<u8> = Vec::with_capacity(64);
    let _ = v.len();
}
`

	got := parseRustCalleeFQNs(t, src)
	// `with_capacity`'s argument is a length, not an element: the vector must
	// not be typed by its capacity.
	if got["v.len"] != "std.Vec.len" {
		t.Errorf("v.len resolved to %q, want %q", got["v.len"], "std.Vec.len")
	}

	// The two `shared.lock()` calls are written identically, so each identity is
	// counted rather than looked up by its call text.
	counts := countRustKeys(parseRustCalleeKeys(t, src))
	for _, want := range []struct {
		key   string
		count int
	}{
		{"std::cell.RefCell.borrow", 1},
		{"std::sync.Mutex.lock", 1},
		{"tokio::sync.Mutex.lock", 1},
		{"std.Result.unwrap", 1},
		// Every cipher call, through all three wrapper shapes.
		{"aes.Aes128.encrypt_block", 3},
	} {
		if counts[want.key] != want.count {
			t.Errorf("want %d x %q, got %d; keys = %v", want.count, want.key, counts[want.key], counts)
		}
	}
}
