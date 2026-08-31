// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// A wrapping constructor written with a bare, unqualified name (`Vec::from`,
// `Mutex::new`) duplicated its own head into the wrapper spelling passed
// downstream (`Vec::Vec<..>`), which a value wrapper -- Option, Result, Vec,
// the locks, none of which Deref to their contents -- never unwraps out of. A
// Deref wrapper (Arc, Box, Rc) masked the same bug by unwrapping straight to
// the wrapped value regardless of the spelling's shape.
func TestRustParser_BareWrappingConstructorKeepsTheStandardLibraryPackage(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		src  string
		call string
		want string
	}{
		{
			name: "bare Vec::from",
			src: `struct P;
fn go(p: P) {
    let v = Vec::from(p);
    v.clone();
}
`,
			call: "v.clone",
			want: "std.Vec.clone",
		},
		{
			name: "bare std::sync::Mutex::new",
			src: `struct Cipher;
fn go(c: Cipher) {
    let m = std::sync::Mutex::new(c);
    m.lock();
}
`,
			call: "m.lock",
			want: "std::sync.Mutex.lock",
		},
		{
			name: "bare std::cell::RefCell::new",
			src: `struct Cipher;
fn go(c: Cipher) {
    let r = std::cell::RefCell::new(c);
    r.borrow();
}
`,
			call: "r.borrow",
			want: "std::cell.RefCell.borrow",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRustCalleeFQNs(t, tt.src)
			if fqn := got[tt.call]; fqn != tt.want {
				t.Errorf("%s -> %q, want %q", tt.call, fqn, tt.want)
			}
		})
	}
}

// A wrapper's own qualified path still distinguishes it from an
// identically-named one elsewhere: `tokio::sync::Mutex` and
// `std::sync::Mutex` differ in whether their lock can be poisoned, and the
// fix for the bare-name duplication bug above must not collapse that.
func TestRustParser_QualifiedWrappingConstructorKeepsItsOwnPath(t *testing.T) {
	t.Parallel()

	src := `struct Cipher;
fn go(c: Cipher) {
    let m = tokio::sync::Mutex::new(c);
    m.lock();
}
`
	got := parseRustCalleeFQNs(t, src)
	if fqn := got["m.lock"]; fqn != "tokio::sync.Mutex.lock" {
		t.Errorf("m.lock -> %q, want %q", fqn, "tokio::sync.Mutex.lock")
	}
}

// A Deref wrapper's own bare constructor still sees through to the wrapped
// value, unaffected by the bare-name fix above.
func TestRustParser_BareBoxConstructorStillSeesThroughToTheValue(t *testing.T) {
	t.Parallel()

	src := `struct Cipher;
impl Cipher { fn encrypt_block(&self) {} }
fn go(c: Cipher) {
    let b = Box::new(c);
    b.encrypt_block();
}
`
	got := parseRustCalleeFQNs(t, src)
	if fqn := got["b.encrypt_block"]; fqn != "app.Cipher.encrypt_block" {
		t.Errorf("b.encrypt_block -> %q, want %q", fqn, "app.Cipher.encrypt_block")
	}
}
