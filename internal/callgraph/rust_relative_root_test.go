// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// A `crate`, `self` or `super` keyword must never reach a callee key's package
// field: it names a path root, not a module, and matches nothing.
//
// Two routes still put one there. `use PATH as NAME;` recorded the path it
// renames RAW, so the keyword survived into every call written through the
// alias; and a use tree nests one relative root under another, so
// `use super::{super::target2::hit2, ..}` concatenated an absolute prefix with a
// second `super` and produced `supers::l1::l2::super::target2.hit2`.
//
// From /tmp/review3-tls/repro/supers, and live on real code: 73 edges across 51
// published crates, 63 of them sequoia-openpgp 2.4.1's
// `crate::policy.(StandardPolicy).*`, 6 of them aes 0.9.2's own
// `crate::backends::soft::hazmat.*` round functions, and 2 sodiumoxide 0.2.7's
// `super::super::super::box_::curve25519xsalsa20poly1305.gen_keypair`.
//
// Each case names the wrong key it prevents.
func TestRustParser_RelativeRootNeverReachesAKey(t *testing.T) {
	t.Parallel()

	// One crate, four levels deep, exercising every spelling at once — which is
	// also how the reproduction is written, because the spellings interact
	// through the shared prefix of a use tree.
	files := map[string]string{
		"Cargo.toml": "[package]\nname = \"supers\"\nversion = \"0.1.0\"\n",
		"src/lib.rs": `pub mod target { pub fn hit() -> u32 { 1 } }
pub mod l1;
`,
		"src/l1/mod.rs": `pub mod target2 { pub fn hit2() -> u32 { 2 } }
pub mod l2;
`,
		"src/l1/l2/mod.rs": `pub mod l3;
pub mod sibling { pub fn hit3() -> u32 { 3 } }
`,
		"src/l1/l2/l3/mod.rs": `// a three-level super with a rename (the sodiumoxide shape)
use super::super::super::target as tgt;
pub fn three() -> u32 { tgt::hit() }

// a nested relative root inside a use tree (the ring shape)
pub fn four() -> u32 {
    use super::{super::target2::hit2, sibling::hit3};
    hit2() + hit3()
}

// a two-level super with a rename
use super::super::target2 as t2;
pub fn six() -> u32 { t2::hit2() }

// crate-relative with a rename
use crate::target as ct;
pub fn seven() -> u32 { ct::hit() }

// self-relative with a rename
pub mod inner { pub fn hitx() -> u32 { 9 } }
use self::inner as si;
pub fn eight() -> u32 { si::hitx() }
`,
	}

	got := countRustKeys(parseRustCrateAllKeys(t, files, "supers"))

	for _, tc := range []struct {
		name   string
		want   string
		absent string
	}{
		{
			name:   "a three-level super with a rename resolves to the crate root's module",
			want:   "supers::target.hit",
			absent: "super::super::super::target.hit",
		},
		{
			name:   "a relative root nested inside a use tree pops the prefix it is under",
			want:   "supers::l1::target2.hit2",
			absent: "supers::l1::l2::super::target2.hit2",
		},
		{
			name:   "a two-level super with a rename resolves two modules up",
			want:   "supers::l1::target2.hit2",
			absent: "super::super::target2.hit2",
		},
		{
			name:   "a crate-relative rename resolves to the crate root",
			want:   "supers::target.hit",
			absent: "crate::target.hit",
		},
		{
			name:   "a self-relative rename resolves to the declaring module's child",
			want:   "supers::l1::l2::l3::inner.hitx",
			absent: "self::inner.hitx",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got[tc.want] == 0 {
				t.Errorf("key %q was not emitted", tc.want)
			}
			if got[tc.absent] != 0 {
				t.Errorf("key %q emitted %d times; its package names a path root, not a module", tc.absent, got[tc.absent])
			}
		})
	}

	// No key anywhere may carry a relative root in its package, whichever
	// spelling produced it.
	for key := range got {
		for _, root := range []string{"crate::", "self::", "super::", "::super::", "::self::", "::crate::"} {
			if len(key) >= len(root) && key[:len(root)] == root {
				t.Errorf("key %q begins with the path root %q", key, root)
			}
		}
	}
}

// `super` must not pop past the crate root. A path that tried would record an
// empty package, which matches nothing either — the failure this replaced when
// it was fixed for the leading-root case (75 edges in openssl 0.10.81).
func TestRustParser_SuperDoesNotPopPastTheCrateRoot(t *testing.T) {
	t.Parallel()

	got := countRustKeys(parseRustCrateAllKeys(t, map[string]string{
		"Cargo.toml": "[package]\nname = \"shallow\"\nversion = \"0.1.0\"\n",
		"src/lib.rs": `pub mod target { pub fn hit() -> u32 { 1 } }
pub mod only;
`,
		"src/only.rs": `use super::super::super::target as far;
pub fn go() -> u32 { far::hit() }
`,
	}, "shallow"))

	for key := range got {
		if key == "" || key[0] == '.' {
			t.Errorf("key %q has an empty package", key)
		}
	}
	if got["shallow::target.hit"] == 0 {
		t.Errorf("over-popping super did not clamp at the crate root; got keys %v", keysOfInt(got))
	}
}
