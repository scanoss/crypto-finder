// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// A declaration the crate index records is qualified with the imports of the
// file that declared it, and a `crate::`/`self::`/`super::` root is only
// meaningful together with WHERE that file sits. The index was qualifying with
// no position at all, so the root resolved to nothing and the crate prefix was
// dropped: one declaration answered two ways depending on which file asked.
//
// From /tmp/review3-tls/repro/usetree case 6. holder.rs writes
// `use crate::ssl::{Ctx};` and declares `fn ctx(&mut self) -> &mut Ctx`; a
// `Ctx::new()` inside holder.rs resolved to `usetree::ssl.(Ctx).new`, while
// `h.ctx().go()` in caller.rs gave `ssl.(Ctx).go` — and `ssl` names no crate.
//
// Each case names the wrong key it prevents.
func TestRustParser_CrateIndexKeepsTheCrateRootOfARelativeImport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		files  map[string]string
		raw    string
		want   string
		absent string
	}{
		{
			name: "a crate::-rooted import keeps its crate in a cross-file return type",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"usetree\"\nversion = \"0.1.0\"\n",
				"src/lib.rs": `pub mod ssl { pub struct Ctx; impl Ctx { pub fn new() -> Self { Ctx } pub fn go(&self) {} } }
pub mod caller;
pub mod holder;
`,
				"src/holder.rs": `use crate::ssl::{
    Ctx,
};
pub struct Holder { c: Ctx }
impl Holder {
    pub fn new() -> Self { Holder { c: Ctx::new() } }
    pub fn ctx(&mut self) -> &mut Ctx { &mut self.c }
}
`,
				"src/caller.rs": `use super::holder::Holder;
pub fn six() { let mut h = Holder::new(); h.ctx().go(); }
`,
			},
			raw:    "h.ctx().go",
			want:   "usetree::ssl.Ctx.go",
			absent: "ssl.Ctx.go",
		},
		{
			name: "a super::-rooted import keeps its crate in a cross-file return type",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"supertree\"\nversion = \"0.1.0\"\n",
				"src/lib.rs": `pub mod ssl { pub struct Ctx; impl Ctx { pub fn new() -> Self { Ctx } pub fn go(&self) {} } }
pub mod holder;
pub mod caller;
`,
				"src/holder.rs": `use super::ssl::Ctx;
pub struct Holder { c: Ctx }
impl Holder {
    pub fn new() -> Self { Holder { c: Ctx::new() } }
    pub fn ctx(&mut self) -> &mut Ctx { &mut self.c }
}
`,
				"src/caller.rs": `use crate::holder::Holder;
pub fn six() { let mut h = Holder::new(); h.ctx().go(); }
`,
			},
			raw:    "h.ctx().go",
			want:   "supertree::ssl.Ctx.go",
			absent: "ssl.Ctx.go",
		},
		{
			// The same route through a struct FIELD rather than a return type:
			// both are qualified by the same pass, so both lost the root.
			name: "a crate::-rooted import keeps its crate in a cross-file field type",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"fieldtree\"\nversion = \"0.1.0\"\n",
				"src/lib.rs": `pub mod ssl { pub struct Ctx; impl Ctx { pub fn go(&self) {} } }
pub mod holder;
pub mod caller;
`,
				"src/holder.rs": `use crate::ssl::Ctx;
pub struct Holder { pub c: Ctx }
`,
				"src/caller.rs": `use crate::holder::Holder;
pub fn seven(h: &Holder) { h.c.go(); }
`,
			},
			raw:    "h.c.go",
			want:   "fieldtree::ssl.Ctx.go",
			absent: "ssl.Ctx.go",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseRustCrateFiles(t, tc.files, "")
			if got[tc.raw] != tc.want {
				t.Errorf("%s resolved to %q, want %q", tc.raw, got[tc.raw], tc.want)
			}
			if got[tc.raw] == tc.absent {
				t.Errorf("%s resolved to %q — the crate root of a relative import was dropped, and that package names no crate", tc.raw, tc.absent)
			}
		})
	}
}
