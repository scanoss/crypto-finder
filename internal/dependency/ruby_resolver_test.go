// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package dependency

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A real Gemfile.lock: the resolved gems come from the specs sections, with
// their exact versions, and nothing else does.
const gemfileLock = `GEM
  remote: https://rubygems.org/
  specs:
    addressable (2.8.6)
      public_suffix (>= 2.0.2, < 6.0)
    openssl (3.2.0)
    public_suffix (5.0.4)

PATH
  remote: vendor/mygem
  specs:
    mygem (0.1.0)
      openssl (~> 3.0)

PLATFORMS
  ruby

DEPENDENCIES
  addressable
  mygem!

BUNDLED WITH
   2.5.6
`

func writeLock(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Gemfile.lock"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Every gem of every specs section is resolved, with the version bundler
// pinned; a gem's own dependency lines carry a range, not a version, and must
// not be taken for gems of their own.
func TestRubyResolverReadsTheLock(t *testing.T) {
	got, err := NewRubyResolver().Resolve(context.Background(), writeLock(t, gemfileLock))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"addressable":   "2.8.6",
		"openssl":       "3.2.0",
		"public_suffix": "5.0.4",
		"mygem":         "0.1.0",
	}
	if len(got.Dependencies) != len(want) {
		t.Fatalf("resolved %d gems, want %d: %+v", len(got.Dependencies), len(want), got.Dependencies)
	}
	for _, d := range got.Dependencies {
		v, ok := want[d.Module]
		if !ok {
			t.Errorf("unexpected gem %q", d.Module)
			continue
		}
		if d.Version != v {
			t.Errorf("%s = %q, want %q", d.Module, d.Version, v)
		}
	}
}

// The DEPENDENCIES section names what the Gemfile asked for, with no version:
// a gem read from there would be mined at the wrong version, or at none.
func TestRubyResolverIgnoresTheDependenciesSection(t *testing.T) {
	got, err := NewRubyResolver().Resolve(context.Background(), writeLock(t, `GEM
  specs:
    openssl (3.2.0)

DEPENDENCIES
  openssl
  rails (~> 7.0)
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Dependencies) != 1 || got.Dependencies[0].Module != "openssl" {
		t.Errorf("resolved %+v, want only openssl 3.2.0", got.Dependencies)
	}
}

// A project with no Gemfile.lock is not a project this resolver can read: a
// Gemfile alone states ranges, and mining the wrong version of a gem is worse
// than mining none.
func TestRubyResolverNeedsTheLock(t *testing.T) {
	r := NewRubyResolver()
	if r.CanResolve(t.TempDir()) {
		t.Error("a directory with no Gemfile.lock resolved")
	}
	if !r.CanResolve(writeLock(t, gemfileLock)) {
		t.Error("a directory with a Gemfile.lock did not resolve")
	}
	if r.Ecosystem() != "ruby" {
		t.Errorf("ecosystem = %q", r.Ecosystem())
	}
}

// Bundler writes a native gem once per platform, with the platform appended
// to the version. Both lines name one gem at one version: kept apart, the
// purl asks the server for a version no release has.
func TestRubyResolverDropsThePlatformSuffix(t *testing.T) {
	got, err := NewRubyResolver().Resolve(context.Background(), writeLock(t, `GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.15.4-arm64-darwin)
    nokogiri (1.15.4-x86_64-linux)
    openssl (3.2.0)

PLATFORMS
  arm64-darwin
  x86_64-linux
`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"nokogiri": "1.15.4", "openssl": "3.2.0"}
	if len(got.Dependencies) != len(want) {
		t.Fatalf("resolved %d gems, want %d: %+v", len(got.Dependencies), len(want), got.Dependencies)
	}
	for _, d := range got.Dependencies {
		if v := want[d.Module]; d.Version != v {
			t.Errorf("%s = %q, want %q", d.Module, d.Version, v)
		}
	}
}
