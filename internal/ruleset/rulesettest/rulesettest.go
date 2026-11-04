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

// Package rulesettest issues signed ruleset bundles the way the SCANOSS API
// serves them, and serves them over HTTP, for tests.
package rulesettest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/ruleset"
)

// RuleYAML is a minimal valid rule file.
const RuleYAML = `rules:
  - id: test-aes
    languages: [java]
    severity: INFO
    message: AES usage
    pattern: Cipher.getInstance("AES")
`

// NewSigner returns a signer with a fresh key. When trust is true the key is
// also trusted through ruleset.PubKeysEnv for the rest of the test.
func NewSigner(t testing.TB, keyID string, trust bool) ruleset.Signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if trust {
		t.Setenv(ruleset.PubKeysEnv, keyID+":"+base64.StdEncoding.EncodeToString(pub))
	}
	return ruleset.Signer{KeyID: keyID, Key: priv}
}

// Issued is one served bundle and what the API sends with it.
type Issued struct {
	Bundle    []byte
	LeaseJSON []byte // the lease envelope sent in the SCANOSS-Ruleset-Lease header
	Lease     ruleset.Lease
	Release   ruleset.Release
}

// Issue builds a bundle of name@version holding files (path -> content) and
// signs its lease, like the API: the bundle is the payload's entries
// re-packed, nothing added, and the lease travels beside it. The API also
// personalises a marked release per tenant, so a bundle's bytes (and
// bundle_sha256) differ from the release payload's (payload_sha256); here
// the payload is packed with a different compression level to the same
// effect.
func Issue(t testing.TB, signer ruleset.Signer, name, version string, files map[string]string, expiresAt time.Time) *Issued {
	t.Helper()
	payload := tarGz(t, files, gzip.BestCompression)
	bundle := tarGz(t, files, gzip.NoCompression)
	release := ruleset.Release{
		Format: ruleset.ReleaseFormat, Name: name, Domain: "crypto", Version: version,
		CreatedAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), PayloadSHA: ruleset.SHA256Hex(payload), PayloadSize: int64(len(payload)),
	}
	lease := ruleset.Lease{
		Format: ruleset.LeaseFormat, Name: name, Domain: "crypto", Version: version,
		PayloadSHA: release.PayloadSHA, BundleSHA: ruleset.SHA256Hex(bundle), KeyRef: "k_test", Tenant: "acme",
		IssuedAt: time.Now().UTC().Truncate(time.Second), ExpiresAt: expiresAt.UTC().Truncate(time.Second),
	}
	leaseJSON, err := signer.Sign(lease)
	if err != nil {
		t.Fatal(err)
	}
	lease.SigningKeyID = signer.KeyID
	return &Issued{Bundle: bundle, LeaseJSON: leaseJSON, Lease: lease, Release: release}
}

// tarGz writes files, sorted by path, as a gzip'd tar.
func tarGz(t testing.TB, files map[string]string, level int) []byte {
	t.Helper()
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, level)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(gz)
	for _, path := range paths {
		content := []byte(files[path])
		if err := tw.WriteHeader(&tar.Header{Name: path, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Server serves one ruleset on the v3 endpoints. Every other path is a 404.
type Server struct {
	*httptest.Server

	mu        sync.Mutex
	current   *Issued
	downloads int
	checks    int
}

// NewServer serves issued until Set replaces it. It is closed with the test.
func NewServer(t testing.TB, issued *Issued) *Server {
	t.Helper()
	s := &Server{current: issued}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v3/rulesets/{name}/{version}/download", s.download)
	mux.HandleFunc("GET /v3/rulesets/{name}/{version}", s.release)
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// Set replaces the served bundle.
func (s *Server) Set(issued *Issued) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = issued
}

// Counts returns how many downloads and release checks were served.
func (s *Server) Counts() (downloads, checks int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.downloads, s.checks
}

func (s *Server) lookup(r *http.Request) *Issued {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.current
	if i == nil || r.PathValue("name") != i.Lease.Name || (r.PathValue("version") != "latest" && r.PathValue("version") != i.Lease.Version) {
		return nil
	}
	return i
}

func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	i := s.lookup(r)
	if i == nil {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	s.downloads++
	s.mu.Unlock()
	h := w.Header()
	h.Set("SCANOSS-Ruleset-Name", i.Lease.Name)
	h.Set("SCANOSS-Ruleset-Version", i.Lease.Version)
	h.Set("SCANOSS-Ruleset-Created-At", i.Release.CreatedAt.Format(time.RFC3339))
	h.Set("X-Checksum-SHA256", ruleset.SHA256Hex(i.Bundle))
	h.Set("SCANOSS-Ruleset-Lease", base64.StdEncoding.EncodeToString(i.LeaseJSON))
	// #nosec G705 -- a test server writing the gzip bundle it was given, not HTML.
	if _, err := w.Write(i.Bundle); err != nil {
		return
	}
}

func (s *Server) release(w http.ResponseWriter, r *http.Request) {
	i := s.lookup(r)
	if i == nil {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	s.checks++
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(i.Release); err != nil {
		return
	}
}
