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

package cli_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The fixture's crypto lives in internal/seal and the replaced module lib,
// while its only caller is cmd/tool/main.go. Scoping detection to seal.go must
// leave that caller in the call graph, so seal.go's findings stay reachable.
var detectScopeFixture = map[string]string{
	"app/go.mod": "module example.com/app\n\ngo 1.22\n\nrequire example.com/lib v0.0.0\n\nreplace example.com/lib => ../lib\n",
	"app/cmd/tool/main.go": `package main

import (
	"fmt"

	"example.com/app/internal/digest"
	"example.com/app/internal/seal"
	"example.com/lib"
)

func main() {
	key := make([]byte, 32)
	out, err := seal.Encrypt(key, []byte("hello"))
	if err != nil {
		panic(err)
	}
	priv, err := seal.NewKey(3072)
	fmt.Println(len(out), priv, err, digest.Sum([]byte("hello")), lib.Protect(key[:8]))
}
`,
	"app/internal/seal/seal.go": `package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
)

func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func NewKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

func unusedKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}
`,
	"app/internal/digest/digest.go": `package digest

import (
	"crypto/md5"
	"crypto/sha256"

	"example.com/lib"
)

func Sum(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return append(h.Sum(nil), lib.Fingerprint(data)...)
}

func legacy(data []byte) [16]byte {
	return md5.Sum(data)
}
`,
	"app/ignored.go": `package main

import "crypto/sha1"

func stray(data []byte) [20]byte { return sha1.Sum(data) }
`,
	"app/docs/snippet.go": `package snippet

import "crypto/sha1"

func Example(data []byte) [20]byte { return sha1.Sum(data) }
`,
	"app/.gitignore": "ignored.go\n",
	"lib/go.mod":     "module example.com/lib\n\ngo 1.22\n",
	"lib/lib.go": `package lib

import (
	"crypto/des"
	"crypto/sha512"
)

func Protect(key []byte) error {
	_, err := des.NewCipher(key)
	return err
}

func Fingerprint(data []byte) []byte {
	h := sha512.New()
	h.Write(data)
	return h.Sum(nil)
}
`,
}

const detectScopeRules = `rules:
  - id: go.aes.new-cipher
    message: AES
    severity: INFO
    languages: [go]
    pattern: aes.NewCipher($KEY)
    metadata: {crypto: {assetType: algorithm, algorithmFamily: AES, algorithmPrimitive: block-cipher, algorithmName: AES}}
  - id: go.gcm.new
    message: GCM
    severity: INFO
    languages: [go]
    pattern: cipher.NewGCM($B)
    metadata: {crypto: {assetType: algorithm, algorithmFamily: AES, algorithmPrimitive: ae, algorithmMode: GCM}}
  - id: go.rsa.generate
    message: RSA
    severity: INFO
    languages: [go]
    pattern: rsa.GenerateKey($R, $BITS)
    metadata: {crypto: {assetType: algorithm, algorithmFamily: RSA, algorithmPrimitive: pke, algorithmParameterSetIdentifier: "$BITS"}}
  - id: go.sha256.new
    message: SHA-256
    severity: INFO
    languages: [go]
    pattern: sha256.New()
    metadata: {crypto: {assetType: algorithm, algorithmFamily: SHA2, algorithmPrimitive: hash, algorithmName: SHA-256}}
  - id: go.sha1.sum
    message: SHA-1
    severity: INFO
    languages: [go]
    pattern: sha1.Sum($D)
    metadata: {crypto: {assetType: algorithm, algorithmFamily: SHA1, algorithmPrimitive: hash, algorithmName: SHA-1}}
  - id: go.md5.sum
    message: MD5
    severity: INFO
    languages: [go]
    pattern: md5.Sum($D)
    metadata: {crypto: {assetType: algorithm, algorithmFamily: MD5, algorithmPrimitive: hash, algorithmName: MD5}}
  - id: go.des.new-cipher
    message: DES
    severity: INFO
    languages: [go]
    pattern: des.NewCipher($KEY)
    metadata: {crypto: {assetType: algorithm, algorithmFamily: DES, algorithmPrimitive: block-cipher, algorithmName: DES}}
  - id: go.sha512.new
    message: SHA-512
    severity: INFO
    languages: [go]
    pattern: sha512.New()
    metadata: {crypto: {assetType: algorithm, algorithmFamily: SHA2, algorithmPrimitive: hash, algorithmName: SHA-512}}
`

// scopedRun is one CLI scan decoded generically, so equality covers every
// field the tool emits rather than the fields a struct happens to name.
type scopedRun struct {
	direct     map[string]map[string]any // occurrence_key -> asset, source "direct"
	directFile map[string]string         // occurrence_key -> file_path
	dependency map[string]map[string]any // occurrence_key -> asset, dependency-backed
	graphs     map[string]map[string]any // occurrence_key -> hydrated finding graph
}

func TestDetectPathsFrom(t *testing.T) {
	if testing.Short() {
		t.Skip("black-box CLI scan with a real opengrep")
	}
	if _, err := exec.LookPath("opengrep"); err != nil {
		t.Skip("opengrep not installed")
	}
	root := repositoryRoot(t)
	binary := buildCryptoFinder(t, root)
	t.Run("reachability uses the whole tree", func(t *testing.T) {
		if _, err := exec.LookPath("go"); err != nil {
			t.Skip("go toolchain required for Go dependency resolution")
		}
		testDetectScopeReachability(t, binary)
	})
	t.Run("key sizes and supporting calls match a full scan", func(t *testing.T) {
		testDetectScopeKeySizes(t, binary, root)
	})
}

func testDetectScopeReachability(t *testing.T, binary string) {
	tmp := t.TempDir()
	for rel, content := range detectScopeFixture {
		path := filepath.Join(tmp, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	target := filepath.Join(tmp, "app")
	gitIgnoring := initFixtureRepo(t, target)
	rules := filepath.Join(tmp, "rules.yaml")
	require.NoError(t, os.WriteFile(rules, []byte(detectScopeRules), 0o600))

	run := func(name string, extra ...string) scopedRun {
		t.Helper()
		args := append([]string{"--languages", "go", "--rules", rules, "--scan-dependencies", "--findings-cache", "none"}, extra...)
		return runScopeScan(t, binary, tmp, name, target, args...)
	}

	full := run("full")
	require.NotEmpty(t, full.dependency, "fixture must produce dependency findings")

	sealed := func(r scopedRun) []string {
		var keys []string
		for key, file := range r.directFile {
			if file == "internal/seal/seal.go" {
				keys = append(keys, key)
			}
		}
		return keys
	}
	sealKeys := sealed(full)
	require.Len(t, sealKeys, 4, "seal.go carries AES, GCM and two RSA findings")
	reachable := 0
	for _, key := range sealKeys {
		if full.graphs[key]["reachability"] == "reachable" {
			reachable++
		}
	}
	require.Equal(t, 3, reachable, "Encrypt and NewKey are called from main; unusedKeyPair is not")

	// Control: excluding the caller the old way flips seal.go's verdicts. The
	// equivalence below is only meaningful because this fixture detects that.
	excluded := run("exclude", "--exclude", "cmd/")
	flipped := 0
	for _, key := range sealKeys {
		if excluded.graphs[key]["reachability"] != full.graphs[key]["reachability"] {
			flipped++
		}
	}
	require.Positive(t, flipped, "--exclude of the caller must change reachability, or the fixture proves nothing")

	list := filepath.Join(tmp, "changed.txt")
	require.NoError(t, os.WriteFile(list, []byte("internal/seal/seal.go\ncmd/tool/main.go\ndeleted/gone.go\nignored.go\ndocs/snippet.go\n"), 0o600))
	scoped := run("scoped", "--detect-paths-from", list)

	// docs/ is a default exclusion: listing a file there must not scan it.
	scope := map[string]bool{"internal/seal/seal.go": true, "cmd/tool/main.go": true}
	if !gitIgnoring {
		scope["ignored.go"] = true // outside git, a full walk reads it too
	}
	want := 0
	for key, asset := range full.direct {
		if !scope[full.directFile[key]] {
			continue
		}
		want++
		require.Containsf(t, scoped.direct, key, "scoped scan lost %s in %s", key, full.directFile[key])
		require.Equalf(t, asset, scoped.direct[key], "finding %s differs from the full scan", key)
		require.Equalf(t, full.graphs[key], scoped.graphs[key], "finding graph %s (reachability, chains, supporting calls) differs from the full scan", key)
	}
	require.Len(t, scoped.direct, want, "scoped scan reported direct findings outside its scope")
	for key, file := range scoped.directFile {
		require.Truef(t, scope[file], "finding %s in unscoped file %s", key, file)
	}
	require.Equal(t, full.dependency, scoped.dependency, "dependencies are scanned whole regardless of scope")
	for key, graph := range full.graphs {
		if _, dep := full.dependency[key]; dep {
			require.Equalf(t, graph, scoped.graphs[key], "dependency finding graph %s differs", key)
		}
	}

	// A list naming no existing file scans nothing rather than falling back
	// to whatever directory the scanner runs in.
	require.NoError(t, os.WriteFile(list, []byte("deleted/gone.go\n"), 0o600))
	empty := run("empty", "--detect-paths-from", list)
	require.Empty(t, empty.direct)
	require.Equal(t, full.dependency, empty.dependency)
}

func testDetectScopeKeySizes(t *testing.T, binary, root string) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "src")
	require.NoError(t, os.MkdirAll(target, 0o700))
	usage, err := os.ReadFile(filepath.Join(root, "internal", "scan", "testdata", "jca_keygen_key_length", "JcaKeygenUsage.java"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(target, "JcaKeygenUsage.java"), usage, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(target, "Other.java"), []byte(`package issue273;

import java.security.MessageDigest;

public class Other {
    public byte[] digest(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }
}
`), 0o600))
	rules := filepath.Join(tmp, "rules.yaml")
	require.NoError(t, os.WriteFile(rules, []byte(`rules:
  - id: java.jca.keygen
    message: keygen
    severity: INFO
    languages: [java]
    pattern: $G.generateKeyPair()
    metadata: {crypto: {assetType: algorithm, algorithmFamily: RSA, algorithmPrimitive: pke}}
  - id: java.jca.dofinal
    message: cipher
    severity: INFO
    languages: [java]
    pattern: $C.doFinal(...)
    metadata: {crypto: {assetType: algorithm, algorithmFamily: AES, algorithmPrimitive: block-cipher}}
  - id: java.jca.digest
    message: digest
    severity: INFO
    languages: [java]
    pattern: $M.digest($D)
    metadata: {crypto: {assetType: algorithm, algorithmFamily: SHA2, algorithmPrimitive: hash}}
`), 0o600))
	list := filepath.Join(tmp, "changed.txt")
	require.NoError(t, os.WriteFile(list, []byte("JcaKeygenUsage.java\n"), 0o600))

	full := runScopeScan(t, binary, tmp, "full", target, "--languages", "java", "--rules", rules)
	scoped := runScopeScan(t, binary, tmp, "scoped", target, "--languages", "java", "--rules", rules, "--detect-paths-from", list)

	bits := 0
	for key, file := range full.directFile {
		if file != "JcaKeygenUsage.java" {
			require.NotContainsf(t, scoped.direct, key, "finding in unscoped %s", file)
			continue
		}
		require.Equalf(t, full.direct[key], scoped.direct[key], "finding %s differs from the full scan", key)
		require.Equalf(t, full.graphs[key], scoped.graphs[key], "finding graph %s differs from the full scan", key)
		calls, _ := full.graphs[key]["supporting_call_ids"].([]any)
		for _, call := range calls {
			if kl, ok := call.(map[string]any)["supporting_call"].(map[string]any)["resolved_key_length"].(map[string]any); ok && kl["bits"] != nil {
				bits++
			}
		}
	}
	require.GreaterOrEqual(t, bits, 7, "the fixture resolves constant key sizes, so equal graphs compare real bits")
	require.Len(t, scoped.direct, 9)
	require.Len(t, full.direct, 10)
}

// runScopeScan runs one CLI scan of target with a callgraph export.
func runScopeScan(t *testing.T, binary, tmp, name, target string, extra ...string) scopedRun {
	t.Helper()
	findings := filepath.Join(tmp, name+"-findings.json")
	graph := filepath.Join(tmp, name+"-callgraph.json")
	args := append([]string{
		"scan", "--scanner", "opengrep", "--no-remote-rules",
		"--output", findings, "--export-callgraph", graph,
	}, extra...)
	args = append(args, target)
	cmd := exec.CommandContext(t.Context(), binary, args...)
	cmd.Env = append(os.Environ(), "HOME="+filepath.Join(tmp, "home"))
	output, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "%s scan output:\n%s", name, output)
	return decodeScopedRun(t, findings, graph)
}

// initFixtureRepo commits the fixture so the scanner's git-aware walk honors
// .gitignore. It reports whether git is in play.
func initFixtureRepo(t *testing.T, dir string) bool {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		return false
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"add", "-A"},
		{"-c", "user.email=test@example.com", "-c", "user.name=test", "commit", "-q", "-m", "fixture"},
	} {
		cmd := exec.CommandContext(t.Context(), "git", args...)
		cmd.Dir = dir
		output, err := cmd.CombinedOutput()
		require.NoErrorf(t, err, "git %v:\n%s", args, output)
	}
	return true
}

func decodeScopedRun(t *testing.T, findingsPath, graphPath string) scopedRun {
	t.Helper()
	var report struct {
		Findings []struct {
			FilePath string           `json:"file_path"`
			Assets   []map[string]any `json:"cryptographic_assets"`
		} `json:"findings"`
	}
	readJSON(t, findingsPath, &report)
	run := scopedRun{
		direct:     map[string]map[string]any{},
		directFile: map[string]string{},
		dependency: map[string]map[string]any{},
		graphs:     map[string]map[string]any{},
	}
	for _, finding := range report.Findings {
		for _, asset := range finding.Assets {
			key, _ := asset["occurrence_key"].(string)
			require.NotEmpty(t, key)
			if asset["source"] == "direct" {
				run.direct[key] = asset
				run.directFile[key] = finding.FilePath
			} else {
				run.dependency[key] = asset
			}
		}
	}

	var graph struct {
		FindingGraphs   []map[string]any `json:"finding_graphs"`
		Functions       []any            `json:"functions"`
		SupportingCalls []map[string]any `json:"supporting_calls"`
	}
	readJSON(t, graphPath, &graph)
	supporting := make(map[string]any, len(graph.SupportingCalls))
	for _, call := range graph.SupportingCalls {
		supporting[call["supporting_id"].(string)] = call
	}
	// functions[] only holds the functions this export's chains touch, so its
	// indexes differ between runs; compare the hydrated frames instead.
	for _, fg := range graph.FindingGraphs {
		if indexes, ok := fg["call_chain_indexes"].([]any); ok {
			chains := make([][]any, len(indexes))
			for i, route := range indexes {
				for _, idx := range route.([]any) {
					chains[i] = append(chains[i], graph.Functions[int(idx.(float64))])
				}
			}
			fg["call_chain_indexes"] = chains
		}
		if ids, ok := fg["supporting_call_ids"].([]any); ok {
			calls := make([]any, len(ids))
			for i, id := range ids {
				calls[i] = supporting[id.(string)]
			}
			fg["supporting_call_ids"] = calls
		}
		run.graphs[fg["occurrence_key"].(string)] = fg
	}
	return run
}
