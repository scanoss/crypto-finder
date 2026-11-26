// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// pythonValueFindings scans Python sources with cards on the developer route
// (source -> graph -> fragment -> cards matcher) and lists `<file>:<line>
// <rule>` for every asset, sorted.
func pythonValueFindings(t *testing.T, files map[string]string, cardsText string) []string {
	t.Helper()
	root := t.TempDir()
	target := filepath.Join(root, "src")
	for rel, text := range files {
		path := filepath.Join(target, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cardsDir := filepath.Join(root, "cards", ecosystemPython)
	if err := os.MkdirAll(filepath.Join(cardsDir, "t"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cardsDir, "t", "rules.cards"), []byte("cards:\n"+cardsText), 0o600); err != nil {
		t.Fatal(err)
	}
	report := devPythonCardsScan(t, target, stubPythonRuleset(t, cardsDir), cardsDir)
	var got []string
	for _, finding := range report.Findings {
		for _, asset := range finding.CryptographicAssets {
			for _, rule := range asset.Rules {
				got = append(got, fmt.Sprintf("%s:%d %s", filepath.ToSlash(finding.FilePath), asset.StartLine, strings.TrimPrefix(rule.ID, "stub.")))
			}
		}
	}
	sort.Strings(got)
	return got
}

// hashNameCards is one taint card per algorithm name on hashlib.new's
// name: a card reports a call once, whatever number of its values match.
func hashNameCards(names ...string) string {
	text := ""
	for _, name := range names {
		text += "- rule: " + name + "\n  match: {call: hashlib.new, args: {0|name: {taint: '\"" + name + "\"'}}}\n"
	}
	return text
}

func checkPythonValueFindings(t *testing.T, got, want []string) {
	t.Helper()
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A parameter takes the literals its callers in the same file pass, by
// position or by keyword, in a function, a method (called through self, on
// an instance, at an instantiation), a class method, a static method and
// for a keyword-only parameter: the call that reads it is reported with
// them, in place (owner decision 1; E1.3a for Java). A caller in another
// file is not read, as OpenGrep's taint does not.
func TestPythonValuesFromSameFileCallers(t *testing.T) {
	files := map[string]string{
		"app/hasher.py": `import hashlib


def by_name(name, data):
    return hashlib.new(name, data)


def keyword_only(data, *, name="sha3_512"):
    return hashlib.new(name, data)


class Hasher:
    def __init__(self, name):
        hashlib.new(name)

    def digest(self, name, data):
        return hashlib.new(name, data)

    @classmethod
    def of(cls, data, name):
        return hashlib.new(name, data)

    @staticmethod
    def plain(data, name):
        return hashlib.new(name, data)

    def use(self):
        return self.digest("sha224", b"x")


def callers(h: Hasher):
    by_name("md5", b"x")
    by_name(data=b"y", name="sha1")
    keyword_only(b"x", name="sha256")
    h.digest(b"x", "sha384")
    h.digest(name="sha384", data=b"x")
    Hasher("sha512")
    Hasher.of(b"x", "blake2b")
    Hasher.plain(b"x", name="blake2s")
`,
		"app/other.py": `from app.hasher import by_name


def elsewhere():
    by_name("sha3_256", b"x")
`,
	}
	names := []string{"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s"}
	got := pythonValueFindings(t, files, hashNameCards(names...))
	checkPythonValueFindings(t, got, []string{
		"app/hasher.py:5 md5", "app/hasher.py:5 sha1",
		"app/hasher.py:9 sha256",
		"app/hasher.py:14 sha512",
		"app/hasher.py:17 sha224", "app/hasher.py:17 sha384",
		"app/hasher.py:21 blake2b",
		"app/hasher.py:25 blake2s",
	})
}

// Inside a branch that fixes a variable (`==`, `in`, `case`) the call that
// reads it is reported with the value, or with each of the values; a
// dispatch table read whose key resolves is its entry's value. An else
// branch and a module's table read with a key that does not resolve report
// nothing; a table of the function read with such a key is reported with
// each value it may hold.
func TestPythonValuesInBranchesAndTables(t *testing.T) {
	files := map[string]string{
		"app/pick.py": `import hashlib
import hmac

TABLE = {"HS256": hashlib.sha256, "HS512": hashlib.sha512}
NAMES = {"a": "md5", "b": "sha1"}


def refine(alg, data):
    if alg == "sha256":
        hashlib.new(alg, data)
    elif alg in ("sha384", "sha512"):
        hashlib.new(alg, data)
    else:
        hashlib.new(alg, data)
    match alg:
        case "blake2b" | "blake2s":
            hashlib.new(alg, data)
        case "sha224":
            hashlib.new(alg, data)
        case _:
            hashlib.new(alg, data)


def tables(key, msg, alg):
    hmac.new(key, msg, TABLE["HS512"])
    hmac.new(key, msg, TABLE[alg])
    if alg == "HS256":
        hmac.new(key, msg, TABLE[alg])
    return hashlib.new(NAMES["b"])


def unknown_key(alg, data):
    hashlib.new(NAMES[alg], data)
    names = {"a": "sha384", "b": "blake2s"}
    hashlib.new(names[alg], data)
    name = names[alg]
    return hashlib.new(name, data)
`,
	}
	names := []string{"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b", "blake2s"}
	cards := hashNameCards(names...) + `- rule: hmac-sha256
  match: {call: hmac.new, args: {2|digestmod: {const: hashlib.sha256}}}
- rule: hmac-sha512
  match: {call: hmac.new, args: {2|digestmod: {const: hashlib.sha512}}}
- rule: hmac-dynamic
  match: {call: hmac.new, args: {2|digestmod: {regex: '^(?!hashlib\.)'}}}
`
	checkPythonValueFindings(t, pythonValueFindings(t, files, cards), []string{
		"app/pick.py:10 sha256",
		"app/pick.py:12 sha384", "app/pick.py:12 sha512",
		"app/pick.py:17 blake2b", "app/pick.py:17 blake2s",
		"app/pick.py:19 sha224",
		"app/pick.py:25 hmac-sha512",
		"app/pick.py:26 hmac-dynamic",
		"app/pick.py:28 hmac-sha256",
		"app/pick.py:29 sha1",
		// A module's table with an unknown key (33) is not read; a table
		// of the function may hold any of its values.
		"app/pick.py:35 blake2s", "app/pick.py:35 sha384",
		"app/pick.py:37 blake2s", "app/pick.py:37 sha384",
	})
}

// A local or module name bound once to a dotted constant or a literal, or a
// branch fixes, reads as that value (owner decision 3, E2.7-py.11b): a
// pattern on the argument's text sees the constant as if it were written at
// the call, so the named rule reports it and the unnamed one does not. A
// name that may hold one of a few literals or constants and nothing else
// reads as each of them. A parameter, a name written after its binding (rebound through
// `global`, augmented) and one that may hold anything else stay as written.
func TestPythonLocalConstants(t *testing.T) {
	files := map[string]string{
		"app/kdf.py": `from argon2 import Type
from argon2.low_level import hash_secret_raw

DEFAULT = Type.D


def derive(password, salt, variant):
    chosen = Type.ID
    a = hash_secret_raw(password, salt, 2, 1024, 1, 32, chosen)
    b = hash_secret_raw(password, salt, 2, 1024, 1, 32, type=DEFAULT)
    c = hash_secret_raw(password, salt, 2, 1024, 1, 32, Type.I)
    return a, b, c, hash_secret_raw(password, salt, 2, 1024, 1, 32, variant)
`,
		"app/mac.py": `import hmac

ALG = "sha512"
CONFIGURED = "sha512"
GROWN = "sha"


def configure():
    global CONFIGURED
    CONFIGURED = "md5"


def sign(key, msg, alg, flag):
    hmac.new(key, msg, digestmod=ALG)
    hmac.new(key, msg, digestmod=CONFIGURED)
    local = "sha384"
    hmac.new(key, msg, local)
    either = "sha256"
    if flag:
        either = "sha512"
    hmac.new(key, msg, digestmod=either)
    mixed = "sha256"
    if flag:
        mixed = alg
    hmac.new(key, msg, mixed)
    hmac.new(key, msg, alg)
    if alg in ("sha256", "sha384"):
        hmac.new(key, msg, alg)
    global GROWN
    GROWN += "1"
    return hmac.new(key, msg, GROWN)
`,
		"app/digest.py": `from cryptography.hazmat.primitives import hashes


def pick(h):
    if h in (hashes.SHA256, hashes.SHA512):
        return hashes.Hash(h)
    return hashes.Hash(h)
`,
	}
	cards := `- rule: argon2id
  match: {call: argon2.low_level.hash_secret_raw, args: {6|type: {taint: '(?:^|\.)Type\.ID$'}}}
- rule: argon2d
  match: {call: argon2.low_level.hash_secret_raw, args: {6|type: {taint: '(?:^|\.)Type\.D$'}}}
- rule: argon2i-written
  match: {call: argon2.low_level.hash_secret_raw, args: {6|type: {const: argon2.Type.I}}}
- rule: argon2id-written
  match: {call: argon2.low_level.hash_secret_raw, args: {6|type: {const: argon2.Type.ID}}}
- rule: argon2d-written
  match: {call: argon2.low_level.hash_secret_raw, args: {6|type: {const: argon2.Type.D}}}
- rule: hmac-sha256
  match: {call: hmac.new, args: {2|digestmod: {regex: '^"sha256"$'}}}
- rule: hmac-sha384
  match: {call: hmac.new, args: {2|digestmod: {regex: '^"sha384"$'}}}
- rule: hmac-sha512
  match: {call: hmac.new, args: {2|digestmod: {regex: '^"sha512"$'}}}
- rule: hmac-unnamed
  match: {call: hmac.new, args: {2|digestmod: {regex: '^(?!")'}}}
- rule: hash-sha256
  match: {call: cryptography.hazmat.primitives.hashes.Hash, args: {0: {const: cryptography.hazmat.primitives.hashes.SHA256}}}
- rule: hash-sha512
  match: {call: cryptography.hazmat.primitives.hashes.Hash, args: {0: {const: cryptography.hazmat.primitives.hashes.SHA512}}}
- rule: hash-unnamed
  match: {call: cryptography.hazmat.primitives.hashes.Hash, args: {0: {regex: '^(?!hashes\.)'}}}
`
	checkPythonValueFindings(t, pythonValueFindings(t, files, cards), []string{
		"app/kdf.py:9 argon2id", "app/kdf.py:9 argon2id-written",
		"app/kdf.py:10 argon2d", "app/kdf.py:10 argon2d-written",
		"app/kdf.py:11 argon2i-written",
		"app/mac.py:14 hmac-sha512",
		"app/mac.py:15 hmac-unnamed",
		"app/mac.py:17 hmac-sha384",
		"app/mac.py:21 hmac-sha256", "app/mac.py:21 hmac-sha512",
		"app/mac.py:25 hmac-unnamed",
		"app/mac.py:26 hmac-unnamed",
		"app/mac.py:28 hmac-sha256", "app/mac.py:28 hmac-sha384",
		"app/mac.py:31 hmac-unnamed",
		"app/digest.py:6 hash-sha256", "app/digest.py:6 hash-sha512",
		"app/digest.py:7 hash-unnamed",
	})
}

// A dispatch table written after its definition keeps the dynamic reading
// (E2.7-py.11b): an item written, a dict method that changes it, the name
// rebound through `global`, or the table handed to other code. A local
// bound to a read of such a table stays as written too.
func TestPythonTablesWrittenAfterDefinition(t *testing.T) {
	files := map[string]string{
		"app/sign.py": `import hashlib
import hmac

FIXED = {"HS512": hashlib.sha512}
WRITTEN = {"HS512": hashlib.sha512}
UPDATED = {"HS512": hashlib.sha512}
REBOUND = {"HS512": hashlib.sha512}
PASSED = {"HS512": hashlib.sha512}


def configure():
    global REBOUND
    WRITTEN["HS512"] = hashlib.md5
    UPDATED.update(HS512=hashlib.md5)
    REBOUND = {"HS512": hashlib.md5}
    register(PASSED)


def sign(key, msg):
    hmac.new(key, msg, FIXED["HS512"])
    hmac.new(key, msg, WRITTEN["HS512"])
    hmac.new(key, msg, UPDATED["HS512"])
    hmac.new(key, msg, REBOUND["HS512"])
    hmac.new(key, msg, PASSED["HS512"])
    digest = PASSED["HS512"]
    hmac.new(key, msg, digest)
    fixed = FIXED["HS512"]
    return hmac.new(key, msg, fixed)
`,
	}
	cards := `- rule: hmac-sha512
  match: {call: hmac.new, args: {2|digestmod: {const: hashlib.sha512}}}
- rule: hmac-dynamic
  match: {call: hmac.new, args: {2|digestmod: {regex: '^(?!hashlib\.)'}}}
`
	checkPythonValueFindings(t, pythonValueFindings(t, files, cards), []string{
		"app/sign.py:20 hmac-sha512",
		"app/sign.py:21 hmac-dynamic",
		"app/sign.py:22 hmac-dynamic",
		"app/sign.py:23 hmac-dynamic",
		"app/sign.py:24 hmac-dynamic",
		"app/sign.py:26 hmac-dynamic",
		"app/sign.py:28 hmac-sha512",
	})
}

// A constant read in a comparison (`==`, `is`, `in`, `case`) is reported
// only when the value compared with it resolves to that constant (owner
// decision E2.6c; `in` is a comparison, E2.7-py.9): from a same-file
// caller's argument, by position or keyword, or from the branch the
// comparison is in. A table entry (dict, list) is always reported.
func TestPythonComparedConstants(t *testing.T) {
	// Each line marked `# hash` is reported, and no other.
	source := `from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hashes import SHA512_256
from cryptography.hazmat.primitives import hashes as h2


def compare(h):
    if h == hashes.SHA256:  # hash: passed by position
        return 1
    if h in (
        hashes.SHA384,  # hash: passed by keyword
        hashes.SHA512,
    ):
        return 2
    match h:
        case hashes.SHA1:
            return 3
        case hashes.MD5:  # hash: passed by position
            return 4
    return 0


def callers():
    compare(hashes.SHA256)  # hash: an argument
    compare(h=hashes.SHA384)  # hash: an argument
    compare(hashes.MD5)  # hash: an argument


def unresolved(h):
    return h == hashes.BLAKE2b


def imported(h):
    if h == SHA512_256:  # hash: the from-imported name, passed under an alias
        return 1
    return h is hashes.SM3  # hash: passed through the module's other name


def imported_callers():
    imported(h2.SHA512_256)  # hash: an argument
    imported(h2.SM3)  # hash: an argument


def refined(h):
    if h is hashes.SHA224:
        return h == hashes.SHA224  # hash: the branch fixes h
    return None


class Signer:
    digest = hashes.SHA3_224  # hash: a class attribute

    def __init__(self, strong):
        if strong:
            self.digest = hashes.SHA3_384  # hash: an assignment

    def strong(self, other):
        if self.digest == hashes.SHA3_384:  # hash: the class assigns it
            return True
        if self.digest == hashes.SHAKE128 or other.digest == hashes.SHA3_224:
            return False
        return self.digest is hashes.SHA3_224  # hash: the class assigns it


def table():
    return {
        "sha3": hashes.SHA3_256,  # hash: a table entry
        "others": [hashes.SHA3_512],  # hash: a table entry
    }
`
	var want []string
	for i, line := range strings.Split(source, "\n") {
		if strings.Contains(line, "# hash") {
			want = append(want, fmt.Sprintf("app/cmp.py:%d hash", i+1))
		}
	}
	cards := `- rule: hash
  constant: {const: cryptography.hazmat.primitives.hashes, member: '^\w+$'}
`
	checkPythonValueFindings(t, pythonValueFindings(t, map[string]string{"app/cmp.py": source}, cards), want)
}
