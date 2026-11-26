// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// pythonRuleFindings scans files (a Python target) with the compiled index of
// rulesYAML (one rules.yaml, no cards): "file:line rule" per finding.
func pythonRuleFindings(t *testing.T, files map[string]string, rulesYAML string) []string {
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
	rules := filepath.Join(root, "ruleset")
	ruleDir := filepath.Join(rules, "semgrep-rules", ecosystemPython, "t")
	cardsDir := filepath.Join(rules, "cards", ecosystemPython)
	for _, dir := range []string{ruleDir, cardsDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(ruleDir, "rules.yaml"), []byte(rulesYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	report := devPythonCardsScan(t, target, rules, cardsDir)
	var got []string
	for _, finding := range report.Findings {
		for _, asset := range finding.CryptographicAssets {
			for _, rule := range asset.Rules {
				id := rule.ID[strings.LastIndexByte(rule.ID, '.')+1:]
				got = append(got, fmt.Sprintf("%s:%d %s", filepath.ToSlash(finding.FilePath), asset.StartLine, id))
			}
		}
	}
	sort.Strings(got)
	return got
}

func pyRule(id, pattern string) string {
	return fmt.Sprintf(`  - id: %s
    message: m
    severity: INFO
    languages: [python]
    pattern: '%s'
    metadata:
      crypto: {assetType: algorithm}
`, id, pattern)
}

// The graph links `super().__init__(..)`, `Base.__init__(self, ..)` and the
// instantiation of a subclass without an `__init__` of its own to the base's
// `__init__`, but none of them is a call `Base(..)`: a rule naming the class
// (with or without its module) matches only where the class is instantiated
// as written, or through `cls(..)` in its classmethod (E2.7-py.15; Java's
// this / super delegation, E2.6a C3).
func TestPythonInitDelegationIsNoInstantiation(t *testing.T) {
	files := map[string]string{
		"lib/__init__.py": "",
		"lib/conn.py": `class Connection:
    def __init__(self, ctx):
        self.ctx = ctx

    @classmethod
    def build(cls):
        return cls(None)


class Secure(Connection):
    def __init__(self, ctx):
        super().__init__(ctx)


class Legacy(Connection):
    def __init__(self, ctx):
        Connection.__init__(self, ctx)


class Plain(Connection):
    pass


def make(ctx):
    return Connection(ctx)


def make_plain(ctx):
    return Plain(ctx)
`,
	}
	rules := "rules:\n" + pyRule("bare", "Connection(...)") + pyRule("typed", "lib.conn.Connection(...)")
	checkPythonValueFindings(t, pythonRuleFindings(t, files, rules), []string{
		"lib/conn.py:7 typed",
		"lib/conn.py:25 bare",
		"lib/conn.py:25 typed",
	})
}

// A call inside the scanned package is an internal edge, which records no
// call text: the matcher reads it from the source, so a pattern written as
// the call is (`SHA512.new(..)` after a relative import) matches as on an
// external call, and a pattern written without a receiver does not match a
// method called on one (`self.new(..)`).
func TestPythonInternalCallWrittenText(t *testing.T) {
	files := map[string]string{
		"Crypto/__init__.py": "",
		"Crypto/Hash/SHA512.py": `def new(data=None):
    return data
`,
		"Crypto/Hash/__init__.py": `def by_name(name):
    if name == "SHA512":
        from . import SHA512

        return SHA512.new()


class Hasher:
    @classmethod
    def new(cls):
        return None

    def run(self):
        return self.new()


class Sub(Hasher):
    @classmethod
    def new(cls):
        return super(Sub, cls).new()
`,
	}
	rules := "rules:\n" + pyRule("written", "SHA512.new(...)") + pyRule("bare", "new(...)")
	checkPythonValueFindings(t, pythonRuleFindings(t, files, rules), []string{
		"Crypto/Hash/__init__.py:5 written",
	})
}

// A name the file imports in a `try` and again in its `except ImportError`
// (cryptography's decrepit ciphers) is the class of either module: the graph
// types the call through the first import, a rule naming the other matches
// it too, for a call and for a table entry (E2.7-py.15).
func TestPythonImportAlternatives(t *testing.T) {
	files := map[string]string{
		"app/__init__.py": "",
		"app/rc4.py": `try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import ARC4

from cryptography.hazmat.primitives.ciphers.algorithms import AES

TABLE = {"rc4": ARC4, "aes": AES}


def cipher(key):
    return ARC4(key)
`,
	}
	cards := `- rule: rc4-call
  match: {call: cryptography.hazmat.primitives.ciphers.algorithms.ARC4}
- rule: rc4-entry
  constant: {const: cryptography.hazmat.primitives.ciphers.algorithms, member: '^ARC4$', at: [dict]}
- rule: aes-entry
  constant: {const: cryptography.hazmat.decrepit.ciphers.algorithms, member: '^AES$', at: [dict]}
`
	checkPythonValueFindings(t, pythonValueFindings(t, files, cards), []string{
		"app/rc4.py:8 rc4-entry",
		"app/rc4.py:12 rc4-call",
	})
}

// A Python internal edge lists the callee's annotated parameters the call
// does not pass (type only, no argument): they are no arguments of the call,
// so `s.sign(buf)` is no three-argument sign (E2.7-py.15: M2Crypto's
// SMIME.sign(data_bio, flags=.., algo=..) read as passing an algorithm).
func TestPythonUnpassedParametersAreNoArguments(t *testing.T) {
	files := map[string]string{
		"lib/__init__.py": "",
		"lib/smime.py": `class SMIME:
    def sign(self, data_bio: bytes, flags: int = 0, algo: str = "sha256"):
        return data_bio
`,
		"lib/demo.py": `from lib.smime import SMIME


def run(buf):
    s = SMIME()
    s.sign(buf)
    s.sign(buf, 1, "sha1")
`,
	}
	rules := "rules:\n" + pyRule("three", "$B.sign($X, $Y, $Z)") + pyRule("one", "$B.sign($X)")
	checkPythonValueFindings(t, pythonRuleFindings(t, files, rules), []string{
		"lib/demo.py:6 one",
		"lib/demo.py:7 three",
	})
}

// An object-flow rule (taint from a constructor to a method call on the
// object) holds for a receiver the graph typed as the class although its
// local was last assigned from another call: a same-file factory returning
// the object, annotated (pyfhel's demos, `HE = get_context(..)`; OpenGrep's
// taint follows the return). A receiver of another type does not hold one.
func TestPythonObjectFlowThroughTypedFactory(t *testing.T) {
	files := map[string]string{
		"app/__init__.py": "",
		"app/demo.py": `from Pyfhel import Pyfhel


def make() -> Pyfhel:
    ctx = Pyfhel()
    ctx.contextGen(scheme="bfv")
    return ctx


def run():
    ctx = make()
    ctx.encrypt(1)
    direct = Pyfhel()
    direct.encrypt(2)
    other = object()
    other.encrypt(3)
`,
	}
	rules := `rules:
  - id: flow
    message: m
    severity: INFO
    languages: [python]
    mode: taint
    pattern-sources:
      - pattern: Pyfhel.Pyfhel()
    pattern-sinks:
      - pattern: $H.encrypt(...)
    metadata:
      crypto: {assetType: algorithm}
`
	checkPythonValueFindings(t, pythonRuleFindings(t, files, rules), []string{
		"app/demo.py:12 flow",
		"app/demo.py:14 flow",
	})
}

// The classes an isinstance / issubclass call tests are no table of
// algorithms, however the call is laid out: a card or rule that excludes
// constants inside these builtins reports neither a one-line nor a
// multi-line tuple of them, and still reports a real table (E2.7-py.15:
// cryptography's backend lists hashes.SHA224 .. SHA512 in an isinstance).
func TestPythonTypeCheckedConstantsAreNoTable(t *testing.T) {
	files := map[string]string{
		"app/__init__.py": "",
		"app/hashes_used.py": `from cryptography.hazmat.primitives import hashes

TABLE = (hashes.SHA256, hashes.SHA512)


def supported(algorithm):
    if isinstance(algorithm, (hashes.SHA256, hashes.SHA384)):
        return True
    return isinstance(
        algorithm,
        (
            hashes.SHA256,
            hashes.SHA512,
        ),
    )
`,
	}
	cards := `- rule: sha2-entry
  constant: {const: cryptography.hazmat.primitives.hashes, member: '^SHA(256|384|512)$', at: [dict, array]}
  not_in: [{call: issubclass}, {call: isinstance}]
- rule: sha2-any
  constant: {const: cryptography.hazmat.primitives.hashes, member: '^SHA(256|384|512)$'}
  not_in: [{call: issubclass}, {call: isinstance}]
`
	checkPythonValueFindings(t, pythonValueFindings(t, files, cards), []string{
		"app/hashes_used.py:3 sha2-any",
		"app/hashes_used.py:3 sha2-any",
		"app/hashes_used.py:3 sha2-entry",
		"app/hashes_used.py:3 sha2-entry",
	})
}

// An instantiation of a class of the scanned package is the call as written
// (with its arguments) and an internal edge to the class's __init__ that
// records none: the edge matches with the written call's arguments, so
// `PKey(cptr, 1)` is no `PKey()` (E2.7-py.15: M2Crypto's own PKey and X509
// matched pyOpenSSL's argument-less constructor rules).
func TestPythonInstantiationEdgeHasWrittenArguments(t *testing.T) {
	files := map[string]string{
		"lib/__init__.py": "",
		"lib/evp.py": `class PKey:
    def __init__(self, ptr=None, flag=0):
        self.ptr = ptr


def wrap(cptr):
    return PKey(cptr, 1)


def fresh():
    return PKey()
`,
	}
	rules := "rules:\n" + pyRule("no-args", "PKey()") + pyRule("two-args", "PKey($P, 1)")
	checkPythonValueFindings(t, pythonRuleFindings(t, files, rules), []string{
		"lib/evp.py:7 two-args",
		"lib/evp.py:11 no-args",
	})
}

// `try: import ssl` / `except ImportError: import compat as ssl` binds ssl
// to the ssl module first: the file's ssl.X are the ssl module's, not the
// fallback's (E2.7-py.15: dnspython's dns._no_ssl hid its CERT_NONE store).
func TestPythonPlainImportWinsOverFallbackAlias(t *testing.T) {
	files := map[string]string{
		"app/__init__.py": "",
		"app/q.py": `try:
    import ssl
except ImportError:
    import app._no_ssl as ssl


def make(verify):
    ctx = ssl.create_default_context()
    if verify is False:
        ctx.verify_mode = ssl.CERT_NONE
    return ctx
`,
	}
	cards := `- rule: verify-none
  store:
    attribute: verify_mode
    operator: '='
    receiver: {via: var, from: {call: ssl.create_default_context}}
    value: {const: ssl.CERT_NONE}
`
	checkPythonValueFindings(t, pythonValueFindings(t, files, cards), []string{
		"app/q.py:10 verify-none",
	})
}
