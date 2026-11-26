// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import "testing"

// A parameter, local, loop, with, except or comprehension variable named
// like an imported module is that variable, not the module (E2.7-py.14b
// gap 1); the module itself, and the optional-import idiom at module level
// (`try: import rsa` / `except ImportError: rsa = None`), still match.
func TestPythonShadowedImport(t *testing.T) {
	files := map[string]string{
		"app/shadow.py": `import rsa


def shadow_param(rsa, m, k):
    return rsa.encrypt(m, k)


def shadow_local(m, k):
    rsa = make()
    return rsa.encrypt(m, k)


def shadow_dotted(rsa, m, k):
    return rsa.session.encrypt(m, k)


def shadow_for(items, m, k):
    for rsa in items:
        rsa.encrypt(m, k)


def shadow_with(m, k):
    with open_it() as rsa:
        rsa.encrypt(m, k)


def shadow_except(m, k):
    try:
        pass
    except Exception as rsa:
        rsa.encrypt(m, k)


def shadow_comp(items, m, k):
    return [rsa.encrypt(m, k) for rsa in items]


def real(m, k):
    return rsa.encrypt(m, k)
`,
		"app/optional.py": `try:
    import rsa
except ImportError:
    rsa = None
    raise

ct = rsa.encrypt(b"x", None)
`,
	}
	cards := `- rule: encrypt
  match: {call: rsa.encrypt}
- rule: session-encrypt
  match: {call: rsa.session.encrypt}
`
	checkPythonValueFindings(t, pythonValueFindings(t, files, cards), []string{
		"app/shadow.py:39 encrypt",
		"app/optional.py:7 encrypt",
	})
}

// A local holds the value of the assignment that reaches its use (E2.7-py.14b
// gap 2): a later assignment in a block that holds the use replaces it, one
// in a branch adds its value to the earlier one, one later in a loop reaches
// a use earlier in the loop on the next iteration, and a rebinding that is no
// call (`k = other`) ends the flow, for a card's receiver origin and for
// flows_to alike.
func TestPythonReachingAssignments(t *testing.T) {
	files := map[string]string{
		"app/evp.py": `from M2Crypto import EVP

c = EVP.Cipher("aes_128_cbc", "k", "iv", 1)
c.update("x")
c = EVP.Cipher("bf_cbc", "k", "iv", 1)
c.update("y")


def branch(x, k, iv, flag):
    e = EVP.Cipher("aes_128_cbc", k, iv, 1)
    if flag:
        e = EVP.Cipher("bf_cbc", k, iv, 1)
    e.update(x)


def both_branches(x, k, iv, flag):
    if flag:
        e = EVP.Cipher("aes_128_cbc", k, iv, 1)
        e.update(x)
    else:
        e = EVP.Cipher("bf_cbc", k, iv, 1)
        e.update(x)


def loop(xs, k, iv):
    e = EVP.Cipher("aes_128_cbc", k, iv, 1)
    for x in xs:
        e.update(x)
        e = EVP.Cipher("bf_cbc", k, iv, 1)


def rebound(x, k, iv, other):
    e = EVP.Cipher("aes_128_cbc", k, iv, 1)
    e = other
    e.update(x)
`,
		"app/jose.py": `from joserfc import jws
from joserfc.jwk import OctKey


def used(token):
    key = OctKey.generate_key(256)
    return jws.deserialize_compact(token, key)


def rebound(token, other):
    key = OctKey.generate_key(256)
    key = other
    return jws.deserialize_compact(token, key)
`,
	}
	cards := `- rule: aes
  match: {method: update, object: {via: [chain, var], from: [{call: M2Crypto.EVP.Cipher, args: {0|alg: {regex: '^"aes_'}}}]}}
- rule: blowfish
  match: {method: update, object: {via: [chain, var], from: [{call: M2Crypto.EVP.Cipher, args: {0|alg: {regex: '^"bf_'}}}]}}
- rule: oct-key
  match:
    call: joserfc.jwk.OctKey.generate_key
    flows_to: [{arg: 1|public_key, to: {call: joserfc.jws.deserialize_compact}}]
`
	checkPythonValueFindings(t, pythonValueFindings(t, files, cards), []string{
		"app/evp.py:4 aes",
		"app/evp.py:6 blowfish",
		"app/evp.py:13 aes", "app/evp.py:13 blowfish",
		"app/evp.py:19 aes",
		"app/evp.py:22 blowfish",
		"app/evp.py:28 aes", "app/evp.py:28 blowfish",
		"app/jose.py:6 oct-key",
	})
}

// A local bound to a list or tuple of literals reads as that display at the
// call, as if written there (E2.7-py.14b gap 3): the named rule written for
// `algorithms=["HS256"]` reports it and the dynamic one, which excludes a
// written list, does not. A list the function changes stays as written.
func TestPythonLiteralDisplayLocals(t *testing.T) {
	files := map[string]string{
		"app/verify.py": `from jose import jws


def named(token, key):
    algs = ["HS256"]
    a = jws.verify(token, key, algorithms=algs)
    pair = ("HS384", "HS512")
    return a, jws.verify(token, key, pair)


def changed(token, key, extra):
    algs = ["HS256"]
    algs.extend(extra)
    return jws.verify(token, key, algorithms=algs)
`,
	}
	cards := `- rule: verify-hmac
  match: {call: jose.jws.verify, args: {2|algorithms: {regex: '^\[.*"HS(?:256|384|512)".*\]$|^\(.*"HS(?:256|384|512)".*\)$'}}}
- rule: verify-dynamic
  match: {call: jose.jws.verify, args: {2|algorithms: {regex: '^(?!["\[(])'}}}
`
	checkPythonValueFindings(t, pythonValueFindings(t, files, cards), []string{
		"app/verify.py:6 verify-hmac",
		"app/verify.py:8 verify-hmac",
		"app/verify.py:14 verify-dynamic",
	})
}

// A tuple or list pattern assigned a call records each name with the element
// of the call's value it holds (E2.7-py.14b gap 4): a card's `from: {call: ..,
// element: i}` ties `priv.save_pkcs1()` to `pub, priv = rsa.newkeys(..)`, and
// to no other element. A card without `element` does not read an element as
// the call's value; a name after a starred target holds no fixed element.
func TestPythonUnpackedElements(t *testing.T) {
	files := map[string]string{
		"app/keys.py": `import rsa
from pgpy import PGPKey


def private():
    pub, priv = rsa.newkeys(2048)
    priv.save_pkcs1()
    return pub.save_pkcs1()


def parenthesised():
    (pub, _) = rsa.newkeys(2048)
    return pub.save_pkcs1()


def starred():
    first, *rest, last = rsa.newkeys(2048)
    return last.save_pkcs1()


def loaded(path, message):
    key, _others = PGPKey.from_file(path)
    return key.sign(message)


def rebound(other):
    pub, priv = rsa.newkeys(2048)
    priv = other
    return priv.save_pkcs1()
`,
	}
	cards := `- rule: private
  match: {method: save_pkcs1, object: {from: [{call: rsa.newkeys, element: 1}]}}
- rule: public
  match: {method: save_pkcs1, object: {from: [{call: rsa.newkeys, element: 0}]}}
- rule: any-element
  match: {method: save_pkcs1, object: {from: [rsa.newkeys]}}
- rule: sign
  match: {method: sign, object: {from: [{call: pgpy.PGPKey.from_file, element: 0}]}}
`
	checkPythonValueFindings(t, pythonValueFindings(t, files, cards), []string{
		"app/keys.py:7 private",
		"app/keys.py:8 public",
		"app/keys.py:13 public",
		"app/keys.py:23 sign",
	})
}

// A receiver that is a parameter has the origins of the arguments its
// callers in the same file pass (E2.7-py.14b gap 5), through a call written
// in place, a local of the caller and a parameter of the caller in turn
// (bounded as same-file parameter literals are), for a function and a
// method. A parameter the body rebinds before the use, and a caller in
// another file, give none.
func TestPythonParameterOrigins(t *testing.T) {
	files := map[string]string{
		"app/sign.py": `from eth_account import Account


def sign_with(acct, text):
    return acct.sign_message(text)


def rebound(acct, text, other):
    acct = other
    return acct.sign_message(text)


def relay(acct, text):
    return sign_twice(acct, text)


def sign_twice(signer, text):
    return signer.sign_message(text)


class Wallet:
    def sign(self, acct, text):
        return acct.sign_message(text)


def callers(key, text):
    sign_with(Account.from_key(key), text)
    local = Account.create()
    rebound(local, text, None)
    relay(local, text)
    Wallet().sign(Account.create(), text)
`,
		"app/other.py": `from app.sign import sign_with
from eth_account import Account


def elsewhere(key, text):
    def inner(acct):
        return acct.sign_message(text)
    return sign_with(Account.from_key(key), text)
`,
	}
	cards := `- rule: sign-message
  match: {method: sign_message, object: {via: [chain, var], from: [eth_account.Account.from_key, eth_account.Account.create]}}
`
	checkPythonValueFindings(t, pythonValueFindings(t, files, cards), []string{
		"app/sign.py:5 sign-message",
		"app/sign.py:18 sign-message",
		"app/sign.py:23 sign-message",
	})
}

// A `not` over a parameter's origins excludes the call only when every
// same-file caller passes a value it matches: an IV drawn by both callers is
// not the cbc-iv card's, an IV one caller draws and another writes as a
// literal is (OpenGrep reports both, reading the function alone). A caller
// that passes the default, and a parameter no caller fills, leave the call
// reported.
func TestPythonNegatedParameterOrigins(t *testing.T) {
	files := map[string]string{
		"app/vault.py": `import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def lock(key, iv, data):
    return Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor().update(data)


def drawn_only(key, iv):
    return modes.CBC(iv)


def defaulted(key, iv=b"0" * 16):
    return modes.CBC(iv)


def uncalled(iv):
    return modes.CBC(iv)


def seal(key, data):
    iv = os.urandom(16)
    lock(key, iv, data)
    drawn_only(key, iv)
    defaulted(key, iv)
    defaulted(key)


def seal_fixed(key, data):
    iv = os.urandom(16)
    iv = b"fedcba9876543210"
    other = os.urandom(16)
    drawn_only(key, other)
    return lock(key, iv, data)
`,
	}
	cards := `- rule: cbc-iv
  match:
    call: cryptography.hazmat.primitives.ciphers.modes.CBC
    arity: 1
    args:
      0:
        not: {via: var, from: {call: os.urandom}}
`
	checkPythonValueFindings(t, pythonValueFindings(t, files, cards), []string{
		"app/vault.py:6 cbc-iv",
		"app/vault.py:14 cbc-iv",
		"app/vault.py:18 cbc-iv",
	})
}
