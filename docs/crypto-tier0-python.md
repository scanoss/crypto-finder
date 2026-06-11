# Python / PyPI Crypto Library Universe — Tier 0

Anchor list of Python/PyPI libraries that **implement, provide, or wrap** cryptography.
Goal: define what to mine (Tier 0) and what to expand via reverse-deps (Tier 1).

Mirrors the shape of `docs/crypto-tier0-java.md` (the reference artifact).
Produced by the `crypto-coverage-expansion` playbook for the Python ecosystem.

## Status legend

- `verified` — PyPI coordinate confirmed by probe-source (primary source attested)
- `sourced` — coordinate attested by fetched primary source but not yet probe-verified
- `known` — canonical coordinate from domain knowledge, NOT yet machine-verified → must probe

## Coverage classification

| Class | Meaning | Action |
|---|---|---|
| ✅ Covered | Rules + contracts already exist | Mine now |
| 🟡 Standard-API | Routes through Python stdlib (`hashlib`, `hmac`, `ssl`, `secrets`) — **detected for free via stdlib rules**. Note: `cryptography.hazmat` itself is 🔴 Own-API and needs its own contract+rule; the 🟡 benefit applies to OTHER libraries that call hazmat internally and are caught transitively, NOT to pyca/cryptography itself. | Own rule optional for richer metadata |
| 🔴 Own-API | Exposes its own non-standard/native API — **needs its own Semgrep rule** | Author rule first |
| ⚪ Wrapper | Wraps a base lib; no distinct crypto API | Mine-only (caught by callgraph stitching) |

**Ordering rules within a tier:** 🔴 before 🟡; within a class, highest reverse-dependent count first; ⚪ wrappers need no authoring.

## Per-library coverage decision

| Library | Coverage decision |
|---|---|
| hashlib (stdlib) | 🟡 rule-only (stdlib rules) |
| hmac (stdlib) | 🟡 rule-only (stdlib rules) |
| ssl (stdlib) | 🟡 rule-only (stdlib rules) |
| secrets (stdlib) | 🟡 rule-only (stdlib rules) |
| cryptography (pyca) | 🔴 contract + rule (hazmat fluent API) |
| pycryptodome | 🔴 contract + rule (own API: Crypto.*) |
| PyNaCl | 🔴 rule-only (libsodium binding, own API) |
| bcrypt | 🔴 rule-only (own thin API) |
| passlib | ⚪ neither (wraps other libs) |
| PyJWT | 🔴 rule-only (own encoding API) |
| argon2-cffi | 🔴 rule-only (own API: argon2.PasswordHasher) |
| paramiko | 🔴 contract + rule (own SSH crypto API) |
| PyOpenSSL | ⚪ neither (wraps OpenSSL/cryptography) |

---

## 1. Standard crypto APIs — Python stdlib (Type 1 / 🟡)

These route exclusively through the standard library. Detection is free when stdlib rules exist.

| PyPI package | purl prefix | coverage | reverse-deps rank | status | notes |
|---|---|---|---|---|---|
| (stdlib) hashlib | — | 🟡 Standard-API | #1 (transitive everywhere) | — | SHA-{1,2,3}, MD5, BLAKE2 — no PyPI pkg; stdlib module |
| (stdlib) hmac | — | 🟡 Standard-API | #2 | — | HMAC + stdlib MAC |
| (stdlib) ssl | — | 🟡 Standard-API | #3 | — | TLS via OpenSSL binding |
| (stdlib) secrets | — | 🟡 Standard-API | #4 | — | CSPRNG for token/key generation |

**Rule output location:** `semgrep-rules/python/stdlib/`

---

## 2. pyca/cryptography — hazmat primitives (Type 2 / 🔴)

Own fluent/builder API (`Cipher(algo, mode).encryptor()`). The hazmat layer exposes non-JCA constructors that crypto-finder cannot detect from stdlib rules alone. Requires contract KB + rule.

| PyPI package | purl | coverage | reverse-deps (PyPI) | status | notes |
|---|---|---|---|---|---|
| cryptography | `pkg:pypi/cryptography` | 🔴 Own-API | ~170 000+ | sourced | pyca/cryptography; hazmat.primitives.ciphers, hashes, hmac, asymmetric, kdf, x509. **Tier-0 anchor** |

**Smoke contract:** `internal/callgraph/contracts/python/pyca-cryptography.yaml`
**Rule output location:** `semgrep-rules/python/cryptography/`
**Representative APIs that need rules/contracts:**
- `cryptography.hazmat.primitives.ciphers.Cipher` + `.encryptor()` / `.decryptor()` → AES/ChaCha20/3DES
- `cryptography.hazmat.primitives.hashes.Hash` → SHA-2/SHA-3/BLAKE2
- `cryptography.hazmat.primitives.hmac.HMAC`
- `cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key` → RSA
- `cryptography.hazmat.primitives.asymmetric.ec.generate_private_key` → ECDSA/ECDH
- `cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate` → EdDSA
- `cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC` → KDF
- `cryptography.hazmat.primitives.kdf.hkdf.HKDF` → KDF
- `cryptography.fernet.Fernet` → AES-128-CBC + HMAC-SHA256 (high-level)
- `cryptography.hazmat.primitives.serialization.*` → key material I/O

---

## 3. pycryptodome / PyCryptodome (Type 2 / 🔴)

Own modular API (`Crypto.Cipher.AES.new(key, AES.MODE_GCM)`). Hard fork of PyCrypto; widely deployed in enterprise Python. Requires contract KB + rule.

| PyPI package | purl | coverage | reverse-deps (PyPI) | status | notes |
|---|---|---|---|---|---|
| pycryptodome | `pkg:pypi/pycryptodome` | 🔴 Own-API | ~60 000+ | sourced | `Crypto.*` namespace; AES, RSA, ECC, SHA, HMAC, PBKDF2, ChaCha20, Salsa20, Blowfish |
| pycryptodomex | `pkg:pypi/pycryptodomex` | 🔴 Own-API | ~15 000 | sourced | `Cryptodome.*` namespace; identical API to pycryptodome |

**GOTCHA:** Both packages install the same code under different namespaces (`Crypto.*` vs `Cryptodome.*`). Author rules/contracts for BOTH namespaces.
**Contract output:** `internal/callgraph/contracts/python/pycryptodome.yaml`
**Rule output location:** `semgrep-rules/python/pycryptodome/`
**Representative APIs:**
- `Crypto.Cipher.AES.new(key, mode)` → AES (block-cipher/ae)
- `Crypto.Cipher.ChaCha20.new(key=...)` → ChaCha20
- `Crypto.Signature.pkcs1_15.new(key).sign(hash_obj)` → RSA sign
- `Crypto.Signature.DSS.new(key, mode).sign(hash_obj)` → ECDSA
- `Crypto.Hash.SHA256.new(data)` → SHA-2
- `Crypto.Hash.HMAC.new(key, digestmod=...)` → HMAC
- `Crypto.Protocol.KDF.PBKDF2(password, salt, ...)` → KDF
- `Crypto.PublicKey.RSA.generate(bits)` → RSA keygen

---

## 4. PyNaCl — libsodium binding (Type 2 / 🔴)

Own high-level API (`nacl.signing.SigningKey`, `nacl.secret.SecretBox`). Wraps libsodium but exposes its own Pythonic API with no detectable stdlib primitive call. Rule-only (no generic return types requiring KB).

| PyPI package | purl | coverage | reverse-deps (PyPI) | status | notes |
|---|---|---|---|---|---|
| PyNaCl | `pkg:pypi/pynacl` | 🔴 Own-API | ~25 000+ | sourced | libsodium binding; Ed25519, X25519, AES-GCM, ChaCha20-Poly1305, BLAKE2b, Argon2 |

**Rule output location:** `semgrep-rules/python/pynacl/`
**Representative APIs:**
- `nacl.signing.SigningKey` + `.sign()` → Ed25519 sign
- `nacl.signing.VerifyKey.verify()` → Ed25519 verify
- `nacl.public.PrivateKey` / `Box` → X25519 + XSalsa20-Poly1305
- `nacl.secret.SecretBox` → XSalsa20-Poly1305 (AE)
- `nacl.hash.sha256()` / `sha512()` → hash
- `nacl.pwhash.argon2id.kdf()` → KDF (Argon2)

---

## 5. bcrypt — password hashing (Type 2 / 🔴)

Thin own API (`bcrypt.hashpw`, `bcrypt.checkpw`). Rule-only; no generic return types.

| PyPI package | purl | coverage | reverse-deps (PyPI) | status | notes |
|---|---|---|---|---|---|
| bcrypt | `pkg:pypi/bcrypt` | 🔴 Own-API | ~55 000+ | sourced | bcrypt password hashing; wraps cffi OpenSSL bcrypt impl |

**Rule output location:** `semgrep-rules/python/bcrypt/`
**Representative APIs:**
- `bcrypt.hashpw(password, salt)` → KDF/keyderive
- `bcrypt.checkpw(password, hashed_password)` → verify
- `bcrypt.gensalt(rounds=...)` → salt generation

---

## 6. passlib — password hashing framework (⚪ Wrapper)

High-level abstraction that delegates to bcrypt, argon2-cffi, scrypt, PBKDF2, etc. No distinct crypto primitive API; all crypto calls trace through the underlying library.

| PyPI package | purl | coverage | notes |
|---|---|---|---|
| passlib | `pkg:pypi/passlib` | ⚪ Wrapper | Mine-only; caught by callgraph stitching through bcrypt/argon2-cffi dependencies |

---

## 7. PyJWT — JSON Web Tokens (Type 2 / 🔴)

Own encoding/decoding API (`jwt.encode`, `jwt.decode`). Crypto algorithm selected by string argument; detectable as Own-API.

| PyPI package | purl | coverage | reverse-deps (PyPI) | status | notes |
|---|---|---|---|---|---|
| PyJWT | `pkg:pypi/pyjwt` | 🔴 Own-API | ~80 000+ | sourced | JWT encode/decode; uses cryptography lib internally |

**Rule output location:** `semgrep-rules/python/pyjwt/`
**Representative APIs:**
- `jwt.encode(payload, key, algorithm="HS256")` → MAC/sign
- `jwt.decode(token, key, algorithms=[...])` → verify

---

## 8. argon2-cffi — Argon2 KDF (Type 2 / 🔴)

Own high-level API (`argon2.PasswordHasher`). CFFI binding to the argon2 C library.

| PyPI package | purl | coverage | reverse-deps (PyPI) | status | notes |
|---|---|---|---|---|---|
| argon2-cffi | `pkg:pypi/argon2-cffi` | 🔴 Own-API | ~20 000+ | sourced | `argon2.PasswordHasher.hash()` / `.verify()`; argon2id/argon2i/argon2d |

**Rule output location:** `semgrep-rules/python/argon2-cffi/`
**Representative APIs:**
- `argon2.PasswordHasher.hash(password)` → KDF (keyderive)
- `argon2.PasswordHasher.verify(hash, password)` → verify
- `argon2.low_level.hash_secret(...)` → KDF (low-level)

---

## 9. paramiko — SSH (Type 2 / 🔴)

Own SSH crypto API. Uses `cryptography` internally but exposes its own transport, key, and cipher types. Requires contract + rule.

| PyPI package | purl | coverage | reverse-deps (PyPI) | status | notes |
|---|---|---|---|---|---|
| paramiko | `pkg:pypi/paramiko` | 🔴 Own-API | ~50 000+ | sourced | SSH transport; RSA/ECDSA/Ed25519 keys, AES-CTR/AES-GCM, ChaCha20-Poly1305 |

**Contract output:** `internal/callgraph/contracts/python/paramiko.yaml`
**Rule output location:** `semgrep-rules/python/paramiko/`
**Representative APIs:**
- `paramiko.RSAKey.generate(bits=...)` → RSA keygen
- `paramiko.ECDSAKey.generate(bits=...)` → ECDSA keygen
- `paramiko.Ed25519Key(filename=...)` → Ed25519 load
- `paramiko.Transport(sock)` → SSH transport setup

---

## 10. PyOpenSSL — OpenSSL binding (⚪ Wrapper)

Wraps `cryptography` (pyca) internally since 17.0; also wraps OpenSSL via cffi. No distinct crypto primitive API visible above `cryptography`. Caught by callgraph stitching.

| PyPI package | purl | coverage | notes |
|---|---|---|---|
| pyOpenSSL | `pkg:pypi/pyopenssl` | ⚪ Wrapper | Delegates to pyca/cryptography; no own crypto API to rule; mine-only |

---

## Ranked backlog (🔴 first, highest reverse-deps first)

| Priority | Library | Class | Reverse-deps | Contract needed | Rule needed |
|---|---|---|---|---|---|
| 1 | cryptography (pyca) | 🔴 | ~170 000 | yes (smoke done) | yes |
| 2 | PyJWT | 🔴 | ~80 000 | no | yes |
| 3 | pycryptodome | 🔴 | ~60 000 | yes | yes |
| 4 | bcrypt | 🔴 | ~55 000 | no | yes |
| 5 | paramiko | 🔴 | ~50 000 | yes | yes |
| 6 | PyNaCl | 🔴 | ~25 000 | no | yes |
| 7 | argon2-cffi | 🔴 | ~20 000 | no | yes |
| 8 | hashlib (stdlib) | 🟡 | ubiquitous | no | yes |
| 9 | hmac (stdlib) | 🟡 | ubiquitous | no | yes |
| 10 | ssl (stdlib) | 🟡 | ubiquitous | no | yes |
| 11 | secrets (stdlib) | 🟡 | ubiquitous | no | yes |
| 12 | passlib | ⚪ | ~18 000 | no | no |
| 13 | pyOpenSSL | ⚪ | ~35 000 | no | no |

---

## Coordinate hygiene notes

- **pycryptodome vs pycryptodomex**: both install the same code; rule two namespaces (`Crypto.*` and `Cryptodome.*`).
- **argon2-cffi**: PyPI slug is `argon2-cffi` (hyphen); import is `argon2` (no hyphen).
- **PyNaCl**: PyPI slug is `PyNaCl`; import is `nacl`.
- **PyJWT**: PyPI slug is `PyJWT`; import is `jwt`.
- **bcrypt**: slug and import both `bcrypt`.
- **stdlib modules** (hashlib, hmac, ssl, secrets): no PyPI coordinate; detection via import patterns only.

## Probe-source verification status

Coordinates above marked `sourced` require `cli probe-source pkg:pypi/<name>@<version>` before including in the mining seed CSV. This document is the **planning artifact** — the seed CSV is the operational artifact and requires all `verified` status.

All reverse-dependent counts are approximate estimates from PyPI download statistics and deps.dev queries at the time of authoring (2026-06-10). They are ranking signals, not exact counts.
