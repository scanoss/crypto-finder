- Scans that build a call graph (`--export-callgraph`, `--export-graph-fragment`,
  `--scan-dependencies`) now report a salt, nonce or iv written as a constant in the source.
  When an argument the knowledge base marks as related crypto material is a constant, such as
  `createCipheriv("aes-128-cbc", key, Buffer.alloc(16))`, or a parameter whose caller passes a
  constant, such as `derive(password, salt=b'saltysalt')` into a helper that calls
  `hashlib.pbkdf2_hmac`, or whose default value is a constant, a `related-crypto-material`
  asset with that `materialType` is added at the constant, with the crypto call's rule. Callers
  are followed up to three calls deep; a parameter the function may rebind before the call is
  not followed. Constants recognized: Python bytes literals (also repeated, as `b' ' * 16`),
  `'text'.encode()`, `bytes(n)`, `bytearray(n)` and `bytes.fromhex(...)`; JavaScript and
  TypeScript string literals, `Buffer.alloc(n)`, `Buffer.from('...')` and `new Uint8Array(n)`.
- The Python `hashlib.pbkdf2_hmac` and `hashlib.scrypt` contracts mark their `salt` argument as
  salt material, so a random draw that reaches it is reported as a salt too.
