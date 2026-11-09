- Scans that build a call graph (`--export-callgraph`, `--export-graph-fragment`,
  `--scan-dependencies`) now report a salt, nonce or iv drawn from a random source in one
  function and used in another. The drawn value of a `drbg` finding (`os.urandom`, `rand.Read`,
  `SecureRandom.nextBytes`, `fill_bytes`, `crypto.randomBytes`, ...) is followed through up to
  three application functions; when it reaches an argument the knowledge base marks as related
  crypto material, a `related-crypto-material` asset with that `materialType` is added at the draw
  line with the draw's rule, and it appears in the CBOM. Seeded for Python `cryptography` and
  PyCryptodome, Go `crypto/cipher`, `pbkdf2`, `hkdf`, `scrypt` and `argon2`, Java JCA parameter
  specs, Rust OpenSSL, `pbkdf2`, `hkdf` and `aes-gcm`, and Node `crypto`. A value that may be
  reassigned or overwritten before use is not reported, and a material a rule already reports at
  the draw is not duplicated.
- Contract knowledge bases accept an optional `material_roles` list per contract, mapping an
  argument position or keyword to a CycloneDX relatedCryptoMaterial type. The schema stays `"2"`.
