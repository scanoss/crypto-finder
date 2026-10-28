- `convert` and `scan --format cyclonedx` no longer fail the whole CBOM when a rule reports a padding, mode,
  primitive, execution environment, implementation platform or key material type that CycloneDX 1.7
  does not list, such as a truncated `OAEPWithSHA-` padding. The field is written as `other` and the
  detected value is kept in a `scanoss:` property (`scanoss:algorithmPadding`, `scanoss:algorithmMode`,
  `scanoss:algorithmPrimitive`, `scanoss:executionEnvironment`, `scanoss:implementationPlatform`,
  `scanoss:materialType`).
- CBOM keys, secret keys and other related crypto material are grouped by type, algorithm, size and
  curve instead of by type alone, and named after them (`RSA-2048-key`, `RSA-3072-key`,
  `EC-secp384r1-key`, `AES-256-secret-key`; plain `key` only when nothing more is known). Each
  component carries its own group's `size`, and the algorithm and curve are kept in the
  `scanoss:materialAlgorithm` and `scanoss:curve` properties. Rules can set the new `materialCurve`
  metadata key for elliptic-curve keys.
- The CBOM writes rule family spellings that the CycloneDX family registry knows under another name
  as that registry family: `DH`, `DHE` and `Diffie-Hellman` as `FFDH`, `DESede` and `TripleDES` as
  `3DES`, `Ed25519` and `Ed448` as `EdDSA`, `X25519` and `X448` as `ECDH`.
- Crypto calls whose algorithm the scan cannot resolve, such as `Cipher.getInstance(name)` with a
  runtime value, are no longer dropped from the CBOM. They appear as `unknown-<primitive>` components
  (for example `unknown-block-cipher`, `unknown-hash`) with the `scanoss:unresolved` property set to
  `true`. Algorithm findings without an `algorithmFamily` are no longer dropped either.
- Scan findings no longer report one call twice when two rules describe it: assets on overlapping
  spans with the same algorithm name and family, or the same key material, merge into one asset that
  lists both rules and keeps the more specific rule's metadata over a `generic` rule's. An unresolved
  algorithm asset on the same call as a named one merges into the named one.
