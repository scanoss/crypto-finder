# OID mapping research and exact-only catalog

**Audience:** SCANOSS crypto-finder maintainers and policy-engine consumers  
**Research date:** 2026-09-08  
**Repositories:** `scanoss/crypto-finder` current worktree and `scanoss/crypto_finder_poc` at `c8db56bd3c4cb64dac36cbdc6b531b1701d8c6c7`

## Executive answer

The exact-only contract is the right output policy. An OID may be emitted only when the finding identifies the same registered object, at the same semantic level and identifier kind. When key size, mode, digest, curve, operation, or another required discriminator is missing, crypto-finder should omit `oid` and retain the facts it actually observed.

The current implementation is not a mostly-complete table with one HMAC typo. It has three separate data-quality failures:

1. exact algorithm aliases often miss and fall through to family arcs;
2. key OIDs, signature OIDs, scheme OIDs, curve OIDs, and namespace arcs are treated as interchangeable strings;
3. the mapper covers only a small part of the current detection vocabulary.

The customer examples are representative. `HMAC-SHA-256` should resolve to `1.2.840.113549.2.9`; the current spelling misses the exact key and emits the `digestAlgorithm` arc. AES with a known mode but unknown key size cannot select one NIST leaf, so its OID should be omitted.

## Scope and definition of "all possible"

There is no finite registry of every cryptographic algorithm or private OID ever created. This review uses two bounded, reproducible universes:

1. every algorithm asset currently emitted by the production rules and proven by repository fixtures;
2. every family in the live [CycloneDX Cryptography Registry](https://cyclonedx.org/registry/cryptography/), which is designed to evolve independently of a CycloneDX schema version.

The live machine-readable registry was last updated `2026-02-24` and contains **96 algorithm families**. The local skill reference was stale at 77 families. This report uses the live registry. Private enterprise OIDs, expired draft allocations, and secondary OID aggregators are excluded unless an owning authority confirms them.

crypto-finder now emits CycloneDX 1.7 and validates serialized documents against the official 1.7 JSON Schema embedded verbatim from cyclonedx-go v0.12.0. The 1.7 registry remains the canonical algorithm naming inventory because CycloneDX publishes it as an independently usable resource.

## Inventory and coverage

| Measure | Result |
| --- | ---: |
| Algorithm detection rules | 2,949 |
| Unique rule metadata signatures | 939 |
| Concrete fixture signatures | 759 |
| Unique concrete fixture names | 448 |
| Live CycloneDX families | 96 |
| Families emitted directly by current rules | 67 / 96 |
| Families with no direct current emission | 29 / 96 |
| Current mapper exact-name declarations | 106 |
| Current mapper family declarations | 36 |
| Fixture signatures resolving exactly today | 150 / 759, about 20% |
| Fixture signatures receiving a branch fallback | 301 / 759 |
| Fixture signatures left unmapped | 308 / 759 |
| Rule-level OID declarations | 44, all currently ignored |

The metadata inventory also found 553 algorithm rules without `algorithmFamily`, 245 without `algorithmName`, and 106 without either field. Some names are not algorithm identities at all, including `CBC mode`, `OAEP`, `PKCS#7`, `EC`, `AEAD`, `CSPRNG`, and `none`. Those rows require metadata repair before any OID decision.

## Exact-only contract

An OID is eligible for output only when all rules below hold:

1. **Identity match.** The OID identifies the asset represented by the CBOM component, not an ancestor arc.
2. **Identifier-kind match.** A key identifier cannot stand in for a signature or key-agreement operation. A curve identifier cannot stand in for ECDSA. A protocol content type cannot stand in for an algorithm.
3. **Required evidence.** The finding contains every discriminator needed to select one registered OID.
4. **Authority.** The mapping cites the assigning standards body or transferred change-control document.
5. **Stable status.** Expired private drafts and unfinalized composite registrations remain excluded unless SCANOSS adopts an explicit non-stable policy.
6. **Parameter preservation.** Selecting an OID does not erase security-relevant ASN.1 parameters such as PBKDF2 iterations, OAEP hash, PSS salt length, RC2 effective key bits, or GCM tag length.
7. **No ancestor fallback.** Ambiguous findings keep their family, mode, name, and parameters but omit `oid`.

Exact-only means "one registered object," not "the OID contains every risk input." OIDs identify algorithms. They do not replace policy evaluation.

## Current implementation defects

### Wrong or misleading mappings

- `HMAC-SHA-256` misses the registered `HMAC-SHA256` key and falls back to `1.2.840.113549.2`.
- bare `RSASSA-PKCS1` maps to `1.2.840.113549.1.1`, the PKCS #1 arc.
- generic `DSA` maps to the NIST signature-algorithms arc.
- generic `ECDSA` and `ECDH` map to `id-ecPublicKey`, a key identifier rather than an operation identifier.
- generic `DES` is silently treated as DES-CBC.
- generic `SM2` maps to SM2-with-SM3, one particular signature construction.
- generic `RSA` uses `rsaEncryption`, which is appropriate for an RSA key or RSAES-PKCS1-v1_5, not every RSA operation.

### Broken data paths

Rule metadata can declare `metadata.crypto.oid`, but the transformer stores it only in `asset.Metadata["oid"]`. Neither the enricher nor the CycloneDX mapper reads that key, so all 44 declarations are ignored. They cannot simply be promoted: several contain branch or conflicting ECDH/SM2 values that violate the exact-only contract.

The scan pipeline also enriches OIDs after graph-fragment export, and annotate has no equivalent enrichment step. OIDs can therefore differ between final JSON/CBOM and fragment-derived findings.

Fifty-one rules emit `algorithmPrimitive: key-wrap`, but the current CycloneDX Go model used by this project does not accept that primitive for the 1.6 conversion path. This must be fixed before those assets can be counted as exportable exact mappings.

## Implementation-ready exact mappings

The tables below list mappings verified from primary authorities. A row is eligible only when its required discriminators are present.

### AES

All values use the NIST `2.16.840.1.101.3.4.1` arc. The family OID itself is not eligible for exact-only output.

| Construction | AES-128 | AES-192 | AES-256 |
| --- | --- | --- | --- |
| ECB | `.1` | `.21` | `.41` |
| CBC | `.2` | `.22` | `.42` |
| OFB | `.3` | `.23` | `.43` |
| CFB | `.4` | `.24` | `.44` |
| Key wrap | `.5` | `.25` | `.45` |
| GCM | `.6` | `.26` | `.46` |
| CCM | `.7` | `.27` | `.47` |
| Key wrap with padding | `.8` | `.28` | `.48` |
| GMAC | `.9` | `.29` | `.49` |

Source: [NIST CSOR Algorithm Registration](https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration). AES-CTR, XTS, CTS, EAX, SIV, GCM-SIV and OCB do not appear in this NIST OID set. Candidate IEEE XTS OIDs remain excluded until their primary registry can be verified.

### Hashes, XOFs and MACs

| Asset | Exact OID or range | Required evidence |
| --- | --- | --- |
| SHA-224/256/384/512 | `2.16.840.1.101.3.4.2.4/.1/.2/.3` | Exact digest |
| SHA-512/224 and SHA-512/256 | `2.16.840.1.101.3.4.2.5/.6` | Exact truncated SHA-512 variant |
| SHA3-224/256/384/512 | `2.16.840.1.101.3.4.2.7` through `.10` | Exact SHA-3 output size |
| SHAKE128/256 | `2.16.840.1.101.3.4.2.11/.12` | Exact XOF |
| SHAKE128-LEN/256-LEN | `2.16.840.1.101.3.4.2.17/.18` | Exact XOF plus output-length parameter |
| SHA-1 | `1.3.14.3.2.26` | Explicit SHA-1 |
| SHA-0 | `1.3.14.3.2.18` | Explicit original SHA only |
| MD2/MD4/MD5 | `1.2.840.113549.2.2/.4/.5` | Exact digest |
| HMAC-SHA1 | `1.2.840.113549.2.7` | Exact underlying SHA-1 hash |
| HMAC-SHA224/256/384/512 | `1.2.840.113549.2.8` through `.11` | Exact underlying hash |
| HMAC-SHA512/224 and /256 | `1.2.840.113549.2.12/.13` | Exact truncated SHA-512 variant |
| HMAC-SHA3-224/256/384/512 | `2.16.840.1.101.3.4.2.13` through `.16` | Exact underlying SHA-3 variant |
| KMAC-with-SHAKE128/256 | `2.16.840.1.101.3.4.2.19/.20` | Exact SHAKE basis; length/customization remain parameters |
| KMAC128/256 | `2.16.840.1.101.3.4.2.21/.22` | Exact security variant; customization remains a parameter |
| BLAKE2b-160/256/384/512 | `1.3.6.1.4.1.1722.12.2.1.5/.8/.12/.16` | b architecture plus digest length |
| BLAKE2s-128/160/224/256 | `1.3.6.1.4.1.1722.12.2.2.4/.5/.7/.8` | s architecture plus digest length |
| RIPEMD-160/128/256 | `1.3.36.3.2.1/.2/.3` | Exact digest size |
| Whirlpool | `1.0.10118.3.0.55` | Exact Whirlpool hash |
| SM3 | `1.2.156.10197.1.401` | Exact SM3 hash |
| HMAC-SM3 | `1.2.156.10197.1.401.2` | HMAC operation with SM3 |
| GOST 2012-256/512 | `1.2.643.7.1.1.2.2/.3` | Generation and output size |
| HMAC-GOST-2012-256/512 | `1.2.643.7.1.1.4.1/.2` | HMAC operation and output size |

HMAC-MD5 remains unresolved because the commonly used `.2.6` value was not found in an accessible primary assignment record. RFC 2104 defines the construction but assigns no OID.

Sources: [NIST CSOR](https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration), [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231.html), [RFC 8018](https://www.rfc-editor.org/rfc/rfc8018.html), [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693.html), [TeleTrusT RIPEMD registry](https://www.teletrust.de/fileadmin/docs/projekte/oid/OID-Liste_1_3_36_3_2.pdf), [RFC 9231](https://www.rfc-editor.org/rfc/rfc9231.html), [RFC 7836](https://www.rfc-editor.org/rfc/rfc7836.html), and the [official GM/T 0006 successor draft](https://std.samr.gov.cn/dcpspTools/gbPlan/download?path=%2Fzxd%2F2024005092%2F20_%E6%A0%87%E5%87%86%E8%B5%B7%E8%8D%89%2F20_WD_2024005092_%E7%BD%91%E7%BB%9C%E5%AE%89%E5%85%A8%E6%8A%80%E6%9C%AF+%E5%AF%86%E7%A0%81%E5%BA%94%E7%94%A8%E6%A0%87%E8%AF%86.pdf).

### Symmetric ciphers, AEAD and key wrap

| Asset | Exact OID or range | Required evidence |
| --- | --- | --- |
| DES ECB/CBC/OFB/CFB | `1.3.14.3.2.6/.7/.8/.9` | Exact mode |
| 3DES-CBC | `1.2.840.113549.3.7` | CBC mode; keying option remains separate |
| RC2-CBC | `1.2.840.113549.3.2` | CBC; effective key bits and IV remain parameters |
| RC4 | `1.2.840.113549.3.4` | Exact stream cipher |
| RC5-CBC-PAD | `1.2.840.113549.3.9` | CBC+padding; rounds/block size/IV remain parameters |
| CAST5-CBC/MAC/wrap | `1.2.840.113533.7.66.10/.11/.15` | Exact construction |
| IDEA-CBC/wrap | `1.3.6.1.4.1.188.7.1.1.2/.6` | Exact construction |
| Camellia 128/192/256-CBC | `1.2.392.200011.61.1.1.1.2/.3/.4` | Key size plus CBC |
| Camellia 128/192/256 wrap | `1.2.392.200011.61.1.1.3.2/.3/.4` | KEK size plus wrap |
| SEED-CBC | `1.2.410.200004.1.4` | CBC |
| SEED wrap | `1.2.410.200004.7.1.1.1` | Key-wrap construction |
| ARIA 128/192/256 ECB-CBC-CFB-OFB-CTR | `1.2.410.200046.1.1.1` through `.15` | Key size plus exact mode |
| ARIA 128/192/256 CMAC | `...1.1.21` through `.23` | Key size plus CMAC |
| ARIA 128/192/256 OCB2 | `...1.1.31` through `.33` | Key size plus OCB2 |
| ARIA 128/192/256 GCM | `...1.1.34` through `.36` | Key size plus GCM |
| ARIA 128/192/256 CCM | `...1.1.37` through `.39` | Key size plus CCM |
| ARIA 128/192/256 KW/KWP | `...1.1.40` through `.45` | KEK size plus exact wrap construction |
| ChaCha20-Poly1305 | `1.2.840.113549.1.9.16.3.18` | Combined IETF AEAD only |
| SM4 ECB/CBC/CFB/OFB/CTR | `1.2.156.10197.1.104.1/.2/.3/.4/.6` | Exact mode |
| SM4 XTS/GCM/CCM/EAX/HCTR | `1.2.156.10197.1.104.9/.10/.11/.12/.13` | Exact mode |
| SM4 CBC-MAC/CMAC | `1.2.156.10197.1.104.5.1/.5` | Exact MAC construction |
| GOST 28147-89 cipher/MAC | `1.2.643.2.2.21/.22` | Cipher versus MAC plus parameter set |
| Magma CTR-ACPKM / with OMAC | `1.2.643.7.1.1.5.1.1/.2` | Exact combined construction |
| Kuznyechik CTR-ACPKM / with OMAC | `1.2.643.7.1.1.5.2.1/.2` | Exact combined construction |

Sources: [RFC 8018](https://www.rfc-editor.org/rfc/rfc8018.html), [RFC 2984](https://www.rfc-editor.org/rfc/rfc2984.html), [RFC 3058](https://www.rfc-editor.org/rfc/rfc3058.html), [RFC 3657](https://www.rfc-editor.org/rfc/rfc3657.html), [RFC 4010](https://www.rfc-editor.org/rfc/rfc4010.html), [RFC 5794](https://www.rfc-editor.org/rfc/rfc5794.html), [RFC 8103](https://www.rfc-editor.org/rfc/rfc8103.html), [RFC 4357](https://www.rfc-editor.org/rfc/rfc4357.html), [RFC 9337](https://www.rfc-editor.org/rfc/rfc9337.html), and [GM/T 0006-2023 publication notice](https://www.oscca.gov.cn/sca/xwdt/2023-12/06/content_1061146.shtml).

### Password, KDF and password-based schemes

| Asset | Exact OID | Required retained parameters |
| --- | --- | --- |
| PBKDF2 | `1.2.840.113549.1.5.12` | PRF, salt, iterations and derived-key length |
| scrypt | `1.3.6.1.4.1.11591.4.11` | Salt, N, r, p and optional key length |
| HKDF-SHA256/384/512 | `1.2.840.113549.1.9.16.3.28/.29/.30` | Exact underlying hash |
| PBES2 | `1.2.840.113549.1.5.13` | KDF and encryption AlgorithmIdentifiers |
| PBMAC1 | `1.2.840.113549.1.5.14` | KDF and MAC AlgorithmIdentifiers |
| PBES1 MD2-DES, MD5-DES, MD2-RC2, MD5-RC2, SHA1-DES, SHA1-RC2 | `1.2.840.113549.1.5.1/.3/.4/.6/.10/.11` | Exact hash+cipher pair, salt and iterations |

PBKDF1 explicitly has no OID in RFC 8018. Argon2, bcrypt, yescrypt, SP800-108, SP800-56C, ANSI-KDF, TLS-PRF and the DRBG families have no verified standalone OID in their defining standards.

Sources: [RFC 8018](https://www.rfc-editor.org/rfc/rfc8018.html), [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914.html), [RFC 8619](https://www.rfc-editor.org/rfc/rfc8619.html), [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html), [NIST SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final), and [NIST SP 800-56C Rev. 2](https://csrc.nist.gov/pubs/sp/800/56/c/r2/final).

### RSA, DSA, ECDSA and key agreement

| Asset | Exact OID or range | Required evidence |
| --- | --- | --- |
| RSA key or RSAES-PKCS1-v1_5 | `1.2.840.113549.1.1.1` | Identifier kind must be key or PKCS#1 v1.5 encryption |
| RSAES-OAEP | `1.2.840.113549.1.1.7` | OAEP; hash, MGF and label remain parameters |
| RSASSA-PSS | `1.2.840.113549.1.1.10` | PSS; hash, MGF, salt length and trailer remain parameters |
| RSA PKCS#1 signatures MD2/MD5/SHA1/SHA224/SHA256/SHA384/SHA512 | `.1.1.2/.4/.5/.14/.11/.12/.13` | Exact digest |
| RSA PKCS#1 SHA-512/224 and /256 | `.1.1.15/.16` | Exact truncated SHA-512 variant |
| RSA PKCS#1 SHA3-224/256/384/512 | `2.16.840.1.101.3.4.3.13` through `.16` | Exact SHA-3 variant |
| RSA-PSS-SHAKE128/256 | `1.3.6.1.5.5.7.6.30/.31` | Exact SHAKE profile |
| DSA-SHA1 | `1.2.840.10040.4.3` | Exact digest |
| DSA SHA2-224/256/384/512 | `2.16.840.1.101.3.4.3.1` through `.4` | Exact digest |
| DSA SHA3-224/256/384/512 | `2.16.840.1.101.3.4.3.5` through `.8` | Exact digest |
| ECDSA-SHA1 | `1.2.840.10045.4.1` | Exact digest |
| ECDSA SHA2-224/256/384/512 | `1.2.840.10045.4.3.1` through `.4` | Exact digest |
| ECDSA SHA3-224/256/384/512 | `2.16.840.1.101.3.4.3.9` through `.12` | Exact digest |
| ECDSA-SHAKE128/256 | `1.3.6.1.5.5.7.6.32/.33` | Exact SHAKE profile |
| X25519/X448 | `1.3.101.110/.111` | Exact algorithm |
| Pure Ed25519/Ed448 | `1.3.101.112/.113` | Pure mode only |
| X9.42 DH public key | `1.2.840.10046.2.1` | Key asset plus domain parameters |
| Restricted ECDH/ECMQV public key | `1.3.132.1.12/.13` | Key kind plus named curve |

Sources: [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html), [RFC 3279](https://www.rfc-editor.org/rfc/rfc3279.html), [RFC 5758](https://www.rfc-editor.org/rfc/rfc5758.html), [RFC 8692](https://www.rfc-editor.org/rfc/rfc8692.html), [RFC 5480](https://www.rfc-editor.org/rfc/rfc5480.html), [RFC 5753](https://www.rfc-editor.org/rfc/rfc5753.html), and [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410.html).

### Chinese public-key and identity-based algorithms

| Asset | Exact OID | Required evidence |
| --- | --- | --- |
| SM2 signature | `1.2.156.10197.1.301.1` | Signature operation; hash remains separate |
| SM2 key exchange | `1.2.156.10197.1.301.2` | Key-exchange operation |
| SM2 public-key encryption | `1.2.156.10197.1.301.3` | Encryption operation |
| SM9 signature/key exchange/encryption/KEM | `1.2.156.10197.1.302.1/.2/.3/.4` | Exact operation |

Source: the [official GM/T 0006 successor draft registry appendix](https://std.samr.gov.cn/dcpspTools/gbPlan/download?path=%2Fzxd%2F2024005092%2F20_%E6%A0%87%E5%87%86%E8%B5%B7%E8%8D%89%2F20_WD_2024005092_%E7%BD%91%E7%BB%9C%E5%AE%89%E5%85%A8%E6%8A%80%E6%9C%AF+%E5%AF%86%E7%A0%81%E5%BA%94%E7%94%A8%E6%A0%87%E8%AF%86.pdf), with [OSCCA's GM/T 0006-2023 publication notice](https://www.oscca.gov.cn/sca/xwdt/2023-12/06/content_1061146.shtml). Do not confuse the generic SM2 signature OID with `1.2.156.10197.1.501`, which identifies the specific SM2-with-SM3 construction.

### Stateful and post-quantum algorithms

| Asset | Exact OID or range | Required evidence |
| --- | --- | --- |
| HSS/LMS | `1.2.840.113549.1.9.16.3.17` | HSS/LMS encoding established |
| XMSS / XMSS^MT | `1.3.6.1.5.5.7.6.34/.35` | Exact scheme |
| ML-DSA-44/65/87 | `2.16.840.1.101.3.4.3.17/.18/.19` | Pure variant and parameter set |
| HashML-DSA-44/65/87-SHA512 | `2.16.840.1.101.3.4.3.32/.33/.34` | Prehash variant and parameter set |
| ML-KEM-512/768/1024 | `2.16.840.1.101.3.4.4.1/.2/.3` | Exact parameter set |
| Pure SLH-DSA parameter sets | `2.16.840.1.101.3.4.3.20` through `.31` | Pure mode plus full parameter set |
| HashSLH-DSA parameter sets | `2.16.840.1.101.3.4.3.35` through `.46` | Prehash mode plus full parameter set |
Sources: [RFC 9802](https://www.rfc-editor.org/rfc/rfc9802.html), [NIST CSOR](https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration), [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html), [RFC 9909](https://www.rfc-editor.org/rfc/rfc9909.html), [RFC 9935](https://www.rfc-editor.org/rfc/rfc9935.html), and [RFC 9936](https://www.rfc-editor.org/rfc/rfc9936.html).

Pre-standard Kyber, Dilithium and SPHINCS+ names must not be aliased to ML-KEM, ML-DSA or SLH-DSA without version evidence. Composite ML-DSA/ML-KEM OIDs are registered while their defining documents remain drafts; they are not part of the stable exact catalog yet.

### Curves

The OID of a named curve is separate from the OID of ECDSA, ECDH or an EC public key. The live CycloneDX curve registry already carries curve OIDs and aliases. The current rules statically emit ten canonical `ellipticCurve` values: `BLS12-381`, `bn254`, `P-256`, `P-384`, `P-521`, `Curve25519`, `Curve448`, `Ed25519`, `Ed448`, and `secp256k1`. The older `curve` metadata field accounts for only four of those values.

- `secp256k1` has curve OID `1.3.132.0.10`.
- `BLS12-381` has no OID in the live CycloneDX registry.
- `Curve25519` is not enough to choose between X25519 and Ed25519.
- `Ed25519` identifies the pure EdDSA algorithm as `1.3.101.112`; it must not be treated as a generic curve substitute.

Common named-curve OIDs include P-192 `1.2.840.10045.3.1.1`, P-224 `1.3.132.0.33`, P-256 `1.2.840.10045.3.1.7`, P-384 `1.3.132.0.34`, P-521 `1.3.132.0.35`, and brainpoolP160r1 through brainpoolP512t1 under `1.3.36.3.3.2.8.1.1.1` through `.14`. Prefer the live [CycloneDX machine-readable registry](https://cyclonedx.org/schema/cryptography-defs.json) for curve alias normalization.

## Full live-family disposition matrix

`Detected` means at least one current rule emits the exact live `algorithmFamily` string. It does not imply the rule carries enough evidence for an OID.

| CycloneDX family | Detected | OID disposition | Exact-only requirement |
| --- | --- | --- | --- |
| `3DES` | Yes | Variant/context exact | 3DES-CBC and CMS 3DES wrap; generic 3DES is insufficient |
| `3GPP-XOR` | No | No verified OID | No authoritative ASN.1 algorithm OID found |
| `A5/1` | No | No verified OID | Uses telecom algorithm identifiers, not a verified OID |
| `A5/2` | No | No verified OID | Uses telecom algorithm identifiers, not a verified OID |
| `AES` | Yes | Variant/context exact | 27 NIST leaves require key size plus mode or construction |
| `ANSI-KDF` | No | No verified OID | No standalone KDF OID; combined ECDH/MQV scheme OIDs are different objects |
| `ARIA` | Yes | Verified exact | Key-size-specific ECB/CBC/CFB/OFB/CTR, CMAC, OCB2, GCM, CCM, KW and KWP |
| `Argon2` | Yes | No verified OID | RFC 9106 assigns no OID |
| `Ascon` | Yes | No verified OID | SP 800-232 defines variants; NIST CSOR currently has no allocation |
| `BLAKE2` | Yes | Variant/context exact | Eight RFC 7693 leaves require b/s architecture and digest length |
| `BLAKE3` | Yes | No verified OID | Defining specification has no OID |
| `BLS` | Yes | No verified OID | Ciphersuite identifiers, no stable IETF/NIST OID |
| `Blowfish` | Yes | Unresolved | Expired private-enterprise Internet-Draft assignments only |
| `CAMELLIA` | Yes | Variant/context exact | RFC leaves for 128/192/256 CBC and wrap |
| `CAST5` | Yes | Variant/context exact | CBC, MAC and CMS wrap identifiers; mode/construction required |
| `CAST6` | Yes | Unresolved | No primary authoritative OID verified |
| `CMAC` | Yes | Variant/context exact | ARIA-CMAC and SM4-CMAC exist; no generic/AES-CMAC OID verified |
| `CMEA` | No | No verified OID | No authoritative ASN.1 algorithm OID found |
| `CTR_DRBG` | No | No verified OID | SP 800-90A defines it without an OID |
| `ChaCha` | Yes | No verified OID | No standalone exact OID verified |
| `ChaCha20` | Yes | Variant/context exact | Only combined ChaCha20-Poly1305 AEAD has a verified OID |
| `DES` | Yes | Variant/context exact | ECB/CBC/OFB/CFB leaves; mode required |
| `DSA` | Yes | Variant/context exact | Key and hash-specific signature OIDs are distinct |
| `ECDH` | Yes | Variant/context exact | Restricted key and CMS scheme identifiers; curve/hash/context required |
| `ECDSA` | Yes | Variant/context exact | Hash-specific signature OID; curve is a separate identifier |
| `ECIES` | Yes | No verified OID | No general IETF/NIST ECIES AlgorithmIdentifier OID |
| `EdDSA` | Yes | Variant/context exact | Pure Ed25519 and Ed448 only; ph/ctx variants are different |
| `ElGamal` | Yes | Unresolved | No stable exact IETF/NIST OID verified |
| `FFDH` | Yes | Variant/context exact | X9.42/PKCS#3 key identifiers; TLS FFDHE groups use numbers |
| `Fortuna` | No | No verified OID | No authoritative ASN.1 algorithm OID found |
| `GOST` | Yes | Variant/context exact | Generation, operation, output size, mode and parameter set required |
| `HC` | No | No verified OID | No authoritative ASN.1 algorithm OID found |
| `HKDF` | Yes | Variant/context exact | RFC leaves only for SHA-256, SHA-384 and SHA-512 |
| `HMAC` | Yes | Variant/context exact | Hash-specific leaves; generic HMAC must remain empty |
| `HMAC_DRBG` | No | No verified OID | SP 800-90A defines it without an OID |
| `HPKE` | No | No verified OID | RFC 9180 uses numeric ciphersuite registries |
| `Hash_DRBG` | No | No verified OID | SP 800-90A defines it without an OID |
| `IDEA` | Yes | Variant/context exact | CBC and CMS wrap identifiers |
| `IKE-PRF` | No | No verified OID | IKE uses transform identifiers, not a standalone OID |
| `J-PAKE` | No | No verified OID | RFC 8236 assigns no OID |
| `LMS` | Yes | Verified exact | HSS/LMS AlgorithmIdentifier; parameter set remains encoded separately |
| `MD2` | Yes | Verified exact | Exact digest OID |
| `MD4` | Yes | Verified exact | Exact digest OID |
| `MD5` | Yes | Verified exact | Exact digest OID |
| `MILENAGE` | No | No verified OID | No authoritative ASN.1 algorithm OID found |
| `ML-DSA` | Yes | Variant/context exact | Pure and prehash variants have distinct NIST leaves |
| `ML-KEM` | Yes | Variant/context exact | 512/768/1024 have distinct NIST leaves |
| `MQV` | Yes | Variant/context exact | Restricted key and CMS scheme identifiers; parameters required |
| `OPAQUE` | No | No verified OID | RFC 9807 assigns no OID |
| `PBES1` | No | Variant/context exact | Six concrete hash+cipher scheme leaves; no family fallback |
| `PBES2` | Yes | Verified exact | Scheme OID exists; KDF and encryption AlgorithmIdentifiers remain parameters |
| `PBKDF1` | Yes | No verified OID | RFC 8018 explicitly assigns no OID |
| `PBKDF2` | Yes | Verified exact | Scheme OID exists; PRF, salt, iterations and key length remain parameters |
| `PBMAC1` | No | Verified exact | Scheme OID exists; KDF and MAC AlgorithmIdentifiers remain parameters |
| `Poly1305` | Yes | Variant/context exact | Only combined ChaCha20-Poly1305 AEAD has a verified OID |
| `RABBIT` | No | No verified OID | No authoritative ASN.1 algorithm OID found |
| `RC2` | Yes | Variant/context exact | RC2-CBC and CMS wrap; parameters retain effective key bits |
| `RC4` | Yes | Verified exact | Exact stream-cipher OID, deprecated |
| `RC5` | Yes | Variant/context exact | RC5-CBC-PAD; rounds/block size/IV remain parameters |
| `RC6` | Yes | Unresolved | No primary authoritative OID verified |
| `RIPEMD` | Yes | Variant/context exact | TeleTrusT leaves for 128/160/256; RIPEMD-320 unresolved |
| `RSAES-OAEP` | Yes | Verified exact | Scheme OID exists; hash, MGF and label remain parameters |
| `RSAES-PKCS1` | Yes | Variant/context exact | rsaEncryption only when PKCS#1 v1.5 encryption or a key is established |
| `RSASSA-PKCS1` | Yes | Variant/context exact | Digest-specific signature leaves; bare PKCS#1 arc is invalid |
| `RSASSA-PSS` | Yes | Variant/context exact | Generic parameterized OID plus exact SHAKE profiles |
| `SEED` | Yes | Variant/context exact | CBC and CMS wrap identifiers |
| `SHA-1` | Yes | Verified exact | Exact digest OID, legacy/restricted |
| `SHA-2` | Yes | Variant/context exact | Six exact digest leaves |
| `SHA-3` | Yes | Variant/context exact | SHA3, SHAKE, HMAC-SHA3 and KMAC leaves |
| `SLH-DSA` | Yes | Variant/context exact | Pure and prehash parameter sets have distinct NIST leaves |
| `SM2` | Yes | Variant/context exact | Signature/key-agreement/encryption uses are distinct; generic SM2 is insufficient |
| `SM3` | Yes | Verified exact | Exact digest OID |
| `SM4` | Yes | Variant/context exact | Exact mode and MAC leaves; family node is not exact |
| `SM9` | No | Variant/context exact | Signature, key exchange, encryption and KEM leaves |
| `SNOW3G` | No | No verified OID | No authoritative ASN.1 algorithm OID found |
| `SP800-108` | No | No verified OID | No standalone OID verified for the KDF family |
| `SP800-56C` | No | No verified OID | Defining standard assigns no OID |
| `SPAKE2` | No | No verified OID | RFC 9382 assigns no algorithm OID |
| `SPAKE2PLUS` | No | No verified OID | RFC 9383 assigns no algorithm OID |
| `SRP` | No | No verified OID | RFC 2945/TLS-SRP use parameters or cipher-suite numbers |
| `Salsa20` | Yes | No verified OID | No authoritative ASN.1 algorithm OID verified |
| `Serpent` | Yes | Unresolved | No primary authoritative OID verified |
| `SipHash` | Yes | No verified OID | No authoritative ASN.1 algorithm OID verified |
| `Skipjack` | Yes | Unresolved | No implementation-ready primary mapping verified |
| `TLS-PRF` | No | No verified OID | Selected through TLS version/cipher suite, not an OID |
| `TUAK` | No | No verified OID | No authoritative ASN.1 algorithm OID found |
| `Twofish` | Yes | Unresolved | No primary authoritative OID verified |
| `UMAC` | Yes | No verified OID | RFC 4418 assigns no OID |
| `Whirlpool` | Yes | Verified exact | ISO/IEC OID published by RFC 9231 |
| `X3DH` | No | No verified OID | Protocol suite identifiers, no stable OID verified |
| `XMSS` | Yes | Variant/context exact | XMSS and XMSS^MT have distinct RFC 9802 OIDs |
| `Yarrow` | Yes | No verified OID | No authoritative ASN.1 algorithm OID found |
| `ZUC` | Yes | Unresolved | No primary authoritative ASN.1 mapping verified |
| `bcrypt` | Yes | No verified OID | No authoritative OID; never use Blowfish cipher OIDs |
| `scrypt` | Yes | Verified exact | Exact scheme OID; cost parameters remain separate |
| `yescrypt` | No | No verified OID | Uses encoded-hash identifiers, no standardized OID |

## Missing-family coverage

The 29 live families with no direct current `algorithmFamily` emission are:

`3GPP-XOR`, `A5/1`, `A5/2`, `ANSI-KDF`, `CMEA`, `CTR_DRBG`, `Fortuna`, `HC`, `HMAC_DRBG`, `HPKE`, `Hash_DRBG`, `IKE-PRF`, `J-PAKE`, `MILENAGE`, `OPAQUE`, `PBES1`, `PBMAC1`, `RABBIT`, `SM9`, `SNOW3G`, `SP800-108`, `SP800-56C`, `SPAKE2`, `SPAKE2PLUS`, `SRP`, `TLS-PRF`, `TUAK`, `X3DH`, and `yescrypt`.

Some have name-only or related detections today: HPKE, TLS-PRF, ANSI-KDF/X9.63, SP800-108, generic DRBG names, and one yescrypt rule mislabeled as bcrypt. These are metadata-normalization tasks, not just mapper additions.

## Correction record: authoritative catalog and fixture expectations

The compiled catalog stores the registered name, registered identifier, authority, primary source, registration state, and explicit required dimensions for each emitting object. Constructor validation rejects duplicate canonical selectors, alias-to-canonical collisions, non-emitting states, and incomplete evidence.

`internal/oid/catalog.json` is the committed authority-evidence manifest used by
production. Each positive row carries the registered name and identifier, object
class, registration state, required dimensions, and the authoritative URL from
the claim-to-source ledger below; resolver code never derives those facts from a
selector or an OID. SHA-1 is recorded as `Legacy` and RC4 as `Deprecated`, as
classified in the disposition matrix. The catalog digest test makes every row
addition, omission, or mutation an explicit evidence-review change.

NIST CSOR leaves must use their concrete registered names. In particular, the twelve pure `SLH-DSA-SHA2/SHAKE-*` objects occupy `2.16.840.1.101.3.4.3.20` through `.31`; the twelve `HASH-SLH-DSA-*-WITH-*` objects occupy `.35` through `.46`. Synthetic arc-derived labels are not registrations and are prohibited. Curve resolution separately includes P-192/P-224/P-256/P-384/P-521 and brainpoolP160r1 through brainpoolP512t1 from the CycloneDX registry evidence cited below.

The 759-row fixture file is a frozen, independently curated expectation: every row contains source selector facts, terminal disposition, record reference, and report evidence. Its generator only reads the pinned fixture corpus and preserves reviewed expectations; it never calls the resolver to manufacture expected policy. `Ascon`, `BLAKE3`, `ECIES`, and `Salsa20` are `no_standard`; `Blowfish`, `Twofish`, `Serpent`, and `ZUC` are `unresolved`, per the primary-source/disposition matrix above.

## Recommended registry design

Replace the two unvalidated string maps with one curated record set:

```go
type OIDRecord struct {
    CanonicalName       string
    OID                 string
    IdentifierKind      IdentifierKind
    RequiredDimensions  []Dimension
    ParameterEncoding   ParameterEncoding
    Status              RegistrationStatus
    Authority           string
    SourceURL           string
    Aliases             []string
}
```

Resolution should return the matched record and missing dimensions, not a bare string. The export policy then emits only exact matches. Registry construction must reject alias collisions and duplicate selectors with different OIDs.

Recommended implementation order:

1. repair rule metadata identity and canonical names using the live CycloneDX registry patterns;
2. add exact alias normalization and regression fixtures, including `HMAC-SHA-256`;
3. introduce the validated record registry and remove all family fallback output;
4. load the implementation-ready mappings in this report;
5. centralize enrichment before every JSON, CBOM, annotate, and graph-fragment export path;
6. validate or reject rule-supplied OIDs against the curated registry;
7. add coverage tests that compare rule fixture signatures to the registry and fail when a new exact asset lacks a disposition;
8. keep unresolved and no-OID assets explicit so missing evidence never becomes a guessed identifier.

## Automated quality gates

The durable tests should assert:

- no emitted OID is a known namespace/family arc;
- every OID maps to the correct identifier kind;
- every exact mapping cites an authority and required dimensions;
- aliases cannot resolve to conflicting records;
- all 759 concrete fixture signatures have a disposition: exact, insufficient evidence, no standard OID, or unresolved;
- the live CycloneDX registry snapshot age is visible and updateable;
- rule-level OIDs are either validated and promoted or rejected;
- enrichment happens before every export form;
- parameterized schemes retain their risk-relevant metadata;
- introducing a new rule family or concrete fixture name fails CI until its OID disposition is recorded.

## Limitations and remaining primary-source gaps

- HMAC-MD5 `.2.6` is common in implementations but still lacks a verified accessible primary assignment in this review.
- AES-XTS candidate OIDs require direct IEEE registry verification.
- RC6, CAST6, Twofish, Serpent, Skipjack and ZUC need owning-registry evidence before admission.
- Blowfish has expired private-enterprise draft OIDs, which are excluded by the stable-policy rule.
- RIPEMD-320 has no entry in the reviewed TeleTrusT registry.
- Some national and telecom algorithms may have non-public or jurisdiction-specific registries. They remain unresolved rather than guessed.
- The production rules inventory is a point-in-time snapshot. The proposed CI disposition check is what keeps the catalog current.

The research stopped after every current live family had a disposition, every currently implemented mapping had been classified, the high-impact missing standards families had primary-source evidence, and another broad search was unlikely to change the exact-only policy. The unresolved rows require access to specific owner registries, not more generic web searching.

## Claim-to-source ledger

| Claim family | Primary source |
| --- | --- |
| CycloneDX algorithm families, patterns and curve registry | [CycloneDX Cryptography Registry](https://cyclonedx.org/registry/cryptography/) and [machine-readable definitions](https://cyclonedx.org/schema/cryptography-defs.json), updated 2026-02-24 |
| CycloneDX OID and algorithm-property semantics | [CycloneDX 1.7 reference](https://cyclonedx.org/docs/1.7/proto/) and [cryptographic algorithm use case](https://cyclonedx.org/use-cases/cryptographic-algorithm/) |
| NIST AES, SHA, SHA3, SHAKE, KMAC, HMAC-SHA3, DSA, ML-DSA, ML-KEM and SLH-DSA registrations | [NIST CSOR Algorithm Registration](https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration), updated 2025-06-13 |
| PKCS#1 RSA schemes and signatures | [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html), IETF, 2016 |
| PKCS#5 password schemes, KDFs and HMAC variants | [RFC 8018](https://www.rfc-editor.org/rfc/rfc8018.html), IETF, 2017 |
| EC key, signature and key-agreement identifiers | [RFC 5480](https://www.rfc-editor.org/rfc/rfc5480.html), [RFC 5753](https://www.rfc-editor.org/rfc/rfc5753.html), [RFC 5758](https://www.rfc-editor.org/rfc/rfc5758.html), and [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410.html) |
| Classical cipher registrations | [RFC 2984](https://www.rfc-editor.org/rfc/rfc2984.html), [RFC 3058](https://www.rfc-editor.org/rfc/rfc3058.html), [RFC 3657](https://www.rfc-editor.org/rfc/rfc3657.html), [RFC 4010](https://www.rfc-editor.org/rfc/rfc4010.html), [RFC 5794](https://www.rfc-editor.org/rfc/rfc5794.html), and [RFC 8103](https://www.rfc-editor.org/rfc/rfc8103.html) |
| SM2, SM3/HMAC-SM3, SM4 and SM9 identifiers | [Official GM/T 0006 successor draft registry appendix](https://std.samr.gov.cn/dcpspTools/gbPlan/download?path=%2Fzxd%2F2024005092%2F20_%E6%A0%87%E5%87%86%E8%B5%B7%E8%8D%89%2F20_WD_2024005092_%E7%BD%91%E7%BB%9C%E5%AE%89%E5%85%A8%E6%8A%80%E6%9C%AF+%E5%AF%86%E7%A0%81%E5%BA%94%E7%94%A8%E6%A0%87%E8%AF%86.pdf) and [OSCCA GM/T 0006-2023 publication notice](https://www.oscca.gov.cn/sca/xwdt/2023-12/06/content_1061146.shtml) |
| Modern PQ identifiers | [RFC 9802](https://www.rfc-editor.org/rfc/rfc9802.html), [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html), [RFC 9909](https://www.rfc-editor.org/rfc/rfc9909.html), [RFC 9935](https://www.rfc-editor.org/rfc/rfc9935.html), and [RFC 9936](https://www.rfc-editor.org/rfc/rfc9936.html) |
| Algorithms whose defining standards assign no OID | [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html), [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html), [RFC 9382](https://www.rfc-editor.org/rfc/rfc9382.html), [RFC 9383](https://www.rfc-editor.org/rfc/rfc9383.html), [RFC 9807](https://www.rfc-editor.org/rfc/rfc9807.html), [NIST SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final), and [NIST SP 800-56C Rev. 2](https://csrc.nist.gov/pubs/sp/800/56/c/r2/final) |
