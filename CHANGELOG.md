# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Fixed
- Java enums, records and annotation types are no longer skipped whole. The class walk dispatched only on `class_declaration` and `interface_declaration`, so an `enum` or `record` produced no function declarations at all: every crypto call inside one was invisible, with no finding, no call chain and no warning. Enum bodies nest their members one level deeper than every other type body, inside `enum_body_declarations`, and that wrapper is now transparent to the member walkers, so methods, constructors, fields and `static` initializers are found in all of them. Constant-specific bodies (`MD5 { MessageDigest get() { ... } }`) are registered as their own type, named `Owner.CONSTANT`, and record compact constructors are parsed as constructors. The enum singleton is the standard Java idiom for a crypto provider or registry, so this was a silent gap in a common shape.
- A Java pattern variable now carries the type it binds. `if (o instanceof Cipher c)` and `case Cipher c ->` left `c` unbound, and the receiver fallback then adopted the variable's own NAME as its type, emitting `com.example.(c).doFinal` — a fabricated identity in the user's package that matches no contract. This produced a wrong edge rather than an unresolved one, and the invented name varied with whatever the developer had called the variable. `instanceof` carries its binding on the expression itself (`right` plus `name`) rather than through a `type_pattern`, so it is read separately from switch labels; record pattern components share the switch-label shape. Ordinary locals, parameters and `catch` variables are unchanged.
- A Java receiver qualified by `this` now resolves. `this` is a keyword and never a type name, but left as receiver text it flowed into the type lookups and became the callee's package or type: `this.cipher.doFinal()` was emitted as `this.(cipher).doFinal` and `this.helper()` as `(this).helper`. Both the bare and the qualified forms (`Outer.this`, JLS 15.8.4) are now substituted before any lookup. The unqualified spellings resolved correctly before and still do; an identifier that merely begins with `this` is untouched.
- A Java type declared in the compilation unit now shadows an on-demand ("*") import of the same simple name (JLS 6.4.1, 7.5.2). The wildcard was consulted first, so a class the project declares itself was attributed to the imported library: BouncyCastle's own `org.bouncycastle.util.Arrays`, sitting next to `import java.util.*;`, resolved to `java.util.Arrays`. Where the shadowed name belongs to a crypto library this invented a finding, with that library's PURL, for code that never calls it. Types are now registered before any call is resolved, so a call written above the class it names is covered too; a single-type import cannot collide, because importing a name the unit also declares does not compile.
- A Java receiver typed by one of its class's type parameters now erases to that parameter's first bound (JLS 4.4). `class C<T extends Cipher>` left a receiver of type `T` unresolved, and it was emitted as `com.example.(T).doFinal` — a fabricated type in the user's package that matches no contract. The bounds were already collected for `TypeParamBounds` but never consulted when resolving a receiver. Only a callee that fell back to the caller's own package is rewritten, so a real class sharing a type parameter's name is untouched. Method-level type parameters are not covered.
- Java local variable types are now scoped to the block that declares them. All declarations in a method were collected into one flat map, so the last declaration of a name won for every call in that method, including calls textually before it. Two sibling blocks that both declared `c` therefore resolved both receivers to whichever came last — reporting an AES `Cipher` as a `Mac`. The same map backs argument tracing, so a shadowed name also traced to the other block's literal: `Cipher.getInstance(alg)` with `alg` bound to `"AES/GCM/NoPadding"` reported the transformation string `"DES/ECB/PKCS5Padding"`. Because rules deliberately leave `algorithmFamily`, `mode` and `padding` to this layer to resolve, that surfaced as a confidently wrong algorithm in the CBOM rather than a missing one. Declarations are now layered per scope, an inner declaration shadowing an outer one inside its own block and nowhere else.
### Added
- Java method references are recorded as calls to their target, so `Cipher::getInstance`, `MessageDigest::new`, `this::helper` and `c::doFinal` are no longer invisible. The node was never visited, so a crypto API reached only through a reference produced no edge. The callee name carries no arity suffix: a reference takes its arity from the functional interface it is assigned to, not from the reference site, and the unsuffixed form is the existing "arity unknown" spelling rather than a guessed number that would join the wrong overload.
### Added
- C callgraph contracts for micro-ecc: the five named curve selectors, the entropy-source configuration, key generation and public-key derivation, ECDH shared-secret agreement, and both signing spellings with verification. Every operation carries its curve argument as operation-determining, so the curve a consumer selects at the call site is what the finding is attributed to, and the selectors give the curve handle a type so the same identity survives being bound to a variable first. The very-long-integer arithmetic surface is deliberately left uncontracted: it implements the primitives above rather than being an API a consumer selects.
### Added
- Rust callgraph contracts for the RustCrypto MAC crates `hmac` and `cmac`: construction, the streaming update lifecycle, tag output and verification, with the key size exposed as a parameter role on the key argument. Version ranges follow the crates' own sources — `new_from_slice` arrives with hmac 0.11.0 and cmac 0.6.0, and earlier releases spell it `new_varkey` on the previous trait and are recorded as a separate disposition.
### Added
- Rust callgraph contracts for `openssl-sys` 0.9.x, the raw FFI bindings to OpenSSL: the EVP digest and cipher selectors, the SHA-1 and SHA-2 one-shot and streaming digests, AES-GCM and AES-CTR selection, AES key wrapping, key agreement, ECDSA, elliptic curve keys and groups, the raw RSA entry points, X.509 certificates, and the TLS and DTLS surface. RSA key generation reports its modulus size from the call site. The padding mode of the raw RSA operations, the cipher passed to `EVP_EncryptInit_ex`, and the curve NID are carried as arguments rather than folded into an algorithm name, because one entry point serves several algorithms.
### Fixed
- A Rust call written through the 2015-edition `extern crate openssl_sys as ffi;` rename now resolves to the renamed crate's own identity. Only `use ... as ...` was handled, so `ffi::EVP_sha256()` was emitted as `ffi.EVP_sha256` and matched no contract. Aliasing an FFI binding crate is the norm, so this affected the shape those crates are normally used in. `extern crate` without a rename, and `extern crate self as ...`, are unchanged.
### Added
- Go callgraph contracts for the `age` file-encryption library: file encryption and decryption, X25519 identity and recipient handling, the scrypt passphrase mode including its work-factor setters, and the v1.3 hybrid post-quantum recipient. The declared range starts at v1.0.0-beta4 because the package is not importable before it — v1.0.0-beta1 and v1.0.0-beta2 keep the library under `internal/`, and v1.0.0-beta3 exposes it at the nested path `filippo.io/age/age` rather than the module root.
- Rust callgraph contracts for the RustCrypto AEAD crates `aes-gcm`, `aes-gcm-siv` and `ccm`, and for the reduced-round `chacha20poly1305` flavors. Each covers construction, the allocating and in-place encrypt and decrypt operations, and both detached-tag spellings, `encrypt_in_place_detached` and the `encrypt_inout_detached` that replaced it in aead 0.6.
### Fixed
- `Key::<T>::generate()`, `Nonce::generate()` and `XNonce::generate()` in the `chacha20poly1305` contract were declared at arity 1 against a zero-argument call, so the served path's exact-arity lookup never matched them. They are now arity 0, and the rng-taking `generate_from_rng(rng)` spelling is contracted alongside.
### Fixed
- The user guide's Rust and C++ callgraph coverage paragraphs rendered as monospaced text inside the "transitive path" code card, whose `<pre><code>` was left unclosed, and the C++ paragraph and the card were duplicated. The paragraphs now sit as prose ahead of the card and the card appears once.
### Fixed
- A Rust local type alias naming an imported type by its bare name now resolves calls made through it to that type's crate: `type Aes256Ccm = Ccm<Aes256, U10, U13>;` then `Aes256Ccm::new(&key)` produced `Ccm.new` with no type segment and no contract match, and now produces `ccm.Ccm.new`. This is the spelling the `ccm` and `aes-gcm` documentation teaches, so that idiom previously carried a detection with no reachability behind it. A renaming import, whose recorded target is already a real path, is unaffected.
### Added
- Rust callgraph contracts for the RustCrypto block ciphers `aes` 0.1.x-0.9.x, `blowfish` 0.1.x-0.10.x and `des` 0.0.x-0.9.x: concrete cipher construction and the single-block and multi-block encrypt and decrypt operations, the encrypt-only and decrypt-only AES types, and the free-function API of the unrelated project that held the `des` name at 0.0.x. Both slice-constructor spellings are inventoried, `new_varkey` for the older trait crates and `new_from_slice` from cipher 0.3 onwards, so an older pinned release is not a silent gap. Construction reports the supplied key as a `keySize` parameter role rather than a declared size, which is the only correct answer for Blowfish: it accepts any key from 4 to 56 bytes.
### Fixed
- Rust calls on a value produced by a turbofish constructor now resolve the receiver type. `Blowfish::<LE>::new_from_slice(key)` left the bound variable typed `Blowfish::`, a name no import resolves, so every later call on it was emitted under the local package as `app.Blowfish::.encrypt_block` instead of `blowfish.Blowfish.encrypt_block`. The call was still produced, so nothing read as a dropped shape; it simply matched no knowledge-base contract and carried no `parameter_roles`. The same applied to a nested-module spelling such as `digest::Context::<u8>::new(..)`, which now resolves to `ring::digest` / `Context`. The non-turbofish spelling, the fully qualified spelling, and a turbofish carrying a generic argument (`Key::<Aes256>::from_slice`) are unchanged. One further shape changes: a generic free function bound with `let` (`let x = compute::<u8>(a); x.finish();`) previously reported the function name as the receiver type; it now agrees with the plain `compute(a)` spelling, which resolved no receiver type. No shipped contract could match the previous form.
### Added
- Rust callgraph contracts for the RustCrypto block modes `cbc`, `cfb-mode` and `ctr`, covering mode construction, the padded block and CFB stream operations, and CTR keystream application. The IV parameter carries `ivSize` evidence derived from the argument rather than a fixed width.
### Fixed
- Rust calls written through a renaming import now resolve to the real library identity, on both the callee and the receiver path. `use cbc::Encryptor as CbcEnc;`, the same clause inside a use list, `use cfb_mode as cfb;` and `use cbc::{self as c};` were all dropped before, leaving the local name in the callee identity so no contract matched.
### Fixed
- A Rust local type alias (`type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;`) now resolves calls made through it to the aliased path, so a detection made through that spelling carries reachability instead of none.
### Fixed
- The ghash and poly1305 contracts now target the versions the coverage matrix lists, 0.6.x and 0.9.x. Both previously declared ranges ending immediately below them. The ghash `new_with_init_block` contract is removed: that constructor no longer exists in 0.6.0.
### Fixed
- The ed25519 contract now targets the 3.x line and covers `Signature::from_components`. It previously declared a range ending before 3.0.0, which excluded the version the coverage matrix lists.
### Added
- Rust callgraph contracts for the RustCrypto signature crates `dsa`, `ecdsa` and `ed25519`: key construction for each, and the Ed25519 signature type the crate exposes in place of an implementation. Signing and verification reach these crates through shared traits, so the contracts anchor on the stable key identities.
### Added
- Rust callgraph contracts for the RustCrypto universal hashes, GHASH and Poly1305: construction, the streaming update lifecycle and tag output. Both expose their key size as a parameter role.
### Added
- Rust callgraph contracts for sodiumoxide: XSalsa20-Poly1305 authenticated encryption, Ed25519 signatures, HMAC-SHA-512-256 authentication, scrypt password hashing, and the SHA-256/SHA-512 hashes. Supporting calls for these carry a lifecycle category, and password derivation exposes its two cost limits as parameter roles.
### Fixed
- C++ types declared inside a namespace opened by a macro (`NAMESPACE_BEGIN(X)`) now resolve to their qualified identity instead of a bare one. Mining such a library previously attributed none of its crypto to the library's own types, because a rule or contract anchored on the qualified name could not match its sources. Crypto++ 8.9.0 goes from 0 to 9 library-attributed entry points. (#96)
### Added
- C++ Tink callgraph contracts for `pkg:github/google/tink` v1.7.0 AEAD/MAC/signature key templates, `KeysetHandle::GenerateNew`, and Aead/Mac/sign/verify terminals. Java Tink AWS KMS and GCP KMS adapter contracts cover client construction, credential config, and `getAead`.
- Crypto++ callgraph contracts for the SHA-256 hash lifecycle, the first C++ library knowledge base. Supporting calls for Crypto++ now carry a lifecycle `category` and the truncated-digest length as a parameter role; previously the C++ KB was an empty placeholder and those calls were exported uncategorized. (#96)

## [0.24.0] - 2026-08-20
### Added
- Graph fragments record one minimum-length route per reachable finding, and the stitched export serves a call chain that spans the component boundary instead of the single frame holding the crypto. A finding reached through a dependency now names every call from the consumer's own method down to the crypto. The entry-point index already stated the distance; the route it measures was computed and discarded. `analysis.call_chains` stays `partial`, because the dependency's leg was recorded under that dependency's own chain cap. A component keeps serving what it serves today until it is re-mined, and a closure mixing re-mined and older members reports each accordingly. (#289)
- Callgraph export schema `6.13` and graph-fragment schema `1.13` add `call_chains[].entry_resolution` and `entry_declared_type`, reporting how the call arriving at each frame was established and, for a dispatch, the static type that could not be narrowed. Both absent on a chain's first frame. A route is chosen by minimum length, so a dispatch edge that happens to be spurious is exactly the kind of hop a route prefers; naming it lets a consumer keep the certain part of a route and read the rest as indicative. Graph fragments add `crypto_entry_points[].reachable_findings[].route` as indexes into `functions[]`, absent on fragments exported earlier. On the largest component measured the route costs 1.89 MB on a 506 MB fragment. (#289)

## [0.23.0] - 2026-08-20
### Added
- Rust callgraph contracts for RSA key generation in the `openssl` and `rsa` crates: `Rsa::generate`, `Rsa::generate_with_e`, and `RsaPrivateKey::new` are modelled as factories whose caller-supplied bit-size argument is marked as `keySize` evidence. Follow-up to the merged detection rules that publish those sizes as `keyLengthCapture` without resolving them.
- Callgraph contracts now model the C key-generation call sites that carry a caller-supplied key size: OpenSSL `EVP_RSA_gen`, `EVP_PKEY_CTX_set_rsa_keygen_bits`, `EVP_PKEY_CTX_set_dsa_paramgen_bits`, `RSA_generate_key`, `RSA_generate_key_ex`, `DSA_generate_parameters_ex`, and Mbed TLS `mbedtls_rsa_gen_key`. The size argument is declared as a `keySize` parameter role, so the call graph carries the same evidence point the detection rules capture.
- Callgraph export schema `6.12` and graph-fragment schema `1.12` add the rule-vs-callgraph key-length conflict marker on `supporting_calls[].supporting_call.resolved_key_length`. When a detection rule declares a static `keyLength` and the callgraph resolves a different value, the resolved `bits` remain the primary value, the rule value is retained as `rule_declared_bits`, and `rule_conflict` is `true` — the rule value is never silently overwritten. Agreement, an unresolved key length, and a rule that declares no `keyLength` all leave both fields absent. Because a supporting call is shared by every finding reaching the same crypto object, the marker states that at least one referencing finding disagreed and reports the smallest disagreeing value; it does not identify which finding. The marker is computed during the scan on the live, graph-fragment, `annotate`, and stitched paths, so downstream consumers read it instead of re-deriving it from rule metadata. `pkg/graphfrag.ResolvedKeyLength` gains the two exported fields plus a `Clone` method. CBOM output is unchanged. (#274)
- Rust callgraph contracts now model RustCrypto `argon2` 0.5.x factories plus password hashing and verification operations, retaining supported password, salt, output, and configuration context in callgraph exports. (#72)
- Callgraph export schema `6.11` and graph-fragment schema `1.11` add optional `supporting_calls[].supporting_call.resolved_key_length` evidence for structurally derived Java `javax.crypto.KeyGenerator.init(int)` configuration calls. A resolved literal or simple propagated constant emits raw `bits`, `provenance: "constant"`, and a `source_call` parameter reference; unresolved or ambiguous values emit `provenance: "unknown"` without a fabricated bit length. Terminal findings remain attached to the detected operation, while the field is preserved by live, graph-fragment, and stitched callgraph exports. CBOM output is unchanged. (#272)
- Java key-length evidence now covers the canonical JCA key-generation entry points, not only `javax.crypto.KeyGenerator.init(int)`: `java.security.KeyPairGenerator.initialize(int)` and `initialize(int, SecureRandom)`, plus the `java.security.spec.RSAKeyGenParameterSpec`, `java.security.spec.ECGenParameterSpec`, and `javax.crypto.spec.SecretKeySpec` constructors. A size that reaches a configuration call through a parameter-spec object is resolved from that constructor, and `source_call.function_name` names it. Elliptic-curve specs resolve the curve's field size (`secp256r1` → 256) through a new `argument_curve_bits` contract derivation, and `SecretKeySpec` key material resolves from a literal byte-array allocation. Unresolved or ambiguous values keep `provenance: "unknown"` without a fabricated bit length. The evaluator is now contract-driven rather than keyed on one hardcoded method, so any knowledge-base contract that marks a parameter with `contributes: {property: keySize}` produces this evidence; today only the Java knowledge base declares the `parameter_types` such a contract needs for a direct match. Callgraph export stays at schema `6.11` and graph fragments at `1.11`; no field was added, removed, or renamed. (#273)
- `javax.crypto.spec.SecretKeySpec` constructors now carry a `factory` lifecycle role and `parameter_roles`, so their supporting-call declarations expose the key-material and algorithm parameter contributions. The four-argument overload keys its size on a byte count no derivation models, so it declares no `keySize` contribution rather than reporting the whole array. (#273)

### Fixed
- Filtering a stitched export by a composed entry point now returns the finding's `reachability` and `analysis` instead of nothing. A composed entry point reaches its findings through a dependency's mine-time index, which records a depth and no route, so the restricted chain enumeration matched nothing and dropped the finding graph the verdict attaches to — a filtered request answered with less than the same unfiltered request. A signature naming nothing still yields nothing. (#286)
- Rust calls written through a module import (`use ring::digest;` then `digest::Context::new(..)`) now resolve the receiver type. The parser dropped the imported module segment and folded the type into the package path, producing a callee such as `ring::Context` with no type, so the `ring::digest::Context.new`, `ring::hmac::Key.new`, `ring::hmac::Key.generate`, `ring::hmac::Context.with_key`, and `ring::hkdf::Salt.new` contracts never matched and those call sites carried no `parameter_roles` (`algorithm`, `keySize`) evidence. The expanded path now keeps the imported module segment and splits an upper-cased trailing segment as the receiver type, so `digest::Context::new(..)` resolves to `ring::digest` / `Context` / `new`. The type-import and fully qualified spellings, method calls, and free-function calls are unchanged. (#280)
- Rust knowledge base contracts now resolve at call sites that carry a receiver type. Rust contract keys keep Rust's `::` module separator while call-site symbols join every segment with `.`, and Rust callees carry no encoded arity, so every Rust contract missed and no Rust call received `call_target_inferred_return` decoration or `parameter_roles` (`keySize`, `nonceSize`, `algorithm` evidence). Rust lookups now normalize the module/type separator and resolve by name when the arity is unknown. Go, Java, Python, C, C++, and Node lookups are unchanged. (#277)

## [0.22.0] - 2026-08-17
### Added
- `StitchOptions.ChainEntrySignatures` restricts call-chain enumeration to routes reaching the named entry points, so a filtered request spends the per-operation chain budget where the caller asked instead of in traversal order. The entry-point index is unaffected, and the zero value leaves the default path unchanged. Schema stays `6.9`; no re-mining.

### Added
- Interim report `1.5`, callgraph export `6.10`, and graph fragments `1.10` add optional `occurrence_key` to canonical findings. The self-versioned key is stable across formatting and rule/evidence changes when AST call evidence is available, with a deterministic file/module-level fallback for valid top-level calls; consumers join by `(finding_id, occurrence_key)` when the key is present and retain `finding_id`-only joins for legacy records. (#232)
- Dependency findings now include an optional canonical `purl` inside `dependency_info` for Java, Python, Go, and Rust dependencies, including versionless package URLs when dependency versions are unavailable. (#233)
- Direct findings now promote valid rule `metadata.purl` values to a top-level `purl`, with exact direct-dependency version enrichment when the resolver provides one unambiguous match. (#264)

### Changed
- Interim reports and findings envelopes use schema `1.6`; callgraph exports use schema `6.10` to carry direct finding package URLs and dependency package URLs without changing graph-fragment wire format. (#233, #264)


## [0.21.0] - 2026-08-17
### Added
- CycloneDX 1.6 CBOM exports now include protocol assets with protocol type/version metadata and certificate assets with certificate format, serial number, and certificate type metadata. (#239)

### Fixed
- `crypto_entry_points` now lists every function that reaches a crypto finding, on the live `--export-callgraph`, the graph-fragment, and the stitched/served paths. The index was previously folded from the call chains that happened to be exported, so a function was omitted whenever its only route collapsed at a shared caller or fell outside the per-finding chain budget — even though the stored graph proved it reaches the crypto. On `redis.clients:jedis@5.1.0`, 71 of the 1,142 reaching functions were published, with `Jedis.set`, `Jedis.get` and `Jedis.auth` among those missing. Consumers filtering with an entry-point signature list were losing the findings reachable only through an omitted entry point. (#249)
- Served call chains are enumerated over the same cycle-condensed graph the live exporter uses, so both report the same routes through a re-convergent graph instead of the stitched export reporting a subset. (#249)

### Changed
- Callgraph export schema is now `6.9`. `crypto_entry_points[]` answers reverse reachability rather than projecting the exported `call_chains`, so it contains more entries than before, and `chain_depth` is the true minimum frame distance — some depths are therefore smaller than the same export previously reported. No field was added or removed; `crypto_entry_points[].root` continues to mark the chain roots. Consumers that treated the index as an inventory of the exported chains should read it as a reachability answer. (#249)

## [0.20.0] - 2026-08-14

### Added
- `scan --progress` now emits opt-in JSONL lifecycle events to stderr while keeping findings on stdout or `--output`; dependency aggregates, optional-phase skips, and terminal structured failures are machine-readable. (#237)
- Stitched exports now compose a dependency's mine-time entry points onto the root component's public surface. When the stitched adjacency shows a root-component function transitively calling one of them, it is served as a composed entry point carrying its `canonical_signature`, a per-finding composed depth (stitched hops plus mine-time chain depth), and the root flag; its findings are upgraded to reachable with `analysis.call_chains: partial`. This closes the consumer join for wrapper APIs — `KafkaTemplate.send` reaches crypto only through an interface with several implementations, so it could never serve as an entry point before.
- Callgraph exports now carry explicit reachability state: `finding_graphs[].reachability` (`reachable` / `unreachable` / `unknown` / `not_applicable`), `finding_graphs[].analysis` completeness for call chains and parameters, and `crypto_entry_points[].root` for explicit chain-root classification. A fail-closed suppression or a trace cap downgrades a would-be `unreachable` to `unknown`, never to `reachable`. Live `--export-callgraph` and the stitched export both honor the contract. (#242)
- Every graph-fragment function, entry point, and supporting call now carries `erased_signature` — generic arguments stripped and type variables replaced by their erased first bound — so a bytecode-level consumer can join on the normal form its own analysis produces instead of reconstructing declared generics.

### Changed
- Callgraph export schema is now `6.8` and the graph-fragment schema is `graph-fragment-1.9`; both bumps are additive and no existing field changed shape. The legacy `finding_graphs[].reachable` boolean keeps its semantics through 6.x but is deprecated in favor of `reachability`.
- `graphfrag.GraphAlgoVersion` is now `graph-algo-2` (was `graph-algo-1`). The Java receiver-type fix below alters the structural call graph, so fragments produced by earlier versions are not interchangeable with new ones. Consumers that cache structural graphs keyed on `scan_metadata.graph_algo_version` must re-mine; the wire schema bump is additive (see above) and no consumer needs a parsing change. (#228)

### Fixed
- Java type hierarchies are now derived from source-declared `extends`/`implements`, not only from indexed jars. Bare-source scans (mining workspaces) index no bytecode, so the type hierarchy stayed empty and every exported fragment function carried an empty `compatible_canonical_signatures` — cross-fragment interface dispatch could never be stitched. On a standalone `kafka-clients 3.7.1` scan this goes from 0 to 3,987 functions with compatible signatures.
- Java `this(...)` / `super(...)` constructor delegation and `super.method(...)` receivers now resolve to the declaring class instead of being dropped or emitted as a never-joinable caller-package `(super)` identity. These are the statically certain subclass-to-base links, and severing them cut every cross-library chain flowing through inheritance.
- Stitch-time overload selection scores candidates by best parameter-type match instead of requiring every known parameter to match, so an imprecise caller-side argument type no longer collapses a resolvable call back to ambiguity. Ties still fail closed exactly as before.
- The scan-progress schema now rejects skip reasons outside `skipped` events and dependency aggregate counts outside completed dependency phases; progress mode documents structured JSON errors for preflight and terminal failures.
- Findings whose rule declares a `parameterCondition` no longer lose every entry in `call_chains` when the condition cannot be evaluated — e.g. the crypto call's argument comes from a field, a config lookup, or any value the analysis cannot resolve statically. The chain filter treated an unanswerable predicate as an unsatisfied one and dropped the chain, silently zeroing the finding's reachability in the callgraph export and making live crypto look like dead code. Filtering is now decided per finding: when no chain can answer the predicate the chains are kept, and only once at least one chain can answer it are the non-matching (and unanswerable) chains dropped — which preserves per-call-site selector materialization. Affects the ruleset entries that declare `parameterCondition`. (#229)
- Java call resolution now erases a receiver's generic type arguments before resolving its declared type, so the callee identity matches the declaration it names (class declarations are indexed under the bare identifier). Previously a call on a variable declared `KafkaTemplate<String, String>` missed the `KafkaTemplate` import key and fell back to the *scanned file's* package, emitting `com.example.(KafkaTemplate<String, String>).send#3` — unjoinable against the declaring component's `org.springframework.kafka.core.(KafkaTemplate).send#3`, and different for every consumer. Three shapes were affected: imported generics (`java.util.Map<String, Object>` surfaced as `com.example.(Map<String, Object>)`), same-package generic classes (`com.example.(MyCache<String>)` never matched the `com.example.(MyCache)` declaration, losing the edge inside the scanned project), and fully-qualified generics whose own argument is qualified (`Map<String, java.util.List<byte[]>>` split its package on the dot *inside* the angle brackets). (#228)

### Fixed
- Java graph-fragment reachability now preserves concrete receiver provenance for interface-typed fields assigned once from a concrete constructor parameter or `new T(...)`, allowing stitch to select the matching implementation without may-reach fan-out. (#262)

## [0.19.0] - 2026-08-14

### Changed
- Replaced the generated DOCX/PDF Crypto Finder guide with a standalone interactive SCANOSS-branded HTML guide at `docs/user-guide/user-guide.html`.
- Dependency-scanning container images now use digest-pinned base/tool images, exact package versions, and checksum-verified installer inputs; CI rejects unpinned tooling.
- Report, callgraph, graph-fragment, and annotation file exports now create missing parent directories and replace existing files only after a complete, synced write.

### Added
- Published JSON Schemas for the interim report and `--export-callgraph` artifacts, with CI validation of generated exports to catch top-level contract drift.
- Public Go contracts are available at `pkg/schema` for interim reports and `pkg/failure` for structured terminal errors, preserving the documented JSON fields and compatibility behavior for downstream integrations.
- Callgraph export findings now carry `reachable`, answering whether user code reaches the crypto — a different question from `unresolved_reason`, which says which function contains it. A finding can be perfectly attributed and still unreachable. Three states: `true`, `false`, and absent when the question does not apply because a library was scanned on its own (`--export-graph-fragment` without dependencies), where there is no user code to be reached from. Callgraph export schema is now `6.7`.
- Java callgraph contracts now model the cloud KMS and secrets-manager facades: AWS KMS across both SDK generations (`software.amazon.awssdk:kms` and `com.amazonaws:aws-java-sdk-kms`, including the v1 bean setters), Google Cloud KMS, Azure Key Vault Keys synchronous and asynchronous cryptography and key clients, and the HashiCorp `vault-java-driver` client, TLS configuration, and `Logical` secrets-engine operations.
- Java callgraph contracts now model the OkHttp 5.x TLS surface — certificate pinning, `ConnectionSpec` cipher-suite and TLS-version selection, handshake inspection, the TLS-related `OkHttpClient.Builder` configuration, and the `okhttp-tls` `HeldCertificate`/`HandshakeCertificates` certificate and key generation.
- Java callgraph contracts now model the JSch (`com.jcraft` and the `com.github.mwiede` fork) session, algorithm-configuration, host-key, and key-pair generation/loading lifecycles, and the sshj 0.40 client connect/auth, algorithm-selection, key-provider, and host-key-verification lifecycles.
- Java callgraph contracts now model the lazysodium-java 5.2 libsodium AEAD, box, secretbox, generic-hash, password-hash, and signing lifecycles (both the high-level `Lazy` and buffer-based `Native` surfaces) and the kalium box, secretbox, sealed-box, AEAD, hash, password, and signing-key lifecycles.
- Java callgraph contracts now model the jbcrypt, at.favre.lib bcrypt, Lambdaworks scrypt, argon2-jvm, and Jasypt password/KDF facades, including the bcrypt cost, scrypt N/r/p, and Argon2/PBE iteration work factors.
- Java callgraph contracts now model the Hutool-crypto 5.8 SecureUtil/DigestUtil/SmUtil/KeyUtil factories and the symmetric, digest, MAC, asymmetric, signing, and SM2 lifecycles.
- Java callgraph contracts now model the I2P ed25519-java (net.i2p.crypto:eddsa) 0.3 EdDSA signing engine, key-pair generation, and key/spec construction lifecycles.
- Java callgraph contracts now model the PGPainless 1.7 OpenPGP encrypt/sign, decrypt/verify, key-generation, and key-parsing fluent lifecycles.
- Java callgraph contracts now model the Auth0 java-jwt 4.x token creation, signing, decoding, and verification lifecycles, and the jwks-rsa JWKS provider construction and signing-key resolution lifecycles.
- Python callgraph contracts now model the python-rsa 4.x key-pair generation, PKCS#1 encryption, signing, and key-serialization lifecycles.
- Python callgraph contracts now model the python-ecdsa 0.19 SigningKey/VerifyingKey generation, signing, verification, serialization, and ECDH key-agreement lifecycles.
- Python callgraph contracts now model the python-jose 3.5 JWT/JWS/JWE operations and JWK key-construction lifecycles.
- Python callgraph contracts now model the Authlib 1.6 JOSE serialization, JWT encode/decode, and JsonWebKey generation and import lifecycles.
- Python callgraph contracts now model the hvac 2.4 Vault client construction and Transit/Transform secrets-engine key-management and crypto-operation lifecycles.
- Python callgraph contracts now model the google-cloud-kms 3.x synchronous and asynchronous client construction, remote encryption, signing, MAC, KEM, random-bytes, and key-lifecycle operations. 

### Fixed
- Dependency-enabled scans now propagate structured scanner cancellation instead of producing partial reports with a successful exit. (#235)
- Active scans now stop cleanly on SIGINT or SIGTERM, terminate their scan subprocesses, and return the structured `scanner_canceled` error without changing timeout results. (#235)
- Java declarations carrying annotations report their real visibility and their declaration line. Modifiers are grouped under one AST node, and the visibility scan compared that node's whole text, which only ever matched when a declaration carried nothing else: `@Override public` equals no keyword, so annotated methods were reported `package-private`, and their start line pointed at the annotation rather than the signature.
- `ParseFunctionID` accepts the unanchored form `.name#0` that `FunctionID.String()` produces for a callee whose receiver never resolved to a type. The two were asymmetric, so every edge built through `recordEdgeResolution` from such a call lost its `method_name` — 2468 of jedis's external calls.
- A receiver that is itself an expression no longer becomes a type name. `key(key).add(...)` and `e.getClass().getSimpleName()` had their source text adopted as the callee's class, producing identities such as `java.util.(key(key)).add#1` that name no class in any graph — 2693 of them when scanning a Redis client. Such calls are now recorded with no type anchor, which is what the resolution actually established. Graph edge count is unchanged.
- Object-lifecycle supporting calls are now scoped to calls made after the receiver was bound to the object. A variable reassigned mid-method holds a different object before and after, and ignoring that attributed the earlier object's calls to the later one: a TLS finding collected the plain socket's `setSoTimeout`, made before the connection was wrapped, and reported it as evidence of TLS.

- Crypto findings that no user-code path reaches no longer contribute entry points. The tracer already discarded such chains, but the exporter then synthesized a single-node chain from the containing function, and every function appearing in a chain became a `crypto_entry_points` member — so a dependency's dead crypto was published beside the code that actually runs, with nothing distinguishing them. Scanning a Redis client that never uses sharding no longer advertises jedis's sharding MD5 as an entry point. Library scans are unaffected: there a chainless finding means the function is a graph root, which for a library is its public API and its most valuable entry point.

- Java casts no longer strip the supporting calls off a crypto finding. A cast between a call and its variable declarator, or between a receiver and its identifier, hid the object the call acts on, so lifecycle derivation collected nothing: scanning a TLS client reported `SSLSocketFactory.getDefault()` with zero supporting calls, omitting the `createSocket(...)` wrap, the `setSSLParameters(...)` protocol and cipher-suite selection, and the `getSession()` handshake trigger. A cast receiver is now read two ways — the asserted type resolves the method, since the declared type may not carry it, while object identity resolves to the variable underneath — which also removes the fabricated `com.example.((SSLSocket) socket)` style callee the raw receiver text used to produce. (#245)

- Java methods declared in anonymous class bodies (`new Hashing() { ... }`) are now registered as functions, under javac's binary name for the type (`Owner$1`, `Owner$2`) and carrying the instantiated supertype in `OwnerBases` so dispatch expansion can link interface call sites to the override. The parser previously descended only into declared class and interface bodies, so a crypto call inside an anonymous class belonged to no function and its finding was exported with `unresolved_reason: "no_containing_function"` and no call chains — the shape jedis uses to publish its MD5 digest from an interface field.

- Java call chains no longer break at variables declared in `try`-with-resources, enhanced-`for`, or `catch` clauses. These forms bind a name without the `variable_declarator` wrapper the type collector required, so their receivers stayed untyped and every call on them resolved into the scanned file's own package (`com.example.jedis.set` instead of `redis.clients.jedis.Jedis.set`) — a callee present in no call graph. The edge was never created, no chain reached user code, and the tracer then dropped every chain for the finding, collapsing dependency call chains to the single function containing the crypto call. Multi-catch variables (`catch (IOException | SQLException e)`) stay deliberately unbound, since their static type is the least upper bound of the alternatives rather than any listed type.

- Java fluent-chain contract resolution no longer loses chain links when a varargs method is called with more literal arguments than its collapsed contract arity (e.g. `SslContextBuilder.protocols("TLSv1.3", "TLSv1.2")`): the chain pass retries the lookup at the contract's collapsed arity, keeps walking past unmodeled links instead of orphaning the remainder of the chain (including the terminal `build()`), and exported symbols and canonical signatures no longer leak raw multi-line receiver text from unresolved links. The fallback is gated on a new `varargs: true` contract-schema marker (populated for the Netty and OkHttp variadic entries), so an ordinary positional lower-arity overload can never absorb a call with more arguments and inherit a role that does not belong to it. The Java receiver-text fallback also excludes inline `// ...` and block `/* ... */` comments, so non-contracted fluent chains cannot leak comment text into exported symbols or canonical signatures either. (#195)

## [0.18.0] - 2026-08-10

### Added
- Opt-in mine-path wall-clock proof for `bcprov-jdk18on@1.84` (`make proof-bcprov-mine` / `CRYPTO_FINDER_BCPROV_MINE_PROOF=1`); documents the post-#214 recovery under a 10m budget (mining `JOB_TIMEOUT` is 30m). See [docs/BCPROV_MINE_PATH_PROOF.md](docs/BCPROV_MINE_PATH_PROOF.md). (#216)
- Mine-path fragment no-regression equivalence harness (`TestMinePathFragment_*`) locking annotations, supporting calls, and entry-point reachable IDs + chain depths. (#215)
- Python callgraph contracts now model the jwcrypto 1.5.8 JOSE key, signing, encryption, and token lifecycles. (#181)
- Java callgraph contracts now model the Netty 4.2 `SslContextBuilder` TLS builder lifecycle. (#183)
- Java callgraph contracts now model the Spring Security Crypto 7.1 password-encoder and byte/text encryptor lifecycles. (#182)
- Java callgraph contracts now model the Nimbus JOSE+JWT 10.0.2 JSON-serialization signing and encryption lifecycles. (#184)
- Java callgraph contracts now model Apache Commons Codec's hand-rolled BLAKE3 hash, keyed-hash, and KDF lifecycles. (#187)
- Java callgraph contracts now model jose4j's JWE key-management, content-encryption, and key-derivation lifecycles. (#188)
- Java callgraph contracts now model the Bouncy Castle bcpkix 1.84 certificate, CMS, PKCS#10, and OCSP builder lifecycles. (#185)
- Go callgraph contracts now model the standard library's rule-covered symmetric, public-key, KDF, MAC, digest, random, TLS, and X.509 cryptographic lifecycles. (#76)
- Go callgraph contracts now model the rule-covered `golang.org/x/crypto` hashing, cipher, KDF, key, certificate, and protocol lifecycles. (#77)
- Node callgraph builds now load embedded schema-v2 contract knowledge bases and select the Node contract type resolver. (#82)
- C callgraph contracts now model wolfSSL wolfCrypt rule APIs and their stateful setup, update, and key import/export lifecycles. (#91)
- JavaScript and TypeScript callgraph parsing now records mapped function return sources for direct values, calls, and constructors. (#81)
- C callgraph contracts now model the rule-covered Mbed TLS 3.6 LTS PKCS#7, LMS, public-key, TLS, and X.509 lifecycles. (#92)
- C++ callgraph builds now load embedded schema-v2 contract knowledge bases. (#95)
- C callgraph contracts now model libsodium 1.x high-level AEAD, authentication, hashing, password-hashing, KDF, key-exchange, box, stream, and signing lifecycles. (#145)
- C callgraph inference now models OpenSSL EVP cipher, digest, KDF, MAC, public-key, KEM, and signature APIs selected by the shipped C detection rules. (#90)
- C++ callgraph builds now populate namespace-qualified return sources and select the C++ contract type resolver. (#94)
- C callgraph builds now load embedded schema-v2 contract knowledge bases. (#89)
- C callgraph builds now select the C contract type resolver; pointer-returning functions can use contract inference when C knowledge bases are embedded. (#88)
- C++ callgraph parsing now recognizes C++ source and header files, include paths, namespace-qualified and receiver calls, assignment targets, and 1-based half-open call columns. (#68)
- Go callgraph contracts now model the legacy `github.com/golang-fips/openssl/v2` API's symmetric, KDF, public-key, and post-quantum cryptographic lifecycles. (#127)
- Graph-fragment exports now carry complete canonical target signatures and hierarchy-proven compatible callable signatures, allowing interface-typed dependency calls to join concrete crypto entry points without fabricating call edges. (#136)
- Java callgraph contracts now model the version-pinned Nimbus JOSE JWE and Spring Security Crypto lifecycles, including factory, operation, output, hierarchy, and key-size parameter-role semantics. (#137)
- Java callgraph lifecycle contracts and public exports now cover Bouncy Castle OpenPGP builders, Tink AEAD operations, and Apache Santuario XMLCipher factories and finalization with applicable operation links and canonical signatures. (#138)
- Rust callgraph inference now recognizes RustCrypto `chacha20poly1305` 0.11 factories and AEAD operations, including ChaCha20-Poly1305 and XChaCha20-Poly1305 detached and in-place calls. (#125)
- Rust callgraph inference now models `ring` 0.17 AEAD, digest, HMAC, HKDF, key-agreement, and signature lifecycles. (#70)
- Rust callgraph builds now load schema-v2 contract knowledge bases and select the Rust contract type resolver. (#69)
- Go callgraph builds now load schema-v2 contract knowledge bases and select the Go contract type resolver. (#75)
- Python callgraph inference now covers synchronous and asynchronous Azure Key Vault Secrets client construction and secret set, get, deleted-secret, backup, and restore results.
- Callgraph schema `6.6` adds deterministic `forward_calls.ambiguous_calls` groups for fail-closed interface dispatch, including completeness state, stable group/candidate IDs, complete callable identities, and preserved call-site argument provenance without promoting candidates to resolved edges. (#122)
- C callgraph parsing now extracts include paths, function declarations, call sites, assignment targets, and 1-based half-open call columns for reachability analysis. (#67)
- JavaScript and TypeScript callgraph parsing and CLI ecosystem routing now cover ES module and CommonJS imports, imported/direct calls, lifecycle receiver and assignment fields, fluent-chain IDs, and source columns. (#66)
- **Method-role and parameter-role classification** (`method_role`, `role_provenance`, `parameter_roles` — callgraph schema `6.3` → `6.4`): contracts now support `role: operation` (alongside the existing `factory`/`config`/`output`, now enum-validated at load time) and a per-parameter `parameters:` sub-schema (`operation-determining`/`metadata-contributing`/`none`, with `contributes: {property, derivation}` for `argument_value`/`argument_bit_length`/`argument_type`). Structural (call-edge-derived) supporting calls now carry a KB-derived `category` too, not just definition-based ones. See `internal/callgraph/contracts/`, `internal/scan/export.go`, `internal/scan/fragment_export.go`, `pkg/graphfrag/stitch.go`, `pkg/graphfrag/callgraph_export.go`. (#108)
- `pkg/graphfrag`: **forward call-chain closure** (`StitchOptions{ForwardClosure, MaxForwardDepth, MaxForwardNodesPerAnchor, MaxForwardEdgesPerAnchor}`): per-finding-anchor forward reachability graph (memoized per distinct anchor) projected as the `forward_calls` block on each `finding_graph` — what the matched method transitively calls, with per-call-site `entry_call` argument data-flow (resolved values). Callgraph schema `6.2` → `6.3`; the field is additive/optional and absent (byte-identical reachability payload) when the option is off. (#107)
- **`pkg/paramcondition`**: parses rule `parameterCondition` predicates (`param[<index|name>] <op> <value>`, ops `==`/`~=`/`:type==`/`:type~=`) into a structured, validated `parameter_conditions` field on finding assets — consumers can mechanically select the right value-variant asset (e.g. `AESEngine.init(true)` → `operation: encrypt`) instead of re-deriving rule logic. Findings/interim schema `1.3` → `1.4`; the flat `parameterCondition` string is retained verbatim in `metadata` for existing consumers. Malformed predicates fail fast at rule load, naming the rule id and raw string. (#106)

### Changed
- Callgraph exports now resolve a caller's static selector through simple wrapper parameters and helper return values while preserving conflicting candidates as unresolved. (#135)
- **Operation contract methods are now supporting-call-only** (callgraph schema `6.4` → `6.5`, graph-fragment schema `1.7` → `1.8`): `role: operation` contract methods are exported as categorized `supporting_calls` referenced by `supporting_call_ids`, including interface-authored contracts resolved to concrete implementations, and are no longer synthesized as operation-only `crypto_entry_points` in live, fragment, or stitched exports. (#116)
- perf: large JSON report/export paths stream to disk instead of buffering the full encoded payload; callgraph finding-graph building streams too, with a compact graph-fragment internal-edge encoding. Benchmark (bcprov 1.70, both exports): 129 s elapsed, ~3.7 GB peak RSS. (#110)
- perf: callgraph source parsing parallelized across directories (`ParserCloner`, implemented by all four language parsers with a serial fallback); dispatch expansion memoized per callee target; `EdgeResolutionsByPair` mirror map dropped. Combined benchmark (bc-java core+prov, 3,104 files): build+dump 144 s → 13.3 s, peak RSS ~13 GB → ~1.07 GB. (#111)
- `--scan-dependencies` now prunes dependency callgraph inputs to packages provably on a user-to-crypto dependency path (resolver-graph proof), falling back conservatively when the graph is missing or incomplete; Maven dependency graph metadata populated best-effort via a bounded `dependency:tree` call. (#110)
- Scanner failure messages now explain documented semgrep/opengrep exit codes (`opengrep execution failed with exit code 7 (rule configuration contains no valid rules)`) and attach a sanitized stderr tail (ANSI-stripped, single line, capped on UTF-8 rune boundaries) to logs and error details; the failure debug log records rule configs + target instead of dumping the full command line. (#112)

### Fixed
- Mine-path `--export-graph-fragment` no longer precomputes full per-asset call-site-expanded finding graphs to build `crypto_entry_points`. Entry-point reachability uses memoized structural reverse traceback (function identity + depth); supporting-call derivation runs once per asset and is reused for annotations and entry-point linkage. Export quantity/quality is preserved — call-site expansion remains on `--export-callgraph` / finding-graph export only. Dense libraries such as `bcprov-jdk18on@1.84` complete the mine path in single-digit minutes instead of timing out at 30m. (#214)
- Parameter provenance resolution no longer scans every function's call list per hop; it uses a once-built reverse-call index (from `Calls` + `Callers`). This removes a multi-minute O(V·calls) hotspot on dense libraries (e.g. BouncyCastle) during conditioned finding materialization and chain `entry_call` export. (#214)
- Java selector findings now preserve per-call-site wrapper values, resolve simple switch-return helpers, and materialize the applicable rule-owned algorithm metadata without guessing dynamic branches. (#135)
- C++ callgraph contracts now match namespace-qualified library calls independently of the scanned project path and resolve simple typed receiver calls without overriding project-local declarations. (#163)
- C callgraph contracts now match global library symbols independently of the scanned project's package path while preserving exact project-qualified matches. (#156)
- C callgraph pointer-return inference now propagates through in-project wrapper functions while preserving arity-qualified contract lookup. (#153)
- Rust callgraph contracts now resolve associated functions using the canonical Rust callable identity, enabling inferred return types from embedded contracts. (#74)
- Nested-call findings now attribute matched operations to the tightest source invocation and preserve external constructor arity and parameter types from source provenance. (#134)
- Supporting-call catalogs now preserve every callable overload deterministically instead of selecting one by traversal order. (#131)
- Stitched graph-fragment callgraph exports now retain parameter roles on supporting calls. (#130)
- Concurrent scans sharing the default rules cache no longer expose partial metadata or lose in-flight filtered rule files when another process refreshes the cache. (#128)
- Rule files with zero rules (`rules: []`) are excluded from language filtering — previously treated as "unknown language", they always survived the filter and could become the sole config passed to opengrep, which exits with code 7 on an empty ruleset and hard-failed the whole scan. (#112)
- `role: operation` contract methods declared on an interface/abstract type now resolve through concrete implementors via the contract hierarchy (e.g. `AESEngine.processBlock` synthesizes an operation entry via the `BlockCipher.processBlock` contract) — closes the concrete-body-only gap flagged in #108. (#109)
- Constructors are excluded from abstract-class dispatch expansion — `new Foo()` with a missing exact declaration was fanned out to every same-arity constructor in the namespace, fabricating edges that polluted `Callers`, exported call chains, and `crypto_entry_points` (92% of all edge resolutions on the bcprov corpus). Also the main perf win behind the #111 numbers. (#111)
- Exported JSON no longer HTML-escapes special characters. (#110)

## [0.13.4] - 2026-07-03


### Changed
- perf: fixed mining-path hotspots exposed by dispatch fan-out on large libraries — indexed the O(N²)-shaped lookups in `resolveParameterPassthroughDispatch` (bcprov-jdk15on 1.70 callgraph build: 900 s+ timeout → 25 s) and `findCallForCalleeAtLine` now uses a per-caller `(name, arity, line)` index instead of re-scanning per exported edge (full `--export-graph-fragment` mining run: 30 min+ timeout → 153 s, 4.1 GB peak RSS). (#59)

## [0.13.3] - 2026-07-02

### Added
- `pkg/graphfrag`: receiver-provenance disambiguation for multi-implementor dispatch — per-caller "bypass" edges synthesized for shared ambiguous call sites (e.g. `HashBuilder.with(HashingFunction)` with 7 concrete implementors), resolving the concrete receiver via constructor/declared-return/KB-contract inference so those chains survive serving-path stitching instead of being fail-closed suppressed. (#58)

### Changed
- Graph-fragment schema `1.5` → `1.6`: optional `resolved_receiver_type` on internal edges and external calls (additive, backward compatible). (#58)

## [0.13.2] - 2026-07-02

### Fixed
- Unqualified `this`-calls inside an abstract class whose target overload only exists in a subclass now fan out to concrete implementations (`expandAbstractClassDispatch`) — fixes previously-broken chains such as password4j's `HashBuilder.withPBKDF2 → ... → PBKDF2Function.internalHash`. (#57)
- Finding-to-function attribution now deterministically picks the tightest enclosing span (tie-broken by function key) instead of an unordered map's first match — eliminates flaky misattribution to a wide synthetic `<clinit>` span (~40% of runs). (#57)

## [0.13.1] - 2026-07-02

### Added
- When ≥2 distinct `cryptoFunction` values are aggregated for one component, CBOM output emits the full `cryptoFunctions` enum array (deduped) plus the joined raw set in `scanoss:cryptoFunction`. (#54)

### Fixed
- Mining now synthesizes every rule-declared operation sharing one entry-point `api` (e.g. `AESEngine.init` encrypt/decrypt selected by a boolean argument) instead of first-declaration-wins, which silently dropped the other variants. (#54)

## [0.13.0] - 2026-06-19

### Fixed
- When a rule-templated `algorithmName` metavariable (e.g. `ECDSA-$curve`, `Argon2$variant`) is unbound at a library-definition mining site, the synthesized entry point falls back to `algorithmFamily` instead of dropping the name entirely; other unresolved non-name metadata fields are still stripped. (#48)

## [0.12.1] - 2026-06-17

### Fixed
- Ruleset filter cache no longer re-ingests previously materialized rules, which caused unbounded cache/directory growth across scans. (#47)

### Added
- Automatic cleanup of stale materialized-rule temp dirs with a 2-hour retention policy (reclaims disk from SIGKILLed mining jobs). (#47)

## [0.12.0] - 2026-06-17

### Added
- Python callgraph contracts for argon2-cffi, bcrypt, passlib, and PyNaCl; contract-based supporting-call derivation classifies methods by lifecycle role. (#46)

### Fixed
- DRBG handling no longer over-suppresses synthesized findings; unresolved metadata variables removed from synthesized crypto findings. (#46)

## [0.11.0] - 2026-06-16

### Added
- Python `.pyi` stub file parsing in call graphs (stub takes precedence where both stub and implementation exist). (#45)
- Same-named functions across different Python modules preserved via module aliasing (fixes sibling-module name collisions). (#45)

### Changed
- Improved Python package/root-module detection. (#45)

## [0.10.0] - 2026-06-11

### Added
- **Python callgraph parity with Java**: per-ecosystem KB loading (was hardcoded to Java), `ReceiverVar`/`AssignedVar`/`ChainID` populated for object-lifecycle supporting calls, contract-driven return-type propagation, arity-tolerant KB lookup (Java stays exact-arity), from-import FQN resolution, Python-specific entry-point synthesis gate, subclass/MRO dispatch, `Cryptodome.*` namespace alias. (#44)
- Tier-0 Python contracts and rules: pyca/cryptography, pycryptodome, pycryptodomex, paramiko, PyNaCl, bcrypt, PyJWT, argon2-cffi. (#44)

### Changed
- pip dependency resolver prefers `VIRTUAL_ENV`/project-local venv over the ambient interpreter. (#44)

## [0.9.4] - 2026-06-09

### Changed
- Contract-based method-role matching walks the contract hierarchy: a role-tagged method attaches when its receiver is the terminal type **or** any transitive supertype (previously exact receiver only), so inherited methods (e.g. `GeneralDigest.update` inherited by `SHA256Digest`) surface as supporting calls. (#43)

### Added
- `GeneralDigest.update` role contract plus digest inheritance edges (`SHA256Digest→GeneralDigest`, `SHA3Digest→KeccakDigest`) so SHA-1/SHA-2/SHA-3 families surface inherited lifecycle calls. (#43)

## [0.9.3] - 2026-06-09

### Added
- Google Tink Java callgraph contract: `KeyTemplates.get(...)` → `KeysetHandle.generateNew` → `getPrimitive` (argument-conditional on `Aead`/`Mac`/`PublicKeySign`/`PublicKeyVerify`, arity-1 and arity-2 forms) → terminal crypto op. BouncyCastle and password4j Java contracts added alongside. (#42)
- Library-level crypto entry points synthesized from rules and surfaced in scan reports; contract-derived supporting crypto calls included in findings. (#42)

### Changed
- Scanner disables external semgrepignore handling so crypto-finder's own skip rules remain the single source of truth. (#42)

## [0.9.2] - 2026-06-08

### Fixed
- Graph-fragment served/stitched output relativizes function `file_path` the same way the live callgraph export does — previously leaked absolute scan-workspace paths into served responses; `equiv.Compare` now enforces the parity.
- Instance-field initializer crypto (not just `static` fields) attributed to the synthetic `<clinit>` entry point — previously such findings had no containing function and surfaced as a blank, reachable-but-empty call-chain frame.

## [0.9.1] - 2026-06-08

### Added
- Synthetic `<clinit>` (class-init) function emitted per class with a `static {}` block or initialized field declarations — crypto findings in static initializers/OID tables get a real, in-degree-0 (class-load entry point) containing function instead of a blank frame. Real methods/constructors still win via tightest-span attribution. (#41)

## [0.9.0] - 2026-06-08

### Changed
- **Reachability revamp**: supporting calls (setup/lifecycle calls around a crypto object, e.g. `digest.update`/`doFinal`) are now derived structurally from the call graph via object identity (`ReceiverVar`/`AssignedVar`/`ChainID`) instead of per-call semgrep rules; the non-CycloneDX `supporting-call` assetType and `supportingCall: "true"` sentinel are gone. (#40)
- Reachability no longer depends on `metadata.api` (now informational CBOM metadata only): `matched_operation.kind` is classified from the matched source text, and the crypto call is located by position (match columns ∩ call-node columns, fluent-chain-root tie-break, line-only fallback). (#40)

### Added
- Callgraph schema `6.2` / graph-fragment schema `1.5`: `supporting_calls`, `crypto_entry_points`, `graph_algo_version` exposed end-to-end. (#40)

## [0.8.0] - 2026-06-04

### Added
- **`crypto-finder annotate --import-fragment <fragment.json> --source <dir>`**: re-annotate a component against its **cached structural graph fragment without rebuilding the callgraph**. Runs only crypto detection over the source and maps each finding onto the imported graph (`Fragment.ContainingFunction`), emitting fresh `crypto_annotations`. For a large library this turns a rules-driven re-annotation from a full scan (~20 min on bcprov) into detection-only (~60 s); the annotations are byte-identical to a full `--export-graph-fragment` for unchanged rules. (#39)
- **`graph_algo_version`** (`GraphAlgoVersion`, stamped into `scan_metadata`): the callgraph-construction algorithm version, independent of the binary version (`tool_version`) and wire schema (`schema_version`). Consumers cache the structural graph keyed on it, so a routine binary release no longer invalidates the cache — only a graph-affecting change does. `Function` now carries `EndLine`. (#39)
- `pkg/graphfrag`: entry-point-rooted stitch option (`StitchWithOptions` / `StitchOptions{EntryRootedOnly}`) — roots traces only at in-degree-0 functions in the dependency closure, preserving the reachable-finding set while drastically reducing roots for large libraries (serving latency). Default `Stitch` behaviour is unchanged. (#39)

### Removed
- `pkg/stitch` (the concat-merge stitcher) — superseded by `pkg/graphfrag`'s true cross-component synthesis. It assumed call chains never span component boundaries, which is false for real dependency trees; it had no remaining in-repo or downstream consumers. (#39)

## [0.7.0] - 2026-06-02

### Added
- Graph-fragment export bumped to **`graph-fragment-1.2`**: edges now carry the per-call data-flow (`entry_call` with `parameters`/`source_nodes`) and crypto annotations carry the full asset metadata (`crypto_call`, `oid`, `metadata`, `source`) — making a fragment self-contained enough to reconstruct the schema-5.x callgraph.
- `pkg/graphfrag`: `Result.ToCallgraphExport()` renders a stitched result into a schema-5.x callgraph **equivalent to a live `--scan-dependencies --export-callgraph` run** (rich spanning chains, `entry_point_index`, dep-prefixed `finding_id`s), resolution-corrected (over-broad dispatch suppressed). `CallFrame` enriched with function identity + edge `entry_call`.
- `pkg/graphfrag/equiv`: semantic diff tool for asserting a stitched callgraph equals the live one minus resolution-suppressed chains (the e2e equivalence gate).
- `pkg/graphfrag`: `ToFindingsEnvelope(root, deps, fragments, meta)` reconstructs the findings.json **v1.3 envelope** (every crypto asset in the dependency closure, with `match`/`oid`/`source`/`metadata`/lines) from stored fragments — the asset-metadata companion to `ToCallgraphExport`. finding_ids are computed identically (dep-prefixed `module@version/path` for transitive findings), so a serving layer can join assets to call chains by finding_id without a live `--scan-dependencies` run. `CryptoOperation` now carries `EndLine` and `Match` (previously dropped on ingest).

### Fixed
- Java call resolution: methods invoked on an **inline constructor or constructor-rooted fluent chain** — `new X().setProvider("BC").method(...)` — now resolve to the constructor type `X` (canonical callee key `pkg.(X).method#arity`) instead of leaking the raw source expression into the callee key. Previously these edges were unresolvable, so in the graph-fragment stitch they dangled and any crypto sink reachable only through them (e.g. `JcaX509CertificateConverter.getCertificate`, `JceOpenSSLPKCS8DecryptorProviderBuilder.build` → `CipherFactory.createCipher` → `AESEngine.newInstance`) was lost. Only chains rooted at `new X()` are resolved (the builder/fluent assumption that intermediate calls return the builder); variable- and static-rooted chains are unchanged, so no false edges are introduced. Surfaced by the graph-fragment ≡ live e2e equivalence gate on a real BouncyCastle project.

## [0.6.0] - 2026-06-01

### Added
- `pkg/graphfrag`: new public package owning the reusable graph-fragment model, the wire schema (`GraphFragmentExport`), `DecodeFragment`, and a tiered fail-closed stitcher that composes per-component fragments into transitive crypto-reachability chains. Downstream services consume this one contract instead of reimplementing schema/merge logic (mirrors `pkg/stitch`).
- Call-graph edge **resolution classification**: each caller→callee edge is now tagged `exact`, `interface_dispatch`, or `name_only` at build time (`CallGraph.EdgeResolutions`), distinguishing exact typed calls from over-broad name+arity dispatch guesses (interface-dispatch expansion, fluent fallback).
- `--exclude` flag for user-supplied skip patterns on top of the built-in defaults. (#36)

### Changed
- Graph-fragment export schema bumped to `graph-fragment-1.1`: `internal_edges[]` and `external_calls[]` now carry `resolution`, `declared_type`, `method_name`, and `arity`. The fields are additive (1.0 fragments decode as unresolved/untrusted). See [docs/OUTPUT_FORMATS.md](docs/OUTPUT_FORMATS.md#graph-fragment-export).

## [0.5.0] - 2026-05-27

### Added
- `cryptoFunction` and `materialSize` CBOM metadata mappers. (#35)

### Changed
- Rulesets are loaded from a single directory containing multiple rule files instead of one file per invocation. (#35)

## [0.4.3] - 2026-05-22

### Fixed
- CLI pre-detects languages before configuring the scan and surfaces the underlying error cause on scan failures instead of a generic message. (#32)

## [0.4.2] - 2026-05-12

### Fixed
- `Dockerfile.deps` image user permissions in release builds.

## [0.4.1] - 2026-05-11

### Changed
- Release builds now run through `ghcr.io/goreleaser/goreleaser-cross:1.25.0` with per-target CGO toolchains so GoReleaser can build the tree-sitter-backed binaries for Linux, macOS, and Windows reliably

## [0.4.0] - 2026-05-11
### Added
- Postgres backend for the findings cache, selectable via `SCANOSS_FINDINGS_CACHE_BACKEND=postgres`, with `SCANOSS_FINDINGS_CACHE_DSN` and `SCANOSS_FINDINGS_CACHE_TABLE` (see `docs/CONFIGURATION.md`)
- Gradle support for Java dependency scanning, including structured error output
- Ruleset manifest stamping (version + checksum) on every scan, exposed in the `rules` field of the interim report for downstream auditing
- Multi-ecosystem repository handling (e.g., Java + Python sources scanned together)
- `name` field on CycloneDX evidence output entries (#26, #27)
- Java callgraph improvements:
  - Extensible multi-library knowledge base infrastructure (`internal/callgraph/contracts/`)
  - Built-in JCA/JCE inferred-types knowledge base
  - In-method field and variable assignment tracing for inferred return propagation
  - Generic type resolution
  - Initial reflection and interface dispatch support
  - Entrypoint index in callgraph export
  - `canonical_signature`, `return_type`, `parameter_types`, `visibility`, and `owner_visibility` fields on call nodes

### Changed
- Reshaped call chain schema for cross-library compatibility
- Refactored Maven source fallback worker into composable helpers
- Pinned `golangci-lint` via Makefile (`make lint-install` / `make lint`) in CI, replacing `golangci-lint-action`
- Cache file-lock acquisition and release now log file-descriptor and unlock failures explicitly

### Fixed
- `Dockerfile.deps` environment paths
- Gradle dependency resolution: pass `--no-parallel` to avoid intermittent build failures
- Java mining stability: resolver edge cases and missing-source fallback

## [0.3.0] - 2026-02-23
### Added
- Dependency scanning: detect cryptographic usage in third-party dependencies with call chain tracing
  - Go support via `go list` and `go mod graph`
  - Java support via Maven dependency resolution
  - Python support via pip with isolated virtualenv
  - Rust support via `cargo metadata`
- `--scan-dependencies` CLI flag to enable dependency scanning
- `--export-callgraph` flag for debugging call graph output
- Java source code parser using tree-sitter
- Python source code parser using tree-sitter
- Rust source code parser using tree-sitter
- `Dockerfile.deps` / `latest-deps` Docker image with all language toolchains for dependency scanning
- Parallel dependency scanning across multiple dependencies
- Support for multiple call chains per cryptographic finding
- Dependency scanning documentation (`docs/DEPENDENCY_SCANNING.md`)

### Fixed
- Docker build compatibility with Go 1.25 and go-tree-sitter (CGO linking)

## [0.2.4] - 2026-02-11
### Added
- Add OID mapping for LMS/HSS hash-based signature algorithm (RFC 8554 / RFC 8708)

## [0.2.3] - 2026-02-09
### Removed
- Remove `timestamp_utc` from JSON output

## [0.2.2] - 2026-02-06
### Added
- Add OID mappings for post-quantum algorithms: ML-DSA (FIPS 204), ML-KEM (FIPS 203), and SLH-DSA (FIPS 205) with all parameter set variants
- Add OID mappings for classic algorithms: MD5, MD4, PBKDF2, scrypt, X25519, X448, Ed25519, Ed448, DH, ECDH, SM2, SM3, RC4, RSA-OAEP, and HMAC family
- Add `--interfile` flag for cross-file analysis support when using Semgrep Pro (`--scanner semgrep --interfile`)

## [0.2.1] - 2026-02-03
### Changed
- Improved deterministic output by sorting findings by file path and cryptographic assets by line number in interim format
- Enhanced CycloneDX CBOM output consistency by sorting components alphabetically by name and occurrences by file path and line number
- Ensured identical code scans always produce byte-for-byte identical JSON output regardless of internal processing order

## [0.2.0] - 2026-01-29
### Added
- Add OID enrichment with proper mappings

## [0.1.5] - 2026-01-28
### Fixed
- Fix metavar resolution for numbered capture groups ($1, $2, etc.) from Semgrep regex patterns

## [0.1.4] - 2026-01-27
### Fixed
- Fix non-deterministic output in deduplicator by preserving asset insertion order
- Fix deduplicator incorrectly merging assets of different types (e.g., IV and algorithm) detected on the same line by including assetType in deduplication key

### Removed
- Remove unused `buildProperties` method from RelatedCryptoMapper (rule information is now properly handled via CycloneDX Evidence structure)

### Added
- Per-line deduplication of cryptographic findings to eliminate duplicate detections when multiple rules identify the same asset
- Support for multiple detection rules per cryptographic asset with new `rules` array field
- Interim report format v1.1 with enhanced data model for multi-rule assets
- Configuration flag for deduplication control

### Changed
- Interim report format version bumped from v1.0 to v1.1 (breaking change: `rule` field replaced with `rules` array)
- Data model updated to support multiple rules per asset in `internal/entities/interim.go`
- Aggregator logic enhanced to handle multi-rule assets in `internal/converter/aggregator.go`
- CycloneDX evidence format alignment improvements
- Updated `schemas/interim-report-schema.json` to reflect v1.1 format

## [0.1.3] - 2026-01-20
### Fixed
- Fix macOS signing secret mapping in release workflow to use correct GitHub organization secrets (MACOS_DEVELOPER_CERT and MACOS_DEVELOPER_CERT_PASSWORD)
- Fix macOS notarization configuration to reference correct build ID (crypto-finder instead of crypto-finder-archive)
- Fix Windows signing to only process .exe files, avoiding errors with metadata.json and other non-executable files
- Enable malware scanning for Windows code signing (required by SSL.com eSigner service)

## [0.1.2] - 2026-01-19
### Fixed
- Disable Sign Windows Binaries step when secrets are not available

## [0.1.1] - 2026-01-19
### Fixed
- Fix ./github/workflows/version-bump.yml workflow to use Github App Token instead of Personal Access Token

## [0.1.0] - 2026-01-13
### Added
- LICENSE file with GPL-2.0-only license text
- CONTRIBUTING.md with comprehensive contribution guidelines
- CODE_OF_CONDUCT.md with Contributor Covenant v2.1
- GPL-2.0-only license headers to all Go source files
- SPDX license identifiers in all source files

### Changed
- Updated README.md with explicit GPL-2.0-only license information
- Updated README.md Contributing section to reference CONTRIBUTING.md and CODE_OF_CONDUCT.md

[0.1.0]: https://github.com/scanoss/crypto-finder/releases/tag/v0.1.0
[0.1.1]: https://github.com/scanoss/crypto-finder/compare/v0.1.0...v0.1.1
[0.1.2]: https://github.com/scanoss/crypto-finder/compare/v0.1.1...v0.1.2
[0.1.3]: https://github.com/scanoss/crypto-finder/compare/v0.1.2...v0.1.3
[0.1.4]: https://github.com/scanoss/crypto-finder/compare/v0.1.3...v0.1.4
[0.1.5]: https://github.com/scanoss/crypto-finder/compare/v0.1.4...v0.1.5
[0.2.0]: https://github.com/scanoss/crypto-finder/compare/v0.1.5...v0.2.0
[0.2.1]: https://github.com/scanoss/crypto-finder/compare/v0.2.0...v0.2.1
[0.2.2]: https://github.com/scanoss/crypto-finder/compare/v0.2.1...v0.2.2
[0.2.3]: https://github.com/scanoss/crypto-finder/compare/v0.2.2...v0.2.3
[0.2.4]: https://github.com/scanoss/crypto-finder/compare/v0.2.3...v0.2.4
[0.3.0]: https://github.com/scanoss/crypto-finder/compare/v0.2.4...v0.3.0
[0.4.0]: https://github.com/scanoss/crypto-finder/compare/v0.3.0...v0.4.0
[0.4.1]: https://github.com/scanoss/crypto-finder/compare/v0.4.0...v0.4.1
[0.4.2]: https://github.com/scanoss/crypto-finder/compare/v0.4.1...v0.4.2
[0.4.3]: https://github.com/scanoss/crypto-finder/compare/v0.4.2...v0.4.3
[0.5.0]: https://github.com/scanoss/crypto-finder/compare/v0.4.3...v0.5.0
[0.6.0]: https://github.com/scanoss/crypto-finder/compare/v0.5.0...v0.6.0
[0.7.0]: https://github.com/scanoss/crypto-finder/compare/v0.6.0...v0.7.0
[0.8.0]: https://github.com/scanoss/crypto-finder/compare/v0.7.0...v0.8.0
[0.9.0]: https://github.com/scanoss/crypto-finder/compare/v0.8.0...v0.9.0
[0.9.1]: https://github.com/scanoss/crypto-finder/compare/v0.9.0...v0.9.1
[0.9.2]: https://github.com/scanoss/crypto-finder/compare/v0.9.1...v0.9.2
[0.9.3]: https://github.com/scanoss/crypto-finder/compare/v0.9.2...v0.9.3
[0.9.4]: https://github.com/scanoss/crypto-finder/compare/v0.9.3...v0.9.4
[0.10.0]: https://github.com/scanoss/crypto-finder/compare/v0.9.4...v0.10.0
[0.11.0]: https://github.com/scanoss/crypto-finder/compare/v0.10.0...v0.11.0
[0.12.0]: https://github.com/scanoss/crypto-finder/compare/v0.11.0...v0.12.0
[0.12.1]: https://github.com/scanoss/crypto-finder/compare/v0.12.0...v0.12.1
[0.13.0]: https://github.com/scanoss/crypto-finder/compare/v0.12.1...v0.13.0
[0.13.1]: https://github.com/scanoss/crypto-finder/compare/v0.13.0...v0.13.1
[0.13.2]: https://github.com/scanoss/crypto-finder/compare/v0.13.1...v0.13.2
[0.13.3]: https://github.com/scanoss/crypto-finder/compare/v0.13.2...v0.13.3
[0.13.4]: https://github.com/scanoss/crypto-finder/compare/v0.13.3...v0.13.4
[0.18.0]: https://github.com/scanoss/crypto-finder/compare/v0.17.0...v0.18.0
[0.19.0]: https://github.com/scanoss/crypto-finder/compare/v0.18.0...v0.19.0
[0.20.0]: https://github.com/scanoss/crypto-finder/compare/v0.19.0...v0.20.0
[0.21.0]: https://github.com/scanoss/crypto-finder/compare/v0.20.0...v0.21.0
[0.22.0]: https://github.com/scanoss/crypto-finder/compare/v0.21.0...v0.22.0
[0.23.0]: https://github.com/scanoss/crypto-finder/compare/v0.22.0...v0.23.0
[0.24.0]: https://github.com/scanoss/crypto-finder/compare/v0.23.0...v0.24.0