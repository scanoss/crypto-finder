# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Go callgraph contracts now model the legacy `github.com/golang-fips/openssl/v2` API's symmetric, KDF, public-key, and post-quantum cryptographic lifecycles. (#127)
- Graph-fragment exports now carry complete canonical target signatures and hierarchy-proven compatible callable signatures, allowing interface-typed dependency calls to join concrete crypto entry points without fabricating call edges. (#136)
- Java callgraph contracts now model the version-pinned Nimbus JOSE JWE and Spring Security Crypto lifecycles, including factory, operation, output, hierarchy, and key-size parameter-role semantics. (#137)
- Java callgraph lifecycle contracts now cover Bouncy Castle OpenPGP builders, Tink AEAD operations, and Apache Santuario XMLCipher factories and finalization. (#138)
- Rust callgraph inference now recognizes RustCrypto `chacha20poly1305` 0.11 factories and AEAD operations, including ChaCha20-Poly1305 and XChaCha20-Poly1305 detached and in-place calls. (#125)
- Rust callgraph inference now models `ring` 0.17 AEAD, digest, HMAC, HKDF, key-agreement, and signature lifecycles. (#70)
- Rust callgraph builds now load schema-v2 contract knowledge bases and select the Rust contract type resolver. (#69)
- Go callgraph builds now load schema-v2 contract knowledge bases and select the Go contract type resolver. (#75)
- Python callgraph inference now covers synchronous and asynchronous Azure Key Vault Secrets client construction and secret set, get, deleted-secret, backup, and restore results. (scanoss/crypto_rules#115)
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
- Nested-call findings now attribute matched operations and canonical call identities to the tightest source invocation instead of an enclosing call. (#134)
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

[0.1.0]: https://github.com/scanoss/crypto-finder/compare/v0.0.0...v0.1.0
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
[Unreleased]: https://github.com/scanoss/crypto-finder/compare/v0.13.4...HEAD
