# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Graph-fragment export bumped to **`graph-fragment-1.2`**: edges now carry the per-call data-flow (`entry_call` with `parameters`/`source_nodes`) and crypto annotations carry the full asset metadata (`crypto_call`, `oid`, `metadata`, `source`) — making a fragment self-contained enough to reconstruct the schema-5.x callgraph.
- `pkg/graphfrag`: `Result.ToCallgraphExport()` renders a stitched result into a schema-5.x callgraph **equivalent to a live `--scan-dependencies --export-callgraph` run** (rich spanning chains, `entry_point_index`, dep-prefixed `finding_id`s), resolution-corrected (over-broad dispatch suppressed). `CallFrame` enriched with function identity + edge `entry_call`.
- `pkg/graphfrag/equiv`: semantic diff tool for asserting a stitched callgraph equals the live one minus resolution-suppressed chains (the e2e equivalence gate).

## [0.6.0] - 2026-06-01

### Added
- `pkg/graphfrag`: new public package owning the reusable graph-fragment model, the wire schema (`GraphFragmentExport`), `DecodeFragment`, and a tiered fail-closed stitcher that composes per-component fragments into transitive crypto-reachability chains. Downstream services consume this one contract instead of reimplementing schema/merge logic (mirrors `pkg/stitch`).
- Call-graph edge **resolution classification**: each caller→callee edge is now tagged `exact`, `interface_dispatch`, or `name_only` at build time (`CallGraph.EdgeResolutions`), distinguishing exact typed calls from over-broad name+arity dispatch guesses (interface-dispatch expansion, fluent fallback).

### Changed
- Graph-fragment export schema bumped to `graph-fragment-1.1`: `internal_edges[]` and `external_calls[]` now carry `resolution`, `declared_type`, `method_name`, and `arity`. The fields are additive (1.0 fragments decode as unresolved/untrusted). See [docs/OUTPUT_FORMATS.md](docs/OUTPUT_FORMATS.md#graph-fragment-export).

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
