# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
