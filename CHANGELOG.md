# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3] - 2026-01-20
### Fixed
- Fix macOS signing secret mapping in release workflow to use correct GitHub organization secrets (MACOS_DEVELOPER_CERT and MACOS_DEVELOPER_CERT_PASSWORD)

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
