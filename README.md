# Crypto Finder

![GitHub release (latest by date)](https://img.shields.io/github/v/release/scanoss/crypto-finder)
![License](https://img.shields.io/badge/license-GPL--2.0--only-brightgreen)
[![Go Version](https://img.shields.io/github/go-mod/go-version/scanoss/crypto-finder)](https://go.dev/)

Crypto Finder is a CLI tool that detects cryptographic algorithm usage in source code. It runs detection rules through a scanning engine (OpenGrep by default, Semgrep supported), builds a call graph of the scanned code, computes which crypto findings are reachable from which API entry points, and exports the results as interim JSON, CycloneDX CBOM, a finding-centric call graph, or a reusable graph fragment.

## Quick Start

```bash
# Configure your API key (one-time setup)
crypto-finder configure --api-key YOUR_API_KEY

# Scan a project using the remote ruleset
crypto-finder scan /path/to/code

# Generate a CycloneDX CBOM
crypto-finder scan --format cyclonedx --output cbom.json /path/to/code

# Scan with call graph reachability export
crypto-finder scan --export-callgraph callgraph.json --output findings.json /path/to/code
```

## Installation

### Prerequisites

- **Go** 1.25+ (only for building from source)
- **OpenGrep** (recommended) or **Semgrep** — the scanning engine. Included in the Docker images.

    ```bash
    # OpenGrep v1.12.1: download from https://github.com/opengrep/opengrep/releases/tag/v1.12.1
    # Semgrep:
    pip install semgrep==1.145.0
    ```

### Setup

**Option 1: Build from source**

```bash
git clone https://github.com/scanoss/crypto-finder.git
cd crypto-finder
make build
sudo make install
```

**Option 2: Go install**

```bash
go install github.com/scanoss/crypto-finder/cmd/crypto-finder@latest
```

**Option 3: Docker**

```bash
# Full image with scanners included (recommended)
docker pull ghcr.io/scanoss/crypto-finder:latest

# Slim image (bring your own scanner)
docker pull ghcr.io/scanoss/crypto-finder:latest-slim

# Deps image (all language toolchains for dependency scanning)
docker pull ghcr.io/scanoss/crypto-finder:latest-deps
```

## Commands

| Command | Purpose |
|---------|---------|
| `scan` | Scan a source tree for crypto usage. Optionally builds the call graph, scans dependencies, and exports reachability artifacts. |
| `annotate` | Re-run **only crypto detection** against a previously exported graph fragment — skips the expensive call graph rebuild. |
| `convert` | Convert interim JSON results to CycloneDX CBOM. |
| `configure` | Persist the SCANOSS API key / URL. |
| `version` | Print version information. |

## Scanning

```bash
# Remote ruleset (default; requires API key)
crypto-finder scan /path/to/code

# Local rules only (rules development loop, offline use)
crypto-finder scan --no-remote-rules --rules-dir ./rules /path/to/code

# CI/CD: fail the build when crypto is detected
crypto-finder scan --fail-on-findings /path/to/code

# Scan third-party dependencies with call chain tracing
crypto-finder scan --scan-dependencies /path/to/code

# Export the finding-centric call graph (reachability slices)
crypto-finder scan --export-callgraph callgraph.json /path/to/code

# Export a reusable structural graph fragment (for stitching / caching)
crypto-finder scan --export-graph-fragment fragment.json /path/to/code
```

The interim JSON report (findings + metadata) goes to `--output` (stdout by default). The call graph and graph fragment exports are **separate files** written to the paths given to `--export-callgraph` / `--export-graph-fragment`. Use `scan --progress` when an integration needs lifecycle JSONL on stderr; it suppresses human logs and leaves findings on stdout or `--output`. See [Output Formats](docs/OUTPUT_FORMATS.md) for all schemas.

## Re-annotation: `annotate` vs `scan`

The call graph build (parsing + type inference) is the expensive ~95% of a scan and is **rules-independent**. When only the detection ruleset changed — new rules version, local rule you are iterating on — you do not need to rebuild the graph:

```bash
# One-time: full scan, cache the structural fragment
crypto-finder scan --export-graph-fragment fragment.json /path/to/code

# Every rules change afterwards: detection-only re-annotation
crypto-finder annotate --import-fragment fragment.json --source /path/to/code --output annotation.json
```

`annotate` runs only the detection pass, maps each finding onto the imported fragment's function line ranges, and emits `crypto_annotations` that are byte-identical to a full `scan --export-graph-fragment` for the same source + rules. On a large library this turns a ~20 minute re-scan into ~1 minute of detection.

Use `scan` when the **source code** changed (the graph must be rebuilt); use `annotate` when only the **rules** changed. The fragment's `graph_algo_version` in `scan_metadata` tells you when a new binary release invalidates cached fragments (it bumps only on graph-construction changes).

## Flag Reference

### Global flags (all commands)

| Flag | Default | Description |
|------|---------|-------------|
| `-v`, `--verbose` | off | Info-level logging |
| `-d`, `--debug` | off | Debug-level logging |
| `-q`, `--quiet` | off | Error-level logging only |
| `--error-format <fmt>` | `text` | Terminal error rendering: `text` or `json`. With `json`, failures are emitted to stderr as a structured payload with a stable `code` and `stage` — see [Error Codes](docs/ERROR_CODES.md). |

### `scan` flags

| Flag | Default | Description |
|------|---------|-------------|
| `-r`, `--rules <file>` | — | Rule file path (repeatable) |
| `--rules-dir <dir>` | — | Rule directory path (repeatable) |
| `--no-remote-rules` | off | Disable the default remote ruleset |
| `--no-cache` | off | Force fresh download of remote rules, bypass cache |
| `--strict` | off | Fail if the rules cache expired and the API is unreachable (no stale-cache fallback) |
| `--max-stale-age <dur>` | `30d` | Maximum age for stale cache fallback (max `90d`) |
| `--scanner <name>` | `opengrep` | Scanner engine: `opengrep`, `semgrep` |
| `-f`, `--format <fmt>` | `json` | Output format: `json` (interim), `cyclonedx` |
| `-o`, `--output <file>` | stdout | Output file path for the findings report |
| `--languages <langs>` | auto | Override language detection (comma-separated) |
| `--fail-on-findings` | off | Exit non-zero if findings are detected |
| `-t`, `--timeout <dur>` | `10m` | Scan timeout (e.g. `10m`, `1h`, `2w`) |
| `--no-dedup` | off | Disable per-line deduplication of findings |
| `--include-tests` | off | Include test sources in findings and dependency scans |
| `--no-default-exclusions` | off | Disable built-in directory exclusions (`vendor`, `node_modules`, `dist`, ...). Slows scans on large repos; combine with `--exclude` to re-add specific dirs |
| `--exclude <glob>` | — | Gitignore-style pattern to skip (repeatable); added on top of the defaults |
| `--scan-dependencies` | off | Recursively scan third-party dependencies (requires the deps image or local toolchains) |
| `--dep-ecosystem <eco>` | `auto` | Dependency ecosystem: `auto`, `go`, `java`, `python`, `rust` |
| `--dep-workers <n>` | `0` | Parallel dependency scan workers (0 = half of CPU cores, max 8; Java max 2) |
| `--findings-cache <backend>` | `disk` | Dependency findings cache backend: `disk`, `none`, `postgres` (also via `SCANOSS_FINDINGS_CACHE_BACKEND`; postgres needs `SCANOSS_FINDINGS_CACHE_DSN`) |
| `--progress` | off | Write scan lifecycle JSONL to stderr; findings remain on stdout or `--output`, and explicit `--error-format=text` is incompatible |
| `--export-callgraph <file>` | — | Write the finding-centric crypto call graph (reachability slices) to `<file>` |
| `--export-callgraph-format <fmt>` | `json` | Call graph export format (only `json`) |
| `--export-graph-fragment <file>` | — | Write a reusable structural graph fragment to `<file>` |
| `--export-graph-fragment-format <fmt>` | `json` | Graph fragment export format (only `json`) |
| `--java-jdk-major <major>` | — | Java JDK major for dependency resolution/type enrichment: `auto`, `8`, `11`, `17`, `21` |
| `--java-jdk-home <major=path>` | — | Explicit JDK home mapping (repeatable) |
| `--java-compiled-artifact <path>` | — | Compiled Java artifact used for standalone callgraph/type enrichment |
| `--interfile` | off | Cross-file analysis (Semgrep Pro only) |
| `--api-key`, `--api-url` | config | Override the configured SCANOSS API key / base URL |

### `annotate` flags

| Flag | Default | Description |
|------|---------|-------------|
| `--import-fragment <file>` | required | Cached structural graph fragment JSON to re-annotate |
| `--source <dir>` | required | Source directory to run crypto detection over |
| `-o`, `--output <file>` | stdout | Output file for the annotation JSON |

`annotate` also accepts the detection-related subset of `scan` flags: `--rules`, `--rules-dir`, `--no-remote-rules`, `--no-cache`, `--scanner`, `--timeout`, `--languages`, `--include-tests`, `--no-default-exclusions`, `--exclude`, `--api-key`, `--api-url`.

## Language Coverage

Detection (rules-based scanning) covers whatever languages the ruleset covers. Call graph construction and reachability analysis support these ecosystems:

| Ecosystem | Call graph parser | Contract knowledge bases (`internal/callgraph/contracts/`) |
|-----------|-------------------|-------------------------------------------------------------|
| C | yes | OpenSSL EVP, libsodium, Mbed TLS, wolfSSL/wolfCrypt |
| C++ | yes | none yet (bootstrap placeholder) |
| Go | yes | stdlib `crypto/*`, `golang.org/x/crypto`, golang-fips/openssl |
| Java | yes | JDK JCA/JCE, BouncyCastle (+ OpenPGP), Tink, jjwt, Nimbus JOSE+JWT, Apache Santuario, Apache SSHD, Password4j, Spring Security Crypto |
| JavaScript / TypeScript (Node) | yes | none yet (bootstrap placeholder) |
| Python | yes | pyca/cryptography, PyCryptodome(x), paramiko, passlib, bcrypt, argon2-cffi, PyNaCl, pyOpenSSL, M2Crypto, PyJWT, flask-jwt-extended, pyotp, werkzeug, boto3, azure-keyvault-keys/secrets |
| Rust | yes | ring, chacha20poly1305 |

Dependency scanning (`--scan-dependencies`) resolves and scans third-party packages for: **Go**, **Java** (Maven/Gradle), **Python** (pip), **Rust** (Cargo).

## Detection Rules

Detection rules are **not in this repository** — they live in [scanoss/crypto_rules](https://github.com/scanoss/crypto_rules) and are served as the remote `dca` ruleset via the SCANOSS API (cached locally with TTL + stale fallback; see [Remote Rulesets](docs/REMOTE_RULESETS.md)).

Local rules development loop:

```bash
# Iterate on rules without touching the remote ruleset
crypto-finder scan --no-remote-rules --rules-dir /path/to/crypto_rules/checkout /path/to/testcode

# Combine remote rules with local additions
crypto-finder scan --rules-dir ./custom-rules /path/to/code
```

Small rule fixtures used by this repo's tests live under `testdata/rules/`. Rules detect **terminal crypto operations only** and carry standard CycloneDX metadata; supporting/lifecycle calls are derived structurally from the call graph, never tagged by rules — see [Architecture](docs/ARCHITECTURE.md#load-bearing-invariants).

## Configuration

```bash
crypto-finder configure --api-key YOUR_API_KEY
crypto-finder configure --api-url https://custom.scanoss.com
```

Environment variables: `SCANOSS_API_KEY`, `SCANOSS_API_URL`. Project-level skip patterns via `scanoss.json`:

```json
{
  "settings": {
    "skip": {
      "patterns": {
        "scanning": ["node_modules/", "target/", "venv/"]
      }
    }
  }
}
```

See [Configuration](docs/CONFIGURATION.md) for the full guide.

## Documentation

| Document | Contents |
|----------|----------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Pipeline overview, package map, load-bearing invariants |
| [docs/OUTPUT_FORMATS.md](docs/OUTPUT_FORMATS.md) | Interim JSON, callgraph export (schema `6.9`), graph fragment (`graph-fragment-1.10`), CycloneDX CBOM |
| [docs/ERROR_CODES.md](docs/ERROR_CODES.md) | Stable failure code/stage taxonomy emitted by `--error-format json` |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Configuration options and skip patterns |
| [docs/DEPENDENCY_SCANNING.md](docs/DEPENDENCY_SCANNING.md) | Dependency scanning, call chain tracing, attribution |
| [docs/REMOTE_RULESETS.md](docs/REMOTE_RULESETS.md) | Remote ruleset API, caching, troubleshooting |
| [docs/DOCKER_USAGE.md](docs/DOCKER_USAGE.md) | Container usage and CI/CD integration |
| [CONTEXT.md](CONTEXT.md) | Domain glossary — the ubiquitous language used across code and docs |
| [AGENTS.md](AGENTS.md) | Conventions for AI agents and contributors (changelog policy, error layering, contracts KB) |

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) and our [Code of Conduct](CODE_OF_CONDUCT.md).

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`make test`)
5. Install pinned linter (`make lint-install`)
6. Run linter (`make lint`)
7. Commit your changes (`git commit -m 'feat: add an amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes — including every partner-facing schema bump.

## License

Copyright (C) 2026 SCANOSS.COM

This program is free software; you can redistribute it and/or modify it under the terms of the **GNU General Public License version 2** as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the [LICENSE](LICENSE) file for the full license text.

**SPDX-License-Identifier:** GPL-2.0-only

## Links

- [SCANOSS Website](https://www.scanoss.com)
- [SCANOSS Documentation](https://scanoss.readthedocs.io)
- [Detection Rules Repository](https://github.com/scanoss/crypto_rules)
- [Issue Tracker](https://github.com/scanoss/crypto-finder/issues)

## Support

For questions, issues, or feature requests, please use the [GitHub Issues](https://github.com/scanoss/crypto-finder/issues) page.
