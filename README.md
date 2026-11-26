# Crypto Finder

![GitHub release (latest by date)](https://img.shields.io/github/v/release/scanoss/crypto-finder)
![License](https://img.shields.io/badge/license-GPL--2.0--only-brightgreen)
[![Go Version](https://img.shields.io/github/go-mod/go-version/scanoss/crypto-finder)](https://go.dev/)

Crypto Finder is a CLI that finds the cryptography a codebase uses and tells you whether the application reaches it. It builds a typed call graph of the code (with the [reach](https://github.com/scanoss/reach) engine), detects cryptographic operations on it, traces call chains from the application's entry points, and writes interim JSON, a CycloneDX CBOM, a finding-centric call graph, or a reusable graph fragment. With `--scan-dependencies` it also reports the cryptography of the project's dependencies and whether the project reaches it.

| | |
|---|---|
| Languages | Java, Python, Go, JavaScript, TypeScript, Rust, Ruby, C, C++ and C#. Other languages fail with `language_not_supported` ([Language Coverage](#language-coverage)). |
| Dependencies | Java (Maven, Gradle) and Python, from the SCANOSS API or `--offline` |
| Runs locally | Everything that reads your code. The API serves the ruleset and dependency findings ([what runs where](docs/CLIENT_SERVER.md)). |
| Upgrading from 0.5x | [docs/MIGRATION_1.0.md](docs/MIGRATION_1.0.md) |

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

- **Go** 1.26+ (only for building from source)
- A **JDK** for Java type resolution, and **Maven** or **Gradle** for `--scan-dependencies`. No external scanning engine is needed: detection runs in-process.

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
# The binary alone
docker pull ghcr.io/scanoss/crypto-finder:latest

# Deps image (JDKs, Maven and Gradle for --scan-dependencies)
docker pull ghcr.io/scanoss/crypto-finder:latest-deps
```

## Commands

| Command | Purpose |
|---------|---------|
| `scan` | Scan a source tree for crypto usage. Optionally builds the call graph, scans dependencies, and exports reachability artifacts. |
| `annotate` | Re-run **only crypto detection** against a previously exported graph fragment — skips the expensive call graph rebuild. |
| `convert` | Convert interim JSON results to CycloneDX CBOM. |
| `cbom` | Build a CycloneDX CBOM for an SBOM from the findings SCANOSS published for its components. |
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

# Report the dependencies' cryptography and whether the project reaches it
crypto-finder scan --scan-dependencies --export-callgraph callgraph.json /path/to/code

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

# Every rules change afterwards: detection-only re-annotation, no source tree needed
crypto-finder annotate --import-fragment fragment.json --output annotation.json --findings-output findings.json
```

`annotate` rebuilds the graph from the imported fragment, matches the ruleset's cards against its call sites, and emits crypto sections (`crypto_annotations`, `supporting_calls`, `crypto_entry_points`) identical to a full `scan --export-graph-fragment` for the same source + rules. A fragment from graph-fragment-1.16 on carries the call sites' source lines; for an older one, `--source` supplies them.

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
| `--strict` | off | Fail if the rules cache expired and the API is unreachable (no stale-cache fallback); a refused key (HTTP 401/403) always fails |
| `--max-stale-age <dur>` | `30d` | Maximum age for stale cache fallback (max `90d`) |
| `--ruleset <name>` | `crypto-cards` | Remote ruleset to fetch |
| `--ruleset-version <ver>` | `latest` | Remote ruleset release to fetch (e.g. `v1.39.0`); pin it to rerun a scan with identical rules |
| `-f`, `--format <fmt>` | `json` | Output format: `json` (interim), `cyclonedx` |
| `-o`, `--output <file>` | stdout | Output file path for the findings report |
| `--languages <langs>` | auto | Override language detection (comma-separated) |
| `--fail-on-findings` | off | Exit non-zero if findings are detected |
| `-t`, `--timeout <dur>` | `10m` | Scan timeout (e.g. `10m`, `1h`, `2w`) |
| `--no-dedup` | off | Disable per-line deduplication of findings |
| `--include-tests` | off | Include test sources in findings |
| `--no-default-exclusions` | off | Disable built-in exclusions (`vendor`, `node_modules`, `shaded/`, generated protobuf stubs, ...). Slows scans on large repos; combine with `--exclude` to re-add specific paths |
| `--exclude <glob>` | — | Gitignore-style pattern to skip (repeatable); added on top of the defaults |
| `--scan-dependencies` | off | Java (Maven, Gradle), and Python (locks, pinned requirements, the installed environment): resolve the pinned dependency closure to compiled JARs, type the project's call graph with them, and take every dependency finding and its reachability verdict from the SCANOSS API in one request (`/v3/cryptography/reachability/application`). No dependency source is downloaded or scanned. Needs the API (`--api-url`, `--api-key`). See [docs/DEPENDENCY_SCANNING.md](docs/DEPENDENCY_SCANNING.md) |
| `--offline` | off | With `--scan-dependencies`: decide dependency reachability locally instead of asking the SCANOSS API. Each dependency is mined from its sources (Java: Maven sources JAR; Python: installed distribution), cached, and stitched with the code the API runs. See [docs/OFFLINE.md](docs/OFFLINE.md) |
| `--offline-cache-dir <dir>` | `~/.scanoss/crypto-finder/cache/mined` | With `--offline`, the mined-dependency cache |
| `--offline-python-packages <dirs>` | — | With `--offline` on a Python target: installed packages to mine the dependencies from (OS path-list separated: virtual environments, site-packages directories, unpacked wheels), after the project's `.venv`, `venv` and `VIRTUAL_ENV`. Nothing is installed, downloaded or run |
| `--offline-memory-mb <n>` | `10240` | With `--offline`, the scan's soft memory limit in MiB (unless `GOMEMLIMIT` is set); half of it bounds the dependencies mined at once |
| `--dependency-reachability-max-chains` | `1` | With `--scan-dependencies`, call chains per dependency finding the API returns for `--export-callgraph` (0: none) |
| `--cards-index <file>` | — | Compiled card index to detect with, instead of compiling it from the ruleset's Java rules |
| `--cards-dir <dir>` | — | Cards directory to detect with, instead of the ruleset's `cards/` |
| `--type-jars <jars>` | — | Compiled dependency JARs (OS path-list separated) indexed for Java type resolution only (the miner passes a component's pinned dependencies) |
| `--type-packages <dirs>` | — | Installed Python dependency packages (OS path-list separated: site-packages or virtual environment directories, unpacked wheels or sdists) indexed for Python type resolution only, read as data: their classes and return annotations type the calls into them |
| `--progress` | off | Write scan lifecycle JSONL to stderr; findings remain on stdout or `--output`, and explicit `--error-format=text` is incompatible |
| `--export-callgraph <file>` | — | Write the finding-centric crypto call graph (reachability slices) to `<file>` |
| `--export-callgraph-format <fmt>` | `json` | Call graph export format (only `json`) |
| `--export-callgraph-max-chains <n>` | `8` | Sampled call chains per finding (depth cap 32); not a complete graph |
| `--export-callgraph-entry-points` | off | Add the full `crypto_entry_points` reverse-reachability index |
| `--export-callgraph-interned-frames` | on | Schema `6.18` interned frames; `=false` writes schema `6.14` inlined frames |
| `--export-callgraph-project-reachability` | off | Without `--scan-dependencies` (or when none resolved), classify reachability against the target's own source packages instead of reporting `not_applicable`; leave off when scanning a library on its own |
| `--export-graph-fragment <file>` | — | Write a reusable structural graph fragment to `<file>` |
| `--export-graph-fragment-format <fmt>` | `json` | Graph fragment export format (only `json`) |
| `--java-jdk-major <major>` | — | Java JDK major for dependency resolution/type enrichment: `auto`, `8`, `11`, `17`, `21` |
| `--java-jdk-home <major=path>` | — | Explicit JDK home mapping (repeatable) |
| `--java-compiled-artifact <path>` | — | Compiled Java artifact used for standalone callgraph/type enrichment |
| `--api-key`, `--api-url` | config | Override the configured SCANOSS API key / base URL |
| `--allow-http` | off | Allow a plain-HTTP `--api-url` on a remote host (sends the API key unencrypted) |

### `annotate` flags

| Flag | Default | Description |
|------|---------|-------------|
| `--import-fragment <file>` | required | Cached structural graph fragment JSON to re-annotate |
| `--source <dir>` | — | Source tree the fragment was exported from; only needed for a fragment older than graph-fragment-1.16, to read the source lines it lacks |
| `--findings-output <file>` | — | Also write the findings report, as `scan --output` writes it |
| `-o`, `--output <file>` | stdout | Output file for the annotation JSON |

`annotate` also accepts the detection-related subset of `scan` flags: `--rules`, `--rules-dir`, `--no-remote-rules`, `--no-cache`, `--ruleset`, `--ruleset-version`, `--timeout`, `--languages`, `--include-tests`, `--no-default-exclusions`, `--exclude`, `--api-key`, `--api-url`, `--allow-http`.

## Language Coverage

Detection runs on the cards engine, which this version supports for **Java** (JDK JCA/JCE, BouncyCastle (+ OpenPGP), Tink, jjwt, Nimbus JOSE+JWT, Apache Santuario, Apache SSHD, Password4j, Spring Security Crypto and the rest of the ruleset's Java rules). Dependency scanning (`--scan-dependencies`) covers **Java** projects built with Maven or Gradle.

**Python** (pyca/cryptography, hashlib, hmac, ssl, PyJWT, PyCryptodome, PyNaCl and the rest of the ruleset's Python rules) is scanned too: a target holding both is scanned for each, against each language's own rules, cards and call graph. `--scan-dependencies` resolves the closure of every scanned ecosystem that has one, including Python projects below the scan root (as for Maven and Gradle modules); on Python it resolves its pinned closure from its lock (`uv.lock`, `poetry.lock`, `Pipfile.lock`, `pdm.lock`, `pylock.toml`), fully pinned requirements or installed environment, and takes the dependency findings from the API (or `--offline`, from the installed distributions). Python dependency findings carry reachability verdicts like Java's; where the analysis cannot decide a route they read `unknown` (measured results in [docs/KNOWN_LIMITS.md](docs/KNOWN_LIMITS.md)). A declared requirement without a pin is listed with reason `unpinned`. See [Python dependencies](docs/DEPENDENCY_SCANNING.md#python-dependencies).

**Go** (the standard library's crypto packages, golang.org/x/crypto and the rest of the ruleset's Go rules) is scanned too, with calls into the standard library of the installed Go toolchain and into the `go.mod` modules the module cache holds typed from their declarations. On Go, `--scan-dependencies` resolves the pinned closure from `go.mod` without downloading anything (requirements at their versions, direct unless `// indirect`, after `replace`); `--offline` mines each dependency from the module cache.

**C**, **C++** and **C#** are scanned too, with no environment variable; `CRYPTO_FINDER_CARDS_C` and `CRYPTO_FINDER_CARDS_CSHARP` are no longer needed and are still accepted.

For any other language:

- a target whose sources are only in other languages fails with `language_not_supported` (exit code 1, `details.languages` names them), so no empty report reads as "no cryptography";
- a target with sources in other languages beside scanned ones is scanned for the scanned ones; a warning and the completed `detection` progress event (`unsupported_languages`) name the others;
- `--scan-dependencies` skips the dependency phase when no scanned ecosystem has anything to resolve: a Java target without a Java build (`ecosystem_not_supported` or `manifest_absent`), a Python target without a Python manifest, lock or environment at or below it, a Go target without a `go.mod` (`manifest_absent`), a JavaScript or TypeScript target without an npm, yarn or pnpm lock file (`manifest_absent`), a Rust target without a `Cargo.toml` or `Cargo.lock` (`manifest_absent`).


## Detection Rules

Detection rules are **not in this repository**. SCANOSS maintains the ruleset privately and serves it as the remote `crypto-cards` ruleset through the SCANOSS API, as a signed, leased bundle that the cache keeps encrypted ([Remote Rulesets](docs/REMOTE_RULESETS.md)). Ruleset content (rules, cards, conditions, fixtures) must never be added to this repository.

| To | Use |
|---|---|
| Scan with the remote ruleset (default) | `crypto-finder scan /path/to/code` |
| Pin a ruleset release | `--ruleset-version v1.39.0` |
| Use a local ruleset you have access to | `--no-remote-rules --rules-dir <dir>` |
| Add local rules to the remote ones | `--rules-dir <dir>` |
| Use a prebuilt card index or cards directory | `--cards-index <file>`, `--cards-dir <dir>` |

Rules detect terminal crypto operations only; supporting and lifecycle calls are derived from the call graph, never tagged by rules ([Architecture](docs/ARCHITECTURE.md#load-bearing-invariants)).

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

| Document | Read it to |
|----------|------------|
| [docs/MIGRATION_1.0.md](docs/MIGRATION_1.0.md) | Upgrade from 0.5x: removed flags, images, Go import paths |
| [docs/CLIENT_SERVER.md](docs/CLIENT_SERVER.md) | See what runs locally, what the SCANOSS API serves, what is sent |
| [docs/OFFLINE.md](docs/OFFLINE.md) | Scan dependencies without the API: cache, flags, limits |
| [docs/KNOWN_LIMITS.md](docs/KNOWN_LIMITS.md) | Know what is not decided (Python verdict coverage, unknowns) and why |
| [docs/DEPENDENCY_SCANNING.md](docs/DEPENDENCY_SCANNING.md) | Understand the dependency pipeline step by step |
| [docs/OUTPUT_FORMATS.md](docs/OUTPUT_FORMATS.md) | Parse interim JSON, the callgraph export, the graph fragment, CycloneDX |
| [docs/ERROR_CODES.md](docs/ERROR_CODES.md) | Handle failures from `--error-format json` |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Configure the API, JDKs, skip patterns, timeouts |
| [docs/REMOTE_RULESETS.md](docs/REMOTE_RULESETS.md) | Understand ruleset leases, caching and troubleshooting |
| [docs/DOCKER_USAGE.md](docs/DOCKER_USAGE.md) | Run in containers and CI |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Find your way in the code: pipeline, packages, invariants |
| [docs/GRAPH_IDS.md](docs/GRAPH_IDS.md) | Change graph construction: ids, when to bump, the guard |
| [CONTEXT.md](CONTEXT.md) | Learn the domain vocabulary |
| [AGENTS.md](AGENTS.md) | Contribute (agents and humans): changelog, errors, KB, merge gate |

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
- [reach, the reachability engine](https://github.com/scanoss/reach)
- [Issue Tracker](https://github.com/scanoss/crypto-finder/issues)

## Support

For questions, issues, or feature requests, please use the [GitHub Issues](https://github.com/scanoss/crypto-finder/issues) page.
