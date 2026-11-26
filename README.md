# Crypto Finder

![GitHub release (latest by date)](https://img.shields.io/github/v/release/scanoss/crypto-finder)
![License](https://img.shields.io/badge/license-GPL--2.0--only-brightgreen)
[![Go Version](https://img.shields.io/github/go-mod/go-version/scanoss/crypto-finder)](https://go.dev/)

Crypto Finder finds the cryptography a codebase uses and tells you whether the
application reaches it. It builds a typed call graph of your code, detects
cryptographic operations on it, and traces call chains from the application's
entry points. With `--scan-dependencies` it does the same for your
dependencies. It writes a findings report, a CycloneDX CBOM, or a call graph
export.

| | |
|---|---|
| Languages | Java, Python, Go, JavaScript, TypeScript, Rust, Ruby, C, C++, C# |
| Dependencies | Java (Maven, Gradle), Python, Go, JavaScript/TypeScript (npm, yarn, pnpm), Rust (Cargo), Ruby (Bundler), C# (NuGet) |
| Runs locally | Everything that reads your code. Source files never leave your machine ([what runs where](docs/CLIENT_SERVER.md)). |
| Upgrading from 0.5x | [docs/MIGRATION_1.0.md](docs/MIGRATION_1.0.md) |

## Quick start

```bash
# 1. Install
go install github.com/scanoss/crypto-finder/cmd/crypto-finder@latest

# 2. Save your SCANOSS API key (once)
crypto-finder configure --api-key YOUR_API_KEY

# 3. Scan
crypto-finder scan --output findings.json /path/to/code
```

`findings.json` lists every cryptographic operation found, with its file, line
and CycloneDX metadata. The API key fetches the detection ruleset; your code is
scanned on your machine.

More first runs:

```bash
# A CycloneDX CBOM
crypto-finder scan --format cyclonedx --output cbom.json /path/to/code

# Dependencies too, with a reachability verdict per finding
crypto-finder scan --scan-dependencies --export-callgraph callgraph.json \
  --output findings.json /path/to/code

# Fail a CI job when cryptography is found
crypto-finder scan --fail-on-findings /path/to/code
```

## Install

| Option | Command |
|---|---|
| Release binary | Download the archive for your platform from [Releases](https://github.com/scanoss/crypto-finder/releases) |
| Go 1.26+ | `go install github.com/scanoss/crypto-finder/cmd/crypto-finder@latest` |
| From source | `git clone https://github.com/scanoss/crypto-finder.git && cd crypto-finder && make install` |
| Docker | `docker pull ghcr.io/scanoss/crypto-finder:latest` (`latest-deps` adds JDKs, Maven, Gradle, Python, Go and Rust for `--scan-dependencies`; see [docs/DOCKER_USAGE.md](docs/DOCKER_USAGE.md)) |

Detection runs inside the binary; there is no external scanner to install.
For Java, put a full JDK 21 (one with a `jmods/` directory) on `JAVA_HOME`:
without it, calls on JDK types resolve by name only and some verdicts end
`unknown`. Dependency scans run the project's own build tools (`mvn`,
`gradle`, `cargo`) where the ecosystem needs them.

## Commands

| Command | Purpose |
|---|---|
| `scan` | Scan a source tree. Optionally scans dependencies and exports call graph artifacts. |
| `annotate` | Re-run detection on a stored graph fragment, without rebuilding the call graph. |
| `convert` | Convert a findings report to a CycloneDX CBOM. |
| `cbom` | Build a CBOM for an SBOM from the findings SCANOSS publishes for its components. |
| `configure` | Save the API key and API URL. |
| `version` | Print version information. |

Every flag: [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md), or
`crypto-finder <command> --help`.

## Documentation

| I want to | Read |
|---|---|
| Run my first scans and read the results | [User guide](docs/user-guide/user-guide.html) |
| Look up a command or flag | [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) |
| Set the API key, JDKs, skip patterns, timeouts | [docs/CONFIGURATION.md](docs/CONFIGURATION.md) |
| Scan dependencies | [docs/DEPENDENCY_SCANNING.md](docs/DEPENDENCY_SCANNING.md) |
| Scan dependencies without the SCANOSS API | [docs/OFFLINE.md](docs/OFFLINE.md) |
| Know what is sent to the SCANOSS API | [docs/CLIENT_SERVER.md](docs/CLIENT_SERVER.md) |
| Pin, cache or troubleshoot the ruleset | [docs/REMOTE_RULESETS.md](docs/REMOTE_RULESETS.md) |
| Run in Docker or CI | [docs/DOCKER_USAGE.md](docs/DOCKER_USAGE.md) |
| Parse the reports | [docs/OUTPUT_FORMATS.md](docs/OUTPUT_FORMATS.md) |
| Handle failures in CI | [docs/ERROR_CODES.md](docs/ERROR_CODES.md) |
| Know what is not detected or decided | [docs/KNOWN_LIMITS.md](docs/KNOWN_LIMITS.md) |
| Upgrade from 0.5x | [docs/MIGRATION_1.0.md](docs/MIGRATION_1.0.md) |
| Contribute | [CONTRIBUTING.md](CONTRIBUTING.md), then [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [AGENTS.md](AGENTS.md) |

Every change, including each schema bump, is in [CHANGELOG.md](CHANGELOG.md).

## Detection rules

The detection ruleset is maintained by SCANOSS and is not in this repository.
Scans fetch it from the SCANOSS API (the `crypto-cards` ruleset), so they need
an API key. With access to a local copy, `--no-remote-rules --rules-dir <dir>`
scans without the API. Ruleset content (rules, cards, conditions, fixtures)
must never be added to this repository.

The reachability engine is [scanoss/reach](https://github.com/scanoss/reach)
(MIT).

## Contributing

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md) and
the [Code of Conduct](CODE_OF_CONDUCT.md). Report bugs and request features in
[GitHub Issues](https://github.com/scanoss/crypto-finder/issues).

## License

Copyright (C) 2026 SCANOSS.COM. Licensed under the
[GNU General Public License version 2 only](LICENSE)
(SPDX-License-Identifier: GPL-2.0-only).
