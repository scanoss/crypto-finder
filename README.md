# Crypto Finder

![GitHub release (latest by date)](https://img.shields.io/github/v/release/scanoss/crypto-finder)
![License](https://img.shields.io/badge/license-GPL--2.0--only-brightgreen)
[![Go Version](https://img.shields.io/github/go-mod/go-version/scanoss/crypto-finder)](https://go.dev/)

A powerful CLI tool for detecting cryptographic algorithm usage in source code repositories. Crypto Finder scans codebases using multiple scanning engines (OpenGrep, Semgrep) and outputs results in standardized formats including JSON and CycloneDX CBOM (Cryptography Bill of Materials).

## TL;DR

```bash
# Configure your API key (one-time setup)
crypto-finder configure --api-key YOUR_API_KEY

# Scan a project using remote rulesets
crypto-finder scan /path/to/code

# Generate CycloneDX CBOM
crypto-finder scan --format cyclonedx --output cbom.json /path/to/code
```

## Installation

### Prerequisites

Before you begin, ensure you have the following installed:

- **Go** - version 1.25 or higher (for building from source)

    ```bash
    # macOS
    brew install go

    # Linux
    # Download from https://go.dev/dl/
    ```

- **OpenGrep** or **Semgrep** - for running scans (included in Docker images)

    ```bash
    # OpenGrep (recommended)
    # Download from https://github.com/returntocorp/semgrep

    # Semgrep
    pip install semgrep
    ```

### Setup

**Option 1: Build from Source**

```bash
git clone https://github.com/scanoss/crypto-finder.git
cd crypto-finder
make build
sudo make install
```

**Option 2: Go Install**

```bash
go install github.com/scanoss/crypto-finder/cmd/crypto-finder@latest
```

**Option 3: Docker**

```bash
# Full image with scanners included (recommended)
docker pull ghcr.io/scanoss/crypto-finder:latest

# Slim image (bring your own scanner)
docker pull ghcr.io/scanoss/crypto-finder:latest-slim
```

## Usage

### Basic Scanning

**Scan with remote rulesets (recommended):**

```bash
crypto-finder scan /path/to/code
```

**Scan with local rules:**

```bash
crypto-finder scan --no-remote-rules --rules-dir ./rules /path/to/code
```

**Generate CycloneDX CBOM:**

```bash
crypto-finder scan --format cyclonedx --output cbom.json /path/to/code
```

### Common Use Cases

**CI/CD Integration:**

```bash
# Fail build if cryptographic assets are detected
crypto-finder scan --fail-on-findings /path/to/code
```

**Custom Rule Combination:**

```bash
# Combine remote rules with local custom rules
crypto-finder scan --rules-dir ./custom-rules /path/to/code
```

**Force Fresh Rules:**

```bash
# Bypass cache and force fresh download
crypto-finder scan --no-cache /path/to/code
```

**Format Conversion:**

```bash
# Convert existing results to CycloneDX
crypto-finder convert results.json --output cbom.json

# Or pipe from scan
crypto-finder scan /path/to/code | crypto-finder convert --output cbom.json
```

### Configuration

The application can be configured via command-line flags, environment variables, or configuration files.

```bash
# Set API key
crypto-finder configure --api-key YOUR_API_KEY

# Set custom API URL
crypto-finder configure --api-url https://custom.scanoss.com
```

**Environment Variables:**

```bash
export SCANOSS_API_KEY=your-key
export SCANOSS_API_URL=https://custom.scanoss.com
```

**Project-level configuration** via `scanoss.json`:

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

For detailed configuration options, see [Configuration Documentation](docs/CONFIGURATION.md).

### Command Line Arguments

```bash
crypto-finder scan [flags] <target>
```

**Common options:**

- `--rules <file>` - Custom rule file (repeatable)
- `--rules-dir <dir>` - Rule directory (repeatable)
- `--no-remote-rules` - Disable remote ruleset fetching
- `--no-cache` - Force fresh download, bypass cache
- `--scanner <name>` - Scanner to use: `opengrep` (default), `semgrep`
- `--format <format>` - Output format: `json` (default), `cyclonedx`
- `--output <file>` - Output file path (default: stdout)
- `--languages <langs>` - Override language detection (comma-separated)
- `--fail-on-findings` - Exit with error if findings detected
- `--timeout <duration>` - Scan timeout (default: 10m)
- `--verbose`, `-v` - Enable verbose logging
- `--help` - Display help information

For a complete list of commands and options, run `crypto-finder --help`.

## Advanced Topics

### Features

- **Multi-Scanner Support** - OpenGrep (default) and Semgrep with advanced taint analysis
- **Remote Rulesets** - Automatically fetch curated rules from SCANOSS API with local caching
- **Flexible Configuration** - Combine remote and local rules, configure via CLI, env vars, or config files
- **Multiple Output Formats** - Interim JSON and CycloneDX 1.6 CBOM formats
- **CI/CD Ready** - Docker images for GitHub Actions, GitLab CI, Jenkins, and more
- **Smart Caching** - TTL-based cache with automatic stale cache fallback (opt-out with `--strict`)

### Documentation

- **[Remote Rulesets](docs/REMOTE_RULESETS.md)** - API configuration, caching strategies, and troubleshooting
- **[Output Formats](docs/OUTPUT_FORMATS.md)** - Interim JSON and CycloneDX CBOM format specifications
- **[Docker Usage](docs/DOCKER_USAGE.md)** - Container usage and CI/CD integration examples
- **[Configuration](docs/CONFIGURATION.md)** - Detailed configuration guide and skip patterns

## Contributing

We welcome contributions! For more details, see [CONTRIBUTING.md](CONTRIBUTING.md) and our [Code of Conduct](CODE_OF_CONDUCT.md).

### Quick Start

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`make test`)
5. Run linter (`make lint`)
6. Commit your changes (`git commit -m 'feat: add an amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes.

## License

Copyright (C) 2026 SCANOSS.COM

This program is free software; you can redistribute it and/or modify it under the terms of the **GNU General Public License version 2** as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the [LICENSE](LICENSE) file for the full license text.

**SPDX-License-Identifier:** GPL-2.0-only

## Links

- [SCANOSS Website](https://www.scanoss.com)
- [SCANOSS Documentation](https://scanoss.readthedocs.io)
- [SCANOSS Settings Schema](https://scanoss.readthedocs.io/projects/scanoss-py/en/latest/scanoss_settings_schema.html)
- [Issue Tracker](https://github.com/scanoss/crypto-finder/issues)

## Support

For questions, issues, or feature requests, please use the [GitHub Issues](https://github.com/scanoss/crypto-finder/issues) page.
