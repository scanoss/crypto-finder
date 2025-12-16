# Crypto Finder

[![Go Version](https://img.shields.io/github/go-mod/go-version/scanoss/crypto-finder)](https://go.dev/)
[![License](https://img.shields.io/github/license/scanoss/crypto-finder)](LICENSE)
[![Release](https://img.shields.io/github/v/release/scanoss/crypto-finder)](https://github.com/scanoss/crypto-finder/releases)

A powerful CLI tool and execution framework for detecting cryptographic algorithm usage in source code repositories. Crypto Finder scans codebases using multiple scanning engines and outputs results in standardized formats including JSON and CycloneDX CBOM (Cryptography Bill of Materials).

## Features

- **Multi-Scanner Support**: Supports OpenGrep (default) and Semgrep with extensible architecture for additional scanners
- **Advanced Taint Analysis**: OpenGrep scanner includes `--taint-intrafile` by default for enhanced dataflow analysis
- **Automatic Language Detection**: Uses [go-enry](https://github.com/go-enry/go-enry) to detect project languages for optimized scanning
- **Flexible Rule Management**: Support for local rule files and directories
- **Standardized Output**: Interim JSON format compatible with the SCANOSS ecosystem
- **CycloneDX Support**: Convert results to CycloneDX 1.7 CBOM format
- **CI/CD Ready**: Docker images and integration-friendly design
- **Performance Optimized**: Language-based rule filtering to minimize scan time
- **Skip Patterns**: Configurable file/directory exclusion via scanoss.json

## Installation

### Build from Source

Requirements: Go 1.23.2 or later

```bash
git clone https://github.com/scanoss/crypto-finder.git
cd crypto-finder
make build
sudo make install
```

### Docker

```bash
# Full image with OpenGrep and Semgrep included
docker pull ghcr.io/scanoss/crypto-finder:latest

# Slim image (requires external scanner)
docker pull ghcr.io/scanoss/crypto-finder:latest-slim
```

### Go Install

```bash
go install github.com/scanoss/crypto-finder/cmd/crypto-finder@latest
```

## Quick Start

```bash
# Scan a directory with custom rules
crypto-finder scan --rules-dir ./rules /path/to/code

# Save output to a file
crypto-finder scan --rules-dir ./rules --output results.json /path/to/code

# Convert to CycloneDX CBOM format
crypto-finder convert results.json --output cbom.json

# Scan and convert in one pipeline
crypto-finder scan --rules-dir ./rules /path/to/code | crypto-finder convert --output cbom.json
```

## Usage

### Scan Command

Scan source code repositories for cryptographic algorithm usage.

```bash
crypto-finder scan [flags] <target>
```

**Common Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--rules <file>` | Rule file path (repeatable) | - |
| `--rules-dir <dir>` | Rule directory path (repeatable) | - |
| `--scanner <name>` | Scanner to use: `opengrep`, `semgrep` | `opengrep` |
| `--format <format>` | Output format: `json`, `cyclonedx` | `json` |
| `--output <file>` | Output file path | stdout |
| `--languages <langs>` | Override language detection (comma-separated) | auto-detect |
| `--fail-on-findings` | Exit with error if findings detected | `false` |
| `--timeout <duration>` | Scan timeout (e.g., 10m, 1h) | `10m` |
| `--scanner-args <arg>` | Pass additional arguments to scanner (repeatable) | - |
| `--verbose`, `-v` | Enable verbose logging | `false` |
| `--quiet`, `-q` | Enable quiet mode | `false` |

**Examples:**

```bash
# Basic scan with rules directory
crypto-finder scan --rules-dir ./rules /path/to/code

# Multiple rule sources
crypto-finder scan --rules rule1.yaml --rules rule2.yaml --rules-dir ./rules/ /path/to/code

# Override language detection
crypto-finder scan --languages java,python --rules-dir ./rules/ /path/to/code

# Output directly to CycloneDX format
crypto-finder scan --format cyclonedx --rules-dir ./rules --output cbom.json /path/to/code

# CI/CD mode (fail on findings)
crypto-finder scan --fail-on-findings --rules-dir ./rules/ /path/to/code

# Pipe output to jq for processing
crypto-finder scan --rules-dir ./rules /path/to/code | jq '.findings | length'

# Use Semgrep scanner instead of default OpenGrep
crypto-finder scan --scanner semgrep --rules-dir ./rules /path/to/code

# Pass extra arguments to the scanner (e.g., increase verbosity)
crypto-finder scan --scanner-args="--verbose" --rules-dir ./rules /path/to/code

# Pass multiple scanner arguments
crypto-finder scan --scanner-args="--verbose" --scanner-args="--max-memory=4GB" --rules-dir ./rules /path/to/code
```

### Convert Command

Convert interim JSON format to CycloneDX 1.6 CBOM format.

```bash
crypto-finder convert [flags] [input-file]
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--output`, `-o <file>` | Output file path | stdout |

**Examples:**

```bash
# Convert from file to stdout
crypto-finder convert results.json

# Convert from file to output file
crypto-finder convert results.json --output cbom.json

# Convert from stdin (pipe from scan)
crypto-finder scan --rules-dir ./rules /path/to/code | crypto-finder convert

# Convert from stdin redirect
crypto-finder convert < results.json
```

### Version Command

Display version information.

```bash
crypto-finder version
```

## Configuration

Crypto Finder supports configuration via `scanoss.json` in the target directory. This file can configure skip patterns and other settings.

**Example `scanoss.json`:**

```json
{
  "settings": {
    "skip": {
      "patterns": {
        "scanning": ["node_modules/", "target/", "venv/"]
      },
      "sizes": {}
    }
  }
}
```

For detailed configuration options, see the [SCANOSS Settings Schema Documentation](https://scanoss.readthedocs.io/projects/scanoss-py/en/latest/scanoss_settings_schema.html).

### Default Skip Patterns

The following patterns are excluded by default:

- Version control: `.git/`, `.svn/`, `.hg/`
- Dependencies: `node_modules/`, `vendor/`, `venv/`
- Build artifacts: `dist/`, `build/`, `target/`, `*.min.js`
- Archives: `*.zip`, `*.tar.gz`, `*.jar`, `*.war`
- Binaries: `*.exe`, `*.dll`, `*.so`, `*.dylib`

For more information on skip patterns, refer to default skip patterns [Default Skip Patterns](internal/skip/source_defaults.go)

## Docker Usage

### Basic Usage

```bash
# Scan with mounted volumes
docker run --rm \
  -v $(pwd)/code:/workspace/code:ro \
  -v $(pwd)/rules:/workspace/rules:ro \
  -v $(pwd)/output:/workspace/output \
  ghcr.io/scanoss/crypto-finder:latest \
  scan --rules-dir /workspace/rules --output /workspace/output/results.json /workspace/code
```

### CI/CD Integration

**GitHub Actions:**

```yaml
name: Crypto Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Crypto Finder
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/workspace \
            ghcr.io/scanoss/crypto-finder:latest \
            scan --rules-dir /workspace/rules \
            --output /workspace/results.json \
            /workspace/src

      - name: Upload results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: crypto-scan-results
          path: results.json
```

**GitLab CI:**

```yaml
crypto_scan:
  image: ghcr.io/scanoss/crypto-finder:latest
  script:
    - crypto-finder scan --rules-dir ./rules --output results.json .
  artifacts:
    paths:
      - results.json
    expire_in: 30 days
```

## Output Formats

### Interim JSON Format

The default output format containing detailed cryptographic asset information.

**Example:**

```json
{
  "version": "1.0",
  "tool": {
    "name": "opengrep",
    "version": "1.12.1"
  },
  "findings": [
    {
      "file_path": "src/crypto/Example.java",
      "language": "java",
      "cryptographic_assets": [
        {
          "match_type": "opengrep",
          "line_number": 29,
          "match": "cipher = Cipher.getInstance(\"AES/CBC/PKCS5Padding\");",
          "rule": {
            "id": "java.crypto.cipher-aes-cbc",
            "message": "AES cipher usage detected",
            "severity": "INFO"
          },
          "type": "algorithm",
          "name": "AES",
          "primitive": "block-cipher",
          "mode": "CBC",
          "padding": "PKCS5Padding"
        }
      ],
      "timestamp_utc": "2025-10-22T10:00:00Z"
    }
  ]
}
```

### CycloneDX CBOM Format

CycloneDX 1.7 compatible Cryptography Bill of Materials format.

**Features:**
- Validates against CycloneDX 1.7 schema
- Maps cryptographic assets to standardized component types
- Includes algorithm properties and metadata
- Supports asset types: `algorithm`, `certificate`, `protocol`, `related-crypto-material`


## Development

### Prerequisites

- Go 1.23.2 or later
- Make
- Docker (optional, for container builds)
- OpenGrep >= 1.12.1 or Semgrep >= 1.119.0 (for running scans)

### Building

```bash
# Build binary
make build

# Run tests
make test

# Generate coverage report
make coverage

# Lint code
make lint

# Install to $GOPATH/bin
make install
```

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage
make coverage

# Run specific test
go test -v ./internal/scanner/opengrep/...
go test -v ./internal/scanner/semgrep/...
```

### Creating a Release

```bash
# Test release build locally
make release-snapshot

# Create a release (requires git tag)
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
make release
```

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`make test`)
5. Run linter (`make lint`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## License

This project is part of the SCANOSS ecosystem. See [LICENSE](LICENSE) for details.

## Links

- [SCANOSS Website](https://www.scanoss.com)
- [SCANOSS Documentation](https://scanoss.readthedocs.io)
- [SCANOSS Settings Schema](https://scanoss.readthedocs.io/projects/scanoss-py/en/latest/scanoss_settings_schema.html)
- [Issue Tracker](https://github.com/scanoss/crypto-finder/issues)

## Support

For questions, issues, or feature requests, please use the [GitHub Issues](https://github.com/scanoss/crypto-finder/issues) page.
