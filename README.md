# Crypto Finder

[![Go Version](https://img.shields.io/github/go-mod/go-version/scanoss/crypto-finder)](https://go.dev/)
[![License](https://img.shields.io/github/license/scanoss/crypto-finder)](LICENSE)
[![Release](https://img.shields.io/github/v/release/scanoss/crypto-finder)](https://github.com/scanoss/crypto-finder/releases)

A powerful CLI tool and execution framework for detecting cryptographic algorithm usage in source code repositories. Crypto Finder scans codebases using multiple scanning engines and outputs results in standardized formats including JSON and CycloneDX CBOM (Cryptography Bill of Materials).

## Features

- **Multi-Scanner Support**: Supports OpenGrep (default) and Semgrep with extensible architecture for additional scanners
- **Advanced Taint Analysis**: OpenGrep scanner includes `--taint-intrafile` by default for enhanced dataflow analysis
- **Automatic Language Detection**: Uses [go-enry](https://github.com/go-enry/go-enry) to detect project languages for optimized scanning
- **Remote Rulesets**: Automatically fetch curated rulesets from SCANOSS API with local caching and TTL-based expiration
- **Flexible Rule Management**: Support for remote rulesets, local rule files, and directories with seamless combination
- **Standardized Output**: Interim JSON format compatible with the SCANOSS ecosystem
- **CycloneDX Support**: Convert results to CycloneDX 1.7 CBOM format
- **CI/CD Ready**: Docker images and integration-friendly design
- **Performance Optimized**: Language-based rule filtering to minimize scan time
- **Skip Patterns**: Configurable file/directory exclusion via scanoss.json
- **Offline Mode**: Use cached rulesets without API access for air-gapped environments

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

### With Remote Rulesets (Recommended)

```bash
# Configure your API key (one-time setup)
crypto-finder configure --api-key YOUR_API_KEY

# Or you can also specify api key and url via cli flags
crypto-finder scan /path/to/code --api-key YOUR_API_KEY --api-url https://your-custom-api.com

# Scan using remote rulesets (automatically downloaded and cached)
crypto-finder scan /path/to/code

# Combine remote rules with local custom rules
crypto-finder scan --rules-dir ./custom-rules /path/to/code
```

### With Local Rules Only

```bash
# Scan a directory with custom rules
crypto-finder scan --no-remote-rules --rules-dir ./rules /path/to/code

# Save output to a file
crypto-finder scan --no-remote-rules --rules-dir ./rules --output results.json /path/to/code

# Convert to CycloneDX CBOM format
crypto-finder convert results.json --output cbom.json

# Scan and convert in one pipeline
crypto-finder scan --no-remote-rules --rules-dir ./rules /path/to/code | crypto-finder convert --output cbom.json
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
| `--no-remote-rules` | Disable default remote ruleset | `false` |
| `--offline` | Use only cached rules, don't contact API | `false` |
| `--api-key <key>` | SCANOSS API key (overrides config file) | - |
| `--api-url <url>` | SCANOSS API base URL (overrides config file) | `https://api.scanoss.com` |
| `--scanner <name>` | Scanner to use: `opengrep`, `semgrep` | `opengrep` |
| `--format <format>` | Output format: `json`, `cyclonedx` | `json` |
| `--output <file>` | Output file path | stdout |
| `--languages <langs>` | Override language detection (comma-separated) | auto-detect |
| `--fail-on-findings` | Exit with error if findings detected | `false` |
| `--timeout <duration>` | Scan timeout (e.g., 10m, 1h) | `10m` |
| `--verbose`, `-v` | Enable verbose logging | `false` |
| `--quiet`, `-q` | Enable quiet mode | `false` |

**Examples:**

```bash
# Scan with remote rulesets (default behavior)
crypto-finder scan /path/to/code

# Combine remote and local rules
crypto-finder scan --rules-dir ./custom-rules /path/to/code

# Disable remote rules, use local only
crypto-finder scan --no-remote-rules --rules-dir ./rules /path/to/code

# Offline mode (use cached rules only)
crypto-finder scan --offline /path/to/code

# Override API key for this scan
crypto-finder scan --api-key YOUR_KEY /path/to/code

# Multiple rule sources
crypto-finder scan --rules rule1.yaml --rules rule2.yaml --rules-dir ./rules/ /path/to/code

# Override language detection
crypto-finder scan --languages java,python /path/to/code

# Output directly to CycloneDX format
crypto-finder scan --format cyclonedx --output cbom.json /path/to/code

# CI/CD mode (fail on findings)
crypto-finder scan --fail-on-findings /path/to/code

# Pipe output to jq for processing
crypto-finder scan /path/to/code | jq '.findings | length'

# Use Semgrep scanner instead of default OpenGrep
crypto-finder scan --scanner semgrep /path/to/code
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

### Configure Command

Configure SCANOSS crypto-finder settings such as API key and base URL.

```bash
crypto-finder configure [flags]
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--api-key <key>` | Set SCANOSS API key |
| `--api-url <url>` | Set SCANOSS API base URL |

**Examples:**

```bash
# Configure API key
crypto-finder configure --api-key YOUR_API_KEY

# Configure custom API URL
crypto-finder configure --api-url https://custom.scanoss.com

# Configure both
crypto-finder configure --api-key YOUR_KEY --api-url https://custom.scanoss.com
```

Configuration is stored in `~/.scanoss/crypto-finder/config.json`.

## Remote Rulesets

Crypto Finder can automatically fetch curated rulesets from the SCANOSS API, providing always-up-to-date cryptographic detection rules without manual management.

### Features

- **Automatic Downloads**: Default "dca" ruleset is automatically fetched on first scan
- **Local Caching**: Downloaded rulesets are cached at `~/.scanoss/crypto-finder/cache/`
- **TTL-Based Expiration**:
  - Pinned versions (e.g., `v1.0.0`): 7 days
  - Latest versions: 24 hours
- **Offline Support**: Use `--offline` flag to work with cached rules without API access
- **Checksum Verification**: SHA256 verification ensures ruleset integrity
- **Retry Logic**: Automatic retry with exponential backoff on network failures
- **Seamless Integration**: Combine remote and local rules effortlessly

### Configuration

#### 1. API Key Setup

You can configure your API key using one of three methods (in priority order):

```bash
# Method 1: CLI flag (highest priority)
crypto-finder scan --api-key YOUR_KEY /path/to/code

# Method 2: Environment variable
export SCANOSS_API_KEY=YOUR_KEY
crypto-finder scan /path/to/code

# Method 3: Config file (recommended for persistent use)
crypto-finder configure --api-key YOUR_KEY
crypto-finder scan /path/to/code
```

#### 2. API URL (Optional)

The default API URL is `https://api.scanoss.com`. To use a custom instance:

```bash
# Via configure command
crypto-finder configure --api-url https://custom.scanoss.com

# Via environment variable
export SCANOSS_API_URL=https://custom.scanoss.com

# Via CLI flag
crypto-finder scan --api-url https://custom.scanoss.com /path/to/code
```

### Usage Examples

```bash
# Use remote rules (default behavior)
crypto-finder scan /path/to/code

# Combine remote rules with local custom rules
crypto-finder scan --rules-dir ./my-rules /path/to/code

# Disable remote rules
crypto-finder scan --no-remote-rules --rules-dir ./local-rules /path/to/code

# Offline mode (use only cached rulesets)
crypto-finder scan --offline /path/to/code
```

### Cache Management

**Cache Location:**
```
~/.scanoss/crypto-finder/cache/rulesets/{name}/{version}/
  ├── manifest.json              # Ruleset metadata
  ├── .cache-meta.json           # Cache metadata (timestamps, checksum, TTL)
  └── [language dirs]/           # Rule files organized by language
```

**Cache Behavior:**
- First scan: Downloads and caches the default "dca" ruleset
- Subsequent scans: Uses cached version if not expired
- Expired cache: Automatically re-downloads on next scan
- Manual cleanup: Simply delete `~/.scanoss/crypto-finder/cache/`

### Troubleshooting

#### No API Key Error

```
Error: API key required for remote rules

Configure your API key using one of:
  1. CLI flag:    crypto-finder scan --api-key <key> [target]
  2. Environment: export SCANOSS_API_KEY=<key>
  3. Config file: crypto-finder configure --api-key <key>

Or disable remote rules: crypto-finder scan --no-remote-rules [target]
```

**Solution**: Configure your API key using any of the methods above.

#### Offline Mode Without Cache

```
Error: Ruleset not cached and offline mode enabled

Run online first to cache rules, or use --no-remote-rules
```

**Solution**: Run a scan while online to cache the rulesets, then use `--offline` for subsequent scans.

#### Network Timeout

If the API is unreachable but cached rules exist, crypto-finder will automatically fall back to the cache with a warning:

```
Warning: Failed to download remote rules (timeout)
Using cached rules from 2025-01-15 10:30:00
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
