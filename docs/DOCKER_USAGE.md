# Docker Usage

Crypto Finder provides official Docker images for containerized scanning workflows and CI/CD integration.

## Available Images

Crypto Finder provides a three-tier image strategy so you can choose the right trade-off between image size and functionality:

| Image | Tag | Size | Use Case |
|-------|-----|------|----------|
| **Standard** | `latest` | ~800MB | Default: binary + OpenGrep + Semgrep |
| **Slim** | `latest-slim` | ~15MB | Binary only, bring your own scanner |
| **Deps** | `latest-deps` | ~3-4GB | All language toolchains for dependency scanning |

### Standard Image (Recommended)

Includes both OpenGrep and Semgrep scanners for maximum flexibility.

```bash
docker pull ghcr.io/scanoss/crypto-finder:latest
```

**Features:**
- OpenGrep 1.12.1+ included
- Semgrep 1.145.0+ included
- All scanning capabilities available

### Slim Image

Minimal image requiring external scanner installation.

```bash
docker pull ghcr.io/scanoss/crypto-finder:latest-slim
```

**Features:**
- crypto-finder binary only
- Requires external OpenGrep or Semgrep
- Smaller image size
- Ideal for custom scanner versions

### Deps Image (Dependency Scanning)

Full image with all language toolchains for scanning third-party dependencies with `--scan-dependencies`.

```bash
docker pull ghcr.io/scanoss/crypto-finder:latest-deps
```

**Features:**
- Everything in the standard image, plus:
- **Go** toolchain for `go list` / `go mod graph` dependency resolution
- **Java** (JDK 8, 11, 17, and 21 + Maven) for JDK-aware Maven dependency resolution and deterministic platform signature indexing
- **Rust** (Cargo) for `cargo metadata` dependency resolution
- **Python** (isolated virtualenv) for pip dependency resolution
- Detects cryptographic usage in third-party dependencies with call chain tracing

## Basic Usage

### Scanning with Mounted Volumes

```bash
# Scan code directory with remote rulesets
docker run --rm \
  -v $(pwd)/code:/workspace/code:ro \
  -v $(pwd)/output:/workspace/output \
  -e SCANOSS_API_KEY=YOUR_KEY \
  ghcr.io/scanoss/crypto-finder:latest \
  scan --output /workspace/output/results.json /workspace/code

# Scan with local rules
docker run --rm \
  -v $(pwd)/code:/workspace/code:ro \
  -v $(pwd)/rules:/workspace/rules:ro \
  -v $(pwd)/output:/workspace/output \
  ghcr.io/scanoss/crypto-finder:latest \
  scan --no-remote-rules --rules-dir /workspace/rules \
  --output /workspace/output/results.json /workspace/code

# Generate CycloneDX CBOM
docker run --rm \
  -v $(pwd)/code:/workspace/code:ro \
  -v $(pwd)/output:/workspace/output \
  -e SCANOSS_API_KEY=YOUR_KEY \
  ghcr.io/scanoss/crypto-finder:latest \
  scan --format cyclonedx --output /workspace/output/cbom.json /workspace/code
```

### Volume Mounting Patterns

| Mount Point | Purpose | Recommended Mode |
|-------------|---------|------------------|
| `/workspace/code` | Source code to scan | `:ro` (read-only) |
| `/workspace/rules` | Custom rule files | `:ro` (read-only) |
| `/workspace/output` | Scan results | `:rw` (read-write) |
| `~/.scanoss/crypto-finder/cache` | Ruleset cache (optional) | `:rw` (read-write) |

### Preserving Cache Between Runs

```bash
# Create a named volume for cache persistence
docker volume create crypto-finder-cache

# Use the volume in scans
docker run --rm \
  -v $(pwd)/code:/workspace/code:ro \
  -v $(pwd)/output:/workspace/output \
  -v crypto-finder-cache:/root/.scanoss/crypto-finder/cache \
  -e SCANOSS_API_KEY=YOUR_KEY \
  ghcr.io/scanoss/crypto-finder:latest \
  scan --output /workspace/output/results.json /workspace/code
```

## CI/CD Integration

### GitHub Actions

Complete workflow for scanning code on push and pull requests:

```yaml
name: Crypto Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run Crypto Finder
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/workspace \
            -e SCANOSS_API_KEY=${{ secrets.SCANOSS_API_KEY }} \
            ghcr.io/scanoss/crypto-finder:latest \
            scan --output /workspace/results.json /workspace/src

      - name: Upload results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: crypto-scan-results
          path: results.json

      - name: Check for findings
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/workspace \
            ghcr.io/scanoss/crypto-finder:latest \
            scan --fail-on-findings /workspace/src
```

#### With Custom Rules

```yaml
name: Crypto Scan (Custom Rules)

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run Crypto Finder with custom rules
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/workspace \
            ghcr.io/scanoss/crypto-finder:latest \
            scan --no-remote-rules \
            --rules-dir /workspace/.crypto-rules \
            --output /workspace/results.json \
            /workspace/src

      - name: Generate CBOM
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/workspace \
            ghcr.io/scanoss/crypto-finder:latest \
            convert /workspace/results.json --output /workspace/cbom.json

      - name: Upload CBOM
        uses: actions/upload-artifact@v3
        with:
          name: crypto-cbom
          path: cbom.json
```

## Dependency Scanning

The `latest-deps` image includes all language toolchains needed for dependency scanning. Use it with the `--scan-dependencies` flag.

### Go Projects

```bash
docker run --rm \
  -v $(pwd):/workspace/code:ro \
  ghcr.io/scanoss/crypto-finder:latest-deps \
  scan --scan-dependencies /workspace/code
```

### Java (Maven) Projects

```bash
docker run --rm \
  -v $(pwd):/workspace/code:ro \
  ghcr.io/scanoss/crypto-finder:latest-deps \
  scan --scan-dependencies /workspace/code
```

### Rust Projects

```bash
docker run --rm \
  -v $(pwd):/workspace/code:ro \
  ghcr.io/scanoss/crypto-finder:latest-deps \
  scan --scan-dependencies /workspace/code
```

### Python Projects

Python projects require installing dependencies before scanning, since pip needs them to be resolved:

```bash
docker run --rm \
  -v $(pwd):/workspace/code:ro \
  --entrypoint sh \
  ghcr.io/scanoss/crypto-finder:latest-deps -c \
  "pip install -r /workspace/code/requirements.txt 2>/dev/null; \
   crypto-finder scan --scan-dependencies /workspace/code"
```

> **Note:** The deps image uses an isolated virtualenv for project dependencies, separate from the scanner tooling (semgrep), so `pip install` only affects the target project's environment.

### CI/CD with Dependency Scanning (GitHub Actions)

```yaml
name: Crypto Scan with Dependencies

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run Crypto Finder with dependency scanning
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/workspace \
            -e SCANOSS_API_KEY=${{ secrets.SCANOSS_API_KEY }} \
            ghcr.io/scanoss/crypto-finder:latest-deps \
            scan --scan-dependencies --output /workspace/results.json /workspace
```

## Advanced Docker Usage

### Running with Specific Scanner

```bash
# Use Semgrep instead of default OpenGrep
docker run --rm \
  -v $(pwd)/code:/workspace/code:ro \
  -v $(pwd)/output:/workspace/output \
  -e SCANOSS_API_KEY=YOUR_KEY \
  ghcr.io/scanoss/crypto-finder:latest \
  scan --scanner semgrep --output /workspace/output/results.json /workspace/code
```

### Custom Timeout and Language Override

```bash
docker run --rm \
  -v $(pwd)/code:/workspace/code:ro \
  -v $(pwd)/output:/workspace/output \
  -e SCANOSS_API_KEY=YOUR_KEY \
  ghcr.io/scanoss/crypto-finder:latest \
  scan \
  --timeout 30m \
  --languages java,python,go \
  --output /workspace/output/results.json \
  /workspace/code
```

## Docker Compose

Example `docker-compose.yml` for local development:

```yaml
version: '3.8'

services:
  crypto-finder:
    image: ghcr.io/scanoss/crypto-finder:latest
    volumes:
      - ./code:/workspace/code:ro
      - ./rules:/workspace/rules:ro
      - ./output:/workspace/output
      - crypto-cache:/root/.scanoss/crypto-finder/cache
    environment:
      - SCANOSS_API_KEY=${SCANOSS_API_KEY}
    command: >
      scan
      --rules-dir /workspace/rules
      --output /workspace/output/results.json
      /workspace/code

volumes:
  crypto-cache:
```

Run with:

```bash
SCANOSS_API_KEY=your_key docker-compose up
```

## Related Documentation

- [Main README](../README.md) - Installation and basic usage
- [Remote Rulesets](REMOTE_RULESETS.md) - API configuration and caching
- [Output Formats](OUTPUT_FORMATS.md) - Understanding scan results
