# Docker Usage

Use `ghcr.io/scanoss/crypto-finder:latest` to scan source code, and
`latest-deps` when you add `--scan-dependencies`. Mount the code read-only,
write reports to a separate directory, and pass the API key as an
environment variable.

## Quick path

```bash
docker run --rm \
  -v "$PWD/code:/workspace/code:ro" \
  -v "$PWD/output:/workspace/output" \
  -e SCANOSS_API_KEY=YOUR_KEY \
  ghcr.io/scanoss/crypto-finder:latest \
  scan --output /workspace/output/results.json /workspace/code
```

Expected: `output/results.json` holds the interim report.

## Images

| Tag | Contents | Runs as | Use for |
|---|---|---|---|
| `latest`, `<version>` | The binary and CA certificates (Debian slim base) | `root` | Scanning source; detection runs in the binary |
| `latest-deps`, `<version>-deps` | The binary plus JDKs 8, 11, 17, 21 (`JAVA_HOME` = 21), Maven, Gradle, a Python virtualenv at `/opt/target-venv`, and Go and Rust toolchains | `crypto` (home `/home/crypto`) | `--scan-dependencies` |

Both images are multi-arch (amd64, arm64) and start with `crypto-finder` as
the entrypoint. Coming from the 0.5x `-slim` tags:
[MIGRATION_1.0.md](MIGRATION_1.0.md#docker-images).

The standard image has no JDK. For Java type resolution with JDK platform
signatures, use `latest-deps` or add a JDK in your own image.

## Mounts

| Mount point | Purpose | Mode |
|---|---|---|
| `/workspace/code` | Source to scan | `:ro` |
| `/workspace/rules` | Local ruleset (with `--rules-dir`) | `:ro` |
| `/workspace/output` | Reports | read-write |
| `/root/.scanoss/crypto-finder/cache` (`latest`) or `/home/crypto/.scanoss/crypto-finder/cache` (`latest-deps`) | Ruleset and type-index caches; `mined/` for `--offline` | read-write, optional |

Keep the cache between runs with a named volume:

```bash
docker volume create crypto-finder-cache
docker run --rm \
  -v "$PWD/code:/workspace/code:ro" \
  -v "$PWD/output:/workspace/output" \
  -v crypto-finder-cache:/root/.scanoss/crypto-finder/cache \
  -e SCANOSS_API_KEY=YOUR_KEY \
  ghcr.io/scanoss/crypto-finder:latest \
  scan --output /workspace/output/results.json /workspace/code
```

The cache is encrypted with the API key it was downloaded with; reuse it
with the same key ([REMOTE_RULESETS.md](REMOTE_RULESETS.md)).

## Common runs

```bash
# Local ruleset, no API
docker run --rm \
  -v "$PWD/code:/workspace/code:ro" \
  -v "$PWD/rules:/workspace/rules:ro" \
  -v "$PWD/output:/workspace/output" \
  ghcr.io/scanoss/crypto-finder:latest \
  scan --no-remote-rules --rules-dir /workspace/rules \
  --output /workspace/output/results.json /workspace/code

# CycloneDX CBOM
docker run --rm \
  -v "$PWD/code:/workspace/code:ro" \
  -v "$PWD/output:/workspace/output" \
  -e SCANOSS_API_KEY=YOUR_KEY \
  ghcr.io/scanoss/crypto-finder:latest \
  scan --format cyclonedx --output /workspace/output/cbom.json /workspace/code

# Longer timeout, explicit languages
docker run --rm \
  -v "$PWD/code:/workspace/code:ro" \
  -v "$PWD/output:/workspace/output" \
  -e SCANOSS_API_KEY=YOUR_KEY \
  ghcr.io/scanoss/crypto-finder:latest \
  scan --timeout 30m --languages java,python \
  --output /workspace/output/results.json /workspace/code
```

## Dependency scanning

Use `latest-deps` for `--scan-dependencies`: it carries the JDKs, Maven,
Gradle, `cargo` and the Go toolchain that resolution and type resolution use.
Per-ecosystem details: [DEPENDENCY_SCANNING.md](DEPENDENCY_SCANNING.md).

### Java (Maven or Gradle)

```bash
docker run --rm \
  -v "$PWD:/workspace/code:ro" \
  -v "$PWD/output:/workspace/output" \
  -e SCANOSS_API_KEY=YOUR_KEY \
  ghcr.io/scanoss/crypto-finder:latest-deps \
  scan --scan-dependencies --export-callgraph /workspace/output/callgraph.json \
  --output /workspace/output/results.json /workspace/code
```

`mvn` and `gradle` run inside the project and can execute code it controls.
Do not mount credentials when scanning a repository you do not trust.

### Python

A lock file (`uv.lock`, `poetry.lock`, `Pipfile.lock`, `pdm.lock`,
`pylock.toml`) or fully pinned requirements are enough; nothing needs to be
installed:

```bash
docker run --rm \
  -v "$PWD:/workspace/code:ro" \
  -e SCANOSS_API_KEY=YOUR_KEY \
  ghcr.io/scanoss/crypto-finder:latest-deps \
  scan --scan-dependencies /workspace/code
```

Without a lock or pins, install the project into the image's virtualenv and
point the scan at it (`VIRTUAL_ENV`); `--offline` mines the dependencies from
the same environment:

```bash
docker run --rm \
  -v "$PWD:/workspace/code:ro" \
  --entrypoint sh \
  ghcr.io/scanoss/crypto-finder:latest-deps -c \
  "pip install -r /workspace/code/requirements.txt && \
   VIRTUAL_ENV=/opt/target-venv crypto-finder scan --scan-dependencies --offline \
     --offline-python-packages /opt/target-venv /workspace/code"
```

## CI/CD (GitHub Actions)

```yaml
name: Crypto Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v7

      - name: Run Crypto Finder
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/workspace \
            -e SCANOSS_API_KEY=${{ secrets.SCANOSS_API_KEY }} \
            ghcr.io/scanoss/crypto-finder:latest \
            scan --output /workspace/results.json /workspace/src

      - name: Upload results
        uses: actions/upload-artifact@v7
        if: always()
        with:
          name: crypto-scan-results
          path: results.json

      - name: Fail on findings
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/workspace \
            -e SCANOSS_API_KEY=${{ secrets.SCANOSS_API_KEY }} \
            ghcr.io/scanoss/crypto-finder:latest \
            scan --fail-on-findings /workspace/src
```

| Variant | Change |
|---|---|
| Dependencies | Image `latest-deps`, add `--scan-dependencies` |
| Local ruleset | Drop the API key; add `--no-remote-rules --rules-dir /workspace/.crypto-rules` |
| CBOM from the report | `convert /workspace/results.json --output /workspace/cbom.json` |
| Fresh rules required | Add `--strict` (no stale-cache fallback) |

## Docker Compose

```yaml
services:
  crypto-finder:
    image: ghcr.io/scanoss/crypto-finder:latest
    volumes:
      - ./code:/workspace/code:ro
      - ./output:/workspace/output
      - crypto-cache:/root/.scanoss/crypto-finder/cache
    environment:
      - SCANOSS_API_KEY=${SCANOSS_API_KEY}
    command: >
      scan
      --output /workspace/output/results.json
      /workspace/code

volumes:
  crypto-cache:
```

```bash
SCANOSS_API_KEY=your_key docker compose up
```

## Related

- [README](../README.md): installation and flags
- [REMOTE_RULESETS.md](REMOTE_RULESETS.md): API key and ruleset cache
- [OFFLINE.md](OFFLINE.md): `--offline`
- [OUTPUT_FORMATS.md](OUTPUT_FORMATS.md): report formats
