# Configuration

Most setups need one command: `crypto-finder configure --api-key <key>`.
Everything else has a working default. A setting can come from a flag, an
environment variable or the config file; the first one set wins, in that
order.

## Quick path

```bash
# 1. Save the API key (and a custom API URL, if you use one)
crypto-finder configure --api-key YOUR_API_KEY
crypto-finder configure --api-url https://custom.scanoss.com

# 2. Scan
crypto-finder scan /path/to/code

# 3. Check what was used: the report's "rules" block names the ruleset release
crypto-finder scan /path/to/code | jq '.rules'
```

## Settings

| Setting | Flag | Environment | Config file key | Default |
|---|---|---|---|---|
| API key | `--api-key` | `SCANOSS_API_KEY` | `api_key` | — |
| API base URL | `--api-url` | `SCANOSS_API_URL` | `api_url` | `https://api.scanoss.com` |
| Allow plain HTTP to a remote API | `--allow-http` | `SCANOSS_ALLOW_HTTP` | `allow_http` | off |
| Java JDK major | `--java-jdk-major` | `SCANOSS_JAVA_JDK_MAJOR` | `java_jdk_major` | `auto` (ambient `JAVA_HOME`) |
| Java JDK homes | `--java-jdk-home <major>=<path>` (repeatable) | `SCANOSS_JAVA_JDK_HOMES` (`17=/opt/jdk17,21=/opt/jdk21`) | `java_jdk_homes` | — |
| Extra trusted ruleset signing keys | — | `SCANOSS_RULESET_PUBKEYS` | — | Built-in key only ([REMOTE_RULESETS.md](REMOTE_RULESETS.md#trusted-signing-keys)) |

Priority, highest first:

1. Command-line flags
2. Environment variables
3. Config file `~/.scanoss/crypto-finder/config.json`
4. Defaults

`configure` writes the config file:

```json
{
  "api_key": "your-scanoss-api-key",
  "api_url": "https://api.scanoss.com",
  "java_jdk_major": "auto",
  "java_jdk_homes": {
    "17": "/opt/jdks/jdk17",
    "21": "/opt/jdks/jdk21"
  }
}
```

## Files and directories

| Path | Holds |
|---|---|
| `~/.scanoss/crypto-finder/config.json` | Saved settings |
| `~/.scanoss/crypto-finder/cache/rulesets/` | Remote rulesets, encrypted ([REMOTE_RULESETS.md](REMOTE_RULESETS.md#cache-management)) |
| `~/.scanoss/crypto-finder/cache/bytecode/` | Java JAR type indexes |
| `~/.scanoss/crypto-finder/cache/python-signatures/` | Python package type indexes |
| `~/.scanoss/crypto-finder/cache/sources/` | Extracted dependency sources |
| `~/.scanoss/crypto-finder/cache/mined/` | Dependencies mined by `--offline` and by the online offline fallback (`--offline-cache-dir`; [OFFLINE.md](OFFLINE.md)) |

Deleting any cache directory is safe; it is rebuilt on the next scan that
needs it.

## Java runtime

Java type resolution and dependency scans use one JDK major per scan.

| Option | Values |
|---|---|
| `--java-jdk-major` | `auto`, `8`, `11`, `17`, `21` |
| `--java-jdk-home` | `<major>=<path>`, repeatable |

```bash
crypto-finder scan --scan-dependencies \
  --java-jdk-major 21 \
  --java-jdk-home 17=/opt/jdks/jdk17 \
  --java-jdk-home 21=/opt/jdks/jdk21 \
  /path/to/java-project
```

The `latest-deps` Docker image sets `SCANOSS_JAVA_JDK_HOMES` for JDKs 8, 11,
17 and 21.

## Detection and languages

Detection runs in process: crypto-finder builds the target's typed call graph
and matches the ruleset against its call sites. There is no scanner to choose
or install.

| Target contains | Result |
|---|---|
| A supported language (Java, Python, Go, JavaScript, TypeScript, Rust, Ruby, C, C++, C#) | Scanned, each language against its own rules and call graph |
| A supported language plus other languages | The supported ones scanned; a warning and the `detection` progress event (`unsupported_languages`) name the others |
| Only other languages | Fails with `language_not_supported` ([ERROR_CODES.md](ERROR_CODES.md)) |

Language detection uses [go-enry](https://github.com/go-enry/go-enry).
Override it with `--languages`:

```bash
crypto-finder scan --languages java /path/to/code
crypto-finder scan --languages java,python /path/to/code
```

Ruleset sources:

```bash
# Local ruleset only
crypto-finder scan --no-remote-rules --rules-dir ./ruleset /path/to/code

# Local ruleset with a precompiled card index and a cards directory
crypto-finder scan --no-remote-rules --rules-dir ./ruleset \
  --cards-index index.json --cards-dir ./cards /path/to/code
```

## Skipping files

| Mechanism | Example |
|---|---|
| Built-in defaults | `vendor`, `node_modules`, `shaded/`, generated protobuf stubs, docs; test sources unless `--include-tests` |
| `scanoss.json` in the target | `{"settings": {"skip": {"patterns": {"scanning": ["target/", "venv/"]}}}}` |
| `--exclude <glob>` (repeatable) | `--exclude vendor --exclude "build/**"` |
| Turn the defaults off | `--no-default-exclusions` (slower on large trees) |

Patterns use gitignore syntax. See the
[SCANOSS settings schema](https://scanoss.readthedocs.io/projects/scanoss-py/en/latest/scanoss_settings_schema.html).

## Timeout

Default: `10m`. Set it with `--timeout` (`90s`, `30m`, `2h`).

| Project size | Suggested timeout |
|---|---|
| Under 1,000 files | `5m` |
| 1,000-10,000 files | `15m` |
| 10,000-50,000 files | `30m` |
| Over 50,000 files | `1h` or more |

## Output and logging

| Want | Flag |
|---|---|
| Report to a file | `--output results.json` (default: stdout) |
| CycloneDX CBOM | `--format cyclonedx` |
| Info / debug / errors-only logging | `-v` / `-d` / `-q` |
| Machine-readable failures | `--error-format json` |
| Lifecycle events on stderr (JSONL) | `--progress` |

## Related

- [README](../README.md): commands and full flag reference
- [REMOTE_RULESETS.md](REMOTE_RULESETS.md): API key, ruleset cache, leases
- [DOCKER_USAGE.md](DOCKER_USAGE.md): container configuration
