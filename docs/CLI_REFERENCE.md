# CLI reference

Every command and flag of `crypto-finder`, grouped by what you want to do.
`crypto-finder <command> --help` prints the same list. For a first scan, start
with the [README](../README.md#quick-start).

## Global flags

These work on every command.

| Flag | Default | Effect |
|---|---|---|
| `-v`, `--verbose` | off | Info-level logging |
| `-d`, `--debug` | off | Debug-level logging |
| `-q`, `--quiet` | off | Errors only |
| `--error-format <fmt>` | `text` | `text` or `json`. With `json`, a failure is one JSON payload on stderr with a stable `code` and `stage` ([ERROR_CODES.md](ERROR_CODES.md)) |

## `scan`

```bash
crypto-finder scan [flags] <target>
```

Builds the target's call graph, detects cryptography on it, and writes the
findings report to stdout or `--output`.

### Output

| Flag | Default | Effect |
|---|---|---|
| `-o`, `--output <file>` | stdout | Findings report path |
| `-f`, `--format <fmt>` | `json` | `json` (interim report) or `cyclonedx` (CBOM) |
| `--fail-on-findings` | off | Exit non-zero when anything is found (`findings_detected`) |
| `--no-dedup` | off | Keep every match instead of one per line |
| `--progress` | off | Write lifecycle events as JSONL to stderr; findings stay on stdout or `--output`. Cannot be combined with `--error-format text` |

### What to scan

| Flag | Default | Effect |
|---|---|---|
| `--languages <list>` | detected | Comma-separated languages to scan, instead of detecting them |
| `--include-tests` | off | Scan test sources too |
| `--exclude <glob>` | — | Gitignore-style pattern to skip, repeatable; added to the built-in exclusions |
| `--no-default-exclusions` | off | Drop the built-in exclusions (`vendor`, `node_modules`, `shaded/`, generated protobuf stubs, docs). Slower on large trees |
| `-t`, `--timeout <dur>` | `10m` | Bound the whole scan (`90s`, `30m`, `2h`, `2w`) |

Skip patterns can also live in the target's `scanoss.json`
([CONFIGURATION.md](CONFIGURATION.md#skipping-files)).

### Rules

| Flag | Default | Effect |
|---|---|---|
| `--ruleset <name>` | `crypto-cards` | Remote ruleset to fetch |
| `--ruleset-version <ver>` | `latest` | Ruleset release, such as `v1.39.0`. Pin it to rerun a scan with identical rules |
| `--no-remote-rules` | off | Do not fetch a remote ruleset; needs `--rules` or `--rules-dir` |
| `-r`, `--rules <file>` | — | Local rule file, repeatable |
| `--rules-dir <dir>` | — | Local rule directory, repeatable. Added to the remote ruleset unless `--no-remote-rules` |
| `--cards-dir <dir>` | — | Cards directory to detect with, instead of the ruleset's `cards/` |
| `--cards-index <file>` | — | Precompiled card index to detect with |
| `--no-cache` | off | Download the remote ruleset again, ignoring the cache |
| `--strict` | off | Fail instead of using an expired cache when the API is unreachable |
| `--max-stale-age <dur>` | `30d` | Oldest expired cache to fall back to (at most `90d`, and never past the ruleset's lease) |

How the ruleset is cached and refreshed: [REMOTE_RULESETS.md](REMOTE_RULESETS.md).

### Dependencies

| Flag | Default | Effect |
|---|---|---|
| `--scan-dependencies` | off | Report the cryptography of the pinned dependencies and whether the project reaches it ([DEPENDENCY_SCANNING.md](DEPENDENCY_SCANNING.md)) |
| `--dependency-reachability-max-chains <n>` | `1` | Call chains per dependency finding in `--export-callgraph` (`0`: none) |
| `--offline` | off | Decide dependency reachability on this machine instead of asking the SCANOSS API ([OFFLINE.md](OFFLINE.md)) |
| `--no-offline-fallback` | off | Online: do not analyse locally the dependencies the API has no data for; leave their findings out |
| `--offline-cache-dir <dir>` | `~/.scanoss/crypto-finder/cache/mined` | Cache of locally analysed dependencies (`--offline` and the fallback) |
| `--offline-memory-mb <n>` | `10240` | Memory budget in MiB for local dependency analysis (unless `GOMEMLIMIT` is set) |
| `--offline-python-packages <dirs>` | — | Python: installed packages to analyse dependencies from (virtual environments, site-packages, unpacked wheels; OS path-list separated), after `.venv`, `venv` and `VIRTUAL_ENV` |

### Call graph exports

| Flag | Default | Effect |
|---|---|---|
| `--export-callgraph <file>` | — | Write the finding-centric call graph: call chains and a reachability verdict per finding |
| `--export-callgraph-max-chains <n>` | `8` | Sampled call chains per finding (depth capped at 32) |
| `--export-callgraph-entry-points` | off | Add the complete `crypto_entry_points` reverse-reachability index |
| `--export-callgraph-interned-frames` | `true` | Schema `6.18` (interned frames); `=false` writes schema `6.14` (inlined frames) |
| `--export-callgraph-project-reachability` | off | Without resolved dependencies, classify reachability against the target's own packages instead of `not_applicable`. Leave off when scanning a library on its own |
| `--export-callgraph-format <fmt>` | `json` | Only `json` |
| `--export-graph-fragment <file>` | — | Write the reusable structural graph fragment (input for `annotate`) |
| `--export-graph-fragment-format <fmt>` | `json` | Only `json` |

Formats: [OUTPUT_FORMATS.md](OUTPUT_FORMATS.md).

### Type resolution

| Flag | Default | Effect |
|---|---|---|
| `--java-jdk-major <major>` | `auto` | JDK for Java type resolution and dependency resolution: `auto`, `8`, `11`, `17`, `21` |
| `--java-jdk-home <major=path>` | — | Where a JDK major lives, repeatable |
| `--java-compiled-artifact <path>` | — | Compiled Java artifact used to type a standalone call graph |
| `--type-jars <jars>` | — | Compiled JARs (OS path-list separated) used for Java types only, never scanned |
| `--type-packages <dirs>` | — | Installed Python packages (OS path-list separated) used for Python types only, never scanned or run |

### API

| Flag | Default | Effect |
|---|---|---|
| `--api-key <key>` | saved config | SCANOSS API key |
| `--api-url <url>` | `https://api.scanoss.com` | SCANOSS API base URL |
| `--allow-http` | off | Allow a plain-HTTP `--api-url` on a remote host (sends the key unencrypted) |

## `annotate`

```bash
crypto-finder annotate --import-fragment fragment.json [flags]
```

Re-runs detection on a graph fragment that `scan --export-graph-fragment`
wrote, without the source tree and without rebuilding the call graph. Use it
when only the rules changed; use `scan` when the code changed.

```bash
# Once: full scan, keep the fragment
crypto-finder scan --export-graph-fragment fragment.json /path/to/code

# After each rules change: detection only
crypto-finder annotate --import-fragment fragment.json \
  --output annotation.json --findings-output findings.json
```

The crypto sections it writes are identical to those of a full scan with the
same rules. A new crypto-finder release that changes graph construction bumps
`graph_algo_version` in the fragment's `scan_metadata`; re-run `scan` then.

| Flag | Default | Effect |
|---|---|---|
| `--import-fragment <file>` | required | Graph fragment to re-annotate |
| `-o`, `--output <file>` | stdout | Annotation JSON path |
| `--findings-output <file>` | — | Also write the findings report, as `scan --output` would |
| `--source <dir>` | — | Source tree of the fragment; only needed for a fragment older than `graph-fragment-1.16` |

It also takes these `scan` flags: `--rules`, `--rules-dir`,
`--no-remote-rules`, `--no-cache`, `--ruleset`, `--ruleset-version`,
`--timeout`, `--languages`, `--include-tests`, `--no-default-exclusions`,
`--exclude`, `--api-key`, `--api-url`, `--allow-http`.

## `convert`

```bash
crypto-finder convert findings.json --output cbom.json
crypto-finder scan /path/to/code | crypto-finder convert > cbom.json
```

Converts a findings report to a CycloneDX 1.7 CBOM. Only assets with complete
metadata are included, and the output is validated against the CycloneDX 1.7
schema. Takes `-o`, `--output`.

## `cbom`

```bash
crypto-finder cbom sbom.cdx.json --output cbom.json
syft dir:. -o cyclonedx-json | crypto-finder cbom - > cbom.json
```

Builds a CBOM for the components an SBOM lists (CycloneDX JSON, SPDX JSON or
SPDX tag-value; `-` reads stdin) from the findings SCANOSS publishes for each
component version. Nothing is scanned locally. A summary per component goes to
stderr.

| Flag | Default | Effect |
|---|---|---|
| `-o`, `--output <file>` | stdout | CBOM path |
| `--max-components <n>` | `2000` | Refuse SBOMs with more distinct components |
| `--api-key`, `--api-url`, `--allow-http` | | As for `scan` |

## `configure`

```bash
crypto-finder configure --api-key YOUR_API_KEY
crypto-finder configure --api-url https://api.scanoss.com
```

Saves settings to `~/.scanoss/crypto-finder/config.json`. Takes `--api-key`,
`--api-url` and `--allow-http` (`--allow-http=false` clears it). Settings and
their environment variables: [CONFIGURATION.md](CONFIGURATION.md).

## `version`

Prints the version, build and runtime information.
