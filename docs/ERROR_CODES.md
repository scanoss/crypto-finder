# Error Codes

crypto-finder reports terminal failures with a **stable machine-readable code and pipeline stage**. Codes are an external contract consumed by CI parsers and downstream tooling: shipped codes are never renamed (see [AGENTS.md](../AGENTS.md#error-handling)). The public source of truth is `pkg/failure/error.go`; `internal/failure` preserves implementation compatibility.

## Public Go Contract

Go consumers can import `github.com/scanoss/crypto-finder/pkg/failure` for the `Code`, `Stage`, `Error`, and `Payload` types without importing implementation packages. `Code` and `Stage` are string enums; their exported constants are the stable values listed below.

`Payload` serializes `code`, `stage`, `retryable`, and `message` in every payload. `details`, `cause`, and `raw_error` are omitted when empty. `ToPayload` retains compatibility by preserving typed failures through wrapping, defaulting missing typed code or stage to `unknown_error` or `unknown`, and converting unclassified errors to that same fallback payload.

## Consuming errors in CI

With `--error-format json`, any failure is emitted to **stderr** as a single JSON payload, and the process exits with code `1`:

```bash
crypto-finder scan --error-format json /path/to/code 2> error.json
```

```json
{
  "code": "scanner_timeout",
  "stage": "scan",
  "retryable": false,
  "message": "scan timed out after 10m: ...",
  "details": { "timeout": "10m" },
  "cause": "context deadline exceeded"
}
```

| Field | Meaning |
|-------|---------|
| `code` | Stable failure identifier (table below). Parse on this, never on `message`. |
| `stage` | Pipeline stage that produced the failure (table below). |
| `retryable` | Whether retrying the same invocation may succeed. |
| `message` | Human-readable description (free text, may change between releases). |
| `details` | Optional structured key/value context (e.g. the offending flag value). |
| `cause` / `raw_error` | Underlying error text, when available. |

Errors that were never classified surface as `code: "unknown_error"`, `stage: "unknown"`.

Note: `--error-format json` also disables log output and colors so stderr carries only the payload.

## Stages

| Stage | Pipeline phase |
|-------|----------------|
| `input` | CLI argument/flag validation |
| `config` | Configuration, cache, and Java runtime initialization |
| `rules` | Rule source loading |
| `scan` | Language detection and scanner execution |
| `dependency` | Dependency resolution and dependency scanning |
| `callgraph` | Call graph construction |
| `export` | Call graph / graph fragment export |
| `output` | Findings report formatting and writing |
| `policy` | Post-scan policy decisions (`--fail-on-findings`) |
| `unknown` | Unclassified |

## Codes

The stage column shows the typical stage; the stage is assigned where the error becomes terminal, so a code can occasionally surface under a different stage.

| Code | Typical stage | Meaning | Typical cause |
|------|---------------|---------|---------------|
| `unknown_error` | `unknown` | Unclassified failure | A plain error escaped without boundary wrapping |
| `invalid_arguments` | `input` | Flag/argument validation failed | Bad flag value, missing required flag, unknown backend/format |
| `invalid_timeout` | `input` | Unparseable duration | `--timeout` / `--max-stale-age` not in `10m` / `1h` / `30d` / `2w` form |
| `config_initialization_failed` | `config` | Configuration could not be initialized | Unreadable/invalid config file or environment |
| `java_runtime_config_invalid` | `config` | Java runtime selection invalid | Bad `--java-jdk-major` / malformed `--java-jdk-home <major>=<path>` |
| `cache_initialization_failed` | `config` | Rules or findings cache setup failed | Cache dir not writable; `--findings-cache=postgres` without `SCANOSS_FINDINGS_CACHE_DSN`, pool/schema failure |
| `rules_load_failed` | `rules` | No usable rule source | `--no-remote-rules` without `--rules`/`--rules-dir`; remote ruleset fetch failed with no cache |
| `scanner_unavailable` | `scan` | Requested scanner not found | `opengrep`/`semgrep` binary not installed or not on `PATH` |
| `scanner_initialization_failed` | `scan` | Scanner setup failed | Scanner present but could not be prepared for the run |
| `scanner_execution_failed` | `scan` | Scanner process failed | Non-zero scanner exit, crash, or invalid rule files |
| `scanner_timeout` | `scan` | Scan exceeded `--timeout` | Target too large for the configured timeout |
| `scanner_canceled` | `scan` | Scan canceled | Context canceled (e.g. SIGINT) |
| `scanner_output_parse_failed` | `scan` | Scanner output unreadable | Scanner emitted output the parser could not decode |
| `language_detection_failed` | `scan` | Language detection failed | Unreadable target tree |
| `dependency_resolution_failed` | `dependency` | Dependency resolution/scan failed | Missing toolchain, unresolvable manifest, dep scan error |
| `java_build_tool_unknown` | `dependency` | Java build tool not detected | No `pom.xml` / Gradle build files found |
| `java_build_tool_ambiguous` | `dependency` | Multiple Java build tools detected | Both Maven and Gradle present without a clear winner |
| `gradle_tool_missing` | `dependency` | Gradle unavailable | No usable `gradle` / wrapper for dependency export |
| `gradle_export_failed` | `dependency` | Gradle dependency export failed | Gradle invocation failed or produced unusable output |
| `gradle_java_incompatible` | `dependency` | Gradle/JDK mismatch | Selected JDK major incompatible with the project's Gradle |
| `callgraph_build_failed` | `callgraph` | Call graph construction failed | Unsupported ecosystem for export, parse failure |
| `callgraph_export_failed` | `export` | Export write failed | `--export-callgraph` / `--export-graph-fragment` destination not writable, serialization failure |
| `output_writer_unavailable` | `output` | No writer for the requested format | Unsupported `--format` value reaching the writer factory |
| `output_write_failed` | `output` | Report write failed | Output path not writable, disk full |
| `findings_detected` | `policy` | Findings found with `--fail-on-findings` | Expected CI gate behavior, not an error in the tool |

## Adding a new failure mode

1. Add a `Code` constant in `pkg/failure/error.go` (and a `Stage` if it is a new pipeline phase), then re-export it through `internal/failure`.
2. Wrap the error at the boundary layer (`internal/cli`, `internal/engine`, `internal/scanner`, `internal/dependency`) — never in deep library code.
3. Add the code to this table.
4. Never rename a shipped code.
