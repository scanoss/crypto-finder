# Migrating from 0.5x to 1.0

Most users change nothing but their command lines and image tags. The
reports (interim JSON format 1.9, CycloneDX CBOM, callgraph and graph-fragment
exports) and the SCANOSS API contract are the same as in 0.54.0. What
changed: flags that were accepted and ignored now fail, OpenGrep and Semgrep
are gone, the `-slim` images are gone, and the engine's Go packages moved to
[`github.com/scanoss/reach`](https://github.com/scanoss/reach).

## Quick path

- [ ] Drop the removed flags from your invocations (table below). An unknown flag now fails the command.
- [ ] Replace `latest-slim` with `latest` (and `<version>-slim` with `<version>`).
- [ ] C, C++ and C# are scanned by 1.0 without `CRYPTO_FINDER_CARDS_C` or `CRYPTO_FINDER_CARDS_CSHARP`; remove them if you set them (they are still accepted).
- [ ] If you scan Rust and want its test code reported, pass `--include-tests`: 1.0 skips `tests/`, `tests.rs`, `*_test.rs` and inline `#[cfg(test)]` modules by default.
- [ ] If you import crypto-finder's Go packages, change the import paths (table below).
- [ ] Remote scans fetch the `crypto-cards` ruleset instead of `dca`; drop any `--ruleset-version` pinned to a `dca` release, or pin a `crypto-cards` release ([Ruleset](#ruleset)).
- [ ] Make sure every machine that scans with remote rules reaches the SCANOSS API at least once a day: leases are short, and a refused key (HTTP 401 or 403) no longer falls back to the cache.
- [ ] Run one scan and compare the report with your last 0.54.0 report.

## Removed flags

These flags were accepted with a `flag_no_effect` warning in 0.54.0 and
changed nothing in the report. In 1.0 they are unknown flags.

| Command | Flag |
|---|---|
| `scan` | `--dep-ecosystem`, `--dep-workers`, `--detect-paths-from`, `--findings-cache`, `--include-dev-dependencies`, `--install-dependencies`, `--interfile`, `--no-dependency-findings-api`, `--opengrep-mode`, `--rule-prefilter`, `--scanner`, `--scanner-jobs` |
| `annotate` | `--opengrep-mode`, `--scanner`, `--scanner-jobs` |

Removed settings: `SCANOSS_OPENGREP_MODE`, `SCANOSS_RULE_PREFILTER`,
`SCANOSS_SCANNER_JOBS`, `SCANOSS_FINDINGS_CACHE_BACKEND`,
`SCANOSS_FINDINGS_CACHE_DSN`, `SCANOSS_FINDINGS_CACHE_TABLE`.

`annotate --source` is still accepted, and now only needed for a fragment
older than graph-fragment-1.16.

## Docker images

| 0.5x tag | 1.0 tag | Contents in 1.0 |
|---|---|---|
| `latest-slim`, `<version>-slim` | `latest`, `<version>` | The binary and CA certificates |
| `latest`, `<version>` | `latest`, `<version>` | Same as above: no OpenGrep, no Semgrep |
| `latest-deps`, `<version>-deps` | unchanged | The binary plus JDKs 8, 11, 17, 21, Maven and Gradle (and the Go, Rust and Python toolchains); no OpenGrep, no Semgrep |

Details: [DOCKER_USAGE.md](DOCKER_USAGE.md).

## Detection and dependency scanning

| Area | 0.54.0 | 1.0 |
|---|---|---|
| Detector | OpenGrep or the cards engine (`--scanner`) | The cards engine only, in process; nothing to install |
| Languages | Java, Python and the OpenGrep languages | Java, Python, Go, JavaScript, TypeScript, Rust, Ruby, C, C++ and C#; a target only in other languages fails with `language_not_supported` |
| `--scan-dependencies` ecosystems | Java, Python, Go, Rust, Node (local pipeline) | Java (Maven, Gradle), Python, Go, JavaScript/TypeScript (npm, yarn, pnpm locks), Rust (`Cargo.lock` through `cargo metadata --locked`), Ruby (`Gemfile.lock`) and C# (NuGet); Rust dev-dependencies and build-dependencies are no longer included |
| Dependency findings | Local pipeline or the API | One request to `POST /v3/cryptography/reachability/application`; versions the API has no data for are analysed locally; `--offline` does everything locally ([OFFLINE.md](OFFLINE.md)) |
| Python dependency verdicts | — | On: reachable, unreachable or `unknown` with a reason ([KNOWN_LIMITS.md](KNOWN_LIMITS.md)) |

## Ruleset

| Item | 0.54.0 | 1.0 |
|---|---|---|
| Default remote ruleset | `dca` (no flag) | `crypto-cards`; `--ruleset <name>` fetches another |
| `--ruleset-version` | A `dca` release | A release of the ruleset `--ruleset` selects; each ruleset numbers its own releases, so take the version from a report made with the same ruleset |
| `--ruleset dca` | | Loads, with a warning that the ruleset holds no card files and its findings may be incomplete |
| API refuses the key (HTTP 401 / 403) | Stale cache used until the lease expired | Fails with `rules_load_failed`; the cache is not used |
| Network error or 5xx, cache expired | Stale cache used until the lease expires | Unchanged |
| Lease length | Set by the API | Short: 24 hours by default, so a machine must reach the API at least daily |

Details: [REMOTE_RULESETS.md](REMOTE_RULESETS.md).

## Go library users

The engine moved to the MIT-licensed module `github.com/scanoss/reach`, with
the same identifiers. Change the import path; the code stays the same.

| 0.5x import | 1.0 import |
|---|---|
| `github.com/scanoss/crypto-finder/pkg/graphfrag` | `github.com/scanoss/reach/graphfrag` |
| `github.com/scanoss/crypto-finder/pkg/graphfrag/equiv` | `github.com/scanoss/reach/graphfrag/equiv` |
| `github.com/scanoss/crypto-finder/pkg/graphwalk` | `github.com/scanoss/reach/graphwalk` |
| `github.com/scanoss/crypto-finder/pkg/paramcondition` | `github.com/scanoss/reach/paramcondition` |
| `github.com/scanoss/crypto-finder/pkg/purl` | `github.com/scanoss/reach/purl` |
| `pkg/graphfrag`: `ToFindingsEnvelope`, `FindingsEnvelope`, `FindingFile`, `FindingAsset`, `FindingsSchemaVersion` | `github.com/scanoss/crypto-finder/pkg/appreach` |

```bash
go get github.com/scanoss/reach@latest
# then, for example:
gofmt -w -r '"github.com/scanoss/crypto-finder/pkg/graphwalk" -> "github.com/scanoss/reach/graphwalk"' .
```

Packages that stay in crypto-finder: `pkg/appreach`, `pkg/schema`,
`pkg/failure`, `pkg/conditioned`, `pkg/pqc`, `pkg/sbomcbom`.

## What did not change

| Item | Status |
|---|---|
| Interim report | Format `1.9` |
| Graph-fragment and callgraph JSON | Same keys, schema versions and graph algorithm ids as before the move |
| SCANOSS API requests | Same endpoints and bodies |
| Ruleset loading | Leased bundles, cache and flags as in 0.54.0, except the default ruleset and the refused-key behavior ([Ruleset](#ruleset)) |
| Failure codes | No shipped code renamed ([ERROR_CODES.md](ERROR_CODES.md)) |

## Verification

1. Run your usual command; it must not fail with `unknown flag`.
2. Compare finding counts and `finding_id`s with your 0.54.0 report for the
   same commit. 1.0 detects with `crypto-cards`, not `dca`, so finding
   counts can differ; to compare like with like, pin a `crypto-cards`
   release with `--ruleset-version`.

Every change is listed in [CHANGELOG.md](../CHANGELOG.md).
