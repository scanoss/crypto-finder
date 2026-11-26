# Client and server: what runs where

crypto-finder runs every scan of your own code on your machine. It calls the
SCANOSS API for two things only: the detection ruleset, and the dependency
findings with their reachability verdicts. Source files never leave the
machine. With `--offline` and a local ruleset, a scan calls no SCANOSS
service at all.

## Quick path

| You run | It calls | It sends |
|---|---|---|
| `scan` (remote ruleset `crypto-cards`, the default; `--ruleset` names another) | Ruleset endpoints | Ruleset name and version |
| `scan --no-remote-rules --rules-dir <dir>` | Nothing | Nothing |
| `scan --scan-dependencies` | Ruleset endpoints + `POST /v3/cryptography/reachability/application` | The pinned dependency list and the project's calls into it |
| `scan --scan-dependencies --offline` | Ruleset endpoints only (none with a local ruleset) | Ruleset name and version |
| `annotate` | Ruleset endpoints (none with a local ruleset) | Ruleset name and version |
| `cbom <sbom>` | `POST /v3/cryptography/reachability/component`, once per component | Each component's package URL and version |
| `convert`, `configure`, `version` | Nothing | Nothing |

## What runs on the client

| Step | Code | Notes |
|---|---|---|
| Language detection, skip patterns | `reach/language`, `reach/skip` | |
| Ruleset loading | `internal/rules`, `internal/cache` | Downloads and verifies the leased bundle, keeps it encrypted in the cache ([REMOTE_RULESETS.md](REMOTE_RULESETS.md)) |
| Call graph build and type resolution | `reach/callgraph` with `internal/cryptokb` | JDK and dependency JARs are read locally |
| Detection | `internal/scanner/cards`, reach `cardmatch` | Matches the ruleset against the call graph's call sites |
| First-party reachability | `internal/scan` | Chains from the project's entry points to its own findings |
| Dependency resolution | `internal/dependency` | Runs `mvn`, `gradle` or `cargo metadata` in the project; reads the other ecosystems' lock files and environments as files |
| Offline analysis and stitch | `internal/offline`, `pkg/appreach` | With `--offline`, and for the dependencies the API has no data for ([OFFLINE.md](OFFLINE.md)) |
| Reports | `internal/output`, `internal/converter` | Interim JSON, CycloneDX, callgraph and graph-fragment exports |

## What the SCANOSS API serves

| Endpoint | Used by | Purpose |
|---|---|---|
| `GET /v3/cryptography/rulesets/{name}/{version}/download` | `scan`, `annotate` | The ruleset bundle with its signed lease |
| `GET /v3/cryptography/rulesets/{name}/{version}` | `scan`, `annotate` | Release check when the cached ruleset's TTL has elapsed |
| `POST /v3/cryptography/reachability/application` | `scan --scan-dependencies` | Every finding of the pinned dependencies, and whether the project reaches it |
| `POST /v3/cryptography/reachability/component` | `cbom` | The findings SCANOSS published for one component version |

A ruleset answer of HTTP 401 or 403 (a refused key) on either ruleset
endpoint fails the scan with `rules_load_failed`, and the cached ruleset is
not used. A network error or a 5xx answer leaves the cached ruleset in use
until its lease expires. Leases are short (24 hours by default), so a
machine that scans with remote rules must reach the API at least once a day.

Every request carries `x-api-key` and `User-Agent: crypto-finder/<version>`.
The base URL is `https://api.scanoss.com` unless `--api-url`,
`SCANOSS_API_URL` or the config file says otherwise. A plain-HTTP URL on a
remote host needs `--allow-http`.

The verdicts come from `pkg/appreach` (over reach's `appreach`), the same Go package the API runs
for `/reachability/application` and `--offline` runs in process.

## What a dependency scan sends and receives

Request (`POST /v3/cryptography/reachability/application`, `schema_version` `"1"`):

| Field | Content |
|---|---|
| `dependencies` | Each pinned dependency: package URL, version, `direct`, the dependencies it `requires`; for Python also its environment `markers` and `extras` |
| `call_sites` | A graph fragment of the project's functions that call a dependency: function names, file paths and lines, each call into a dependency with its target, call text and arguments, and the project's supertypes and ServiceLoader registrations |
| `include_call_chains`, `max_chains_per_finding` | Whether to return chains, and how many per finding (`--dependency-reachability-max-chains`, default 1) |
| `conditioned_rules` | The loaded ruleset's parameter-conditioned rules for the ecosystem, so the API can specialize a dependency finding by the values another dependency passes it |

Not sent: source files, functions that call no dependency, first-party
findings.

Response, merged into the report:

| Field | Becomes |
|---|---|
| Each dependency finding with its asset | A report finding with `source: dependency` and `dependency_info` |
| `reachability`, `reachability_reason` | `finding_graphs[].reachability` and `unresolved_reason` in `--export-callgraph` |
| `call_chains`, `analysis` | The finding's chains and analysis in `--export-callgraph` |
| Dependencies without data | Answered locally by the offline fallback ([OFFLINE.md](OFFLINE.md#online-scans-the-offline-fallback)), listed in `deps_answered_offline_list`; those it cannot answer, or all of them with `--no-offline-fallback`, in `deps_skipped_list` (reason `no_reachability_data`) |

Field-by-field formats: [OUTPUT_FORMATS.md](OUTPUT_FORMATS.md) and
[DEPENDENCY_SCANNING.md](DEPENDENCY_SCANNING.md).

## Online vs offline

| | Online (default) | `--offline` |
|---|---|---|
| Who analysed the dependencies | SCANOSS, ahead of time | The client, on first use; then cached |
| Where the stitch runs | SCANOSS API | In process, same code (`pkg/appreach`) |
| Dependency coverage | Versions SCANOSS has analysed | Versions whose sources are on this machine ([OFFLINE.md](OFFLINE.md#what-it-does)) |
| Network | SCANOSS API | The ruleset download unless `--no-remote-rules`; Maven repositories for missing sources JARs |
| Versions SCANOSS has not analysed | Analysed locally by the offline fallback (off with `--no-offline-fallback`) | Analysed like the others |
| First run | Fast | Slow: analyses every dependency |
| Later runs | Fast | About as fast as online |

Details: [OFFLINE.md](OFFLINE.md).
