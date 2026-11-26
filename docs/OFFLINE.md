# Offline dependency scanning

`scan --scan-dependencies --offline` decides dependency reachability on your
machine instead of asking the SCANOSS API. The answer has the same shape and
comes from the same code (`pkg/appreach`); only who mines the
dependencies, and where the stitch runs, changes. The first run is slow
because it mines every dependency; later runs read the cache.

## Quick path

```bash
# Java (Maven or Gradle): sources JARs come from the local Maven repository
crypto-finder scan --scan-dependencies --offline --export-callgraph callgraph.json ./service

# Python: dependencies are mined from installed distributions
crypto-finder scan --scan-dependencies --offline \
  --offline-python-packages ./ci-venv --export-callgraph callgraph.json ./service

# No SCANOSS service at all: add a local ruleset
crypto-finder scan --scan-dependencies --offline \
  --no-remote-rules --rules-dir ./ruleset ./service
```

Expected: the same report and `--export-callgraph` fields as an online scan.
With `-v`, the log line `Offline: dependencies prepared` counts the
dependencies read from the cache, re-annotated, mined and unavailable.

## Flags

| Flag | Default | Effect |
|---|---|---|
| `--offline` | off | Mine and stitch locally. Without `--scan-dependencies` it only warns: the scan resolves no dependencies. |
| `--offline-cache-dir <dir>` | `~/.scanoss/crypto-finder/cache/mined` | The mined-dependency cache |
| `--offline-python-packages <dirs>` | — | Python targets: installed packages to mine from (OS path-list separated: virtual environments, site-packages directories, unpacked wheels), searched after the project's `.venv`, `venv` and `VIRTUAL_ENV` |
| `--offline-memory-mb <n>` | `10240` | The scan's soft memory limit in MiB (unless `GOMEMLIMIT` is set); half of it bounds the dependencies mined at once |

The other `scan` flags apply as online. The default memory budget is sized
for a closure of about 130 Java dependencies.

`--timeout` (default `10m`) bounds the whole scan, mining included. Give a
first run of a large closure more time: mining the npm closure of a
450-package project took about 25 minutes. When the time runs out while
dependencies are mined, the scan fails at once with `scanner_timeout`
instead of mining on; each dependency mined by then is cached, so the next
run mines only the rest.

## Online scans: the offline fallback

An online scan (`--scan-dependencies` without `--offline`) asks the SCANOSS
API first. For each dependency the API answers without data (reason
`no_reachability_data`: a version SCANOSS has not mined), it then runs this
offline path and serves the local answer in place of the API's, the same
findings and verdicts `--offline` gives for that dependency.

- **What is mined.** Only the dependencies without data, plus every
  dependency that leads to one of them in the resolved tree, so a route from
  the project through an API-answered dependency into a locally mined one is
  in the stitch. The stitch runs over the whole request; the other
  dependencies are served without a graph and spliced out, as the API
  splices a dependency it has no data for. Their findings and verdicts stay
  the API's.
- **What is not mined.** Dependencies without data for another reason keep
  today's reporting: `unpinned`, `other_version_requested`,
  `under_other_version`.
- **Flags.** `--offline-cache-dir`, `--offline-memory-mb` and
  `--offline-python-packages` apply. `--timeout` bounds the scan, fallback
  included. `--no-offline-fallback` turns the fallback off: the API's answer
  is served as it is.
- **Failures.** A dependency the fallback cannot answer (no sources, mining
  failed, the scan's time ran out) stays in `deps_skipped_list` with reason
  `no_reachability_data` and an `offline_fallback` field saying why, with a
  warning. The scan does not fail for it.
- **Reporting.** The completed `dependencies` progress event adds
  `deps_answered_online`, `deps_answered_offline` and
  `deps_answered_offline_list` (`purl`, `version` of each dependency the
  fallback answered).
- **No API key, API unreachable.** Unchanged: the request fails the scan as
  before (`dependency_resolution_failed`); the fallback only fills in an
  answer the API gave.

Known limit: a route into a fallback dependency that does not pass through
its ancestors in the resolved tree (a Python import the lock does not
declare, a closure resolved without a tree) crosses dependencies served
without a graph, and is judged as the API judges a route through a
dependency without data. An API-answered dependency the API judged
`unknown` with reason `dependency_without_graph`, because its only routes
cross a dependency now answered locally, keeps that verdict.

## What it does

1. **Resolves** the pinned closure, as online (Maven or Gradle for Java;
   locks, pinned requirements or the environment for Python; `go.mod` for Go;
   the npm, yarn or pnpm lock for JavaScript and TypeScript).
2. **Builds** the project's call graph once, typed by the closure's JARs.
3. **Mines** each dependency the way the SCANOSS miner does: a scan of its
   sources with the loaded ruleset, typed by its own subtree of the resolved
   tree, exporting its graph fragment and findings. Several dependencies run
   at once, largest first, within the memory budget.
4. **Caches** each mined dependency.
5. **Stitches** the closure in process with `pkg/appreach` and merges the
   answer into the report.

Where the sources come from:

| Ecosystem | Source of a dependency | If missing |
|---|---|---|
| Java | Its `-sources.jar` beside the compiled JAR (local Maven repository or Gradle cache). Maven fetches a missing one (`mvn dependency:get`, classifier `sources`); Maven's repositories, settings and offline flag apply. | No findings for it; `deps_skipped_list` reason `no_reachability_data`, and a warning |
| Python | The files its installed distribution's `RECORD` lists (`.py`, `.pyi`), found by name and version | Same as Java |
| Go | Its directory in the Go module cache | Same as Java |
| JavaScript/TypeScript | Its package directory under the project's `node_modules` (npm, yarn, or the pnpm virtual store), found by the name and version its `package.json` states | Same as Java |

Nothing is downloaded from the SCANOSS API, and for Python and npm nothing is
installed, downloaded or run.

## Cache

```
~/.scanoss/crypto-finder/cache/mined/
  <graph key>/graph.json.gz                          structural graph
  <graph key>/meta.json                              what it is
  <graph key>/rules-<ruleset key>/annotation.json.gz findings on that graph
  <graph key>/rules-<ruleset key>/findings.json.gz   findings report
```

| Key | Built from |
|---|---|
| Graph key | Package, version, graph algorithm id, fragment schema, and the content of every type JAR of the dependency's closure (Python: its source files' path, size and modification time) |
| Ruleset key | The ruleset's content |

| Change | Effect on the next run |
|---|---|
| Nothing | Reads the cache; about as fast as online |
| New ruleset | Re-detects each cached graph without its sources (the `annotate` path; an npm package's installed source is read for its API entry points, as the SCANOSS miner does); no re-mining |
| New graph algorithm id (a crypto-finder release that changes graph construction) | Re-mines that ecosystem's dependencies ([GRAPH_IDS.md](GRAPH_IDS.md)) |
| New dependency version | Mines only that dependency |

Entries are written to a temporary file and renamed, so two runs never see a
partial entry. Deleting the directory is safe; the next run mines again.

Other caches under `~/.scanoss/crypto-finder/cache/` serve online and offline
scans alike: `rulesets/` (the encrypted ruleset), `bytecode/` (JAR type
indexes), `python-signatures/` (Python package indexes), `sources/` (extracted
dependency sources).

## Measured cost

From the 1.0 validation (Python targets, wall clock):

| Run | synapse |
|---|---|
| Online | 13-15 s |
| Offline, first run (fills the cache) | 68 s |
| Offline, later run | 13 s |

## Limits

| Limit | What happens |
|---|---|
| Java dependency without a sources JAR in any reachable Maven repository | Reported without findings (`no_reachability_data`) |
| Python dependency not installed in any searched environment | Same |
| npm dependency not installed under the project's `node_modules` | Same |
| Repository code runs | `mvn` and `gradle` run in the project and can execute code it controls; scan untrusted repositories in a sandbox |
| Memory | Mining is bounded by `--offline-memory-mb`; a large closure on a small budget mines fewer dependencies at once and takes longer |
| Time | Mining counts against `--timeout`; a first run that outlasts it fails with `scanner_timeout` and keeps what it mined in the cache |
| Python verdicts | Served as online ([KNOWN_LIMITS.md](KNOWN_LIMITS.md)) |

See also [CLIENT_SERVER.md](CLIENT_SERVER.md) for what each mode sends, and
[DEPENDENCY_SCANNING.md](DEPENDENCY_SCANNING.md#offline-mode) for the full
dependency pipeline.
