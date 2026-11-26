# Dependency reachability (application reachability from the API)

`--scan-dependencies` resolves the Java project's pinned dependency closure to compiled JARs, types the project's one call graph with them, and asks the SCANOSS API in one request (`POST /v3/cryptography/reachability/application`) for every finding of those dependencies and whether the project reaches it. A dependency finding carries its module, `dependency_info`, and the API's verdict (`reachable`, `unreachable` or `unknown` with a reason) and chains in the call graph export. This is the product's core claim: the user sees crypto in a library two levels down and whether the application really uses it. No dependency source is fetched or scanned.

## Sub-features

- `deps-project-request` sends the closure (direct flags, requires) and the project's call sites into it, with the scan's conditioned rules, in one request.
- `deps-merge` adds each served finding as `source: dependency` with `dependency_info`, its served `occurrence_key`, and the API's verdict in `finding_graphs[].reachability`.
- `deps-skips` reports `dependencies` `skipped` with `manifest_absent` (no Java build) or `ecosystem_not_supported` (an ecosystem this version does not resolve, such as Ruby; Go, Python, Node and Rust resolve, or skip with `manifest_absent` without a manifest or lock), and `deps_skipped_list` for dependencies the API has no data for.

## How to get to it (user POV)

- `crypto-finder scan --api-url <url> --api-key <key> --output findings.json --export-callgraph callgraph.json --scan-dependencies <java-app>`
- Optional flags: `--dependency-reachability-max-chains N` (chains per dependency finding, default 1), `--include-tests`, `--progress`.
- Read `finding_graphs[].reachability`, `unresolved_reason` and `call_chain_indexes` in the call graph, and `dependency_info` in the findings.

## Driving it with run.sh

This feature has no drive in this version. The 0.54.0 drive (OpenGrep, non-Java fixtures) was removed. A new drive for this version is to be written against the cards engine.

## Gotchas

- The scan needs the SCANOSS API. Drives never use a real key or URL; a port must serve the endpoint from a stub on `127.0.0.1`.
- Maven resolution reads the local repository Maven names (`settings.xml`, `MAVEN_OPTS`); an offline sandbox needs the closure's JARs in it.
- A dependency version the API has not mined has no findings: it shows only in `deps_skipped_list`.

## Code paths

- `internal/cli/scan.go`
- `internal/dependency/**`
- `internal/api/application_reachability.go`
- `internal/engine/application_reachability.go`
- `internal/engine/scan_result.go`
- `internal/cli/scan_application_reach.go`
- `internal/engine/orchestrator.go`
- `internal/scan/export.go`
- `internal/scan/export_ecosystems.go`
- `internal/cryptokb/**`
- `internal/engine/rule_entrypoint_synthesis*.go`
