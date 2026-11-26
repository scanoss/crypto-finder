# Intra-project reachability

A scan that exports a call graph labels each finding `reachable` (a traced call chain from the project's entry points reaches it), `unreachable` or `not_applicable`. With `--export-callgraph-project-reachability`, a scan that resolves no dependencies still classifies first-party findings against the target's own packages. Its contract is that every first-party verdict matches what a `--scan-dependencies` run reports for the same finding, apart from findings reached only through dependency code.

## Sub-features

- `project-verdicts` reads used crypto as `reachable` with a chain from `main`, and dead crypto as `unreachable`.
- `project-equivalence` gives every first-party finding the same verdict as a `--scan-dependencies` pass, except the declared divergences.
- `project-divergence` shows crypto reached only through a dependency's callback or interface (Go `hasher.Hash`) as `unreachable` project-only and `reachable` with dependencies.
- `project-no-flag` reads every finding as `not_applicable` without either flag.

## How to get to it (user POV)

- `crypto-finder scan --no-remote-rules --rules <r> --output findings.json --export-callgraph callgraph.json --export-callgraph-project-reachability <target>`
- For comparison, `crypto-finder scan ... --export-callgraph callgraph.json --scan-dependencies <target>`.
- Read `finding_graphs[].reachability` in the call graph, joined to the report by `finding_id`.

## Driving it with run.sh

This feature has no drive in this version. The 0.54.0 drive (OpenGrep, non-Java fixtures) was removed. A new drive for this version is to be written against the cards engine.

## Gotchas

- `app/main.go:29` (`callback`, handed to `reachlib.Visit`) reads `unreachable` in both passes today. The equivalence check covers it, but nothing pins its value, because no test states that this is the contract. Do not cite it as proof of callback reachability.
- The Python venv must live outside the target. A venv inside `app/` counts as project source for the project-only flag but as a dependency for `--scan-dependencies`, which is a documented difference and not this contract.
- Java has a fixture (`project_reachability/java`), but Maven resolution reads the real `~/.m2`. That breaks the fresh-HOME sandbox, so a drive cannot cover it there.
- Leave the flag off when scanning a library on its own: it treats the target as the application.

## Code paths

- `internal/cli/scan.go`
- `internal/scan/export.go`
- `internal/scan/export_ecosystems.go`
- `internal/cryptokb/**`
- `internal/engine/rule_entrypoint_synthesis*.go`
- `internal/deadcode/**`
