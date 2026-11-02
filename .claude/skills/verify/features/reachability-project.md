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

Preconditions:

- `doctor.sh` reports `lang go: ready` (and `lang python: ready` for python).
- Fixture `testdata/projects/project_reachability/<lang>/app`. For Go, `go.mod` replaces `example.com/reachlib` with `../lib`. For Python, the driver builds a venv outside the target holding `reachlib` (`digest()` hashing with SHA-256), as `pythonVenvWithDependency` does.
- Rules: `testdata/rules/project-reachability.yaml`.

- **Drive it.** Run `.claude/skills/verify/scripts/run.sh reachability-project go` (or `python`, or `all`). It exits 0, and `evidence/reachability-project/<lang>/verdict.txt` reads `VERDICT: PASS`.
- **Three passes.** The driver runs the same scan three times: with `--export-callgraph-project-reachability` (into `project/`), with `--scan-dependencies` (into `deps/`), and with neither (into `plain/`). Each pass exits 0. `<pass>/verdicts.json` joins findings to graphs.
- **Go verdicts.** In the project pass, `app/main.go:21` (`fingerprint`, SHA-256) is `reachable` with a chain starting in `app`, `app/main.go:25` (`legacy`, MD5) is `unreachable`, and `app/main.go:35` (`hasher.Hash`, SHA-512) is `unreachable`.
- **Python verdicts.** `app/main.py:7` is `reachable` and `app/main.py:11` is `unreachable`.
- **Equivalence.** For every first-party `finding_id`, project and deps verdicts are equal (`PASS main.go:NN: both passes read ...`). The exception is `main.go:35`, a declared divergence: project-only `unreachable`, dependency scan `reachable`.
- **Isolation of passes.** The deps pass has dependency rows (`module != app`). The project pass has none.
- **No flag.** Every verdict in `plain/` is `not_applicable`.

## Gotchas

- `app/main.go:29` (`callback`, handed to `reachlib.Visit`) reads `unreachable` in both passes today. The equivalence check covers it, but nothing pins its value, because no test states that this is the contract. Do not cite it as proof of callback reachability.
- The Python venv must live outside the target. A venv inside `app/` counts as project source for the project-only flag but as a dependency for `--scan-dependencies`, which is a documented difference and not this contract.
- Java has a fixture (`project_reachability/java`), but Maven resolution reads the real `~/.m2`. That breaks the fresh-HOME sandbox, so the driver does not cover it. Report Java as not driven.
- Leave the flag off when scanning a library on its own: it treats the target as the application.

## Code paths

- `internal/cli/scan.go`
- `internal/scan/export.go`
- `internal/scan/export_ecosystems.go`
- `internal/callgraph/*.go`
- `internal/callgraph/contracts/contracts.go`
- `internal/callgraph/entrypoints/**`
- `internal/engine/rule_entrypoint_synthesis*.go`
- `internal/deadcode/**`
- `pkg/graphfrag/callgraph_export.go`
- `pkg/graphfrag/stitch*.go`
- `pkg/graphfrag/containing_function.go`
- `pkg/graphwalk/**`
