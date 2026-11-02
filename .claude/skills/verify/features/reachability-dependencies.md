# Dependency reachability (direct and transitive)

`--scan-dependencies` resolves the target's dependency tree, scans each dependency's sources, and stitches one call graph across application and dependencies. A finding inside a dependency carries its module, whether the application declares that module (`direct`) or reaches it through another dependency (`transitive`), and the dependency path. Crypto the application actually calls reads `reachable`, with a call chain that crosses every module on the way. Crypto that nothing calls reads `unreachable`. This is the product's core claim: the user sees crypto in a library two levels down and whether the application really uses it.

## Sub-features

- `deps-transitive-reachable` reads libb's used hash as `reachable`, with a chain app -> liba -> libb, attribution `transitive`, and path `[liba, libb]`.
- `deps-transitive-unreachable` reads libb's hash behind a liba function the app never calls as `unreachable`, still `transitive`.
- `deps-app-verdicts` reads the application's own used hash as `reachable` (`source: direct`, no dependency) and its dead hash as `unreachable`.
- `deps-ecosystems` covers Go modules (`replace`), Python (an installed venv), npm (`package-lock.json` plus `node_modules`) and Cargo (path dependencies).

## How to get to it (user POV)

- `crypto-finder scan --no-remote-rules --rules <r> --languages <lang> --output findings.json --export-callgraph callgraph.json --scan-dependencies <app>`
- Optional flags: `--dep-ecosystem auto|go|java|node|python|rust`, `--dep-workers N`, `--include-dev-dependencies` (npm), `--include-tests`.
- Read `finding_graphs[].dependency.{module,relationship,path}` and `call_chain_indexes` (indexes into `functions[]`, whose `dependency_info.module` names each frame's module) in the call graph.

## Driving it with run.sh

Preconditions:

- `doctor.sh` shows the language ready: `go` needs `go`, `python` needs `python3 -m venv`, `rust` needs `cargo` plus a rustup dir (kept as `RUSTUP_HOME`), and `node` needs nothing (the resolver reads the lockfile and tree).
- Fixture `testdata/projects/transitive_reachability/<lang>`: `app/` depends on `liba/` (no crypto), which depends on `libb/` (crypto). Rust also has `hash/`, a stand-in hashing crate.
- Rules: `testdata/rules/transitive-reachability.yaml`.
- Wiring mirrors `TestTransitiveReachability`:
  - Go: the app `go.mod` `replace`s both modules.
  - Python: a venv outside the target, with `translibb` installed and `transliba` installed as `Requires-Dist: translibb`.
  - Node: `liba`/`libb` are copied to `app/node_modules/transliba|translibb`.
  - Rust: path dependencies, with `CARGO_NET_OFFLINE=true`.

- **Drive one language.** Run `.claude/skills/verify/scripts/run.sh reachability-dependencies go`. It exits 0, and `evidence/reachability-dependencies/go/verdict.txt` reads `VERDICT: PASS (5 passed, 0 failed)`.
- **Drive every present language.** Run `.claude/skills/verify/scripts/run.sh reachability-dependencies all`. It runs one verdict per language and prints `SKIP` lines for missing toolchains.
- **Scan.** `scan --scan-dependencies` exits 0 and writes `findings.json` and `callgraph.json`. `verdicts.json` has one row per finding graph.
- **Transitive used hash.** For Go: `PASS example.com/translibb/libb.go:11: reachable (transitive via example.com/transliba>example.com/translibb), chain app>example.com/transliba>example.com/translibb`. For python, node and rust it reads `translibb/<file>:<line>` via `transliba>translibb`.
- **Transitive unused hash.** `libb.go:17` (Python `__init__.py:11`, Node `index.js:9`, Rust `lib.rs:12`) is `unreachable` and still `transitive` via liba>libb.
- **App hashes.** `app/main.go:18` is `reachable` with chain `app`, and `app/main.go:22` is `unreachable`. Python uses `main.py:7`/`:11`, Node `index.js:5`/`:9`, Rust `main.rs:4`/`:9`.
- **Proof.** Keep `verdict.txt`, `verdicts.json` (the joined rows), `findings.json`, `callgraph.json` and `transcript.txt`.
- **Prove the check can fail.** Copy `testdata/projects` to a temp dir and change `liba.Used` to `return data`. Then run `VERIFY_FIXTURES=<tmp> run.sh reachability-dependencies go`. It exits 1 with `VERDICT: FAIL (4 passed, 1 failed)` and `FAIL example.com/translibb/libb.go:11: reachability unreachable, want reachable; no chain crosses app>example.com/transliba>example.com/translibb; chains: ["example.com/translibb"]`. Rerun without `VERIFY_FIXTURES` afterwards: each drive replaces its evidence directory.

## Gotchas

- Without its own git repository, the fixture copy under the gitignored `bin/` loses every application finding and only the libb rows come back (see `scan.md`). The check names those as `no finding at this location`.
- `VIRTUAL_ENV` from your shell would point the Python resolver at your real venv. `env -i` strips it, and the driver sets it to the sandbox venv.
- Rust needs the rustup toolchains under the real `~/.rustup`, because the `cargo` on `PATH` is a rustup proxy. A fresh HOME moves `CARGO_HOME` but not `RUSTUP_HOME`.
- `findings.json` reports dependency findings with `source: "dependency"` and `dependency: null`. The module, relationship and path live in the call graph only, so assert there.
- An API key would make the CLI take dependency findings from the SCANOSS API instead of scanning locally. Drives never have one, so dependencies are always scanned locally.

## Code paths

- `internal/cli/scan.go`
- `internal/dependency/**`
- `internal/engine/dependency_*.go`
- `internal/engine/orchestrator.go`
- `internal/scan/export.go`
- `internal/scan/export_ecosystems.go`
- `internal/callgraph/**`
- `pkg/graphfrag/callgraph_export.go`
- `pkg/graphfrag/stitch*.go`
- `pkg/graphfrag/ingest.go`
- `pkg/purl/**`
