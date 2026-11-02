# crypto-finder verification map

This directory is the maintained source for verifying what a crypto-finder user can observe. Read this index before driving the CLI, then use the matching feature file as the recipe. The feature id is the file name without `.md`, and it is also the argument to `run.sh` and the name of the driver in `scripts/drive/`.

## Baseline preconditions

- `.claude/skills/verify/scripts/build.sh` has run, and `doctor.sh` reports `ok binary` with no `FAIL` line.
- `opengrep` (1.12 or later) and `jq` are on `PATH`. Each per-language feature needs that language's toolchain; `doctor.sh` lists which languages are ready.
- No real API key, API URL or ruleset is involved. Drives run under `env -i` with a fresh `HOME`/`XDG_*` per drive, always pass `--no-remote-rules`, and take rules only from `testdata/rules/`. See "Isolation rules" in `../SKILL.md`.
- Never drive a binary or a sandbox that this checkout's scripts did not create.

## Driving conventions

- Every drive starts from a fresh copy of a `testdata/projects/` fixture in `bin/verify/sandbox/<feature>[-<lang>]/work/`. That directory is its own git repository (see Gotchas in `scan.md`).
- Run commands as written. Every recipe passes `--error-format json`, so a failure is a JSON object on the last line of stderr, and its `code` is what the drive asserts.
- Every flag a recipe names is one the shipped CLI exposes (`crypto-finder scan --help`, `convert --help`, `cbom --help`). Drives never use test-only hooks.
- To provoke a failure, drive a temp copy through `VERIFY_FIXTURES=<dir>`. Never edit `testdata/`.

## Proof and skip reporting

- Proof is `bin/verify/evidence/<feature>/[<lang>/]verdict.txt` plus the files it was derived from. Quote its `VERDICT` line and the `PASS`/`FAIL` lines you rely on.
- Exit codes:
  - `0`: every check passed;
  - `1`: a check failed (the verdict names it);
  - `2`: the drive refused to run (isolation guard, missing binary, lock).
- A language that `run.sh <id> all` prints as `SKIP` is unverified. Say so, and name the missing toolchain.
- Do not report a sub-feature as verified when the drive exercised a different entry point.

## Feature entry contract

Each feature file starts with an H1 title and one paragraph describing the user-visible behavior. It then has exactly five H2 sections, in this order:

1. `Sub-features` lists short IDs, one line each.
2. `How to get to it (user POV)` lists the commands and flags a user types.
3. `Driving it with run.sh` starts with `Preconditions:` and pairs each user action with the exact invocation and the observable result the driver asserts.
4. `Gotchas` lists traps that waste or invalidate a run.
5. `Code paths` lists repo-relative globs of the code that implements the feature: its own commands, packages and handlers. It leaves out shared primitives (`internal/failure`, `internal/utils`, `internal/config`), generated code and tests. Use it to decide which features a diff touches.

## Features

- [scan](./scan.md): scan a project with local rules; findings JSON on a file or stdout; `--fail-on-findings` and failure exit codes.
- [reachability-project](./reachability-project.md): intra-project reachable/unreachable verdicts with `--export-callgraph-project-reachability`, checked against a `--scan-dependencies` run.
- [reachability-dependencies](./reachability-dependencies.md): `--scan-dependencies` reachability into direct and transitive dependencies (app -> liba -> libb) for Go, Python, Node and Rust.
- [convert-cbom](./convert-cbom.md): `convert` and `scan --format cyclonedx` to a CycloneDX 1.7 CBOM.
- [cbom-from-sbom](./cbom-from-sbom.md): the `cbom` subcommand building a CBOM for an SBOM's components from API-mined findings (driven against a local stub).
- [callgraph-export](./callgraph-export.md): `--export-callgraph` (schema 6.18 / 6.14), chain budget, entry-point index, and `--export-graph-fragment`.
