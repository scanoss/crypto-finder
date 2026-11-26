# crypto-finder verification map

This directory is the maintained source for verifying what a crypto-finder user can observe. Read this index before driving the CLI, then use the matching feature file as the recipe. The feature id is the file name without `.md`, and it is also the argument to `run.sh` and the name of the driver in `scripts/drive/`.

## Port status (reach engine v2)

One feature has a drive: `cbom-from-sbom`. The other six (`scan`, `convert-cbom`, `callgraph-export`, `related-material`, `reachability-project`, `reachability-dependencies`) have a feature file and no drive. Their drives were written for crypto-finder 0.54.0 and earlier (OpenGrep, non-Java fixtures, the local dependency pipeline) and were removed. This version detects with the cards engine, for Java only, and `--scan-dependencies` takes dependency findings and verdicts from the SCANOSS API in one request. A new drive for each is to be written against the cards engine. `run.sh` reports a feature without a drive as unknown (exit 2), which reads as unreachable, never as pass. `budgets.sh size` and `startup` still run.

## Baseline preconditions

- `.claude/skills/verify/scripts/build.sh` has run, and `doctor.sh` reports `ok binary` with no `FAIL` line.
- `jq` and `python3` are on `PATH`.
- No real API key, API URL or ruleset is involved. Drives run under `env -i` with a fresh `HOME`/`XDG_*` per drive, always pass `--no-remote-rules`, and take rules only from `testdata/rules/`. See "Isolation rules" in `../SKILL.md`.
- Never drive a binary or a sandbox that this checkout's scripts did not create.

## Driving conventions

- Every drive starts in a fresh sandbox, `bin/verify/sandbox/<feature>/`, and runs from its `work/` directory. A drive that scans a fixture copies it there and makes `work/` its own git repository (see Gotchas in `scan.md`).
- Run commands as written. Every recipe passes `--error-format json`, so a failure is a JSON object on the last line of stderr, and its `code` is what the drive asserts.
- Every flag a recipe names is one the shipped CLI exposes (`crypto-finder scan --help`, `convert --help`, `cbom --help`). Drives never use test-only hooks.
- To provoke a failure, change a copy of the input inside the drive. Never edit `testdata/`.

## Proof and skip reporting

- Proof is `bin/verify/evidence/<feature>/verdict.txt` plus the files it was derived from. Quote its `VERDICT` line and the `PASS`/`FAIL` lines you rely on.
- Exit codes:
  - `0`: every check passed;
  - `1`: a check failed (the verdict names it);
  - `2`: the drive refused to run (isolation guard, missing binary, lock, unknown feature).
- A feature without a drive is unverified. Say so.
- Do not report a sub-feature as verified when the drive exercised a different entry point.

## Feature entry contract

Each feature file starts with an H1 title and one paragraph describing the user-visible behavior. It then has exactly five H2 sections, in this order:

1. `Sub-features` lists short IDs, one line each.
2. `How to get to it (user POV)` lists the commands and flags a user types.
3. `Driving it with run.sh` starts with `Preconditions:` and pairs each user action with the exact invocation and the observable result the driver asserts. For a feature without a drive it is one paragraph saying so.
4. `Gotchas` lists traps that waste or invalidate a run.
5. `Code paths` lists repo-relative globs of the code that implements the feature: its own commands, packages and handlers. It leaves out shared primitives (`internal/failure`, `internal/utils`, `internal/config`), the per-library knowledge-base YAML under `internal/cryptokb/<ecosystem>/` (no drive exercises one library's entry, and it is validated when it loads), generated code and tests. The engine (call graph, contracts loader, graph fragments, stitcher, entry points) lives in the `github.com/scanoss/reach` module, outside this repository, so no glob names it: an engine change reaches crypto-finder as a `go.mod` bump of reach. `go run ./scripts/featuremap check-pr` uses these globs to decide which features a diff touches; see "How the map is checked" below.

## Features

- [scan](./scan.md): scan a project with local rules; findings JSON on a file or stdout; `--fail-on-findings` and failure exit codes. No drive in this version.
- [reachability-project](./reachability-project.md): intra-project reachable/unreachable verdicts with `--export-callgraph-project-reachability`, checked against a `--scan-dependencies` run. No drive in this version.
- [reachability-dependencies](./reachability-dependencies.md): `--scan-dependencies` reachability into direct and transitive dependencies (app -> liba -> libb) for Go, Python, Node and Rust. No drive in this version.
- [convert-cbom](./convert-cbom.md): `convert` and `scan --format cyclonedx` to a CycloneDX 1.7 CBOM. No drive in this version.
- [cbom-from-sbom](./cbom-from-sbom.md): the `cbom` subcommand building a CBOM for an SBOM's components from API-mined findings (driven against a local stub).
- [callgraph-export](./callgraph-export.md): `--export-callgraph` (schema 6.18 / 6.14), chain budget, entry-point index, and `--export-graph-fragment`. No drive in this version.
- [related-material](./related-material.md): related crypto material (salt, iv, nonce) reported at a random draw whose value reaches a KDF or cipher in another function. No drive in this version.

## How the map is checked

`go run ./scripts/featuremap check-docs` fails when a feature file lacks one of the five sections or has them out of order, when its `Code paths` lists no backticked glob, when a glob matches no file of `git ls-files`, or when the `Features` list above does not link exactly the feature files. Run it after editing this directory.

`go run ./scripts/featuremap check-pr --base <sha> --head <sha> --body-file <file>` maps the files a pull request changes to features through their globs. A rename counts its old and new path; `*_test.go` and `testdata/` never count. The PR body must then name each touched feature under `## Evidence`, as `<id>: <evidence>` or `<id>: N/A: <reason>`. An id counts only as a whole token, so `reachability-dependencies` does not name a feature called `reachability`. It also runs the leak guard over the PR title, body, commit messages and added lines (see "Leak guard" in AGENTS.md). The `PR hygiene` workflow runs both checks.

Globs follow git pathspec glob rules, anchored at the repository root: `*`, `?` and `[...]` stay within one path segment, and a `**` segment matches zero or more segments. Err narrow. A glob that is too wide costs every PR an `N/A` line; one that is too narrow lets a change through unnamed. After changing globs, run `go run ./scripts/featuremap replay --rev origin/main -n 60` and check how many recent commits would have asked for each feature and which globs matched most.
