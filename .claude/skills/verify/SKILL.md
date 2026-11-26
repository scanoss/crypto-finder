---
name: verify
description: Drive the crypto-finder CLI (cmd/crypto-finder) the way a user does and capture proof - today that is `cbom` from an SBOM against a local API stub, plus binary size and startup budgets. Use it to confirm a change works in the real binary, not just in go test, and before claiming a user-facing behavior is fixed or shipped.
---

# Verify crypto-finder

crypto-finder is a short-lived CLI, so there is no server to keep alive. "Launch" builds the binary once; every drive runs it in a fresh sandbox, asserts on the files it writes and its exit codes, and leaves evidence behind. Each drive follows a recipe in [`features/`](features/README.md). Read the index before picking one.

Everything lives under `bin/verify/` in this checkout, which `.gitignore` already covers through `bin/`. Two checkouts never share a binary, a sandbox, or evidence.

```
bin/verify/crypto-finder                   binary built by build.sh
bin/verify/state.env                       HEAD, Go-source fingerprint, `crypto-finder version` line
bin/verify/sandbox/<feature>/              HOME, XDG dirs, work directory (cleanup.sh removes it)
bin/verify/evidence/<feature>/            transcript, JSON outputs, verdict.txt (cleanup.sh keeps it)
```

## Port status

One drive exists: `cbom-from-sbom`. Six features have no drive in this version: `scan`, `convert-cbom`, `callgraph-export`, `related-material`, `reachability-project` and `reachability-dependencies`. Their 0.54.0 drives (OpenGrep, non-Java fixtures) were removed. `run.sh` reports them as an unknown feature (exit 2). A new drive for each is to be written against the cards engine. See "Port status" in [`features/README.md`](features/README.md).

## Isolation rules (non-negotiable)

The production detection rules are private and are the company's core value. Never fetch them, reference them, or point a drive at them. Never use a real API key.

- Every drive runs the binary through `env -i`, with a fresh `HOME`, `XDG_CACHE_HOME`, `XDG_CONFIG_HOME` and `TMPDIR` under its sandbox. No `SCANOSS_*`, `SC_*` or `VIRTUAL_ENV` variable from your shell gets through. Only `PATH` and `LANG` are kept.
- `lib.sh` `guard_args` refuses to run:
  - a `scan` without `--no-remote-rules`;
  - a `scan` without a `--rules` file under `testdata/rules/`, or with `--rules-dir`, `--api-key`, `--api-url` or `--no-cache`;
  - `configure`;
  - a `cbom` whose `--api-url` is not `http://127.0.0.1:<port>`.
- After every invocation the drive aborts (exit 2) if the sandbox ruleset cache `~/.scanoss/crypto-finder/cache/rulesets` has any content. The binary creates that directory empty on every scan, and only a remote-rules download fills it.
- Rules come only from `testdata/rules/*.yaml`. These are synthetic rules that match only the fixtures' calls.

Do not bypass `cf` (the wrapper in `lib.sh`) to run the binary by hand. If you need a variation, add it to a driver so it stays guarded and recorded.

## Launch (build)

```bash
.claude/skills/verify/scripts/build.sh
```

This runs `go build -buildvcs=false ./cmd/crypto-finder` into `bin/verify/crypto-finder` with `-X` version ldflags: `Version=verify-<head12>-<fingerprint>`, `GitCommit=<HEAD>`. It writes `bin/verify/state.env` and prints it. It is ready when the printed `VERIFY_VERSION` reads `crypto-finder version verify-...`. Rebuild after any Go change; doctor tells you when the binary is stale.

## Doctor

```bash
.claude/skills/verify/scripts/doctor.sh
```

This check is read-only. It exits 1 in these cases:

- the binary is missing;
- `state.env` is missing;
- the Go sources (`cmd`, `internal`, `pkg`, `go.mod`, `go.sum`, committed or not) differ from what was built;
- `jq`, `git`, `realpath` or `python3` (the API stub) is missing;
- a stale drive lock exists;
- a sandbox holds a remote ruleset.

It also reports the following:

- which API variables are set in your shell (they are stripped anyway);
- the last verdict of every evidence directory.

Run it first, and again whenever a drive surprises you.

## Drive

```bash
.claude/skills/verify/scripts/run.sh <feature-id>
```

| feature-id | what it proves |
| --- | --- |
| `cbom-from-sbom` | `cbom` from CycloneDX and SPDX SBOMs against `scripts/api-stub.py` on 127.0.0.1 |

The other six feature files (`scan`, `convert-cbom`, `callgraph-export`, `related-material`, `reachability-project`, `reachability-dependencies`) have no drive. Do not report them as verified.

`run.sh` exits with one of these codes:

- 0 when `verdict.txt` reads `VERDICT: PASS`;
- 1 when any check failed;
- 2 when the drive refused to run (no binary, isolation guard, unknown feature, a lock held by another drive of the same feature).

The drive prints the verdict and the evidence path.

## Evidence

Each drive replaces `bin/verify/evidence/<feature>/` with these files:

- `transcript.txt` holds the binary version, HEAD, sandbox, and every `crypto-finder ...` command with its exit code;
- `<step>.stdout` and `<step>.stderr` hold each invocation's raw output (with `--error-format json`, the last JSON line of stderr is the typed error);
- the JSON the binary wrote, such as `cbom.json`;
- `verdict.txt` opens with a first line `VERDICT: PASS|FAIL (n passed, m failed)`, then one `PASS`/`FAIL` line per check, derived with `jq` from the files above.

Proof standards:

- Drive the real binary through its real flags. Assert on output files, exit codes and stderr codes, never on internal setters or test hooks.
- Quote the `verdict.txt` lines, not only "exit 0".
- `cbom` talks to a local stub because the real API is an external system behind a production HTTP boundary. Its evidence includes `api-requests.jsonl`, the requests the binary actually sent.
- A feature map entry lists sub-features. Driving one entry point does not verify the others.

## Budgets

```bash
.claude/skills/verify/scripts/budgets.sh [all|size|startup]...
```

This measures what a change can make worse and holds it to [`budgets.json`](budgets.json):

- `size`: the size of a build with the release ldflags (`-s -w` plus the version `-X` flags, as the Makefile and `.goreleaser.yml` build it). It is deterministic, so its limit is the measured size plus 10%.
- `startup`: the median wall time of 11 runs of `--help` and of `version`.

Timings are noisy, so they hold only loose limits that catch a stall, not a 20% slowdown. Every run goes through the same sandbox and guards as a drive. It prints `PASS <key> <value> within its budget <limit>` or `FAIL <key> <value> over its budget <limit>` per metric, exits 1 on any breach and 2 when it refused to run, and writes `measured.tsv`, `samples.tsv` (every run), `transcript.txt` and `verdict.txt` to `bin/verify/evidence/budgets/`. startup needs `build.sh` first.

`budgets.json` records each budget's measured value, its limit and a `why`, plus the date, commit, machine and method of the measurement. Never invent a number: change a limit only after measuring three runs of `budgets.sh` (take the highest), and update `measured` with it. `go run ./scripts/budgetcheck` (and its test) fails on a budget the script does not measure, a metric with no budget, a limit with no `why`, a limit below its measurement, and a deterministic limit more than 10% over its measurement. The `METRICS` line of `budgets.sh` is the list it reads.

CI runs `size` on every PR (`lint.yml`) and `startup` nightly (`nightly-e2e.yml`), never timings on PRs. `tracked` in `budgets.json` holds the CI test-suite duration for reference. No check reads it.

## Cleanup

```bash
.claude/skills/verify/scripts/cleanup.sh [--force]
```

This removes `bin/verify/sandbox/`, after making Go's read-only module cache writable first. It stops only the API stubs that drives recorded in `stub.pid`, checked against `/proc/<pid>/cmdline`, and never kills by process name. It refuses while a drive holds a lock unless you pass `--force`. It keeps `bin/verify/evidence/`, the binary and `state.env`, and lists the verdicts that survived. Run it after a failed or interrupted iteration too.

## Helpers

All helpers live in `scripts/`:

- `lib.sh`: sourced by the other scripts. It holds the paths, `sandbox_env`, `guard_args`, `cf`, `expect`, `expect_jq` and `error_code`.
- `drive/<feature-id>.sh`: one driver per feature file, sourced by `run.sh`.
- `api-stub.py`: the local component-findings endpoint for `cbom`, serving synthetic data only.
- `budgets.sh`: the budget checker (see "Budgets" above).

To add a feature, write `features/<id>.md` and `scripts/drive/<id>.sh` (a `drive` function). Then run it until it passes, and break it once to watch it fail.

Keep the map honest as the CLI changes with `/maintain-verification-skill`.

## The map in pull requests

Each feature file's `## Code paths` globs tie a diff to the features it touches. Every PR body names each touched feature under `## Evidence`, as `<id>: <evidence>` (the `VERDICT` line and evidence path of `run.sh <id>`, or a link to them) or `<id>: N/A: <reason>`. Two commands enforce this, and the `PR hygiene` workflow runs both:

```bash
go run ./scripts/featuremap check-docs        # sections, live globs, index matches the files
go run ./scripts/featuremap check-pr --base origin/main --head HEAD --body-file body.md
```

Evidence stays on the PR. Never commit `bin/verify/evidence/` to the tree. See "How the map is checked" in [`features/README.md`](features/README.md) for the glob rules and how to replay them.

## Post-merge QA

After every merge to `main`, `.github/workflows/post-merge-qa.yml` runs this skill with an agent. `go run ./scripts/featuremap select --base <merge>^1 --head <merge>` picks the features the merge touched, with the same globs `check-pr` uses (at most `QA_MAX_FEATURES`, default 5; the rest are named in the report). A merge that touches none stops there. Otherwise the job runs `build.sh` and `doctor.sh`, and hands `.github/post-merge-qa.md` to `claude -p`. The agent drives each feature with `bash .claude/skills/verify/scripts/run.sh <id>`, reads its evidence, and answers `pass`, `fail` or `unreachable` per feature. It may run only these scripts and read-only commands, and write only under `bin/verify/evidence/` and `/tmp`. A second job comments the verdict table on the merged PR, edited in place on a re-run, and opens an issue on a `fail`. No verdict (turn cap, crash, malformed output) turns that job red. The evidence is uploaded as the `post-merge-qa-evidence` artifact.

QA is off, with a notice, until the repository has the `CLAUDE_CODE_OAUTH_TOKEN` secret. To replay a merged PR, run the workflow by hand with its number. To reproduce the agent's view locally, run `run.sh` for the features `select` prints; the agent sees nothing else.
