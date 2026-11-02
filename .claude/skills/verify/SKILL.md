---
name: verify
description: Drive the crypto-finder CLI (cmd/crypto-finder) the way a user does and capture proof - scan with synthetic local rules, intra-project and dependency (direct and transitive) reachability, callgraph and graph-fragment exports, convert to CycloneDX 1.7 CBOM, and cbom from an SBOM against a local API stub. Use it to confirm a change works in the real binary, not just in go test, and before claiming a user-facing behavior is fixed or shipped.
---

# Verify crypto-finder

crypto-finder is a short-lived CLI, so there is no server to keep alive. "Launch" builds the binary once; every drive runs it in a fresh sandbox, asserts on the files it writes and its exit codes, and leaves evidence behind. Each drive follows a recipe in [`features/`](features/README.md). Read the index before picking one.

Everything lives under `bin/verify/` in this checkout, which `.gitignore` already covers through `bin/`. Two checkouts never share a binary, a sandbox, or evidence.

```
bin/verify/crypto-finder                   binary built by build.sh
bin/verify/state.env                       HEAD, Go-source fingerprint, `crypto-finder version` line
bin/verify/sandbox/<feature>[-<lang>]/     HOME, XDG dirs, venv, fixture copy (cleanup.sh removes it)
bin/verify/evidence/<feature>/[<lang>/]    transcript, JSON outputs, verdict.txt (cleanup.sh keeps it)
```

## Isolation rules (non-negotiable)

The production detection rules are private and are the company's core value. Never fetch them, reference them, or point a drive at them. Never use a real API key.

- Every drive runs the binary through `env -i`, with a fresh `HOME`, `XDG_CACHE_HOME`, `XDG_CONFIG_HOME` and `TMPDIR` under its sandbox. No `SCANOSS_*`, `SC_*` or `VIRTUAL_ENV` variable from your shell gets through. Only `PATH`, `LANG` and `RUSTUP_HOME` are kept. `GOPROXY=off`, `GOTOOLCHAIN=local` and `CARGO_NET_OFFLINE=true` keep the toolchains offline.
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
- `opengrep`, `jq`, `git` or `realpath` is missing;
- a stale drive lock exists;
- a sandbox holds a remote ruleset.

It also reports the following:

- which languages are ready (`go`, `python` needs `python3 -m venv`, `rust` needs `cargo` plus a rustup dir, `node` needs nothing);
- that `java` is not driven, because Maven resolution needs the real `~/.m2`;
- which API variables are set in your shell (they are stripped anyway);
- the last verdict of every evidence directory.

Run it first, and again whenever a drive surprises you.

## Drive

```bash
.claude/skills/verify/scripts/run.sh <feature-id> [lang|all]
```

| feature-id | lang | what it proves |
| --- | --- | --- |
| `scan` | - | findings JSON, stdout output, `--fail-on-findings` exit codes, typed failure on a bad target |
| `reachability-project` | `go` (default), `python`, `all` | `--export-callgraph-project-reachability` verdicts match a `--scan-dependencies` run for first-party findings |
| `reachability-dependencies` | `go` (default), `python`, `node`, `rust`, `all` | app -> liba (no crypto) -> libb (crypto): used hash `reachable` with chain app>liba>libb and `transitive` attribution, unused hash `unreachable` |
| `convert-cbom` | - | `convert` (file and stdin) and `scan --format cyclonedx` produce CycloneDX 1.7 CBOMs that passed the embedded schema |
| `cbom-from-sbom` | - | `cbom` from CycloneDX and SPDX SBOMs against `scripts/api-stub.py` on 127.0.0.1 |
| `callgraph-export` | - | `--export-callgraph` schema 6.18 and 6.14, chains, `--export-callgraph-max-chains`, `--export-callgraph-entry-points`, `--export-graph-fragment` |

`all` drives every language whose toolchain is present and prints `SKIP <feature> <lang>` for the rest. A skipped language is not verified. Report it as skipped.

`run.sh` exits with one of these codes:

- 0 when `verdict.txt` reads `VERDICT: PASS`;
- 1 when any check failed;
- 2 when the drive refused to run (no binary, isolation guard, unknown feature, a lock held by another drive of the same feature and language).

The drive prints the verdict and the evidence path.

Fixtures are copied from `testdata/projects/` into the sandbox before every drive, and wired as the CLI integration tests wire them (see each driver's header). Set `VERIFY_FIXTURES=<dir>` to drive a different tree with the same layout, such as a temp copy with a fixture deliberately broken. Never edit `testdata/` to provoke a failure.

```bash
tmp=$(mktemp -d) && cp -R testdata/projects/. "$tmp"/
# make libb's used hash dead code: liba.Used stops calling it
sed -i 's/return translibb.UsedHash(data)/return data/' "$tmp"/transitive_reachability/go/liba/liba.go
VERIFY_FIXTURES=$tmp .claude/skills/verify/scripts/run.sh reachability-dependencies go   # exits 1, verdict FAIL
```

## Evidence

Each drive replaces `bin/verify/evidence/<feature>/[<lang>/]` with these files:

- `transcript.txt` holds the binary version, HEAD, fixture source, sandbox, and every `crypto-finder ...` command with its exit code;
- `<step>.stdout` and `<step>.stderr` hold each invocation's raw output (with `--error-format json`, the last JSON line of stderr is the typed error);
- the JSON the binary wrote: `findings.json`, `callgraph.json`, `graph-fragment.json`, `cbom.json`, and so on;
- `verdicts.json` (reachability drives) joins findings and the call graph into one row per finding: module, file, line, source, reachability, relationship, dependency path, and chains as module lists;
- `verdict.txt` opens with a first line `VERDICT: PASS|FAIL (n passed, m failed)`, then one `PASS`/`FAIL` line per check, derived with `jq` from the files above.

Proof standards:

- Drive the real binary through its real flags. Assert on output files, exit codes and stderr codes, never on internal setters or test hooks.
- A reachability claim needs the verdict row and the chain, not only "exit 0". Quote the `verdict.txt` lines.
- `cbom` talks to a local stub because the real API is an external system behind a production HTTP boundary. Its evidence includes `api-requests.jsonl`, the requests the binary actually sent.
- A feature map entry lists sub-features. Driving one entry point does not verify the others.

## Cleanup

```bash
.claude/skills/verify/scripts/cleanup.sh [--force]
```

This removes `bin/verify/sandbox/`, after making Go's read-only module cache writable first. It stops only the API stubs that drives recorded in `stub.pid`, checked against `/proc/<pid>/cmdline`, and never kills by process name. It refuses while a drive holds a lock unless you pass `--force`. It keeps `bin/verify/evidence/`, the binary and `state.env`, and lists the verdicts that survived. Run it after a failed or interrupted iteration too.

## Helpers

All helpers live in `scripts/`:

- `lib.sh`: sourced by the other scripts. It holds the paths, `sandbox_env`, `guard_args`, `cf`, fixture wiring, `expect` and `expect_jq`.
- `drive/<feature-id>.sh`: one driver per feature file, sourced by `run.sh`.
- `verdicts.jq` and `check-findings.jq`: the reachability join and its expectations.
- `api-stub.py`: the local component-findings endpoint for `cbom`, serving synthetic data only.

To add a feature, write `features/<id>.md` and `scripts/drive/<id>.sh` (a `drive` function, plus `LANGS`/`DEFAULT_LANG` if it is per language). Then run it until it passes, and break it once to watch it fail.

Keep the map honest as the CLI changes with `/maintain-verification-skill`.

## The map in pull requests

Each feature file's `## Code paths` globs tie a diff to the features it touches. Every PR body names each touched feature under `## Evidence`, as `<id>: <evidence>` (the `VERDICT` line and evidence path of `run.sh <id>`, or a link to them) or `<id>: N/A: <reason>`. Two commands enforce this, and the `PR hygiene` workflow runs both:

```bash
go run ./scripts/featuremap check-docs        # sections, live globs, index matches the files
go run ./scripts/featuremap check-pr --base origin/main --head HEAD --body-file body.md
```

Evidence stays on the PR. Never commit `bin/verify/evidence/` to the tree. See "How the map is checked" in [`features/README.md`](features/README.md) for the glob rules and how to replay them.

## Post-merge QA

After every merge to `main`, `.github/workflows/post-merge-qa.yml` runs this skill with an agent. `go run ./scripts/featuremap select --base <merge>^1 --head <merge>` picks the features the merge touched, with the same globs `check-pr` uses (at most `QA_MAX_FEATURES`, default 5; the rest are named in the report). A merge that touches none stops there. Otherwise the job installs opengrep, runs `build.sh` and `doctor.sh`, and hands `.github/post-merge-qa.md` to `claude -p`. The agent drives each feature with `bash .claude/skills/verify/scripts/run.sh <id> [lang]`, reads its evidence, and answers `pass`, `fail` or `unreachable` per feature. It may run only these scripts and read-only commands, and write only under `bin/verify/evidence/` and `/tmp`. A second job comments the verdict table on the merged PR, edited in place on a re-run, and opens an issue on a `fail`. No verdict (turn cap, crash, malformed output) turns that job red. The evidence is uploaded as the `post-merge-qa-evidence` artifact.

QA is off, with a notice, until the repository has the `CLAUDE_CODE_OAUTH_TOKEN` secret. To replay a merged PR, run the workflow by hand with its number. To reproduce the agent's view locally, run `run.sh` for the features `select` prints; the agent sees nothing else.
