# Scan

`crypto-finder scan` runs OpenGrep with the given rules over a target directory and reports every cryptographic operation it finds. It writes an interim findings JSON to `--output` or to stdout, and exits non-zero on failure or, with `--fail-on-findings`, when anything was found.

## Sub-features

- `scan-output` writes the findings report to `--output`.
- `scan-stdout` prints the same report to stdout when `--output` is omitted.
- `scan-fail-on-findings` exits 1 with code `findings_detected` when there are findings, and still writes the report.
- `scan-fail-on-findings-clean` exits 0 with an empty report when the target has no crypto.
- `scan-bad-target` makes a missing target a typed `invalid_arguments` failure, exit 1.

## How to get to it (user POV)

- `crypto-finder scan --no-remote-rules --rules <rule.yaml> [--languages go] [--output findings.json] <target>`
- `crypto-finder scan ... --fail-on-findings <target>` in CI.
- `--error-format json` turns any failure into one JSON object on stderr.

## Driving it with run.sh

Preconditions:

- `doctor.sh` is clean and `opengrep` is present.
- Fixture `testdata/projects/transitive_reachability/go`: `app/main.go:18` has `sha256.Sum256` and `app/main.go:22` has `md5.Sum`. `liba/` has no crypto.
- Rules: `testdata/rules/transitive-reachability.yaml`.

- **Drive it.** Run `.claude/skills/verify/scripts/run.sh scan`. It exits 0, and `bin/verify/evidence/scan/verdict.txt` reads `VERDICT: PASS`.
- **Report to file.** The driver runs `scan --scanner opengrep --no-remote-rules --findings-cache none --languages go --rules .../transitive-reachability.yaml --output findings.json app/`. The scan exits 0. `findings.json` has `tool.name == "crypto-finder"` and assets `18:go.transitive-reachability.sha256` and `22:go.transitive-reachability.md5` in `main.go`, all with `source: "direct"`. The SHA-256 asset metadata reads `algorithmName: SHA-256, assetType: algorithm`.
- **Report to stdout.** The same scan without `--output` exits 0, and `scan-stdout.stdout` parses with 2 assets.
- **Fail on findings.** The same scan with `--fail-on-findings` exits 1. The last stderr line has `code: findings_detected`, and `findings-fail.json` still holds 2 assets.
- **Clean target.** `--fail-on-findings` on `liba/` exits 0, and `findings-clean.json` holds 0 assets.
- **Bad target.** A non-existent target exits 1 with `code: invalid_arguments`.
- **Proof.** Keep `verdict.txt`, `transcript.txt` (each command with its exit code), `findings*.json`, and `*.stderr`.

## Gotchas

- The primary scan honours the `.gitignore` of the git repository that contains the target. This checkout ignores `bin/`, so a fixture copied under `bin/verify/` with no repository of its own reports only dependency findings, and every application finding silently disappears. `copy_fixture` runs `git init` in `work/` for this reason. Keep that in place for any new driver.
- `finding_id` is `null` in the findings report unless the same scan also exports a call graph (`--export-callgraph`). Do not assert on it in a plain scan.
- `opengrep` dies with exit 2 (the CLI reports `scanner_initialization_failed`) when `XDG_CONFIG_HOME` points at a missing directory. `begin_drive` creates it. A hand-made sandbox must create it too.
- With `--error-format json`, stderr holds log lines before the error object. Read the last line that starts with `{` (`error_code` in `lib.sh`).
- A fresh `HOME` means OpenGrep re-extracts itself into the sandbox cache on every drive, which costs a few seconds. That cost is expected and is not a hang.

## Code paths

- `cmd/crypto-finder/*.go`
- `internal/cli/root.go`
- `internal/cli/scan.go`
- `internal/cli/scan_profile.go`
- `internal/cli/detect_scope.go`
- `internal/cli/opengrep_modes.go`
- `internal/cli/opengrep_probe_cache.go`
- `internal/cli/scanner_jobs.go`
- `internal/engine/orchestrator.go`
- `internal/engine/processor.go`
- `internal/engine/rule_filter.go`
- `internal/scanner/**`
- `internal/rules/**`
- `internal/skip/**`
- `internal/language/**`
- `internal/deduplicator/**`
- `internal/enricher/**`
- `internal/output/json.go`
- `internal/output/writer.go`
- `internal/output/factory.go`
- `pkg/schema/**`
