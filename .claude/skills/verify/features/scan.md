# Scan

`crypto-finder scan` matches the given rules' cards against the call graph of a target directory and reports every cryptographic operation it finds. It writes an interim findings JSON to `--output` or to stdout, and exits non-zero on failure or, with `--fail-on-findings`, when anything was found.

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

This feature has no drive in this version. The 0.54.0 drive (OpenGrep, non-Java fixtures) was removed. A new drive for this version is to be written against the cards engine.

## Gotchas

- The primary scan honours the `.gitignore` of the git repository that contains the target. This checkout ignores `bin/`, so a fixture copied under `bin/verify/` with no repository of its own reports only dependency findings, and every application finding silently disappears. A new drive must run `git init` in its sandbox `work/` directory for this reason.
- `finding_id` is `null` in the findings report unless the same scan also exports a call graph (`--export-callgraph`). Do not assert on it in a plain scan.
- With `--error-format json`, stderr holds log lines before the error object. Read the last line that starts with `{` (`error_code` in `lib.sh`).

## Code paths

- `cmd/crypto-finder/*.go`
- `internal/cli/root.go`
- `internal/cli/scan.go`
- `internal/cli/scan_profile.go`
- `internal/cli/scan_cards.go`
- `internal/engine/orchestrator.go`
- `internal/engine/processor.go`
- `internal/engine/rule_filter.go`
- `internal/scanner/**`
- `internal/rules/**`
- `internal/deduplicator/**`
- `internal/enricher/**`
- `internal/output/json.go`
- `internal/output/writer.go`
- `internal/output/factory.go`
- `pkg/schema/**`
