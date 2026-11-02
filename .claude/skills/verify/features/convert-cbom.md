# Convert findings to a CBOM

`crypto-finder convert` turns an interim findings report into a CycloneDX 1.7 Cryptography Bill of Materials. It validates the result against the embedded CycloneDX 1.7 schema and refuses to write an invalid one, so exit 0 means the schema accepted it. `scan --format cyclonedx` does the same in one step.

## Sub-features

- `convert-file` converts `findings.json` to `--output cbom.json`.
- `convert-stdin` converts from stdin (`convert < findings.json`) to stdout.
- `scan-cyclonedx` writes a CBOM directly with `scan --format cyclonedx`.
- `convert-invalid` makes input that is not a report exit 1 with a JSON error, and writes no CBOM.

## How to get to it (user POV)

- `crypto-finder convert findings.json --output cbom.json`
- `crypto-finder scan ... | crypto-finder convert` or `crypto-finder convert < findings.json`
- `crypto-finder scan --format cyclonedx --output cbom.json ...`

## Driving it with run.sh

Preconditions:

- `doctor.sh` is clean.
- Fixture `testdata/projects/transitive_reachability/go/app` (SHA-256 and MD5) with `testdata/rules/transitive-reachability.yaml`. The rules carry `assetType`/`algorithmName` metadata, so both assets map.

- **Drive it.** Run `.claude/skills/verify/scripts/run.sh convert-cbom`. It exits 0, and `evidence/convert-cbom/verdict.txt` reads `VERDICT: PASS`.
- **Scan first.** `scan ... --output findings.json app/` exits 0.
- **File to file.** `convert findings.json --output cbom.json` exits 0. `cbom.json` has `bomFormat: CycloneDX` and `specVersion: 1.7`. Its `cryptographic-asset` components with `cryptoProperties.assetType: algorithm` are named `MD5,SHA-256`, and every one has `evidence.occurrences`.
- **Stdin to stdout.** `convert` with `findings.json` on stdin exits 0, and `convert-stdin.stdout` passes the same checks.
- **Direct CBOM.** `scan --format cyclonedx --output scan-cbom.json app/` exits 0 and passes the same checks.
- **Invalid input.** `convert broken.json` (truncated JSON) exits 1. The JSON error message starts `failed to parse interim JSON`, and no `cbom-broken.json` is written.

## Gotchas

- "Strict mapping": an asset whose rule metadata is incomplete is left out of the CBOM, without an error. A CBOM with fewer components than the report has assets is not automatically a bug. Check the rule metadata first.
- The invalid-input error code is `unknown_error` with stage `unknown` today: `convert` does not type its parse failure. The driver asserts the message, not the code. If that changes, update this note and the check.
- No separate validation command exists. Schema validation happens inside `convert`/`--format cyclonedx` (`internal/converter/validator.go`), so a written CBOM is a validated one.

## Code paths

- `internal/cli/convert.go`
- `internal/converter/**`
- `internal/output/cyclonedx.go`
- `internal/oid/**`
