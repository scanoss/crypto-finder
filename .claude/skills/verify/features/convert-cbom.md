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

This feature has no drive in this version. The 0.54.0 drive (OpenGrep, non-Java fixtures) was removed. A new drive for this version is to be written against the cards engine.

## Gotchas

- "Strict mapping": an asset whose rule metadata is incomplete is left out of the CBOM, without an error. A CBOM with fewer components than the report has assets is not automatically a bug. Check the rule metadata first.
- Malformed or missing input fails with `invalid_arguments` at stage `input` (exit 1), like `cbom` does for an unreadable SBOM. Other `convert` failures (writer, conversion) are still untyped.
- No separate validation command exists. Schema validation happens inside `convert`/`--format cyclonedx` (`internal/converter/validator.go`), so a written CBOM is a validated one.

## Code paths

- `internal/cli/convert.go`
- `internal/converter/**`
- `internal/output/cyclonedx.go`
- `internal/oid/**`
