# Related material

When a scan builds a call graph, a random draw that a rule reports as a `drbg` algorithm also gets the related crypto material its value becomes: the drawn value is followed into the functions it is passed to until it reaches a contract parameter with a material role (a KDF salt, a cipher iv, an AEAD nonce). The scan then adds a `related-crypto-material` asset with that `materialType` at the draw line, with the draw's rule. A draw whose value is overwritten before it is used gets nothing.

## Sub-features

- `material-cross-function` reports the material at a draw whose value a helper passes to a KDF or cipher.
- `material-overwritten` reports no material for a draw whose value is reassigned or overwritten before use.
- `material-needs-callgraph` adds nothing in a scan that builds no call graph.
- `material-cbom` writes the material as CycloneDX `relatedCryptoMaterial` components.

## How to get to it (user POV)

- `crypto-finder scan --no-remote-rules --rules <rule.yaml> --export-callgraph callgraph.json --output findings.json <target>`
- `crypto-finder scan ... --scan-dependencies <target>`, or `--export-graph-fragment`, also builds the call graph.
- `crypto-finder scan ... --format cyclonedx --export-callgraph callgraph.json <target>` for the CBOM.

## Driving it with run.sh

Preconditions:

- `doctor.sh` is clean and `opengrep` is present; each language needs its toolchain (`doctor.sh` lists them).
- Fixture `testdata/projects/related_material/<lang>/app`: `seal` draws a salt and an iv (Go: a nonce) and hands them to helpers that call the KDF and the cipher; a second function draws a value and overwrites it before handing it on.
- Rules: `testdata/rules/related-material.yaml`, which report only the draws.

- **Drive it.** Run `.claude/skills/verify/scripts/run.sh related-material all` (or one of `go`, `python`, `rust`, `node`). It exits 0 and each `bin/verify/evidence/related-material/<lang>/verdict.txt` reads `VERDICT: PASS`.
- **Cross-function material.** The driver scans `app/` with `--export-callgraph`. `findings.json` holds `related-crypto-material` assets at exactly these lines: Python `19:salt,21:initialization-vector`, Go `31:salt,39:nonce`, Rust `17:salt,21:initialization-vector`, Node `13:salt,15:initialization-vector`. Each sits at its draw's span with the draw's rule, carries only `assetType` and `materialType`, and has a `finding_id`.
- **Overwritten value.** The overwritten draw (Python 27, Go 48, Rust 27, Node 20) has only its `algorithm` asset.
- **No call graph.** The same scan without `--export-callgraph` reports no related material.
- **CBOM.** `--format cyclonedx` writes components whose `relatedCryptoMaterialProperties.type` values are the materials above.
- **Proof.** Keep `verdict.txt`, `transcript.txt`, `findings.json`, `findings-plain.json` and `cbom.json`.

## Gotchas

- The material is added only when the scan builds a call graph (`--export-callgraph`, `--export-graph-fragment`, `--scan-dependencies`); a plain scan reports the draw alone.
- Java is not driven: its call graph export needs a JDK the sandbox does not provide. `internal/scan/related_material_test.go` covers Java with the real parser.
- A draw is followed only through plain variables and application functions the graph resolves exactly. A value passed through a field, a collection or an interface call reports no material.

## Code paths

- `internal/scan/related_material.go`
- `internal/callgraph/contracts/contracts.go`
