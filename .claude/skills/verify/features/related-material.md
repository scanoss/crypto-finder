# Related material

When a scan builds a call graph, a random draw that a rule reports as a `drbg` algorithm also gets the related crypto material its value becomes: the drawn value is followed into the functions it is passed to until it reaches a contract parameter with a material role (a KDF salt, a cipher iv, an AEAD nonce). The scan then adds a `related-crypto-material` asset with that `materialType` at the draw line, with the draw's rule. A draw whose value is overwritten before it is used gets nothing. A salt, nonce or iv written as a constant (a bytes or string literal, `Buffer.alloc(16)`) at such an argument, as the default of the parameter the call reads, or by a caller of that parameter, is reported at the constant with the crypto call's rule.

## Sub-features

- `material-cross-function` reports the material at a draw whose value a helper passes to a KDF or cipher.
- `material-overwritten` reports no material for a draw whose value is reassigned or overwritten before use.
- `material-needs-callgraph` adds nothing in a scan that builds no call graph.
- `material-cbom` writes the material as CycloneDX `relatedCryptoMaterial` components.
- `material-constant` reports a constant salt, nonce or iv at the constant, from a crypto call a rule reports.

## How to get to it (user POV)

- `crypto-finder scan --no-remote-rules --rules <rule.yaml> --export-callgraph callgraph.json --output findings.json <target>`
- `crypto-finder scan ... --scan-dependencies <target>`, or `--export-graph-fragment`, also builds the call graph.
- `crypto-finder scan ... --format cyclonedx --export-callgraph callgraph.json <target>` for the CBOM.

## Driving it with run.sh

This feature has no drive in this version. The 0.54.0 drive (OpenGrep, non-Java fixtures) was removed. A new drive for this version is to be written against the cards engine.

## Gotchas

- The material is added only when the scan builds a call graph (`--export-callgraph`, `--export-graph-fragment`, `--scan-dependencies`); a plain scan reports the draw alone.
- `internal/scan/related_material_test.go` covers Java with the real parser.
- `material-constant` needs a rule that reports the crypto call a constant reaches, not only the draw. `internal/scan/literal_material_test.go` covers Python and Node with the real parsers.
- A draw is followed only through plain variables and application functions the graph resolves exactly. A value passed through a field, a collection or an interface call reports no material.

## Code paths

- `internal/scan/related_material.go`
- `internal/scan/literal_material.go`
- `internal/cryptokb/**`
