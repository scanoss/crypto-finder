# CBOM from an SBOM

`crypto-finder cbom <sbom>` builds a CycloneDX 1.7 CBOM for the components an SBOM lists, without scanning anything locally. For every component with a package URL and a version, it asks the SCANOSS API for the findings SCANOSS mined for that component, converts them exactly as `convert` does, and makes each component that uses cryptography a library whose dependencies are its crypto assets. A per-status summary goes to stderr.

**It needs the SCANOSS API.** The driver never contacts the real API and never uses a real key. It starts `scripts/api-stub.py` on `127.0.0.1` and passes `--api-url http://127.0.0.1:<port> --api-key verify-stub-key`. The stub serves synthetic findings in the shape `internal/cli/cbom_test.go` uses. `guard_args` refuses `cbom` with any other URL. Requests the binary actually sent are logged to `api-requests.jsonl`.

## Sub-features

- `cbom-cyclonedx` builds a CBOM from a CycloneDX JSON SBOM: crypto components become libraries with `dependsOn` assets.
- `cbom-statuses` gives every component a stderr summary status: `crypto`, `no crypto`, `not mined`, `unsupported` (no version) or `failed`.
- `cbom-spdx-stdin` reads SPDX tag-value from stdin (`cbom -`).
- `cbom-not-sbom` makes a document that is not an SBOM exit 1 with `invalid_arguments` before any API request.

## How to get to it (user POV)

- `crypto-finder cbom sbom.cdx.json --output cbom.json` (with an API key configured)
- `syft dir:. -o cyclonedx-json | crypto-finder cbom - > cbom.json`
- Flags: `--api-key`, `--api-url`, `--max-components` (default 2000), `--output`.

## Driving it with run.sh

Preconditions:

- `doctor.sh` is clean, and `python3` is present for the stub.
- The stub answers `POST /v3/cryptography/reachability/component` as follows:
  - `pkg:npm/node-forge`: an AES finding (READY);
  - `pkg:npm/left-pad`: READY with no findings;
  - anything else: `COMPONENT_NOT_FOUND`.

- **Drive it.** Run `.claude/skills/verify/scripts/run.sh cbom-from-sbom`. It exits 0, and `evidence/cbom-from-sbom/verdict.txt` reads `VERDICT: PASS`.
- **CycloneDX SBOM.** The driver runs `cbom sbom.cdx.json --output cbom.json --api-url <stub> --api-key verify-stub-key`. The SBOM lists node-forge 1.3.1, left-pad 1.3.0, unmined 9.9.9, and no-version with no version. The command exits 0. `cbom.json` is CycloneDX `1.7`, its `dependencies[].ref` holds only `pkg:npm/node-forge@1.3.1`, and that ref's `dependsOn` reaches a component named `AES`. `metadata.component.name` is `verify-app`.
- **What was asked.** `api-requests.jsonl` holds exactly the purls `pkg:npm/left-pad,pkg:npm/node-forge,pkg:npm/unmined`, all sent to the component endpoint with an `x-api-key` header. The version-less component is never looked up.
- **Summary.** stderr reads `crypto 1, no crypto 1, not mined 1, unsupported 1, failed 0`.
- **SPDX on stdin.** `cbom -` with an SPDX tag-value document for node-forge exits 0, and stdout's CBOM depends on `pkg:npm/node-forge@1.3.1`.
- **Not an SBOM.** `cbom not-sbom.json` (`{"name":"package.json"}`) exits 1 with `code: invalid_arguments`, and the stub log gains no request.
- **Teardown.** The drive's EXIT trap kills the stub by the pid recorded in `sandbox/cbom-from-sbom/stub.pid`. `cleanup.sh` stops a stranded one by that pid.

## Gotchas

- This drive proves the CLI's handling of API answers, not what the real API serves. A claim about mined data for a real package needs the real service, and that is out of scope for this skill.
- `--api-url` is a base URL: the CLI appends `/v3/cryptography/reachability/component`. A trailing slash is trimmed.
- A refused key (HTTP 401/403) stops the whole run with `component_lookup_failed`. Other per-component errors only mark that component `failed`.

## Code paths

- `internal/cli/cbom.go`
- `pkg/sbomcbom/**`
- `internal/api/component_findings.go`
- `internal/api/client.go`
