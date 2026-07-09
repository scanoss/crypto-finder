# Output Formats

Crypto Finder supports two output formats: an interim JSON format for detailed analysis and CycloneDX CBOM format for standardized Bill of Materials reporting.

## Interim JSON Format

The default output format containing detailed cryptographic asset information optimized for the SCANOSS ecosystem.

The interim report is the primary findings artifact. It contains finding metadata such as `finding_id`, but it does not currently embed the finding-centric reachability slices produced by `--export-callgraph`.

### Format Specification

```json
{
  "version": "1.4",
  "tool": {
    "name": "crypto-finder",
    "version": "0.1.0"
  },
  "findings": [
    {
      "file_path": "path/to/file",
      "language": "language_name",
      "cryptographic_assets": [
        {
          "start_line": 123,
          "end_line": 123,
          "match": "code snippet",
          "rules": [
            {
              "id": "rule.id",
              "message": "description",
              "severity": "INFO|WARNING|ERROR"
            }
          ],
          "status": "pending|identified|dismissed|reviewed",
          "metadata": {
            "assetType": "algorithm|certificate|protocol|related-crypto-material",
            "algorithmFamily": "algorithm_family",
            "algorithmPrimitive": "primitive_type",
            "algorithmMode": "mode_of_operation",
            "algorithmPadding": "padding_scheme"
          },
          "source": "direct|dependency",
          "dependency_info": {
            "module": "golang.org/x/crypto",
            "version": "v0.17.0"
          },
          "finding_id": "a1b2c3d4"
        }
      ]
    }
  ]
}
```

> **Note:** Version 1.1 introduced the `rules` array field (replacing single `rule` field) to support per-line deduplication. Version 1.2 added `source` and `dependency_info` for dependency scanning attribution. Version 1.3 adds `finding_id` for cross-referencing with the callgraph export. Dependency-backed `file_path` values are dependency-root-relative; the package identity stays in `dependency_info`. Reachability slices such as `call_chains` are emitted by the dedicated call graph export, not by the interim report. See [Dependency Scanning](DEPENDENCY_SCANNING.md) for details.

### Field Descriptions

| Field | Description |
|-------|-------------|
| `version` | Format version (currently "1.4") |
| `tool.name` | Scanner used (crypto-finder) |
| `tool.version` | Scanner version |
| `findings` | Array of file-level findings |
| `file_path` | Relative path to scanned file |
| `language` | Detected programming language |
| `cryptographic_assets` | Array of crypto findings in the file |
| `start_line` | First line where the asset was detected |
| `end_line` | Last line where the asset was detected |
| `match` | Actual code snippet matched |
| `rules` | Array of detection rules that identified this asset |
| `rules[].id` | Unique rule identifier |
| `rules[].message` | Human-readable description |
| `rules[].severity` | Finding severity level |
| `status` | Finding status (pending, identified, dismissed, reviewed) |
| `metadata` | Key-value pairs with asset-specific metadata |
| `metadata.assetType` | Asset classification |
| `metadata.algorithmFamily` | Algorithm/protocol family name |
| `metadata.algorithmPrimitive` | Cryptographic primitive type |
| `metadata.algorithmMode` | Mode of operation (for block ciphers) |
| `metadata.algorithmPadding` | Padding scheme used |
| `source` | `"direct"` (user code) or `"dependency"` (v1.2+) |
| `dependency_info` | Attribution for dependency findings: `module`, `version` (v1.2+) |
| `finding_id` | Stable short hash used to join the interim report to the call graph export (v1.3+) |
| `parameter_conditions` | Structured argument predicates parsed from the rule's `parameterCondition` metadata — which argument value/type selects this asset variant (v1.4+, omitted when the rule carries no predicate) |
| `file_path` | For dependency findings, path relative to the dependency root; use `dependency_info` for artifact identity |

### Call Graph Export

When `--export-callgraph` is enabled, Crypto Finder also writes a separate finding-centric call graph JSON file. This export contains the reachability slices and value-flow details associated with findings from the interim report.

Schema note: call graph export version `6.0` is the current customer-facing reachability contract. It removes the legacy `entry_point_index` projection and makes `crypto_entry_points[]` canonical. Version `4.3` added Java runtime provenance in `scan_metadata` for JDK-aware platform signature enrichment.

- Each top-level record stays keyed by `finding_id`, which is the join key back to the interim report.
- `call_chains` is the primary value-flow structure. Each chain is ordered from the first reachable caller to the function that contains the matched crypto call.
- Each chain node contains a fully qualified `function_name`, a normalized `file_path`, `start_line`, optional `dependency_info`, and optional `entry_call`.
- `entry_call` describes how execution entered the current node from the previous step. Its `file_path` and `line` refer to the call site in the previous node's source file.
- The last node in each chain carries `crypto_call`, which is the matched crypto-relevant call for the finding.
- `entry_call.parameters[]` and `crypto_call.parameters[]` both use the same parameter model: `parameter_index` (always `0`-based), best-effort `type`, `argument_expression`, `resolved_value`, `variable_name` for simple identifiers only, and recursive `source_nodes`.
- For Java scans, `scan_metadata` may also include `java_requested_jdk_major`, `java_runtime_version`, `java_platform_signatures_used`, `java_platform_signature_source`, and `java_platform_signature_unavailable_reason` to show which JDK major was requested and whether JDK platform signatures contributed to type enrichment.
- `source_nodes` can span multiple wrapper hops. A local `PARAMETER` node may contain nested upstream provenance such as `PARAMETER -> PARAMETER -> VALUE`, and propagated nested nodes keep `location.file_path` plus `location.line` when known.
- Method-call provenance is preserved as `CALL_RESULT` nodes. When the parser can resolve the invoked method, the node also exports `call_target`, and any traceable receiver value is nested under that `CALL_RESULT` via `source_nodes` (for example `CALL_RESULT -> PARAMETER alg -> VALUE SignatureAlgorithm.HS256`).
- Findings missing a containing function or crypto-call match are still exported with `finding_location` and `unresolved_reason`.
- `crypto_entry_points[]` is the stitch/API index. Each entry carries `function_key`, canonical/display symbols, aliases, and `reachable_findings[]` / `reachable_supporting_calls[]`.
- `supporting_calls[]` carries config/lifecycle/context crypto-adjacent calls, such as builder options or parameter setup. These calls are not findings and do not inflate `finding_graphs[]`.
- Constructor joins remain canonical (`<init>`), while display fields and aliases expose IBM-style names such as `com.acme.Factory.Factory`.
- `entry_point_index` is not emitted by schema `6.0`. Consumers should migrate to `crypto_entry_points[]`.

Example:

```json
{
  "finding_id": "69669f02",
  "call_chains": [
    [
      {
        "function_name": "io.jsonwebtoken.jjwtfun.controller.SecretsController.traceToken",
        "file_path": "src/main/java/io/jsonwebtoken/jjwtfun/controller/SecretsController.java",
        "start_line": 33
      },
      {
        "function_name": "io.jsonwebtoken.jjwtfun.service.SecretService.issueTraceToken",
        "file_path": "src/main/java/io/jsonwebtoken/jjwtfun/service/SecretService.java",
        "start_line": 72,
        "entry_call": {
          "file_path": "src/main/java/io/jsonwebtoken/jjwtfun/controller/SecretsController.java",
          "line": 34,
          "parameters": [
            {
              "parameter_index": 0,
              "type": "io.jsonwebtoken.SignatureAlgorithm",
              "argument_expression": "SignatureAlgorithm.HS256",
              "resolved_value": "SignatureAlgorithm.HS256"
            }
          ]
        }
      },
      {
        "function_name": "org.springframework.security.core.token.Sha512DigestUtils.getSha512Digest",
        "file_path": "org/springframework/security/core/token/Sha512DigestUtils.java",
        "start_line": 43,
        "dependency_info": {
          "module": "org.springframework.security:spring-security-core",
          "version": "5.7.11"
        },
        "crypto_call": {
          "function_name": "java.security.MessageDigest.getInstance",
          "line": 45,
          "parameters": [
            {
              "parameter_index": 0,
              "type": "String",
              "argument_expression": "\"SHA-512\"",
              "resolved_value": "\"SHA-512\""
            }
          ]
        }
      }
    ]
  ]
}
```

### Example Output

**Single Rule Detection:**
```json
{
  "version": "1.1",
  "tool": {
    "name": "crypto-finder",
    "version": "0.1.0"
  },
  "findings": [
    {
      "file_path": "src/crypto/Example.java",
      "language": "java",
      "cryptographic_assets": [
        {
          "start_line": 29,
          "end_line": 29,
          "match": "cipher = Cipher.getInstance(\"AES/CBC/PKCS5Padding\");",
          "rules": [
            {
              "id": "java.crypto.cipher-aes-cbc",
              "message": "AES cipher usage detected",
              "severity": "INFO"
            }
          ],
          "status": "pending",
          "metadata": {
            "assetType": "algorithm",
            "algorithmFamily": "AES",
            "algorithmPrimitive": "block-cipher",
            "algorithmMode": "CBC",
            "algorithmPadding": "PKCS5Padding"
          }
        }
      ],
    }
  ]
}
```

**Multiple Rules Detection (Deduplicated):**
```json
{
  "version": "1.1",
  "tool": {
    "name": "crypto-finder",
    "version": "0.1.0"
  },
  "findings": [
    {
      "file_path": "src/crypto/cipher.go",
      "language": "go",
      "cryptographic_assets": [
        {
          "start_line": 42,
          "end_line": 42,
          "match": "cipher.NewGCM(block)",
          "rules": [
            {
              "id": "go-crypto-aes-gcm",
              "message": "AES-GCM encryption detected",
              "severity": "INFO"
            },
            {
              "id": "go-crypto-authenticated-encryption",
              "message": "Authenticated encryption pattern detected",
              "severity": "INFO"
            }
          ],
          "status": "pending",
          "metadata": {
            "assetType": "algorithm",
            "algorithmFamily": "AES",
            "algorithmPrimitive": "ae",
            "algorithmParameterSetIdentifier": "256",
            "algorithmMode": "GCM"
          }
        }
      ],
    }
  ]
}
```

### Use Cases

- Integration with SCANOSS platform
- Custom analysis pipelines
- Detailed cryptographic asset tracking
- Security auditing and compliance

## Graph Fragment Export

When `--export-graph-fragment <file>` is enabled, Crypto Finder writes a
**reusable structural graph fragment** for the scanned component: its call
graph plus rules-versioned crypto annotations. Unlike the finding-centric call
graph export (above), a fragment is designed to be composed with other fragments
across a dependency tree to answer "what crypto is transitively reachable from
artifact X?" The pure model and the stitcher that composes fragments live in the
public package `github.com/scanoss/crypto-finder/pkg/graphfrag`, so downstream
consumers can use one contract instead of reimplementing schema knowledge.

Current schema version: `graph-fragment-1.3`.

As of `graph-fragment-1.3`, a fragment is **self-contained enough to reconstruct
the two artifacts a live `--scan-dependencies` run would produce** — see
*Rendered artifacts* below.

### Structure

| Field | Description |
|-------|-------------|
| `schema_version` | Fragment schema version (currently `graph-fragment-1.3`). |
| `scan_metadata` | Ecosystem, root module, tool/rules versions, `graph_algo_version` (callgraph-construction algorithm version; cache key for annotate-only re-annotation), and per-array counts. |
| `functions[]` | Callable nodes. `key` is the stable function identity (`pkg.(Type).name#arity`); also carries `file_path`, `package`, `type`, `name`, signature, etc. |
| `internal_edges[]` | Caller→callee edges **within** the component (both functions are in this fragment). Each edge may carry `entry_call` (1.2+, see below). |
| `external_calls[]` | Calls whose target may live in **another** component; resolved at stitch time against the dependency tree. Each edge may carry `entry_call` (1.2+, see below). |
| `crypto_annotations[]` | Terminal crypto findings attached to a function. Beyond `function_key`/`finding_id`/`rule_id`/`symbol`, a 1.2+ annotation carries the data-flow and metadata needed to reconstruct a findings entry (see *Crypto annotation fields (1.2+)* below). A component with no crypto still emits a fragment (zero `crypto_annotations`) so it can serve as a bridge in transitive chains. |
| `supporting_calls[]` | Non-finding config/lifecycle/context calls useful for explaining crypto behavior without increasing finding counts. |
| `crypto_entry_points[]` | Canonical reachability index: API functions plus display aliases and links to reachable findings/supporting calls. |

### Per-call data flow: `entry_call` (1.2+)

Every `internal_edges[]` and `external_calls[]` entry may carry an `entry_call`
describing the call-site argument data-flow for that edge — the same model the
finding-centric call graph export uses (see *Call Graph Export* above):
`entry_call.parameters[]` each have `parameter_index`, best-effort `type`,
`argument_expression`, `resolved_value`, `variable_name` (simple identifiers
only), and recursive `source_nodes` provenance. Carrying it **on the edge** is
what lets the stitcher rebuild full per-frame value flow when composing chains
across components, so a stitched chain matches a live run frame-for-frame.

### Crypto annotation fields (1.2+)

A `graph-fragment-1.2+` `crypto_annotations[]` entry carries enough to
reconstruct a full findings.json entry for the matched crypto call:

| Field | Description |
|-------|-------------|
| `crypto_call` | Identity and call-site argument data-flow of the matched crypto call (`function_name`, `line`, `parameters[]` — same parameter model as `entry_call`). |
| `oid` | Object Identifier for the cryptographic algorithm, when known. |
| `metadata` | Raw asset metadata block from the scanner. |
| `source` | How the finding was discovered: `direct` or `indirect`. |
| `matched_operation` | Kind / symbol / `expression` of the matched crypto operation. |
| `end_line` | Last source line of the crypto finding (often equal to its start line). |
| `match` / expression | The exact source expression that triggered the detection. |

### Rendered artifacts: `ToCallgraphExport` / `ToFindingsEnvelope`

Because a 1.3 fragment carries per-call data flow, full crypto-annotation,
supporting-call, and entrypoint metadata, `pkg/graphfrag` can render a stitched
`Result` into the same two artifacts a live `--scan-dependencies` run produces:

- **`Result.ToCallgraphExport(root, meta)`** — renders the stitched result into
  a schema-6.0 callgraph, equivalent to a live
  `--scan-dependencies --export-callgraph` run. Dep-component findings get
  `module@version/`-prefixed `finding_id`s, matching live output.
- **`ToFindingsEnvelope(root, deps, fragments, meta)`** — reconstructs the
  findings.json v1.3 envelope (asset metadata). Its `finding_id`s are computed
  with the **same inputs** as `ToCallgraphExport`, so the two agree: consumers
  join assets (envelope) to call chains (callgraph) by `finding_id`.

`pkg/graphfrag/equiv` is a semantic diff tool that asserts a stitched callgraph
equals a live one minus the chains intentionally dropped by resolution
suppression (see below) — the equivalence guarantee these renderers rely on.

### Edge resolution metadata (v1.1+)

Every `internal_edges[]` and `external_calls[]` entry carries **resolution
metadata** describing *how confidently* the edge was resolved. This lets a
consumer distinguish exact typed calls from over-broad name/arity dispatch
guesses, and refuse to present the latter as typed reachability proof.

| Field | Description |
|-------|-------------|
| `resolution` | How the target was resolved: `exact`, `interface_dispatch`, or `name_only`. Absent ⇒ treat as unresolved/untrusted. |
| `declared_type` | The static/interface type at the call site (e.g. the interface whose method was dispatched). Present on dispatch edges. |
| `method_name` | The invoked method name, independent of the resolved target. |
| `arity` | The argument count of the call. |

`resolution` values:

- **`exact`** — the receiver's static type was known and the method resolved to
  a unique declared target on that type (or an overload set on that exact type).
- **`interface_dispatch`** — the target was found by expanding an
  interface/abstract method to concrete implementations matching name + arity
  within a namespace root. Trustworthy only when exactly one implementation is
  present in the dependency closure; otherwise it is an ambiguous guess.
- **`name_only`** — the target was guessed by method name + arity (plus
  namespace heuristics) with no receiver-type anchor (e.g. fluent-chain
  fallback).

`method_name` + `arity` + the call-site line let a consumer **group sibling
candidates of one call site** so ambiguity can be detected across edges that
span the component boundary. The reference consumer (`pkg/graphfrag`'s stitcher)
applies a **tiered, fail-closed** policy: traverse `exact` edges and
`interface_dispatch` edges with exactly one implementation in the dependency
closure; **drop** ambiguous interface dispatch (>1 impl) and `name_only` edges,
recording them rather than emitting a chain. This is what prevents a DRBG's
`generate()` from name-colliding with `BCrypt.generate#3` (or
`provider.get(...)` fanning out to unrelated `get(...)` methods) from being
reported as reachable crypto.

> Fragments exported by older versions (without `resolution`) decode as
> unresolved and are treated as untrusted (fail-closed): under-report, never a
> false positive.

### Example

```json
{
  "schema_version": "graph-fragment-1.3",
  "scan_metadata": { "ecosystem": "java", "root_module": "org.bouncycastle:bcpkix-jdk18on", "graph_algo_version": "graph-algo-1", "function_count": 4000, "internal_edge_count": 6417, "external_call_count": 9469, "crypto_operation_count": 160, "supporting_call_count": 12, "crypto_entry_point_count": 42 },
  "functions": [
    { "key": "org.bouncycastle.pkcs.(PKCS8EncryptedPrivateKeyInfo).decryptPrivateKeyInfo#1", "file_path": "org/bouncycastle/pkcs/PKCS8EncryptedPrivateKeyInfo.java" }
  ],
  "external_calls": [
    {
      "caller_key": "org.bouncycastle.pkcs.(PKCS8EncryptedPrivateKeyInfo).decryptPrivateKeyInfo#1",
      "target_key": "org.bouncycastle.operator.(InputDecryptorProvider).get#1",
      "line": 90,
      "resolution": "exact",
      "method_name": "get",
      "arity": 1,
      "entry_call": {
        "file_path": "org/bouncycastle/pkcs/PKCS8EncryptedPrivateKeyInfo.java",
        "line": 90,
        "parameters": [
          { "parameter_index": 0, "type": "org.bouncycastle.operator.InputDecryptorProvider", "argument_expression": "inputDecryptorProvider" }
        ]
      }
    },
    {
      "caller_key": "org.bouncycastle.pkcs.(PKCS8EncryptedPrivateKeyInfo).decryptPrivateKeyInfo#1",
      "target_key": "org.bouncycastle.cms.(RecipientInformationStore).get#1",
      "line": 90,
      "resolution": "interface_dispatch",
      "declared_type": "org.bouncycastle.operator.InputDecryptorProvider",
      "method_name": "get",
      "arity": 1
    }
  ],
  "supporting_calls": [
    {
      "supporting_id": "cfg123",
      "function_key": "org.example.(Builder).configure#0",
      "category": "config",
      "matched_operation": { "kind": "call", "symbol": "org.example.Builder.withParameter" }
    }
  ],
  "crypto_entry_points": [
    {
      "function_key": "org.example.(Facade).encrypt#1",
      "function_name": "org.example.Facade.encrypt",
      "display_symbol": "org.example.Facade.encrypt",
      "reachable_findings": [{ "finding_id": "abc123", "chain_depth": 3, "finding_graph_ref": "abc123" }],
      "reachable_supporting_calls": [{ "supporting_id": "cfg123", "chain_depth": 2 }]
    }
  ],
  "crypto_annotations": [
    {
      "function_key": "org.bouncycastle.asn1.pkcs.(EncryptedPrivateKeyInfo).getEncryptedData#0",
      "finding_id": "abc123",
      "symbol": "getEncryptedData",
      "source": "direct",
      "end_line": 142,
      "match": "getEncryptedData()",
      "oid": "1.2.840.113549.1.5.13",
      "matched_operation": { "kind": "decrypt", "symbol": "getEncryptedData", "expression": "getEncryptedData()" },
      "crypto_call": {
        "function_name": "org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo.getEncryptedData",
        "line": 142,
        "parameters": []
      }
    }
  ]
}
```

In this slice, `decryptPrivateKeyInfo` has one **`exact`** edge to the real
`InputDecryptorProvider.get` and one over-broad **`interface_dispatch`** edge to
an unrelated `get#1` from the same call site (`line: 90`). A stitcher that sees
more than one implementation for that call site drops the ambiguous group.

## CycloneDX CBOM Format

CycloneDX 1.6 compatible Cryptography Bill of Materials format for standardized reporting.

### Features

- **Schema Validation**: Validates against CycloneDX 1.6 specification
- **Standardized Components**: Maps cryptographic assets to standardized component types
- **Rich Metadata**: Includes algorithm properties, evidence, and provenance
- **Industry Standard**: Compatible with CycloneDX ecosystem tools

### Supported Asset Types

| Type | Description |
|------|-------------|
| `algorithm` | Cryptographic algorithms (AES, RSA, SHA-256, etc.) |
| `certificate` | Digital certificates and certificate chains |
| `protocol` | Cryptographic protocols (TLS, SSH, etc.) |
| `related-crypto-material` | Keys, seeds, nonces, and other crypto material |

### Example Output

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-15T10:00:00Z",
    "tools": [
      {
        "vendor": "SCANOSS",
        "name": "crypto-finder",
        "version": "0.1.0"
      }
    ],
    "component": {
      "type": "application",
      "name": "scanned-project"
    }
  },
  "components": [
    {
      "type": "cryptographic-asset",
      "name": "AES",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "block-cipher",
          "mode": "CBC",
          "padding": "PKCS5Padding"
        }
      },
      "evidence": {
        "occurrences": [
          {
            "location": "src/crypto/Example.java:29"
          }
        ]
      }
    }
  ]
}
```

### Converting Formats

Use the `convert` command to transform interim JSON to CycloneDX:

```bash
# Convert from file
crypto-finder convert results.json --output cbom.json

# Convert from stdin (pipe from scan)
crypto-finder scan /path/to/code | crypto-finder convert --output cbom.json

# Direct output during scan
crypto-finder scan --format cyclonedx --output cbom.json /path/to/code
```

### Integration

CycloneDX CBOM output can be consumed by:

- Dependency track systems
- Software Bill of Materials (SBOM) aggregators
- Security scanning platforms
- Compliance reporting tools
- Supply chain risk management systems

## Format Comparison

| Feature | Interim JSON | CycloneDX CBOM |
|---------|-------------|----------------|
| **Ecosystem** | SCANOSS-specific | Industry standard |
| **Detail Level** | High (findings metadata, code snippets) | Medium (structured metadata) |
| **File Size** | Larger | Smaller |
| **Best For** | Deep analysis, custom tooling | Compliance, integration, reporting |
| **Schema** | SCANOSS interim spec | CycloneDX 1.6 |
| **Validation** | SCANOSS tools | CycloneDX validators |

## Related Documentation

- [Main README](../README.md) - Usage and command reference
- [Dependency Scanning](DEPENDENCY_SCANNING.md) - How dependency scanning, call graph tracing, and attribution work
- [Docker Usage](DOCKER_USAGE.md) - Container-based scanning and format conversion
