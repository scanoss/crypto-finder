# Output Formats

Crypto Finder supports two output formats: an interim JSON format for detailed analysis and CycloneDX CBOM format for standardized Bill of Materials reporting.

## Interim JSON Format

The default output format containing detailed cryptographic asset information optimized for the SCANOSS ecosystem.

The interim report is the primary findings artifact. It contains finding metadata such as `finding_id`, but it does not currently embed the finding-centric reachability slices produced by `--export-callgraph`.

### Format Specification

```json
{
  "version": "1.3",
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
| `version` | Format version (currently "1.3") |
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
| `file_path` | For dependency findings, path relative to the dependency root; use `dependency_info` for artifact identity |

### Call Graph Export

When `--export-callgraph` is enabled, Crypto Finder also writes a separate finding-centric call graph JSON file. This export contains the reachability slices and value-flow details associated with findings from the interim report.

Schema note: call graph export version `4.3` adds Java runtime provenance in `scan_metadata` for JDK-aware platform signature enrichment.

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
