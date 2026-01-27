# Output Formats

Crypto Finder supports two output formats: an interim JSON format for detailed analysis and CycloneDX CBOM format for standardized Bill of Materials reporting.

## Interim JSON Format

The default output format containing detailed cryptographic asset information optimized for the SCANOSS ecosystem.

### Format Specification

```json
{
  "version": "1.1",
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
          "match_type": "scanner_name",
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
          }
        }
      ],
      "timestamp_utc": "2025-01-15T10:00:00Z"
    }
  ]
}
```

> **Note:** Version 1.1 introduces the `rules` array field (replacing single `rule` field) to support per-line deduplication. Multiple detection rules can now identify the same cryptographic asset. See [Migration Guide](MIGRATION_GUIDE.md) for details.

### Field Descriptions

| Field | Description |
|-------|-------------|
| `version` | Format version (currently "1.1") |
| `tool.name` | Scanner used (crypto-finder) |
| `tool.version` | Scanner version |
| `findings` | Array of file-level findings |
| `file_path` | Relative path to scanned file |
| `language` | Detected programming language |
| `cryptographic_assets` | Array of crypto findings in the file |
| `match_type` | Scanner that detected the asset |
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
          "match_type": "opengrep",
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
      "timestamp_utc": "2025-10-22T10:00:00Z"
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
          "match_type": "opengrep",
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
      "timestamp_utc": "2025-01-27T10:00:00Z"
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
| **Detail Level** | High (includes code snippets) | Medium (structured metadata) |
| **File Size** | Larger | Smaller |
| **Best For** | Deep analysis, custom tooling | Compliance, integration, reporting |
| **Schema** | SCANOSS interim spec | CycloneDX 1.6 |
| **Validation** | SCANOSS tools | CycloneDX validators |

## Related Documentation

- [Main README](../README.md) - Usage and command reference
- [Docker Usage](DOCKER_USAGE.md) - Container-based scanning and format conversion
