# Output Formats

Crypto Finder supports two output formats: an interim JSON format for detailed analysis and CycloneDX CBOM format for standardized Bill of Materials reporting.

## Interim JSON Format

The default output format containing detailed cryptographic asset information optimized for the SCANOSS ecosystem.

### Format Specification

```json
{
  "version": "1.0",
  "tool": {
    "name": "opengrep",
    "version": "1.12.1"
  },
  "findings": [
    {
      "file_path": "path/to/file",
      "language": "language_name",
      "cryptographic_assets": [
        {
          "match_type": "scanner_name",
          "line_number": 123,
          "match": "code snippet",
          "rule": {
            "id": "rule.id",
            "message": "description",
            "severity": "INFO|WARNING|ERROR"
          },
          "type": "algorithm|certificate|protocol|related-crypto-material",
          "name": "algorithm_name",
          "primitive": "primitive_type",
          "mode": "mode_of_operation",
          "padding": "padding_scheme"
        }
      ],
      "timestamp_utc": "2025-01-15T10:00:00Z"
    }
  ]
}
```

### Field Descriptions

| Field | Description |
|-------|-------------|
| `version` | Format version (currently "1.0") |
| `tool.name` | Scanner used (opengrep or semgrep) |
| `tool.version` | Scanner version |
| `findings` | Array of file-level findings |
| `file_path` | Relative path to scanned file |
| `language` | Detected programming language |
| `cryptographic_assets` | Array of crypto findings in the file |
| `match_type` | Scanner that detected the asset |
| `line_number` | Line where the match was found |
| `match` | Actual code snippet matched |
| `rule.id` | Unique rule identifier |
| `rule.message` | Human-readable description |
| `rule.severity` | Finding severity level |
| `type` | Asset classification |
| `name` | Algorithm/protocol name |
| `primitive` | Cryptographic primitive type |
| `mode` | Mode of operation (for block ciphers) |
| `padding` | Padding scheme used |

### Example Output

```json
{
  "version": "1.0",
  "tool": {
    "name": "opengrep",
    "version": "1.12.1"
  },
  "findings": [
    {
      "file_path": "src/crypto/Example.java",
      "language": "java",
      "cryptographic_assets": [
        {
          "match_type": "opengrep",
          "line_number": 29,
          "match": "cipher = Cipher.getInstance(\"AES/CBC/PKCS5Padding\");",
          "rule": {
            "id": "java.crypto.cipher-aes-cbc",
            "message": "AES cipher usage detected",
            "severity": "INFO"
          },
          "type": "algorithm",
          "name": "AES",
          "primitive": "block-cipher",
          "mode": "CBC",
          "padding": "PKCS5Padding"
        }
      ],
      "timestamp_utc": "2025-10-22T10:00:00Z"
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
