# Migration Guide: Interim Report Format v1.0 to v1.1

This guide documents the changes to the interim report format and how to migrate consumers of the interim report JSON output.

## Overview

Version 1.1 of the interim report format introduces per-line rule deduplication, allowing multiple detection rules to identify the same cryptographic asset on a single line of code. This eliminates duplicate findings while preserving complete traceability of which rules triggered the detection.

## Schema Changes

### Changed: `rule` → `rules` Array

**Before (v1.0):**
```json
{
  "cryptographic_assets": [
    {
      "line_number": 42,
      "rule": {
        "id": "go-crypto-aes-256",
        "severity": "info"
      },
      "metadata": {
        "assetType": "algorithm",
        "algorithmFamily": "AES"
      }
    }
  ]
}
```

**After (v1.1):**
```json
{
  "cryptographic_assets": [
    {
      "line_number": 42,
      "rules": [
        {
          "id": "go-crypto-aes-256",
          "severity": "info"
        }
      ],
      "metadata": {
        "assetType": "algorithm",
        "algorithmFamily": "AES"
      }
    }
  ]
}
```

### Multiple Rules on Same Line

**Before (v1.0):** Duplicate assets
```json
{
  "cryptographic_assets": [
    {
      "line_number": 42,
      "rule": {
        "id": "go-crypto-aes-gcm",
        "severity": "info"
      },
      "metadata": { "assetType": "algorithm" }
    },
    {
      "line_number": 42,
      "rule": {
        "id": "go-crypto-authenticated-encryption",
        "severity": "info"
      },
      "metadata": { "assetType": "algorithm" }
    }
  ]
}
```

**After (v1.1):** Single deduplicated asset
```json
{
  "cryptographic_assets": [
    {
      "line_number": 42,
      "rules": [
        {
          "id": "go-crypto-aes-gcm",
          "severity": "info",
          "message": "AES-GCM encryption detected"
        },
        {
          "id": "go-crypto-authenticated-encryption",
          "severity": "info",
          "message": "Authenticated encryption pattern detected"
        }
      ],
      "metadata": { "assetType": "algorithm" }
    }
  ]
}
```

## Migration Steps

### 1. Update JSON Parsing Code

If you're parsing the interim report format, update your code to handle the `rules` array:

**Python Example:**
```python
# Before (v1.0)
for asset in cryptographic_assets:
    rule_id = asset['rule']['id']
    severity = asset['rule']['severity']
    process_finding(rule_id, severity)

# After (v1.1)
for asset in cryptographic_assets:
    for rule in asset['rules']:
        rule_id = rule['id']
        severity = rule['severity']
        process_finding(rule_id, severity)
```

**JavaScript/TypeScript Example:**
```typescript
// Before (v1.0)
interface CryptographicAsset {
  line_number: number;
  rule: {
    id: string;
    severity: string;
  };
  metadata: Record<string, string>;
}

// After (v1.1)
interface CryptographicAsset {
  line_number: number;
  rules: Array<{
    id: string;
    severity: string;
    message?: string;
  }>;
  metadata: Record<string, string>;
}
```

**Go Example:**
```go
// Before (v1.0)
type CryptographicAsset struct {
    LineNumber int               `json:"line_number"`
    Rule       RuleInfo          `json:"rule"`
    Metadata   map[string]string `json:"metadata"`
}

// After (v1.1)
type CryptographicAsset struct {
    LineNumber int               `json:"line_number"`
    Rules      []RuleInfo        `json:"rules"`
    Metadata   map[string]string `json:"metadata"`
}
```

### 2. Backward Compatibility

The crypto-finder tool includes automatic backward compatibility when reading interim reports:

- Old format (`"rule": {}`) is automatically converted to new format (`"rules": [{}]`)
- Your existing v1.0 JSON files will still work with crypto-finder v1.1+
- No migration of existing JSON files is required

### 3. Expect Fewer Duplicate Assets

With deduplication enabled by default:

- **Before:** Multiple assets at the same line position (one per rule)
- **After:** Single asset with multiple rules in the `rules` array

**Impact on analytics:**
- Asset counts will decrease (duplicates removed)
- Rule coverage remains the same (all rules preserved in array)
- Line-level analysis remains unchanged

### 4. Handling Deduplication in Aggregations

If you aggregate findings by rule, iterate over all rules in the array:

```python
# Example: Count findings by rule ID
rule_counts = {}
for finding in findings:
    for asset in finding['cryptographic_assets']:
        for rule in asset['rules']:
            rule_id = rule['id']
            rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
```

### 5. Disabling Deduplication (Optional)

If you need the old behavior for compatibility, use the `--no-dedup` flag:

```bash
crypto-finder scan --no-dedup /path/to/code
```

This will produce separate assets for each rule match, similar to v1.0 behavior.

## CycloneDX Output Changes

The CycloneDX CBOM output format has also been updated in alignment with the specification:

### Evidence Structure

**Occurrences:** Now contain code snippets (not rule IDs)
```json
{
  "evidence": {
    "occurrences": [
      {
        "location": "src/crypto/cipher.go:42",
        "additionalContext": "cipher.NewGCM(block)"
      }
    ]
  }
}
```

**Identity Methods:** Now contain rule IDs (not code snippets)
```json
{
  "evidence": {
    "identity": {
      "methods": [
        {
          "technique": "source-code-analysis",
          "value": "scanoss:ruleid,go-crypto-aes-gcm"
        },
        {
          "technique": "source-code-analysis",
          "value": "scanoss:ruleid,go-crypto-authenticated-encryption"
        }
      ]
    }
  }
}
```

This aligns with CycloneDX 1.6 specification where:
- **Occurrences** document where/how the asset appears in code
- **Identity methods** document how the asset was identified/detected

## Testing Your Migration

1. **Generate test outputs:**
   ```bash
   # New format (deduplicated)
   crypto-finder scan /path/to/code > output-v1.1.json

   # Old format (no dedup)
   crypto-finder scan --no-dedup /path/to/code > output-v1.0-compat.json
   ```

2. **Validate your parser:**
   - Test with single-rule assets
   - Test with multi-rule assets (same line)
   - Verify rule array iteration works correctly

3. **Compare results:**
   ```bash
   # Count total assets (will be lower in v1.1)
   jq '[.findings[].cryptographic_assets] | add | length' output-v1.1.json

   # Count total rule detections (should be same)
   jq '[.findings[].cryptographic_assets[].rules] | add | length' output-v1.1.json
   ```

## FAQ

### Q: Do I need to update existing JSON files?

**A:** No. The crypto-finder tool automatically handles the old format when reading files.

### Q: Will asset counts change?

**A:** Yes, asset counts will decrease because duplicates are merged. However, rule counts remain the same.

### Q: Can I still get the old behavior?

**A:** Yes, use the `--no-dedup` flag to disable deduplication.

### Q: What if I have custom tooling that parses interim JSON?

**A:** Update your parsing code to iterate over the `rules` array instead of accessing a single `rule` object.

### Q: Does this affect CycloneDX output?

**A:** Yes, the CycloneDX evidence structure has been updated to align with the specification (occurrences contain code, methods contain rule IDs).

### Q: When should I iterate over multiple rules?

**A:** Always iterate when processing assets. Even if an asset has only one rule, it will be in an array.

## Support

For questions or issues with migration:
- File an issue: https://github.com/scanoss/crypto-finder/issues
- Review examples: `/internal/converter/testdata/` directory
- Check schema: `/schemas/interim-report-schema.json`

## Version History

- **v1.0** - Initial interim report format with single `rule` field
- **v1.1** - Added `rules` array for per-line deduplication (backward compatible)
