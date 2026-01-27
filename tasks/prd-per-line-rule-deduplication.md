# PRD: Per-Line Rule Deduplication

## Introduction

Currently, crypto-finder produces duplicate findings when multiple detection rules match the same line of code. This creates noise in the interim report output, clutters analysis results, and degrades the user experience for security analysts reviewing cryptographic asset findings. This PRD defines a per-line rule aggregation system that merges multiple rule detections on the same code line while preserving complete traceability of which rules triggered the detection.

## Goals

- Eliminate duplicate findings when multiple rules match the same line of code
- Preserve all rule IDs and metadata for complete detection traceability
- Reduce interim report size and improve analysis efficiency
- Align CycloneDX evidence format with specification (occurrences = locations, identity methods = detection techniques)
- Maintain backward compatibility through opt-out configuration flag
- Ensure zero information loss during deduplication process

## User Stories

### US-001: Deduplicate findings at interim report level
**Description:** As a developer, I need to implement deduplication logic that merges CryptographicAsset entries with identical line positions after scanning completes.

**Acceptance Criteria:**
- [ ] Create new deduplicator component in `internal/deduplicator/deduplicator.go`
- [ ] Implement grouping by `(file_path, start_line, end_line)` tuple
- [ ] Merge CryptographicAssets with matching positions into single asset
- [ ] Preserve all unique metadata from merged rules
- [ ] Call deduplicator from scanner transformer before returning interim report
- [ ] Typecheck passes
- [ ] Unit tests cover merge logic with multiple rules

### US-002: Update data model to support multiple rules per asset
**Description:** As a developer, I need to change the CryptographicAsset structure to store an array of rules instead of a single rule.

**Acceptance Criteria:**
- [ ] Change `CryptographicAsset.Rule` to `CryptographicAsset.Rules []RuleInfo` in `internal/entities/interim.go`
- [ ] Change `AssetOccurrence.RuleID` to `AssetOccurrence.RuleIDs []string` in `internal/converter/aggregator.go`
- [ ] Update JSON schema `schemas/interim-report-schema.json` to v1.1 with rules array
- [ ] Add backward compatibility handling for old `rule` field (optional migration shim)
- [ ] Typecheck passes
- [ ] All existing tests updated to use new structure

### US-003: Update aggregator to handle multi-rule assets
**Description:** As a developer, I need to update the aggregator to process assets with multiple rules and create proper identities.

**Acceptance Criteria:**
- [ ] Update `aggregator.go:138-147` to extract all rule IDs from `asset.Rules[]` array
- [ ] Update `addIdentityIfNew()` to iterate over all rules and create one identity per rule
- [ ] Ensure identity deduplication still works (check for existing rule+API combinations)
- [ ] Preserve all rule metadata (message, severity) in respective identities
- [ ] Typecheck passes
- [ ] Unit tests verify multiple identities created from multi-rule asset

### US-004: Fix CycloneDX evidence format alignment
**Description:** As a developer, I need to correct the evidence structure to align with CycloneDX specification (occurrences contain locations/code, identity methods contain rule IDs).

**Acceptance Criteria:**
- [ ] Change `converter.go:182` occurrence.additionalContext to use code snippet: `occ.Match` instead of rule ID
- [ ] Change `converter.go:198-200` identity method value to use rule ID: `fmt.Sprintf("scanoss:ruleid,%s", identity.RuleID)` instead of code snippet
- [ ] Each identity.methods[] entry contains single rule ID (not comma-separated)
- [ ] Multiple rules create multiple method entries in the methods array
- [ ] Typecheck passes
- [ ] Integration tests verify correct CycloneDX output format

### US-005: Add configuration flag for deduplication control
**Description:** As a user, I want to disable per-line deduplication if needed for debugging or compatibility with existing workflows.

**Acceptance Criteria:**
- [ ] Add `--no-dedup` CLI flag in `internal/cli/` with description
- [ ] Default behavior: deduplication enabled
- [ ] When `--no-dedup` is set, skip deduplicator call and preserve original behavior
- [ ] Flag documented in CLI help text
- [ ] Typecheck passes
- [ ] Manual test confirms both modes work correctly

### US-006: Update test fixtures and documentation
**Description:** As a developer, I need to update all test fixtures to use the new data structure and document the changes for users.

**Acceptance Criteria:**
- [ ] Update all `testdata/*.json` fixtures to use `"rules": []` array format
- [ ] Update test assertions to expect new evidence structure
- [ ] Add test case with multiple rules on same line showing deduplication
- [ ] Create before/after example outputs in documentation
- [ ] Document migration guide for consumers of interim report format
- [ ] All tests pass with new structure

## Functional Requirements

### Deduplication Logic
- FR-1: After scanning completes, group all CryptographicAsset entries by the tuple `(file_path, start_line, end_line)`
- FR-2: For assets with matching positions, merge into single CryptographicAsset with combined rules array
- FR-3: Preserve all unique metadata values during merge (union of all metadata maps)
- FR-4: Preserve all rule information (ID, message, severity) in the merged asset's rules array
- FR-5: Deduplication must be deterministic (same input always produces same output)

### Data Model Changes
- FR-6: `CryptographicAsset` must have `Rules []RuleInfo` field instead of singular `Rule RuleInfo`
- FR-7: `AssetOccurrence` must have `RuleIDs []string` field instead of singular `RuleID string`
- FR-8: Interim report schema version must increment from v1.0 to v1.1
- FR-9: All marshallers/unmarshallers must handle the new array-based structure

### CycloneDX Evidence Format
- FR-10: Each `evidence.occurrence` must represent one code location (file + line)
- FR-11: `occurrence.additionalContext` must contain the matched code snippet, not rule IDs
- FR-12: `evidence.identity.methods[]` must contain one entry per detection rule
- FR-13: Each `identity.methods[].value` must contain format `"scanoss:ruleid,{ruleID}"` with single rule ID
- FR-14: `identity.methods[].technique` must be `"source-code-analysis"` for all entries
- FR-15: When same line is detected by N rules, create one occurrence with N methods in identity

### Configuration
- FR-16: CLI must accept `--no-dedup` flag to disable per-line deduplication
- FR-17: Default behavior (no flag) must enable deduplication
- FR-18: Flag must be documented in `--help` output

### Performance
- FR-19: Deduplication overhead must be less than 5% of total scan time
- FR-20: Memory usage must not increase significantly (assets are merged, not duplicated)

## Non-Goals (Out of Scope)

- No fingerprint-based deduplication (Semgrep-style content hashing) in initial version
- No cross-file deduplication (only per-line within same file)
- No severity conflict resolution logic (all rules are INFO level currently)
- No confidence scoring based on rule quality/specificity
- No automatic priority assignment when rules conflict
- No rule effectiveness analytics (which rules frequently co-detect)
- No changes to rule authoring or rule format
- No changes to scanner implementation (Semgrep, OpenGrep, CBOM Toolkit)
- No UI changes (this is CLI/API level only)

## Design Considerations

### Metadata Merging Strategy
When multiple rules detect the same line, metadata must be intelligently merged:

**Strategy:**
- **Union approach:** Combine all unique metadata values
- **Key conflicts:** If same key has different values, keep most specific/detailed value
- **Algorithm naming:** Prefer explicit `algorithmName` over constructed names
- **API field:** Keep first non-empty API value (usually same for same line)
- **Library field:** Keep first non-empty library value

**Example:**
```
Rule A metadata: {algorithmFamily: "AES", algorithmParameterSetIdentifier: "256"}
Rule B metadata: {algorithmFamily: "AES", algorithmMode: "GCM"}
Merged metadata: {algorithmFamily: "AES", algorithmParameterSetIdentifier: "256", algorithmMode: "GCM"}
```

### CycloneDX Evidence Structure

**Before (incorrect per CDX spec):**
```json
{
  "occurrences": [
    {"location": "file.go", "line": 42, "additionalContext": "scanoss:ruleid,rule1"}
  ],
  "identity": [{
    "methods": [{
      "technique": "source-code-analysis",
      "value": "scanoss:match,crypto.SHA256.New()"
    }]
  }]
}
```

**After (correct per CDX spec + deduplication):**
```json
{
  "occurrences": [
    {"location": "file.go", "line": 42, "additionalContext": "crypto.SHA256.New()"}
  ],
  "identity": [{
    "methods": [
      {
        "technique": "source-code-analysis",
        "value": "scanoss:ruleid,go.crypto.sha256.new",
        "confidence": 1.0
      },
      {
        "technique": "source-code-analysis",
        "value": "scanoss:ruleid,go.crypto.hash.sha256",
        "confidence": 1.0
      }
    ],
    "confidence": 1.0
  }]
}
```

## Technical Considerations

### Architecture Integration Points

**Deduplication Pipeline:**
```
Scanner Output (Semgrep JSON)
    ↓
Transformer (parse to interim format)
    ↓
Deduplicator (NEW - merge per-line) ← Insert here
    ↓
Interim Report (with merged assets)
    ↓
Aggregator (group by asset key)
    ↓
CycloneDX Converter
    ↓
CBOM Output
```

### Files Requiring Modification

**Core Implementation:**
1. `internal/deduplicator/deduplicator.go` (NEW) - Lines: ~100-150
2. `internal/entities/interim.go` - Lines: 59-84 (data model change)
3. `internal/converter/aggregator.go` - Lines: 45-64, 138-147, 180-202
4. `internal/converter/converter.go` - Lines: 171-186, 188-208
5. `internal/scanner/semgrep/transformer.go` - Call deduplicator before return

**Schema & Tests:**
6. `schemas/interim-report-schema.json` - Update to v1.1
7. `internal/deduplicator/deduplicator_test.go` (NEW)
8. `internal/converter/aggregator_test.go` - Update assertions
9. `internal/converter/converter_test.go` - Update fixtures
10. All `internal/converter/testdata/*.json` - Use rules array

**CLI:**
11. `internal/cli/scan.go` or similar - Add `--no-dedup` flag

### Backward Compatibility Considerations

**Breaking Change:** Interim report schema changes from v1.0 to v1.1
- `rule` (object) → `rules` (array)

**Migration Options:**
- **Option A:** Hard break - require v1.1, no compatibility layer
- **Option B:** Support both during transition - check for both `rule` and `rules` fields
- **Option C:** Version-gated behavior based on schema version

**Recommendation:** Option A (hard break) with clear version bump and migration guide, as interim report is primarily internal format.

### Performance Optimization

**Deduplication Algorithm Complexity:**
- Grouping by (file, line): O(n) with hash map
- Merging metadata: O(k) where k = number of metadata keys (small, ~10-20)
- Overall: O(n) where n = number of assets

**Expected Impact:**
- Large codebase: 10,000 findings → ~7,000 after deduplication (30% reduction)
- Processing time: +50ms for deduplication step on 10k findings
- Memory: Reduced (fewer asset objects after merge)

## Success Metrics

### Quantitative Metrics
1. **Deduplication Rate:** Measure percentage reduction in finding count
   - Target: 20-40% reduction in findings for typical codebase
   - Measure on 3-5 real-world codebases before/after

2. **Performance Impact:** Measure deduplication overhead
   - Target: < 5% increase in total scan time
   - Measure on large codebase (10k+ findings)

3. **Output Size Reduction:** Measure interim report file size reduction
   - Target: 15-30% smaller JSON output
   - Measure serialized JSON byte size

4. **Information Preservation:** Verify zero data loss
   - Metric: All rule IDs present in final CBOM evidence
   - Verify: Count of unique rule IDs same before/after deduplication

### Qualitative Metrics
5. **User Feedback:** Collect feedback from security analysts
   - Survey question: "Does deduplication improve analysis workflow?"
   - Target: > 80% positive response

6. **Integration Testing:** Verify downstream consumers still work
   - Test with existing CBOM consumers/parsers
   - Ensure no parsing errors with new evidence format

## Migration & Rollout Plan

### Phase 1: Implementation (Week 1-2)
- Implement deduplicator component
- Update data models and aggregator
- Fix CycloneDX evidence format
- Add CLI flag

### Phase 2: Testing (Week 2)
- Unit tests for all components
- Integration tests with real rules
- Performance benchmarking
- Test on sample codebases

### Phase 3: Documentation (Week 3)
- Update interim report schema docs
- Migration guide for v1.0 → v1.1
- Before/after examples
- CLI documentation

### Phase 4: Rollout (Week 3-4)
- Default: deduplication ON
- Announce breaking change (schema v1.1)
- Monitor for issues
- Collect user feedback

### Rollback Plan
If critical issues found:
- Users can use `--no-dedup` flag immediately
- Hotfix to change default to OFF while investigating
- Fix issues and re-enable in patch release

## Open Questions

1. **Metadata conflict resolution:** If two rules have different values for same metadata key (rare), which should win?
   - Proposed: Keep first non-empty value, log warning if conflict detected

2. **Confidence scoring:** Should confidence vary by rule quality, or always 1.0?
   - Current: All rules have confidence 1.0
   - Future: Could add per-rule confidence metadata

3. **Cross-file deduplication:** Should same asset in multiple files be deduplicated?
   - Current scope: No (out of scope)
   - Future: Could aggregate in CBOM conversion layer (already does this)

4. **Rule effectiveness tracking:** Should we log which rules frequently co-detect for rule optimization?
   - Current scope: No (analytics/observability feature)
   - Future: Could add telemetry for rule authors

5. **Backward compatibility shim:** Should we support reading old v1.0 interim reports?
   - Decision needed: How long to maintain compatibility?
   - Proposed: No shim - clean break with version bump

## Dependencies

- No external library dependencies
- Requires Go 1.21+ (existing requirement)
- CycloneDX library: `github.com/CycloneDX/cyclonedx-go` (already used)
- Testing framework: standard Go testing package

## Risks & Mitigation

### Risk 1: Breaking changes affect downstream tools
**Likelihood:** Medium
**Impact:** High
**Mitigation:**
- Clear communication of schema version bump
- Provide migration guide with examples
- `--no-dedup` flag for temporary compatibility

### Risk 2: Metadata merge logic loses important information
**Likelihood:** Low
**Impact:** Medium
**Mitigation:**
- Extensive testing with real-world rules
- Log warnings when conflicts detected
- Preserve all rule IDs for manual review

### Risk 3: Performance degradation on large codebases
**Likelihood:** Low
**Impact:** Medium
**Mitigation:**
- Benchmark with 10k+ findings
- Optimize hash map lookups
- Profile and optimize hot paths if needed

### Risk 4: CycloneDX format changes not backward compatible
**Likelihood:** Low
**Impact:** Medium
**Mitigation:**
- Validate output against CycloneDX 1.6 schema
- Test with existing CBOM parsers/consumers
- Document evidence format changes clearly

## Future Enhancements

**Post-MVP features** (not in scope for initial release):

1. **Configurable deduplication strategies**
   - `--dedup-strategy=line` (current)
   - `--dedup-strategy=fingerprint` (Semgrep-style content hash)
   - `--dedup-strategy=semantic` (by asset type + algorithm)

2. **Rule confidence scoring**
   - Assign confidence based on rule specificity
   - Higher confidence for specific rules vs. generic patterns

3. **Analytics dashboard**
   - Which rules frequently co-detect (rule effectiveness)
   - Deduplication rate trends over time
   - Most common duplicate patterns

4. **Smart metadata merging**
   - ML-based conflict resolution
   - Prefer metadata from higher-confidence rules
   - Merge CWE IDs, references, etc.

5. **Cross-scan deduplication**
   - Track findings across multiple scans
   - Identify new vs. existing findings
   - Integrate with issue tracking systems

## Appendix: Example Scenarios

### Scenario A: Two rules match same AES usage

**Input (interim report before deduplication):**
```json
{
  "findings": [{
    "file_path": "src/crypto.go",
    "cryptographic_assets": [
      {
        "start_line": 42,
        "end_line": 42,
        "match": "cipher.NewGCM(block)",
        "rule": {"id": "go.crypto.aes-gcm", "message": "AES-GCM detected", "severity": "INFO"},
        "metadata": {"algorithmFamily": "AES", "algorithmMode": "GCM"}
      },
      {
        "start_line": 42,
        "end_line": 42,
        "match": "cipher.NewGCM(block)",
        "rule": {"id": "go.crypto.cipher-usage", "message": "Cipher API usage", "severity": "INFO"},
        "metadata": {"api": "cipher.NewGCM"}
      }
    ]
  }]
}
```

**Output (after deduplication):**
```json
{
  "findings": [{
    "file_path": "src/crypto.go",
    "cryptographic_assets": [
      {
        "start_line": 42,
        "end_line": 42,
        "match": "cipher.NewGCM(block)",
        "rules": [
          {"id": "go.crypto.aes-gcm", "message": "AES-GCM detected", "severity": "INFO"},
          {"id": "go.crypto.cipher-usage", "message": "Cipher API usage", "severity": "INFO"}
        ],
        "metadata": {"algorithmFamily": "AES", "algorithmMode": "GCM", "api": "cipher.NewGCM"}
      }
    ]
  }]
}
```

**CycloneDX Output:**
```json
{
  "components": [{
    "name": "AES-GCM",
    "evidence": {
      "occurrences": [
        {"location": "src/crypto.go", "line": 42, "additionalContext": "cipher.NewGCM(block)"}
      ],
      "identity": [{
        "methods": [
          {"technique": "source-code-analysis", "value": "scanoss:ruleid,go.crypto.aes-gcm", "confidence": 1.0},
          {"technique": "source-code-analysis", "value": "scanoss:ruleid,go.crypto.cipher-usage", "confidence": 1.0}
        ],
        "confidence": 1.0
      }]
    }
  }]
}
```

### Scenario B: Different assets on same line (no deduplication)

**Input:**
```json
{
  "cryptographic_assets": [
    {
      "start_line": 42,
      "rule": {"id": "go.crypto.aes"},
      "metadata": {"assetType": "algorithm", "algorithmFamily": "AES"}
    },
    {
      "start_line": 42,
      "rule": {"id": "go.crypto.hardcoded-key"},
      "metadata": {"assetType": "related-crypto-material", "materialType": "secret-key"}
    }
  ]
}
```

**Output:** No deduplication - these are different asset types (algorithm vs. key), so they remain separate even though on same line. Deduplication only merges truly duplicate detections of the same asset.

---

**Document Version:** 1.0
**Created:** 2026-01-27
**Status:** Draft
**Owner:** SCANOSS crypto-finder team

## VERY IMPORTANT NOTE
When committing changes, ensure to use descriptive commit messages that clearly explain the changes made.
DO NOT USE commit messages that use "[<user-storie-nr>] - commit description". For example "[US-001] - updated X and Y to use Z"
Commit messages should be concise and descriptive, providing enough information for others to understand the purpose and impact of the change.
Good examples: "[SP-3908] feat: updated x and y to use z" if you know the jira ticket number. Otherwise just "fet: updated x and y to use z" should be enough.
