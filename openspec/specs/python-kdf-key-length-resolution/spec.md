# python-kdf-key-length-resolution Specification

## Purpose

Populates the existing `resolved_key_length` field on the supporting-call
declaration for Python KDF calls, matching Java's coverage in
`internal/scan/key_length.go`, without a schema bump. New capability.

## Requirements

### Requirement: Keyword-argument-aware parameter-index mapping

The declared parameter index used to resolve `resolved_key_length` MUST be
correct for a KDF called with keyword arguments (`dklen=32`, `length=32`),
regardless of the argument's syntactic position. **Field decision**: no new
`FunctionCall` field is introduced. `Arguments[i]` already captures the raw
`name=value` text for a keyword argument (`extractPythonCallArguments`
splits on commas without dropping the `keyword_argument` prefix);
`internal/scan/key_length.go` MUST parse that leading `identifier=` and match
it against the KB contract's key-size-contributing parameter `name` (declared
alongside `contributes.property: keySize`) when index-based matching yields
nothing. `mergeCallParameters` (`internal/scan/export.go`) is NOT modified and
the exported `parameter_index` is NOT remapped; `SourceCall.ParameterIndex`
reports the contract's declared index.

#### Scenario: Keyword argument out of declared order still resolves

- GIVEN `hashlib.pbkdf2_hmac(hash_name, password, salt, iterations,
  dklen=32)` where `dklen` is written as a trailing keyword argument
- WHEN the KB contract's `dklen` parameter role is matched by name
- THEN the exported `resolved_key_length.bits` MUST equal `256`
  (32 bytes × 8)

#### Scenario: Existing positional calls are unaffected

- GIVEN a purely positional KDF call with the same arity
- WHEN parameters are mapped
- THEN resolution MUST be unchanged from today's index-based matching
  (`mergeCallParameters` and `contractParameterTypesMatch` are untouched)

#### Scenario: Positional call without call-site type evidence still resolves

- GIVEN a Python KDF contract declaring `parameter_types` and a purely
  positional call whose length argument is an integer literal (e.g.
  `PBKDF2(password, salt, 32)`)
- WHEN no call-site declared type is available for the key-size parameter
  index (no `SourceNode.DeclaredType`, empty `parameterTypes[index]`)
- THEN `resolved_key_length.bits` MUST resolve with `provenance: "constant"`,
  and a non-constant positional argument MUST resolve nothing (no
  `resolved_key_length` record is fabricated)
- Pinned by: `TestResolvedKeyLength_Python_PositionalLength`

### Requirement: `argument_byte_length` derivation

The contracts loader MUST accept a new `Derivation` enum value
`argument_byte_length` (whitelisted in `contracts.go` `validDerivation`),
converting an integer byte count to bits (`bytes * 8`) for
`resolved_key_length`, distinct from `argument_value` (raw bits) and
`argument_bit_length` (byte-array/string length).

#### Scenario: Byte-length contract yields correct bits

- GIVEN a KDF contract parameter role with
  `contributes: {property: keySize, derivation: argument_byte_length}`
- WHEN a call passes `length=32` (or `dklen=32`) for that parameter
- THEN `resolvedContractKeyBits` MUST return `256, true`

### Requirement: Integer literal and module-level constant resolution

An integer literal or a module-level integer constant (`KEY_LEN = 32`)
referenced as a KDF length/`dklen`/`hash_len`/`desired_key_bytes` argument
MUST resolve to its value. An unresolvable expression MUST leave
`resolved_key_length` at `provenance: unknown`, `bits: nil` — never
fabricated.

#### Scenario: Module-level constant resolves

- GIVEN `KEY_LEN = 32` at module scope and `PBKDF2HMAC(length=KEY_LEN)`
- WHEN the parser resolves the `length` argument
- THEN `resolved_key_length` MUST report `bits: 256`,
  `provenance: "constant"`

#### Scenario: Non-constant expression stays unknown

- GIVEN `PBKDF2HMAC(length=compute_len())`
- WHEN the parser resolves the `length` argument
- THEN `resolved_key_length` MUST report `provenance: "unknown"` with no
  `bits` value

### Requirement: KB coverage for Python KDF APIs

The Python KB MUST declare `parameters[].contributes.property: keySize`
entries, in both positional and keyword forms, for: `hashlib.pbkdf2_hmac`
(`dklen`), `hashlib.scrypt` (`dklen`), cryptography `PBKDF2HMAC`/`Scrypt`/
`HKDF`/`HKDFExpand`/`ConcatKDFHash`/`X963KDF` (`length`), argon2
`PasswordHasher` (`hash_len`), bcrypt `kdf` (`desired_key_bytes`),
PyCryptodome `PBKDF2` (`dkLen`), `scrypt` (`key_len`), `HKDF` (`key_len`).

#### Scenario: Every listed API exports resolved key length

- GIVEN a table-driven fixture covering each listed API called both
  positionally and by keyword, with a literal or module-constant length
- WHEN `internal/scan` exports the callgraph
- THEN each `supporting_calls[].supporting_call.resolved_key_length.bits`
  MUST match the expected value
- Pinned by: `TestResolvedKeyLength_Python*` in `internal/scan`

### Requirement: Export schema unchanged

`resolved_key_length` surfaces through the existing schema field; this
capability MUST NOT bump `pkg/graphfrag.CallgraphSchemaVersion` (stays
`"6.13"`) or `SchemaVersion` (stays `"graph-fragment-1.13"`).

#### Scenario: Schema version tests remain green

- GIVEN this capability fully implemented
- WHEN `internal/scan/export_schema_test.go` and
  `internal/scan/fragment_export_test.go` run
- THEN both schema version assertions MUST still pass unchanged
