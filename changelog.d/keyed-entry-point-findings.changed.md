- Every finding that has a call graph now carries an `occurrence_key`, so a
  consumer that joins assets to finding graphs on `(finding_id,
  occurrence_key)` can attach all of them. Findings synthesized from library
  API contracts (rule id `crypto-finder.api-entry-point`) and rule matches
  with no call to anchor, such as a cast or a declaration of a certificate
  type, were left without one; they are now keyed by the function that holds
  them and their position. Findings that already had a key keep it.
- Variants of one library entry point are now separate findings. A contract
  that specializes an API by an argument type (for example `PBKDF2-SHA-256`
  and `PBKDF2-SHA-1` selected by the digest passed to the constructor) or by
  a variant such as `ECDSA` and `ECDSA-deterministic` used to give every
  variant one shared `finding_id`; each variant except the base now has its
  own `finding_id` and `occurrence_key`, derived from its `algorithmName`,
  `algorithmHashFunction` and `parameterCondition`, so other edits to a
  contract do not change them. The base entry point keeps its `finding_id`. Variants still share the function-level call chains of their
  declaration; per-type chain filtering is not applied. The identities of the
  keyless findings and of the variants change once, on the first scan with
  this release. No call graph algorithm changed, so `graph-algo-7` still
  covers it.
