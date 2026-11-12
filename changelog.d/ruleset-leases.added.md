- Remote rulesets are downloaded only from
  `/v3/rulesets/{name}/{version}/download`, with a signed lease
  (`SCANOSS-Ruleset-Lease`). An API key without access to `/v3/rulesets`
  gets no remote rules: the scan fails with the API's 403, or, when the API
  does not serve `/v3/rulesets`, with `ruleset dca@latest not found: the
  SCANOSS API has no such ruleset or does not serve /v3/rulesets`; scan with
  `--no-remote-rules --rules-dir` instead. An answer without a lease is
  rejected. The lease's signature, expiry and bundle hash are checked on
  download and on every scan, the cache keeps the ruleset encrypted with the
  API key (`bundle.enc` and `lease.json`, no plain rule files), and each
  scan extracts it into a per-run directory that is removed when the scan
  ends. An expired lease is never used, not even as stale cache; the error
  names the expiry date and asks to download the ruleset again. When the TTL
  of a cached `latest` elapses, the ruleset is downloaded again only if
  `GET /v3/rulesets/{name}/{version}` reports a new release or the lease
  expires within 7 days. The production signing key `srv-2026-11` is built
  in; `SCANOSS_RULESET_PUBKEYS` (`id:base64pub,...`) adds trusted signing
  keys.
- Interim report format 1.9: for a remote ruleset, `rules.checksum_sha256`
  is the release payload hash from the lease (`payload_sha256`), the same for
  every tenant, and `rules` carries an optional `lease` object (`expires_at`,
  `signing_key_id`). The report never names the key or tenant the ruleset was
  issued to. `pkg/graphfrag.FindingsSchemaVersion` follows to 1.9.
