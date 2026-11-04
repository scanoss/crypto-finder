- Remote rulesets are downloaded from `/v3/rulesets/{name}/{version}/download`
  first, falling back to the `/v2/cryptography/rulesets/...` endpoint only
  when `/v3` answers 404 (as it does until the gateway routes it). A v3
  ruleset comes with a signed lease (`SCANOSS-Ruleset-Lease`): its signature,
  expiry and bundle hash are checked on download and on every scan, the cache
  keeps it encrypted with the API key (`bundle.enc` and `lease.json`, no
  plain rule files), and each scan extracts it into a per-run directory that
  is removed when the scan ends. An expired lease is never used, not even as
  stale cache; the error names the expiry date and asks to download the
  ruleset again. When the TTL of a cached `latest` elapses, the ruleset is
  downloaded again only if `GET /v3/rulesets/{name}/{version}` reports a new
  release or the lease expires within 7 days. The production signing key
  `srv-2026-11` is built in; `SCANOSS_RULESET_PUBKEYS`
  (`id:base64pub,...`) adds trusted signing keys. Rulesets served from v2
  keep their current behavior.
- `crypto-finder rules import <bundle.tar.gz> [--lease <file>]` verifies an
  offline bundle against its lease (default `<bundle>.lease.json`) and stores
  it encrypted for use with `--ruleset-version` until the lease expires.
  `crypto-finder rules status` lists the cached rulesets with their mode
  (`leased` or `legacy`), lease expiry and signing key id.
- Interim report format 1.9: for a leased remote ruleset, `rules.checksum_sha256`
  is the release payload hash from the lease (`payload_sha256`), the same for
  every tenant, and `rules` carries an optional `lease` object (`expires_at`,
  `signing_key_id`). The report never names the key or tenant the ruleset was
  issued to. `pkg/graphfrag.FindingsSchemaVersion` follows to 1.9.
