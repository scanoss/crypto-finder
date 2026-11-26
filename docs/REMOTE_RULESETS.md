# Remote rulesets

Every scan detects with the `crypto-cards` ruleset that the SCANOSS API serves.
crypto-finder downloads it once, keeps it encrypted in a local cache, and
refreshes it when the cache expires. You need an API key with access to the
ruleset endpoints (`/v3/cryptography/rulesets`). With a local copy of a
ruleset, `--no-remote-rules --rules-dir <dir>` scans without the API.

## Quick path

```bash
crypto-finder configure --api-key YOUR_KEY       # once
crypto-finder scan /path/to/code                 # downloads and caches crypto-cards@latest
crypto-finder scan /path/to/code | jq '.rules'   # the ruleset name, version and checksum used
```

## Behavior

| Situation | What happens |
|---|---|
| First scan | Downloads `crypto-cards@latest` and caches it |
| Cache still fresh | Used without asking the API: 24 h for `latest`, 7 days for a pinned version |
| Cache expired | Asks the API for the current release; downloads only when it changed |
| API unreachable or 5xx, cache expired | Uses the expired cache with a warning, up to `--max-stale-age` (default `30d`, max `90d`); `--strict` fails instead |
| Lease expired | The cache is never used, not even as a fallback; the error names the expiry date |
| API refuses the key (HTTP 401 / 403) | Fails with `rules_load_failed`; the cache is not used, however recent |
| API requires an upgrade (HTTP 410 / 426) | Fails with `upgrade_required` and the server's message; no retry, no cache |
| Network error | Retried with exponential backoff |

**Leases.** Every downloaded ruleset comes with a signed lease that the API
issues for 24 hours. crypto-finder checks it on download and before every
scan. A machine that scans with remote rules must therefore reach the API at
least once a day; an air-gapped machine scans with local rules.

**At rest.** The cache holds the ruleset encrypted with a key derived from your
API key, never as plain rule files. It opens only with the API key that
downloaded it: after changing keys, run once with `--no-cache`.

## Choose and pin a ruleset

```bash
# Pin a release to rerun a scan with identical rules
crypto-finder scan --ruleset-version v1.39.0 /path/to/code

# Fetch another ruleset your key has access to
crypto-finder scan --ruleset <name> /path/to/code

# Add local rules to the remote ruleset
crypto-finder scan --rules-dir ./my-rules /path/to/code

# Local rules only, no API
crypto-finder scan --no-remote-rules --rules-dir ./local-rules /path/to/code
```

- The report's `rules` block records the ruleset name, version and checksum
  each scan used. Take the version to pin from there.
- Each ruleset numbers its own releases, so pin a version taken from a report
  made with the same `--ruleset`.
- `--ruleset` and `--ruleset-version` have no environment variable or config
  key, and cannot be combined with `--no-remote-rules`.
- `annotate` takes the same flags.

## Cache

```
~/.scanoss/crypto-finder/cache/rulesets/{name}/{version}/
```

Deleting it is safe: the next scan downloads the ruleset again. In Docker,
keep it in a volume ([DOCKER_USAGE.md](DOCKER_USAGE.md#mounts)).

## On-premises APIs

| Need | Setting |
|---|---|
| Another API URL | `--api-url`, `SCANOSS_API_URL` or `crypto-finder configure --api-url <url>` |
| Plain HTTP to a remote host | `--allow-http` ([CONFIGURATION.md](CONFIGURATION.md#settings)) |
| An API that signs leases with its own key | `SCANOSS_RULESET_PUBKEYS="<key-id>:<base64 Ed25519 public key>[,...]"` adds trusted keys. A lease signed by an untrusted key is rejected |

## Troubleshooting

### API key required

```
Error: API key required for remote rules
```

Set the key with `--api-key`, `SCANOSS_API_KEY` or
`crypto-finder configure --api-key <key>`. Or scan with local rules:
`--no-remote-rules --rules-dir <dir>`.

### Ruleset not found (404)

The API has no ruleset of that name, or does not serve
`/v3/cryptography/rulesets`. Check `--ruleset` and `--api-url`.

### Refused key (`rules_load_failed`, HTTP 401 / 403)

The key is invalid, revoked, or has no ruleset access. The message includes
the HTTP status (also in the failure's `http_status` detail). Check the key, or
ask SCANOSS for one with ruleset access. A revoked key keeps working only until
the cache expires (24 h for `latest`).

### Upgrade required (`upgrade_required`)

The API no longer serves this crypto-finder version. Upgrade:

```bash
go install github.com/scanoss/crypto-finder/cmd/crypto-finder@latest
```

### Stale cache warning

```
WARN: Failed to download remote rules (timeout). Using stale cache (age: 5d, ...)
```

The scan succeeds with the expired cache. Pass `--strict` to fail instead, for
example in a compliance pipeline that requires fresh rules.

### Cache too stale

When the cache is older than `--max-stale-age` and the API is still
unreachable, the scan fails with the download error. Wait for the API, raise
`--max-stale-age` (up to `90d`, never past the lease), or use local rules.

### Notices

An API answer may carry a `SCANOSS-Notice` header, for example the date a
crypto-finder version stops working. The request is not affected.
crypto-finder shows the first notice of a run once on stderr (a box on a
terminal, a `NOTICE:` line otherwise), and never while stderr carries JSON
(`--error-format json`, `--progress`).

## Related

- [CLIENT_SERVER.md](CLIENT_SERVER.md): every API call crypto-finder makes
- [CONFIGURATION.md](CONFIGURATION.md): API key, URL and other settings
- [ERROR_CODES.md](ERROR_CODES.md): `rules_load_failed`, `upgrade_required`
