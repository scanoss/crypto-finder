# Remote Rulesets

By default every scan uses the `crypto-cards` ruleset that the SCANOSS API serves: the cards the cards detector of crypto-finder 1.0 matches. `--ruleset <name>` fetches another ruleset. You only need an API key with access to `/v3/cryptography/rulesets`. The ruleset is downloaded once, verified, kept encrypted in a local cache, and refreshed when its TTL elapses. A scan with `--no-remote-rules --rules-dir <dir>` uses a local ruleset and calls no API.

## Quick path

```bash
crypto-finder configure --api-key YOUR_KEY   # once
crypto-finder scan /path/to/code             # downloads and caches crypto-cards@latest
crypto-finder scan /path/to/code | jq '.rules'   # name, version and checksum used
```

## At a glance

| Behavior | Value |
|---|---|
| Default ruleset | `crypto-cards@latest` (`--ruleset <name>`, `--ruleset-version <ver>`) |
| Cache location | `~/.scanoss/crypto-finder/cache/rulesets/{name}/{version}/` |
| Cache TTL | 24 h for `latest`, 7 days for a pinned version (`--ruleset-version v1.39.0`) |
| API unreachable or 5xx, cache expired | Stale cache used with a warning, up to `--max-stale-age` (default 30 days, max 90) and never past the lease expiry; `--strict` fails instead |
| API refuses the key (HTTP 401 / 403) | Fails with `rules_load_failed`; the cache is not used, however recent |
| Lease | Short: the API issues leases for 24 h by default, so a machine must reach the API at least daily to keep using remote rules |
| Integrity | SHA-256 checksum and a signed lease, verified on download and on every scan |
| At rest | Encrypted with a key derived from your API key; never plain rule files |
| Network failures | Retried with exponential backoff |
| API says "upgrade" (HTTP 410 / 426) | Fails with `upgrade_required`; no stale fallback |

## Configuration

### 1. API Key Setup

You can configure your API key using one of three methods (in priority order):

```bash
# Method 1: CLI flag (highest priority)
crypto-finder scan --api-key YOUR_KEY /path/to/code

# Method 2: Environment variable
export SCANOSS_API_KEY=YOUR_KEY
crypto-finder scan /path/to/code

# Method 3: Config file (recommended for persistent use)
crypto-finder configure --api-key YOUR_KEY
crypto-finder scan /path/to/code
```

### 2. API URL (Optional)

The default API URL is `https://api.scanoss.com`. To use a custom instance:

```bash
# Via configure command
crypto-finder configure --api-url https://custom.scanoss.com

# Via environment variable
export SCANOSS_API_URL=https://custom.scanoss.com

# Via CLI flag
crypto-finder scan --api-url https://custom.scanoss.com /path/to/code
```

## Usage Examples

```bash
# Use remote rules (default behavior with stale cache fallback)
crypto-finder scan /path/to/code

# Pin a ruleset release to rerun a scan with identical rules
# (the report's "rules" block records the release every scan used)
crypto-finder scan --ruleset-version v1.39.0 /path/to/code

# Fetch another ruleset than crypto-cards
crypto-finder scan --ruleset dca /path/to/code

# Combine remote rules with local custom rules
crypto-finder scan --rules-dir ./my-rules /path/to/code

# Disable remote rules
crypto-finder scan --no-remote-rules --rules-dir ./local-rules /path/to/code

# Force fresh download (bypass cache)
crypto-finder scan --no-cache /path/to/code

# Strict mode: fail if cache expired and API unreachable (no stale cache fallback)
crypto-finder scan --strict /path/to/code

# Configure maximum age for stale cache fallback (default: 30 days, max: 90 days)
crypto-finder scan --max-stale-age 60d /path/to/code  # 60 days
```

## Leased rulesets

crypto-finder downloads a ruleset from `GET /v3/cryptography/rulesets/{name}/{version}/download`, and only from there. Your API key needs access to `/v3/cryptography/rulesets`; without it there are no remote rules (use `--rules-dir` with `--no-remote-rules`). A 404 means the API has no such ruleset or does not serve `/v3/cryptography/rulesets`, and fails like any other download error:

```
ERROR: failed to load rules: failed to load rules from remote:crypto-cards@latest: failed to get ruleset 'crypto-cards@latest': failed to download ruleset: ruleset crypto-cards@latest not found: the SCANOSS API has no such ruleset or does not serve /v3/cryptography/rulesets (download failed: not found: resource does not exist: 404 Not Found)
```

### Choosing the ruleset

`scan` and `annotate` fetch `crypto-cards` unless `--ruleset <name>` names another ruleset (lowercase letters and digits joined by `-`, `_` or `.`). Like `--ruleset-version`, the flag has no environment variable or config key, and it cannot be combined with `--no-remote-rules`.

`--ruleset-version` picks a release of the ruleset `--ruleset` selects: `latest` (the default) or `vX.Y.Z`. Each ruleset numbers its own releases, so a version recorded by a scan with `dca` is not a `crypto-cards` release; take the version to pin from the `rules` block of a report made with the same ruleset.

`dca` holds OpenGrep rule YAML and no card files. crypto-finder 1.0 still loads it (it compiles the rules into a card index), but warns that the ruleset holds no card files and that its findings may be incomplete. Use `crypto-cards` with crypto-finder 1.0.

Every download carries a signed **lease** in the `SCANOSS-Ruleset-Lease` header (base64 of the lease envelope JSON); an answer without one is rejected. The lease names the ruleset and version, the hash of the release payload (`payload_sha256`) and of the served bytes (`bundle_sha256`, also sent as `X-Checksum-SHA256`), the key and tenant it was issued to (`key_ref`, `tenant`), its expiry (`expires_at`) and the id of the key that signed it (`signing_key_id`). The served bundle holds only rule files; it can be personalised per tenant, so its bytes differ between tenants for the same release.

- **On download**, crypto-finder checks `X-Checksum-SHA256`, the lease signature against its trusted signing keys, the expiry, and that the lease vouches for exactly the downloaded bytes. A bundle that fails any check is rejected and not cached.
- **In the cache**, it keeps `bundle.enc` (the bundle encrypted with AES-256-GCM under a key derived from your API key) and `lease.json`, never plain rule files. The cache opens only with the API key it was downloaded with; after changing keys, run once with `--no-cache`.
- **On every scan**, it decrypts the bundle, verifies the lease again (signature, expiry, bundle hash) and extracts the rules into a per-run directory under `~/.scanoss/crypto-finder/cache/rulesets/{name}/.crypto-finder-filtered/{version}/run-*`. The directory is removed when the scan ends, also when it fails; one left by a killed process is removed by a later scan after two hours.
- **Expiry**: an expired lease is never used, not even as stale cache. The scan fails with an error that names the expiry date; refresh the ruleset by scanning online with a valid API key, or scan with `--rules-dir`. Leases are short: the SCANOSS API issues them for 24 hours by default, so a machine must reach the API at least once a day to keep using remote rules.
- **Refused key**: an API answer of HTTP 401 or 403 (an invalid or revoked key, or a key without ruleset access) on the release check or on the download is final. The scan fails with `rules_load_failed` and the HTTP status, and the cached ruleset is not opened, however recent it is. A cached ruleset whose TTL has not elapsed is used without asking the API, so a revoked key is refused at the first scan after the TTL (24 hours for `latest`).
- **Freshness**: when the cache TTL of a ruleset elapses, crypto-finder asks `GET /v3/cryptography/rulesets/{name}/{version}` for the current release and downloads again only when the version or `payload_sha256` differs from the cached lease, or when the cached lease expires within 7 days. Otherwise it records the check and keeps the cache.
- **Report**: `checksum_sha256` in the report's `rules` block is the lease's `payload_sha256`, the same for every tenant, never the hash of the personalised bundle; the block adds `lease: {expires_at, signing_key_id}`. Neither names the key or the tenant.

### Trusted signing keys

crypto-finder trusts the signing keys built into it: `srv-2026-11`, the key the SCANOSS API signs leases with. `SCANOSS_RULESET_PUBKEYS` adds keys (for example a test or on-premises API) or replaces a built-in key of the same id:

```bash
export SCANOSS_RULESET_PUBKEYS="srv-2026-11:BASE64_ED25519_PUBLIC_KEY[,other-id:BASE64...]"
```

Each entry is a key id and the base64 of a raw 32-byte Ed25519 public key. A lease signed by a key that is not trusted is rejected.

## Cache Management

### Cache Location

```
~/.scanoss/crypto-finder/cache/rulesets/{name}/{version}/
  ├── bundle.enc                 # The ruleset bundle, encrypted with your API key
  ├── lease.json                 # The signed lease issued with it
  └── .cache-meta.json           # Cache metadata (timestamps, checksum, TTL, lease expiry, languages)
```

`.cache-meta.json` records `expires_at` (the lease expiry) and, as `checksum_sha256`, the release payload hash from the lease, the same value the report carries.

A ruleset cached as plain rule files by an older crypto-finder is never loaded as rules, not even as stale cache. crypto-finder warns `Ignoring a ruleset cached by an older crypto-finder; downloading it again` and downloads the ruleset; only when that download succeeds does it replace the old directory (written to a temporary directory and swapped in). When the download fails, the old directory is left as it is, unused, and the scan fails with the download error. Only this cache directory is affected; directories passed with `--rules-dir` are never touched.

`.cache-meta.json` also lists the languages the ruleset's rules cover, so they can be read without the rule files, which the cache does not keep in plain form:

```json
"languages": ["java", "python"]
```

The list is computed when the ruleset is stored, from the verified bundle before it is encrypted: each rule's `languages`, lowercased, deduplicated and sorted, `generic` for a rule that names none. The field is left out when the ruleset has no rules or its rule files cannot be parsed.

### Cache Behavior

- **First scan**: Downloads and caches the default `crypto-cards` ruleset
- **Subsequent scans**: Uses cached version if not expired
- **Expired cache**: Automatically re-downloads on next scan
- **API unreachable or 5xx + expired cache**: Uses stale cache as fallback (if within max age limit and before its lease expires)
- **API refuses the key (401/403)**: Fails with `rules_load_failed`; never the stale cache
- **Manual cleanup**: Simply delete `~/.scanoss/crypto-finder/cache/`

### Stale Cache Fallback (Default Behavior)

When the cache expires and the API is unreachable or answers with a server error, crypto-finder automatically falls back to the expired cache if it's within the maximum stale age (default: 30 days):

**Flow:**
1. Check if cache is valid (not expired)
   - ✅ Valid → Use cached rules
2. Cache expired → Try to download fresh rules from API
   - ✅ API reachable → Download and update cache
   - ❌ API unreachable → Check stale cache fallback:
     - If cache age ≤ max stale age (30 days) → **Use stale cache with warning**
     - If cache age > max stale age → **Fail with error**
     - If `--strict` flag enabled → **Fail with error**
   - ❌ API answers that this crypto-finder must be upgraded (HTTP 410 or 426, see [Upgrade required](#upgrade-required)) → **Fail with the server's message**, never the stale cache
   - ❌ API refuses the key (HTTP 401 or 403, on the release check or the download) → **Fail with `rules_load_failed`**, never the stale cache

**Why This Matters:**
- **Resilience**: Transient API issues don't block scans
- **CI/CD Reliability**: Pipelines don't fail due to infrastructure problems
- **Offline Capability**: Continue scanning with slightly stale rules

**When to Use `--strict`:**
- Compliance audits requiring fresh rules
- Security-critical scans where staleness is unacceptable
- Environments where failure is preferred over using outdated rules

## Troubleshooting

### No API Key Error

```
Error: API key required for remote rules

Configure your API key using one of:
  1. CLI flag:    crypto-finder scan --api-key <key> [target]
  2. Environment: export SCANOSS_API_KEY=<key>
  3. Config file: crypto-finder configure --api-key <key>

Or disable remote rules: crypto-finder scan --no-remote-rules [target]
```

**Solution**: Configure your API key using any of the methods above.

### Cache Not Available / Air-Gapped Environments

An air-gapped environment scans with local rules (add `--scan-dependencies --offline` for dependencies; see [OFFLINE.md](OFFLINE.md)):

```bash
crypto-finder scan --no-remote-rules --rules-dir ./local-rules /path/to/code
```

A cache downloaded while connected and transferred (`~/.scanoss/crypto-finder/cache/`) is used within its TTL (24h for latest, 7d for pinned versions), then as stale cache (up to 30 days) with a warning, only with the same API key and never past its lease expiry. Leases are short (24 hours by default), so a transferred cache stops working within a day of its download; air-gapped scans use local rules.

### Upgrade required

When the SCANOSS API no longer serves your crypto-finder version, a ruleset download from `/v3/cryptography/rulesets/...` answers HTTP 410 Gone or 426 Upgrade Required. That answer is final: crypto-finder does not retry it and does not fall back to a cached ruleset. The scan fails with the code `upgrade_required` and prints the server's message on its own:

```
ERROR: crypto-finder must be upgraded to download rulesets.
Run: go install github.com/scanoss/crypto-finder/cmd/crypto-finder@latest
```

The message is taken from `error.message` of a JSON error body (`{"status":"error","error":{"code":…,"message":…}}`, with the code in parentheses) or from a `text/plain` body; control characters are removed and it is cut at 10 lines and 1000 characters. A cached ruleset whose TTL has not elapsed is still used until it does, since no request is made then.

**Solution**: upgrade crypto-finder.

### Refused API key

A refused API key (HTTP 401 or 403, on the release check or the download) fails the scan with `rules_load_failed` and reads `the SCANOSS API refused the ruleset download (HTTP 403): <server message>`, with the status in the failure's `http_status` detail. It is final: crypto-finder does not fall back to a cached ruleset, however recent, so a revoked key stops scanning with remote rules as soon as the API is asked again (when the cache TTL elapses, or at once with `--no-cache`).

**Solution**: check the key with `crypto-finder configure`, or ask for one with access to `/v3/cryptography/rulesets`.

### Notices from the SCANOSS API

Any answer of the SCANOSS API (ruleset downloads and dependency findings alike) may carry a `SCANOSS-Notice` header, for example to announce that a crypto-finder version stops working on a given date. The request is not affected. crypto-finder shows the first notice of a run once, however many requests carry it: in a box on a terminal, and as one `NOTICE: <text>` line on stderr otherwise. Nothing is shown while stderr carries JSON (`--error-format json` or `--progress`). The text is cleaned like an upgrade-required message. crypto-finder 0.55.0 reads the header as `X-SCANOSS-Notice`; later versions read `SCANOSS-Notice`.

```
┌─ SCANOSS ───────────────────────────────────────────────┐
| crypto-finder 0.54 stops working on 2026-12-15. Update: |
| https://github.com/scanoss/crypto-finder/releases       |
└─────────────────────────────────────────────────────────┘
```

### API Unreachable / Network Timeout

When the API is unreachable and expired cache exists, crypto-finder will automatically fall back to stale cache with a warning:

**Example Warning:**
```
WARN: Failed to download remote rules (timeout). Using stale cache (age: 5d, cached: 2025-01-10 10:30:00 UTC)
```

**Behavior:**
- Scan continues successfully using stale cache
- Warning is logged to stderr
- Exit code is 0 (success)

**To Disable Fallback (Fail Instead):**
```bash
crypto-finder scan --strict /path/to/code
```

### Cache Too Stale

If cached rules exceed the maximum stale age (default: 30 days), the scan will fail:

**Error:**
```
Error: failed to download ruleset: server error: please try again later: 500 Internal Server Error
```

**Solutions:**
1. **Wait for API to recover** and retry
2. **Increase max stale age** (up to 90 days):
   ```bash
   crypto-finder scan --max-stale-age 90d /path/to/code  # 90 days
   ```
3. **Use local rules** instead:
   ```bash
   crypto-finder scan --no-remote-rules --rules-dir ./local-rules /path/to/code
   ```

## Best Practices

1. **Initial Setup**: Configure API key once using `crypto-finder configure --api-key <key>`
2. **Hybrid Approach**: Combine remote rules with project-specific local rules for customization
3. **CI/CD Pipelines**:
   - Use environment variable `SCANOSS_API_KEY` for secure key management
   - **Default behavior** (with stale cache fallback) is recommended for most pipelines to prevent failures due to transient API issues
   - Use `--strict` for compliance-critical pipelines where fresh rules are mandatory
   - Consider using `--max-stale-age` to tune the acceptable staleness window (e.g., `--max-stale-age 7d` for 7 days)
4. **Offline/Air-Gapped Environments**:
   - Pre-cache rules before going offline
   - Stale cache fallback lasts until the lease expires (24 hours by default), whatever `--max-stale-age` allows
   - For longer periods, use `--no-remote-rules --rules-dir` with local rules

## Related Documentation

- [Configuration](CONFIGURATION.md) - settings, paths and skip patterns
- [Client and server](CLIENT_SERVER.md) - every API call crypto-finder makes
- [Main README](../README.md) - General usage and installation
