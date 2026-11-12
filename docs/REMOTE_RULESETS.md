# Remote Rulesets

Crypto Finder can automatically fetch curated rulesets from the SCANOSS API, providing always-up-to-date cryptographic detection rules without manual management.

## Features

- **Automatic Downloads**: Default "dca" (deep code analysis) ruleset is automatically fetched on first scan
- **Local Caching**: Downloaded rulesets are cached at `~/.scanoss/crypto-finder/cache/`
- **TTL-Based Expiration**:
  - Pinned versions (e.g., `v1.0.0`): 7 days
  - Latest versions: 24 hours
- **Stale Cache Fallback**: Automatically uses expired cache (up to 30 days old) when API is unreachable (opt-out with `--strict`)
- **Checksum Verification**: SHA256 verification ensures ruleset integrity
- **Signed Leases**: A ruleset served with a signed lease is verified (signature, expiry, bundle hash) on download and again on every scan, and is kept encrypted in the cache (see [Leased rulesets](#leased-rulesets))
- **Retry Logic**: Automatic retry with exponential backoff on network failures
- **Seamless Integration**: Combine remote and local rules effortlessly

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

crypto-finder downloads a ruleset from `GET /v3/rulesets/{name}/{version}/download`. When that endpoint answers 404 (a server or gateway that does not route `/v3/rulesets` yet), crypto-finder downloads from `/v2/cryptography/rulesets/{name}/{version}/download` and caches the ruleset as plain rule files, as described under [Cache Management](#cache-management). Any other answer from `/v3`, a 401 or 403 included, is reported as is and never retried on `/v2`.

A v3 download carries a signed **lease** in the `SCANOSS-Ruleset-Lease` header (base64 of the lease envelope JSON). The lease names the ruleset and version, the hash of the release payload (`payload_sha256`) and of the served bytes (`bundle_sha256`, also sent as `X-Checksum-SHA256`), the key and tenant it was issued to (`key_ref`, `tenant`), its expiry (`expires_at`) and the id of the key that signed it (`signing_key_id`). The served bundle holds only rule files; it can be personalised per tenant, so its bytes differ between tenants for the same release. A ruleset that comes with a lease is a **leased** ruleset:

- **On download**, crypto-finder checks `X-Checksum-SHA256`, the lease signature against its trusted signing keys, the expiry, and that the lease vouches for exactly the downloaded bytes. A bundle that fails any check is rejected and not cached.
- **In the cache**, it keeps `bundle.enc` (the bundle encrypted with AES-256-GCM under a key derived from your API key) and `lease.json`, never plain rule files. The cache opens only with the API key it was downloaded with; after changing keys, run once with `--no-cache`.
- **On every scan**, it decrypts the bundle, verifies the lease again (signature, expiry, bundle hash) and extracts the rules into a per-run directory under `~/.scanoss/crypto-finder/cache/rulesets/{name}/.crypto-finder-filtered/{version}/run-*`. The directory is removed when the scan ends, also when it fails; one left by a killed process is removed by a later scan after two hours. With a leased ruleset, OpenGrep core mode writes its rules file to a temporary file instead of keeping it in `~/.scanoss/crypto-finder/cache/opengrep-core-rules/`.
- **Expiry**: an expired lease is never used, not even as stale cache. The scan fails with an error that names the expiry date; refresh the ruleset by scanning online with a valid API key (or importing a new bundle), or scan with `--rules-dir`.
- **Freshness**: when the cache TTL of a leased ruleset elapses, crypto-finder asks `GET /v3/rulesets/{name}/{version}` for the current release and downloads again only when the version or `payload_sha256` differs from the cached lease, or when the cached lease expires within 7 days. Otherwise it records the check and keeps the cache.
- **Report**: `checksum_sha256` in the report's `rules` block is the lease's `payload_sha256`, the same for every tenant, never the hash of the personalised bundle; the block adds `lease: {expires_at, signing_key_id}`. Neither names the key or the tenant.

### Trusted signing keys

crypto-finder trusts the signing keys built into it: `srv-2026-11`, the key the SCANOSS API signs leases with. `SCANOSS_RULESET_PUBKEYS` adds keys (for example a test or on-premises API) or replaces a built-in key of the same id:

```bash
export SCANOSS_RULESET_PUBKEYS="srv-2026-11:BASE64_ED25519_PUBLIC_KEY[,other-id:BASE64...]"
```

Each entry is a key id and the base64 of a raw 32-byte Ed25519 public key. A lease signed by a key that is not trusted is rejected.

### Offline bundles

An air-gapped installation receives a bundle (`dca-v1.40.0.tar.gz`) and the lease envelope issued with it (the JSON `scanoss-services ruleset lease` prints). Import them once:

```bash
crypto-finder rules import dca-v1.40.0.tar.gz                     # reads dca-v1.40.0.tar.gz.lease.json
crypto-finder rules import dca-v1.40.0.tar.gz --lease lease.json  # lease elsewhere
crypto-finder scan --ruleset-version v1.40.0 /path/to/code
```

`rules import` verifies the bundle against the lease like a download and stores it encrypted with the configured API key under the name and version the lease names. An imported ruleset counts as current until its lease expires, so scans with `--ruleset-version <version>` use it without contacting the API.

### Listing the cache

```bash
$ crypto-finder rules status
NAME  VERSION  MODE    EXPIRES AT            KEY ID       LANGUAGES
dca   latest   leased  2026-12-04T10:00:00Z  srv-2026-11  c,generic,go,java,python
dca   v1.39.0  legacy  -                     -            c,generic,go,java,python
```

`MODE` is `leased` for an encrypted, lease-bound ruleset and `legacy` for plain rule files from the v2 endpoint. `LANGUAGES` is the `languages` list from the cache metadata (`-` for a ruleset cached before crypto-finder recorded it).

## Cache Management

### Cache Location

```
~/.scanoss/crypto-finder/cache/rulesets/{name}/{version}/
  ├── manifest.json              # Ruleset metadata
  ├── .cache-meta.json           # Cache metadata (timestamps, checksum, TTL, languages)
  └── [language dirs]/           # Rule files organized by language
```

A leased ruleset holds `bundle.enc`, `lease.json` and `.cache-meta.json` (with `leased: true`, `expires_at`, and the release payload hash from the lease as `checksum_sha256`, the same value the report carries) instead.

`.cache-meta.json` also lists the languages the ruleset's rules cover, so they can be read without the rule files, which a leased cache does not keep in plain form:

```json
"languages": ["c", "generic", "go", "java", "python"]
```

The list is computed when the ruleset is stored (for a leased ruleset, from the bundle after it is verified and before it is encrypted): every `.yaml`/`.yml` rule file outside `.crypto-finder-filtered`, each rule's `languages` lowercased and trimmed, `generic` for a rule that names none, without duplicates and sorted. The field is left out when the ruleset has no rules or its rule files cannot be parsed.

### Cache Behavior

- **First scan**: Downloads and caches the default "dca" ruleset
- **Subsequent scans**: Uses cached version if not expired
- **Expired cache**: Automatically re-downloads on next scan
- **API unreachable + expired cache**: Uses stale cache as fallback (if within max age limit and, for a leased ruleset, before its lease expires)
- **Manual cleanup**: Simply delete `~/.scanoss/crypto-finder/cache/`

### Stale Cache Fallback (Default Behavior)

When the cache expires and the API is unreachable, crypto-finder automatically falls back to the expired cache if it's within the maximum stale age (default: 30 days):

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

If you're in an air-gapped environment and need to use cached rules:

**Solution**:
1. Import an offline bundle with `crypto-finder rules import` (see [Offline bundles](#offline-bundles)) and scan with `--ruleset-version <version>`, or
2. Run a scan while connected to download and cache rulesets, then transfer the cache directory (`~/.scanoss/crypto-finder/cache/`) to the air-gapped environment. The tool uses the cache within the TTL period (24h for latest, 7d for pinned versions), then falls back to the stale cache (up to 30 days) with a warning. A leased ruleset also needs the same API key there and stops at its lease expiry.
3. For long-term offline use without a bundle, use `--no-remote-rules --rules-dir` with local rules

### Upgrade required

When the SCANOSS API no longer serves your crypto-finder version, a ruleset download (`/v3/rulesets/...` or the `/v2` fallback) answers HTTP 410 Gone or 426 Upgrade Required. That answer is final: crypto-finder does not retry it, does not ask the other endpoint, and does not fall back to a cached ruleset. The scan fails with the code `upgrade_required` and prints the server's message on its own:

```
ERROR: crypto-finder must be upgraded to download rulesets.
Run: go install github.com/scanoss/crypto-finder/cmd/crypto-finder@latest
```

The message is taken from `error.message` of a JSON error body (`{"status":"error","error":{"code":…,"message":…}}`, with the code in parentheses) or from a `text/plain` body; control characters are removed and it is cut at 10 lines and 1000 characters. A cached ruleset whose TTL has not elapsed is still used until it does, since no request is made then.

**Solution**: upgrade crypto-finder.

A refused API key (HTTP 401 or 403) reads `the SCANOSS API refused the ruleset download (HTTP 403): <server message>`; like an unreachable API, it still falls back to a stale cache when one is available.

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
   - Stale cache fallback provides up to 30 days of grace period (configurable to 90 days)
   - For longer periods, use `--no-remote-rules --rules-dir` with local rules

## Related Documentation

- [Configuration](CONFIGURATION.md) - scanoss.json and skip patterns
- [Main README](../README.md) - General usage and installation
