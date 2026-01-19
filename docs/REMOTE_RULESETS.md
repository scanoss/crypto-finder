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

## Cache Management

### Cache Location

```
~/.scanoss/crypto-finder/cache/rulesets/{name}/{version}/
  ├── manifest.json              # Ruleset metadata
  ├── .cache-meta.json           # Cache metadata (timestamps, checksum, TTL)
  └── [language dirs]/           # Rule files organized by language
```

### Cache Behavior

- **First scan**: Downloads and caches the default "dca" ruleset
- **Subsequent scans**: Uses cached version if not expired
- **Expired cache**: Automatically re-downloads on next scan
- **API unreachable + expired cache**: Uses stale cache as fallback (if within max age limit)
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
1. Run a scan while connected to download and cache rulesets
2. Transfer the cache directory (`~/.scanoss/crypto-finder/cache/`) to the air-gapped environment
3. The tool will automatically use the cache within the TTL period (24h for latest, 7d for pinned versions)
4. After TTL expires, scans will use stale cache fallback (up to 30 days) with a warning
5. For long-term offline use, consider using `--no-remote-rules --rules-dir` with local rules

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
