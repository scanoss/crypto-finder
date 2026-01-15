# Remote Rulesets

Crypto Finder can automatically fetch curated rulesets from the SCANOSS API, providing always-up-to-date cryptographic detection rules without manual management.

## Features

- **Automatic Downloads**: Default "dca" (deep code analysis) ruleset is automatically fetched on first scan
- **Local Caching**: Downloaded rulesets are cached at `~/.scanoss/crypto-finder/cache/`
- **TTL-Based Expiration**:
  - Pinned versions (e.g., `v1.0.0`): 7 days
  - Latest versions: 24 hours
- **Automatic Fallback**: Uses cached rules when API is unreachable
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
# Use remote rules (default behavior)
crypto-finder scan /path/to/code

# Combine remote rules with local custom rules
crypto-finder scan --rules-dir ./my-rules /path/to/code

# Disable remote rules
crypto-finder scan --no-remote-rules --rules-dir ./local-rules /path/to/code

# Force fresh download (bypass cache)
crypto-finder scan --no-cache /path/to/code
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
- **Manual cleanup**: Simply delete `~/.scanoss/crypto-finder/cache/`

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

### Cache Not Available

If you're in an air-gapped environment and need to use cached rules:

**Solution**:
1. Run a scan while connected to download and cache rulesets
2. Transfer the cache directory (`~/.scanoss/crypto-finder/cache/`) to the air-gapped environment
3. The tool will automatically use cached rules when the API is unreachable

### Network Timeout

If the API is unreachable but cached rules exist, crypto-finder will automatically fall back to the cache with a warning:

```
Warning: Failed to download remote rules (timeout)
Using cached rules from 2025-01-15 10:30:00
```

## Best Practices

1. **Initial Setup**: Configure API key once using `crypto-finder configure --api-key <key>`
2. **Hybrid Approach**: Combine remote rules with project-specific local rules for customization
3. **CI/CD Pipelines**:
   - Use environment variable `SCANOSS_API_KEY` for secure key management
   - Use `--no-cache` to ensure latest rules in critical security scans

## Related Documentation

- [Configuration](CONFIGURATION.md) - scanoss.json and skip patterns
- [Main README](../README.md) - General usage and installation
