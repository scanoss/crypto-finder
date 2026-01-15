# Configuration

Crypto Finder supports flexible configuration through multiple mechanisms: `scanoss.json` files, command-line flags, and environment variables.

## Configuration Priority

Settings are applied in the following priority order (highest to lowest):

1. **Command-line flags** (e.g., `--api-key`, `--scanner`)
2. **Environment variables** (e.g., `SCANOSS_API_KEY`)
3. **Config file** (`~/.scanoss/crypto-finder/config.json`)
4. **Project settings** (`scanoss.json` in target directory)
5. **Default values**

## Application Configuration

### Config File Location

```
~/.scanoss/crypto-finder/config.json
```

### Setting Up Configuration

Use the `configure` command to set persistent application settings:

```bash
# Configure API key
crypto-finder configure --api-key YOUR_API_KEY

# Configure custom API URL
crypto-finder configure --api-url https://custom.scanoss.com

# Configure both
crypto-finder configure --api-key YOUR_KEY --api-url https://custom.scanoss.com
```

### Config File Format

```json
{
  "api_key": "your-scanoss-api-key",
  "api_url": "https://api.scanoss.com"
}
```

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SCANOSS_API_KEY` | SCANOSS API key for remote rulesets | `export SCANOSS_API_KEY=abc123` |
| `SCANOSS_API_URL` | Custom API base URL | `export SCANOSS_API_URL=https://custom.com` |

## Project Configuration (scanoss.json)

The `scanoss.json` file in your project directory configures scan behavior and skip patterns.

### File Location

Place `scanoss.json` in the root of the directory you're scanning:

```
your-project/
├── scanoss.json
├── src/
└── ...
```

### Configuration Schema

Crypto Finder follows the [SCANOSS Settings Schema](https://scanoss.readthedocs.io/projects/scanoss-py/en/latest/scanoss_settings_schema.html).

### Basic Example

```json
{
  "settings": {
    "skip": {
      "patterns": {
        "scanning": [
          "node_modules/",
          "target/",
          "venv/",
          "*.min.js"
        ]
      },
      "sizes": {
        "max_file_size": 10485760
      }
    }
  }
}
```

## Skip Patterns

Skip patterns control which files and directories are excluded from scanning.

### Default Skip Patterns

The following patterns are automatically excluded:

**Version Control:**
- `.git/`
- `.svn/`
- `.hg/`
- `.bzr/`

**Dependencies:**
- `node_modules/`
- `vendor/`
- `venv/`
- `virtualenv/`
- `__pycache__/`

**Build Artifacts:**
- `dist/`
- `build/`
- `target/`
- `*.min.js`
- `*.min.css`

**Archives:**
- `*.zip`
- `*.tar`
- `*.tar.gz`
- `*.tar.bz2`
- `*.jar`
- `*.war`
- `*.ear`

**Binaries:**
- `*.exe`
- `*.dll`
- `*.so`
- `*.dylib`
- `*.bin`

For the complete list, see [Default Skip Patterns](../internal/skip/source_defaults.go).

### Custom Skip Patterns

#### Pattern Types

1. **Directory patterns** (end with `/`):
   ```json
   {
     "settings": {
       "skip": {
         "patterns": {
           "scanning": ["custom-dir/", "temp/"]
         }
       }
     }
   }
   ```

2. **File extension patterns**:
   ```json
   {
     "settings": {
       "skip": {
         "patterns": {
           "scanning": ["*.log", "*.tmp", "*.cache"]
         }
       }
     }
   }
   ```

3. **Specific file patterns**:
   ```json
   {
     "settings": {
       "skip": {
         "patterns": {
           "scanning": ["package-lock.json", "yarn.lock"]
         }
       }
     }
   }
   ```

4. **Path patterns**:
   ```json
   {
     "settings": {
       "skip": {
         "patterns": {
           "scanning": ["src/generated/", "test/fixtures/"]
         }
       }
     }
   }
   ```

### Size Limits

Configure maximum file size to scan:

```json
{
  "settings": {
    "skip": {
      "sizes": {
        "max_file_size": 10485760
      }
    }
  }
}
```

## Advanced Configuration Examples

### Monorepo Configuration

For large monorepos with multiple subprojects:

```json
{
  "settings": {
    "skip": {
      "patterns": {
        "scanning": [
          "*/node_modules/",
          "*/dist/",
          "*/build/",
          "*/target/",
          "docs/",
          "scripts/",
          "*.test.js",
          "*.spec.ts"
        ]
      }
    }
  }
}
```

### Frontend Project Configuration

Optimized for JavaScript/TypeScript projects:

```json
{
  "settings": {
    "skip": {
      "patterns": {
        "scanning": [
          "node_modules/",
          "dist/",
          "build/",
          ".next/",
          ".nuxt/",
          "coverage/",
          "*.min.js",
          "*.bundle.js",
          "*.map"
        ]
      }
    }
  }
}
```

### Backend Project Configuration

Optimized for Java/Python/Go projects:

```json
{
  "settings": {
    "skip": {
      "patterns": {
        "scanning": [
          "target/",
          "venv/",
          "vendor/",
          "__pycache__/",
          "*.pyc",
          "*.class",
          "*.jar"
        ]
      }
    }
  }
}
```

### CI/CD Optimized Configuration

Minimal scanning for fast CI/CD pipelines:

```json
{
  "settings": {
    "skip": {
      "patterns": {
        "scanning": [
          "node_modules/",
          "vendor/",
          "venv/",
          "target/",
          "dist/",
          "build/",
          "test/",
          "tests/",
          "*.test.*",
          "*.spec.*",
          "*.min.*"
        ]
      }
    }
  }
}
```

## Scanner Configuration

### Choosing a Scanner

Crypto Finder supports multiple scanners. Select via command-line flag:

```bash
# Use OpenGrep (default, recommended)
crypto-finder scan /path/to/code

# Use Semgrep
crypto-finder scan --scanner semgrep /path/to/code
```

## Language Detection

### Automatic Detection

By default, crypto-finder uses [go-enry](https://github.com/go-enry/go-enry) to automatically detect project languages.

### Manual Override

Override detected languages when needed:

```bash
# Scan only Java and Python files
crypto-finder scan --languages java,python /path/to/code

# Scan single language
crypto-finder scan --languages go /path/to/code
```

### Supported Languages

The scanner supports rules for:

- C/C++
- C#
- Go
- Java
- JavaScript/TypeScript
- Kotlin
- PHP
- Python
- Ruby
- Rust
- Swift
- And more...

Language detection ensures only relevant rules are loaded, improving scan performance.

## Timeout Configuration

### Default Timeout

Default scan timeout: **10 minutes**

### Custom Timeout

```bash
# 30 minute timeout
crypto-finder scan --timeout 30m /path/to/code

# 2 hour timeout
crypto-finder scan --timeout 2h /path/to/code

# 90 second timeout
crypto-finder scan --timeout 90s /path/to/code
```

### Recommended Timeouts

| Project Size | Recommended Timeout |
|--------------|---------------------|
| Small (<1000 files) | 5m |
| Medium (1000-10000 files) | 15m |
| Large (10000-50000 files) | 30m |
| Very Large (>50000 files) | 1h+ |

## Output Configuration

### Output Destination

```bash
# Write to file
crypto-finder scan --output results.json /path/to/code

# Write to stdout (default)
crypto-finder scan /path/to/code

# Pipe to another tool
crypto-finder scan /path/to/code | jq '.findings | length'
```

### Output Format

```bash
# SCANOSS Interim JSON format (default)
crypto-finder scan --format json /path/to/code

# CycloneDX CBOM format
crypto-finder scan --format cyclonedx /path/to/code
```

## Logging Configuration

### Verbosity Levels

```bash
# Normal output
crypto-finder scan /path/to/code

# Verbose logging (info level)
crypto-finder scan -v /path/to/code
crypto-finder scan --verbose /path/to/code

# Debug mode (debug info)
crypto-finder scan -d /path/to/code
crypto-finder scan --debug /path/to/code
```

## Related Documentation

- [Main README](../README.md) - Overview and quick start
- [Remote Rulesets](REMOTE_RULESETS.md) - API key and ruleset configuration
- [Docker Usage](DOCKER_USAGE.md) - Container configuration
- [SCANOSS Settings Schema](https://scanoss.readthedocs.io/projects/scanoss-py/en/latest/scanoss_settings_schema.html) - Official schema documentation
