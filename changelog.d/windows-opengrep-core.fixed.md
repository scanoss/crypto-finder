- On Windows, scans run OpenGrep's core mode again: `opengrep-core.exe` is found
  in the OpenGrep cache. Before, every Windows scan fell back to the OpenGrep CLI
  and logged "no opengrep-core 1.22.0 found".
- OpenGrep runs with a temporary directory of its own that is removed when the
  scan ends. On Windows the OpenGrep CLI used to leave copies of the decrypted
  rules (`semgrep-*.rules`, `tmp*.json`) in `%TEMP%` after every scan.
- The "Using stale cache" warning shows the cache age in days and hours and the
  download time as a date, instead of milliseconds and a Unix timestamp.
