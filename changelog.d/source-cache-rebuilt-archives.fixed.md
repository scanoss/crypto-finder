- `--scan-dependencies` on Maven and Gradle projects scans the sources of a
  library rebuilt at the same version (a `-SNAPSHOT`, or a module reinstalled
  with `mvn install`). Before, crypto-finder kept scanning the sources it had
  extracted into `~/.scanoss/crypto-finder/cache/sources` from the earlier
  sources JAR until the cache was deleted by hand. Deleting a cache entry
  while another scan used it made that scan fail with opengrep
  `File not found` and drop the dependency's findings.
- An interrupted extraction of a sources JAR (a killed scan, a full disk) no
  longer leaves a partial cache entry that later scans read as the
  dependency's complete sources, and scans running side by side on one host
  no longer read an entry another scan is still extracting.
