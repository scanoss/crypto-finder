- Dependency findings cache entries for published package versions are now portable across
  home directories, hosts and checkout paths. The key no longer holds the dependency's
  absolute source directory when it lies in a package store (crypto-finder's source cache
  for Maven/Gradle, the Go module cache, Cargo's registry and git checkouts, `node_modules`,
  `site-packages`), only its place in that store (for example
  `sources:io.jsonwebtoken-jjwt-impl/0.12.6`), and keys the working directory only when rule
  files lie below it. Dependencies from local directories (a Go `replace` naming a path) and
  scans with extra scanner arguments or the `semgrep` scanner keep keying the absolute
  directory and working directory. Existing entries are rescanned once.
