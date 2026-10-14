- The dependency findings cache no longer serves one install's findings for another
  install of the same package version whose source differs. For dependencies in
  `node_modules`, `site-packages`, `dist-packages` and crypto-finder's own source cache
  (Maven and Gradle sources), which hold whatever was installed under a version's name,
  the cache key now also hashes the dependency's file contents: a git fork or
  `patch-package` edit of `lodash@4.17.21`, a pip install from a path or a git URL, or a
  Maven SNAPSHOT extracted again is scanned rather than reused, including through a
  findings cache shared between projects or tenants (the Postgres backend). Identical
  content installed in another home, host or checkout still reuses the entry. Entries
  of the Go module cache and of Cargo's registry and git checkouts keep their
  module@version keys, since those stores verify their content. A dependency whose
  source cannot be read is scanned and not cached. Entries of the affected stores
  written by earlier versions are rescanned once.
