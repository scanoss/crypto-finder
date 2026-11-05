- `scan --scan-dependencies` now links Rust calls into a crate whose package name holds a
  dash, or whose manifest sets `[lib] name`. Callgraph symbols of a Cargo dependency or
  workspace member are keyed by the crate's library name, the name source code writes
  (`cbench_transitive_libb.digest` for package `cbench-transitive-libb`), so a call such as
  `cbench_transitive_libb::digest(..)` from another crate resolves. Before, every finding in
  such a crate read `unreachable` with a one-frame chain. Dependency identity
  (`dependency_info.module`, `purl`, `dependency.path`) keeps the package name.
