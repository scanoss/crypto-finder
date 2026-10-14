- Findings no longer depend on where the scanned project or dependency lies. opengrep
  1.30.2's taint results depended on the target's absolute path string (a class whose
  constructors delegate with `this(...)` reported a field-borne flow, for example
  `pbkdf2-detailed` on a key length, for some directory names and not others), so the same
  code found different assets under another `$HOME`, checkout path or mining job workspace.
  The opengrep adapter now runs every opengrep process, CLI and `--opengrep-mode core`
  alike, inside the scanned project with project-relative targets, and dependency scans
  inside the package store holding the dependency (crypto-finder's source cache, the Go
  module cache, Cargo's registry, the project directory above `node_modules`, the
  directory above `site-packages`), so opengrep sees each file by its place in the store,
  the same on every host; dependencies of one store still share a process. Report,
  findings and `--export-graph-fragment` paths and rule ids are unchanged. Which taint
  flows opengrep reports for a file can still change once when upgrading, since it now
  sees the relative path.
- `--exclude` patterns, the default exclusions and dependency test patterns no longer match
  directories above the scan target: a project checked out below a directory named like a
  pattern (`build`, `test`, `vendor`, `docs`, ...) was silently scanned without findings
  when given by an absolute path. In npm dependencies, `node_modules/` directories at any
  depth inside the package are skipped, as they are nested dependencies.
