- `--scan-dependencies` with `--dep-ecosystem auto` (the default) now resolves
  dependencies for an ecosystem that has a manifest, instead of always taking
  the language with the most files. A Flask application with a
  `requirements.txt`, whose browser JavaScript outnumbers its Python and that
  has no `package.json`, used to pick Node and skip the dependency phase with
  `manifest_absent`; it now resolves its Python dependencies. The ecosystems
  of the detected languages, dominant first, are tried before the other
  ecosystems whose manifest sits at the target, and the first one whose
  resolver can read the target or a module root below it is picked. Python,
  which reads the interpreter's installed packages rather than a manifest, is
  picked over the dominant language only when the target has a Python
  manifest (`pyproject.toml`, `requirements.txt`, `Pipfile` or `setup.py`).
  When no ecosystem can be resolved the scan skips the phase exactly as
  before. An explicit `--dep-ecosystem` is unchanged.
- The skipped `dependencies` event of `--progress` now names the ecosystem it
  skipped in the new optional `details.ecosystem` (for example
  `{"reason": "lockfile_absent", "ecosystem": "node"}`). It is absent for
  `ecosystem_unknown` and `not_requested`. The progress schema stays at
  version `1`, and `schemas/scan-progress-schema.json` declares the field.
