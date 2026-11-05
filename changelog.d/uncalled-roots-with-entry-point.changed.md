- Reachability with application code known (`scan --scan-dependencies`,
  `--export-callgraph-project-reachability`) no longer takes an application function nothing
  calls as a chain root when its module has a recognized entry point: `main`, a Python
  `if __name__ == "__main__":` module or console script, a `package.json` `main` or `bin`
  target, `require.main === module`, or a framework entry from the entry-point catalog. Crypto
  that only such dead code reaches now reads `unreachable` instead of `reachable` with a
  `no_callers` root. A module is the directory of the nearest build manifest (`go.mod`,
  `package.json`, `pom.xml`, `build.gradle`, `Cargo.toml`, `pyproject.toml`, `setup.py`,
  `setup.cfg`), so one application in a monorepo does not affect its siblings. A module with
  no entry point (a library scanned alone, or an application whose framework the catalog does
  not know) keeps `no_callers` roots as before. An uncalled function stays a root when it is
  an instance method, when its name appears anywhere else in the application's source or in
  its module's configuration files (a handler passed to a router, a callback, a value in a
  table, a handler named in `template.yaml` or a Spring XML file), or when a decorator,
  attribute or annotation other than a test marker sits on it (`#[get("/")]`,
  `@app.on_event`). Go `init` functions,
  Java static initializers and module bodies stay roots. Test code nothing calls is no longer
  a root in a module with an entry point. The `root_kind` values are unchanged.
