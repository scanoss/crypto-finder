- Reachability with application code known (`scan --scan-dependencies`,
  `--export-callgraph-project-reachability`): in a module with an entry point, an application
  function nothing calls no longer stays a `no_callers` root just because its name occurs in a
  comment, inside a longer string literal (a route path such as `"/fingerprint?data=hello"`, a
  log message), or as the member of a qualified name whose qualifier the file imports from
  another module (`liba.fingerprint(...)`, `liba::fingerprint`). Source references are now read
  with the language parser for Go, Python, Java, JavaScript, TypeScript and Rust (C and C++ skip
  strings and comments only). A string literal that is exactly the name (`getattr(m, "f")`,
  `getMethod("f")`) and a member of the function's own module still count, and configuration
  files are still read word by word. Crypto reached only from such a never-registered handler or
  callback now reads `unreachable` instead of `reachable` with `analysis.no_callers_only: true`.
