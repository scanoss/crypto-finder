- An unresolved Java, Python, JavaScript or TypeScript finding whose algorithm
  argument is read at run time now names that input in the new metadata key
  `algorithmSource`: `env:NAME` for an environment variable
  (`System.getenv("NAME")`, `os.environ["NAME"]`, `os.environ.get`,
  `os.getenv`, `process.env.NAME`, `process.env["NAME"]`), `property:KEY` for
  `System.getProperty("KEY")` or `getProperty("KEY")` on a
  `java.util.Properties`, and `argv:N` for a program argument (`args[N]` of a
  Java `main`, `sys.argv[N]`, `process.argv[N]`). The input is followed
  through a local bound once to the read and through function parameters in
  any project file; a key held in a constant, also of another file, resolves
  to its value. Several routes give a sorted, comma-joined list, at most 16.
  The key is set only on the generic asset the scan keeps when the algorithm
  stays unresolved, when the scan builds a call graph and a rule states a
  `parameterCondition` for the call. It is not added to the CBOM, and the
  report format version is unchanged.
- The name, key or default of such a read is no longer taken as the algorithm:
  `Signature.getInstance(System.getenv("SHA256withECDSA"))` or
  `hashlib.new(os.getenv("sha256"))` stays an unresolved finding instead of
  matching a rule for that algorithm, and `process.env.HASH_ALG` is no longer
  exported as the `resolved_value` of the argument. Call-graph exports stamp
  `graph_algo_version` `graph-algo-24`; cached Python and Node structural
  graphs from `graph-algo-23` are rebuilt.
