- Reachability with application code known (`scan --scan-dependencies`,
  `--export-callgraph-project-reachability`): in a Java module with an entry point, an uncalled
  instance method is no longer a `no_callers` root when its class can have no instance. That is
  when the application never creates or names the class (no `new C(..)`, `C::new`, `C.class`,
  `C` in a created type's type arguments, `C` in a string literal or in a configuration file such
  as Spring XML, `META-INF/services` or `spring.factories`), no annotation other than
  `@Deprecated`, `@SuppressWarnings`, `@SafeVarargs` or `@Override` sits on the class, the class
  is a plain class or record that extends and implements only application types, and no subclass
  of it is live. Crypto reached only from such a method now reads `unreachable` instead of
  `reachable` with `analysis.no_callers_only: true`. Enum, interface and framework-annotated
  classes, classes with an outside supertype, and instance methods in Python, TypeScript,
  JavaScript, Go and Rust keep the old rule.
