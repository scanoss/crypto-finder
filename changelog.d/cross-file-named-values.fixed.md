- Java scans now resolve an algorithm written as an enum constant's name:
  `KeyPairGenerator.getInstance(AlgoName.EC.name())` is reported as `EC`, also
  when the enum is declared in another file or package, and so is
  `AlgoName.EC.toString()` when neither the enum nor the constant overrides
  `toString`. An overridden `toString` or a getter on the enum stays
  unresolved. A bare `AlgoName.EC` argument is reported as before.
- Python scans now resolve an algorithm named by a module string constant of
  another module, through `from app.cfg.settings import ALG` (also with
  `as`), `import app.cfg.settings as s; s.ALG` or `from app.cfg import
  settings; settings.ALG`, and by a member of an `Enum` class: `Alg.SHA.value`
  gives the member's string and `Alg.SHA.name` its name. A bare `Alg.SHA` is
  resolved only for a `StrEnum` or `(str, Enum)` class. A name the module
  binds more than once, or a name the calling function rebinds, stays
  unresolved. Call-graph exports stamp `graph_algo_version` `graph-algo-21`;
  cached Java and Python structural graphs from `graph-algo-20` are rebuilt.
