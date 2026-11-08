- Reachability with application code known: in a module with an entry point, an uncalled
  application function no longer stays a `no_callers` root because of an inert built-in marker.
  Rust lint, codegen and conditional-compilation attributes (`#[allow(dead_code)]`, `warn`,
  `deny`, `forbid`, `expect`, `inline`, `cold`, `track_caller`, `must_use`, `deprecated`, `doc`,
  `cfg`, `target_feature`, `rustfmt::*`, `clippy::*`, and a `cfg_attr` applying only those),
  Python standard-library decorators (`functools.cache`, `functools.lru_cache`, `functools.wraps`,
  `contextlib.contextmanager`, `typing.overload`, `typing.override`, `abc.abstractmethod`,
  `staticmethod`, `classmethod`, ...) and Java `@Deprecated`, `@SuppressWarnings`, `@SafeVarargs`
  and `@Override` register nothing. Crypto reached only from such a function now reads
  `unreachable`. Any other decorator, attribute or annotation (a framework's, a procedural
  macro, `#[no_mangle]`, `#[export_name]`) still keeps it a root, and every marker on a line is
  now read, not only the first.
