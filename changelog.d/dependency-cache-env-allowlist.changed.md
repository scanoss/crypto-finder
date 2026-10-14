- The dependency findings cache now keys an opengrep dependency scan on an audited
  allowlist of environment variables instead of the whole environment: the locale
  (`LANG`, `LC_ALL`, `LC_CTYPE`, `LOCPATH`), the dynamic loader (`LD_PRELOAD`,
  `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`), the OCaml runtime
  (`OCAMLRUNPARAM`, `CAMLRUNPARAM`) and the engine settings crypto-finder does not pass
  as flags (`SEMGREP_CORE_EXTRA`, `SEMGREP_BASELINE_COMMIT`, `SEMGREP_BASELINE_REF`,
  `SEMGREP_R2C_INTERNAL_EXPLICIT_SEMGREPIGNORE`, `SEMGREP_PYTHON_RECURSION_LIMIT_INCREASE`).
  `HOSTNAME`, `PATH`, `HOME`, CI run ids (`GITHUB_RUN_ID`, `CI_JOB_ID`, `BUILD_NUMBER`, ...),
  SSH session variables and other ambient variables no longer split the cache, so CI
  runs and hosts sharing a findings cache (for example the Postgres backend) reuse each
  other's dependency findings. Instead the key now includes the SHA-256 of the opengrep
  executable (and of `SCANOSS_OPENGREP_CORE` in core mode) and the dependency's source
  directory, which cached findings name and opengrep's results can depend on. Other
  scanners (`semgrep`) keep keying on every variable except crypto-finder's diagnostics
  and shell/login bookkeeping. Existing cache entries are rescanned once.
