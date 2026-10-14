- Warm `--scan-dependencies` runs now reuse cached dependency findings when only
  per-run diagnostics or shell bookkeeping differ. The findings-cache identity no
  longer includes `SCANOSS_PHASE_TIMINGS`, `SCANOSS_CPUPROFILE`, `SCANOSS_MEMPROFILE`,
  `SCANOSS_TRACE`, `SCANOSS_SCANNER_JOBS`, `_`, `OLDPWD`, `PWD`, `SHLVL` or login-session
  variables (`SSH_*` session, `GPG_TTY`, `TERM_SESSION_ID`, `WINDOWID`, `TMUX_PANE`,
  `XDG_SESSION_ID`). Before, a timings file named per run made every dependency a
  cache miss. Findings are unchanged. Every other environment variable still
  partitions the cache. Cache entries written by earlier versions are rescanned once.
- Dependency scans log the findings-cache outcome per lookup and store (hit, absent,
  disabled, no identity, read error, stored, not stored because incomplete) at the end
  of the dependency scan, and `SCANOSS_PHASE_TIMINGS` writes them as a
  `phase_note dependency_findings_cache` line. Debug logging prints a digest of each
  cache-identity component per dependency, so the component that split two runs' keys
  can be found by diffing their logs.
