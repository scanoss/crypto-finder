- `SCANOSS_PHASE_TIMINGS=1` (or a file path) reports wall time, CPU time and
  allocations per scan phase, plus the call-graph source files that took longest to
  parse. `SCANOSS_CPUPROFILE`, `SCANOSS_MEMPROFILE` and `SCANOSS_TRACE` write Go
  CPU, heap and execution-trace profiles of a scan, as the hidden `--cpuprofile`,
  `--memprofile` and new `--trace` flags do.
