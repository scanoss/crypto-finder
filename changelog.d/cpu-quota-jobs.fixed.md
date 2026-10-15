- Scans inside a container with a CPU limit no longer oversubscribe it. The default
  OpenGrep jobs for the project scan (`--scanner-jobs 0`), the jobs each concurrent
  dependency scan gets, and the default `--dep-workers` now count the CPUs the process
  may use, which honors the container's CPU limit, instead of the host's cores. On a
  32-core host with a 4-CPU limit, a core-mode scan of Bouncy Castle's `bcprov` drops
  from 213 s to 28 s, and a `--opengrep-mode cli` scan from 107 s to 41 s, with the same
  findings. The CLI mode now always passes `--jobs` to OpenGrep.
