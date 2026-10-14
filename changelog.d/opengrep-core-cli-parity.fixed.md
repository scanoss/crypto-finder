- `--opengrep-mode core` now fails a scan over an invalid rule the way the
  `opengrep` CLI does. A rule `opengrep-core` cannot load (a misspelled key, an
  unknown language, a pattern or regex it cannot parse) used to be dropped
  silently, with the other rules' findings reported as a success; the scan now
  runs the CLI instead, which rejects the rules file (exit code 7, 8 or 2 as
  before). Rules the CLI itself skips, such as ones incompatible with the
  installed version, are still skipped.
- `--opengrep-mode core` no longer reports findings of rules whose severity is
  `INVENTORY` or `EXPERIMENT`; the CLI leaves those out of its output.
- In `--opengrep-mode core`, the `lines` text of a finding in a file with
  invalid UTF-8 now replaces each undecodable byte sequence with U+FFFD, as the
  CLI does, instead of folding a run of them into one.
- The dependency findings cache now keys core-mode scans on the `opengrep-core`
  binary that actually runs (the one `SCANOSS_OPENGREP_CORE` names, the one
  found beside the `opengrep` executable, or the one the CLI unpacked), and on
  the `opengrep` executable only when core mode will run the CLI instead. Core
  mode keys change once: the first `--scan-dependencies` run after upgrading
  scans dependencies again. `--opengrep-mode cli` keys are unchanged.
