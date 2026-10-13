- `scan --opengrep-mode core` (or `SCANOSS_OPENGREP_MODE=core`) runs `opengrep-core`
  directly instead of the Python `opengrep` CLI, for the project scan and every
  dependency batch. Targets, rule ids, messages, metadata, metavariables, lines
  and errors match what the CLI reports, so findings are unchanged. Core mode is
  pinned to OpenGrep 1.30.2 and finds the core binary the CLI unpacked (or the
  one `SCANOSS_OPENGREP_CORE` names); with another version, without the binary,
  or when the core run fails, the scan runs the CLI instead. The core-ready rules
  file is cached under the crypto-finder cache directory (`opengrep-core-rules/`).
  The default stays `cli`.
- `scan --rule-prefilter imports` (or `SCANOSS_RULE_PREFILTER=imports`) drops, per
  scanned unit (the project and each dependency batch), the rules whose library
  the unit's Go, Java, Python, JavaScript/TypeScript, Rust or C/C++ sources never
  import, judged from the import guards and qualified names in each rule's
  patterns or an explicit `metadata.imports` list. Rules whose requirement is
  unknown are kept. The default stays `off`. The OpenGrep mode and the prefilter
  are part of the dependency findings cache key.
