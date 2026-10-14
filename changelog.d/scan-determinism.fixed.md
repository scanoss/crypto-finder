- A rule that reaches the analysis engine's per-file time limit (5 s for the
  project scan, 30 s for dependency scans) now runs once more on that file with
  four times the limit, at least 30 s, and a file the engine gave up on after
  three timed-out rules runs every rule again. Findings the retry recovers are
  added and the file no longer counts as incomplete. Before, a busy host
  silently dropped such findings (for example PBKDF2 key sizes in Bouncy
  Castle's `PKCS12KeyStoreSpi`), so repeated scans of the same code could report
  different asset counts.
- Assets that two rules match at the same location now list their rules, and
  keep the first rule's match text, in a fixed order (location, then rule id)
  whatever order the engine reported them in. `--opengrep-mode core` orders
  results as the CLI does (by location, then rule id, not by rule), so both modes
  name the same first rule, e.g. for Bouncy Castle's `ISO9797Alg3Mac` in `DES.java`.
