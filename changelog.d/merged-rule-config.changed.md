- Detection now loads the language-filtered rules from one merged YAML file
  instead of one file per rule file. This applies to the project scan and to
  every `--scan-dependencies` scan, for `--rules-dir`, `--rules` and the
  cached remote ruleset. OpenGrep loads each config file separately on every
  run, so each run starts faster: with the 709 rule files (3,696 rules) a
  Java, Python and JavaScript project needs, rule loading went from 45.7 s to
  32.5 s and from 138 s to 43 s of CPU on a busy host, and peak scan memory
  went from about 2.3 GB to 1.8 GB. Each npm dependency run loaded its rules
  in 24.7 s instead of about 30.5 s. Findings and rule IDs are unchanged. The
  dependency findings cache key changes once, so the first dependency scan
  after upgrading rescans dependencies. An OpenGrep error about a merged rule
  names a line of `merged-rules.yaml`; `--debug` logs the line where each
  source rule file starts in that file.
