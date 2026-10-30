- `scan --rule-prefilter` now defaults to `imports`: for the project and each
  dependency batch, the rules for libraries its sources never import are
  skipped before the scanner runs. Rules whose import requirement is unknown
  and rules declaring `metadata.imports: ["*"]` are always kept. Pass
  `--rule-prefilter off` or set `SCANOSS_RULE_PREFILTER=off` to run every
  rule. The prefilter is part of the dependency findings cache identity, so
  the first dependency scan after upgrading does not reuse cached results.
