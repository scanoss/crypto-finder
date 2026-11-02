- `convert` now reports an input file it cannot open or parse, such as malformed
  findings JSON, as `invalid_arguments` at stage `input` instead of
  `unknown_error` / `unknown`, so CI parsers can tell bad input from internal
  failures. The exit code stays `1`.
