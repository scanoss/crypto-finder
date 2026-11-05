- `scan`, `annotate`, `cbom` and `configure` now refuse a plain-HTTP SCANOSS API URL
  on a remote host, wherever it comes from (`--api-url`, `SCANOSS_API_URL` or the
  config file), and refuse a redirect from HTTPS to plain HTTP. Plain HTTP would send
  the API key and the downloaded ruleset unencrypted. HTTP to `localhost` or a loopback
  address still works. **Migration:** an on-premises API that only serves HTTP needs the
  new opt-in: pass `--allow-http`, set `SCANOSS_ALLOW_HTTP=true`, or save it once with
  `crypto-finder configure --api-url http://<host> --allow-http`. Each run that uses
  plain HTTP logs a warning. The command fails with `invalid_arguments` before any
  request, so a refused URL no longer falls back to a stale cached ruleset.
- `pkg/sbomcbom`: `Options.AllowHTTP` is new, and `Generate` returns `ErrInsecureURL`
  for a plain-HTTP `APIURL` on a remote host unless it is set.
