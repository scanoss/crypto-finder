- Every request to the SCANOSS API (ruleset downloads from `/v3/rulesets`,
  the release check, and the `/v3/cryptography/reachability/component`
  lookups of `scan` and `cbom`)
  sends `User-Agent: crypto-finder/<version>` instead of
  `scanoss-crypto-finder`, so the API gateway reports the client as
  `crypto-finder` with its version.
